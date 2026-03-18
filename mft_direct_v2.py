#!/usr/bin/env python3
"""
mft_direct.py — Raw $MFT Binary Parser & Targeted Forensic Analyser
Version: 2.0

Changes in v2.0:
  - Two-pass analysis: first pass builds parent chain map for full path resolution
  - Duplicate entries for same filename grouped under earliest timestamp (expandable tree)
  - LOLBins separated from true IOC matches — different severity, different section
  - Path-aware analysis: suspicious exec / LOLBin classification uses full resolved path
  - Known-benign path suppressions (System32, WinSxS, etc.) reduce noise

Analysis modules:
  1.  IOC filename matching          (configurable + 46 built-in terms)
  2.  LOLBin observed                (known Windows binaries abusable for proxy execution)
  3.  Suspicious executable locations (executables in user-writable paths)
  4.  Timestamp stomping detection   (SI vs FN divergence)
  5.  Staging / exfiltration clues   (archives, large files)
  6.  High-entropy executable names
  7.  Alternate Data Streams
  8.  Deleted entry recovery
  9.  Burst file creation windows    (ransomware / mass staging)

Usage:
    python mft_direct.py -f "$MFT" -o ./results/
    python mft_direct.py -f "$MFT" -o ./results/ --window-start "2024-03-15 08:00:00" --window-end "2024-03-15 18:00:00"
    python mft_direct.py -f "$MFT" -o ./results/ --ioc-file iocs.txt

Acquiring $MFT:
    CyLR.exe -of output.zip                    (collects $MFT automatically)
    FTK Imager > Logical Drive > right-click $MFT > Export Files
"""

import struct
import os
import sys
import math
import sqlite3
import argparse
import datetime
from collections import defaultdict

# ── CONSTANTS ──────────────────────────────────────────────────────────────────

MFT_RECORD_SIZE  = 1024
MFT_RECORD_MAGIC = b'FILE'
FILETIME_EPOCH   = datetime.datetime(1601, 1, 1)

ATTR_STANDARD_INFORMATION = 0x10
ATTR_FILE_NAME            = 0x30
ATTR_DATA                 = 0x80
ATTR_END                  = 0xFFFFFFFF

FLAG_IN_USE    = 0x0001
FLAG_DIRECTORY = 0x0002

# ── IOC / ANALYSIS CONFIGURATION ──────────────────────────────────────────────

DEFAULT_IOC_TERMS = [
    # Credential tools
    'mimikatz','mimi','sekurlsa','wce.exe','fgdump','procdump','nanodump','lsassy',
    # RAT / C2 — specific executable forms only to avoid false positives
    'meterpreter','cobaltstrike','brute_ratel',
    'beacon.exe','beacon.dll','beaconloader',
    'msf.exe','payload.exe','stager.exe',
    # Trickbot staging filenames
    'dinj','sinj','dpost','pwgrab','mailsearcher','wormdll','shareddll',
    'injectdll','importdll','bcctest','newbctest',
    # Recon tools
    'sharphound','bloodhound','adfind','masscan','nbtscan',
    # Lateral movement
    'psexesvc','wmiexec','smbexec','atexec','dcsync','secretsdump',
    # Exfil tools
    'rclone','megasync',
    # Suspicious loader names
    'svchost32','svch0st','taskhost32',
]

# LOLBins — legitimate Windows/system binaries that can be abused for proxy execution,
# defense evasion, or code injection. Reported separately from IOC hits.
# Source: https://lolbas-project.github.io/
LOLBIN_NAMES = {
    # Proxy execution
    'ttdinject.exe':    'Time Travel Debug injector — can proxy-execute arbitrary binary (T1218)',
    'tttracer.exe':     'Time Travel Tracer — can launch arbitrary process under debugger',
    'mshta.exe':        'HTML Application host — executes .hta files, commonly abused for payloads',
    'wscript.exe':      'Windows Script Host — executes VBS/JS scripts',
    'cscript.exe':      'Windows Script Host (console) — executes VBS/JS scripts',
    'regsvr32.exe':     'COM DLL registration — Squiblydoo technique for proxy execution',
    'rundll32.exe':     'DLL runner — proxy-execute code inside a DLL',
    'installutil.exe':  '.NET installer utility — bypass AppLocker via /logfile= trick',
    'regasm.exe':       '.NET assembly registration — proxy-execute .NET code',
    'regsvcs.exe':      '.NET component services — proxy-execute .NET code',
    'msiexec.exe':      'Windows Installer — can execute remote MSI payloads',
    'odbcconf.exe':     'ODBC configurator — can load arbitrary DLL via /a {REGSVR}',
    'pcalua.exe':       'Program Compatibility Assistant — proxy-execute via -a flag',
    'syncappvpublishingserver.exe': 'App-V publishing — execute PS commands without powershell.exe',
    'appsyncpublishingserver.exe':  'App-V alternate — same abuse path',
    'cmstp.exe':        'Connection Manager Profile Installer — UAC bypass + proxy exec',
    'xwizard.exe':      'Extensible Wizard host — proxy execute via COM',
    'ftp.exe':          'FTP client — can read commands from file, used to launch processes',
    'mavinject.exe':    'Microsoft Application Virtualization Injector — inject DLL into process',
    'microsoft.workflow.compiler.exe': '.NET workflow compiler — execute arbitrary XOML/C#',
    # Recon / discovery
    'nltest.exe':       'Network location testing — domain trust / DC enumeration',
    'dsquery.exe':      'Active Directory query tool — user/group/computer enumeration',
    'csvde.exe':        'AD CSV import/export — can dump AD object data',
    'ldifde.exe':       'AD LDIF import/export — can dump AD object data',
    'net.exe':          'Net command — user, group, share enumeration',
    'net1.exe':         'Net command variant — same abuse path as net.exe',
    'whoami.exe':       'Current user context — recon tool',
    'ipconfig.exe':     'IP configuration — network recon',
    'arp.exe':          'ARP table — local network host discovery',
    'nbtstat.exe':      'NetBIOS stats — host/share enumeration',
    'quser.exe':        'Query logged-on users — lateral movement recon',
    'qwinsta.exe':      'Query RDP sessions — lateral movement recon',
    'tasklist.exe':     'Process listing — AV/EDR detection evasion recon',
    # Credential / data access
    'ntdsutil.exe':     'AD database utility — can dump NTDS.dit for offline cracking',
    'esentutl.exe':     'ESE database utility — can copy locked files including NTDS.dit',
    'vssadmin.exe':     'Volume Shadow Copy admin — delete backups, copy locked files',
    'wbadmin.exe':      'Windows Backup — delete backups to prevent recovery',
    'diskshadow.exe':   'Disk Shadow — script-driven VSS operations, NTDS.dit access',
    'psexec.exe':       'Sysinternals remote exec — lateral movement (also IOC if not IT tool)',
    # Exfil / download
    'certutil.exe':     'Certificate utility — download files, base64 decode (T1105)',
    'bitsadmin.exe':    'BITS job manager — download files, persist via BITS jobs',
    'expand.exe':       'CAB expander — extract files, occasionally used as dropper',
    'extrac32.exe':     'CAB extractor — same abuse path as expand.exe',
    'makecab.exe':      'CAB creator — package files for exfiltration',
    'replace.exe':      'File replacer — overwrite files, occasionally used in attacks',
    'xcopy.exe':        'Extended copy — mass file staging',
    'robocopy.exe':     'Robust copy — large-scale file staging for exfiltration',
    # Script / compile
    'msbuild.exe':      '.NET build engine — compile and execute C# inline (T1127)',
    'csc.exe':          'C# compiler — compile and run arbitrary C# code',
    'vbc.exe':          'VB.NET compiler — compile and run arbitrary VB code',
    'jsc.exe':          'JScript compiler — compile JS to executable',
    'ilasm.exe':        'IL assembler — compile MSIL to executable',
    'aspnet_compiler.exe': 'ASP.NET compiler — compile and execute ASP.NET code',
    'bash.exe':         'WSL bash — execute Linux binaries, bypass some AV',
    'wsl.exe':          'Windows Subsystem for Linux — same bypass path',
    # Persistence / config
    'schtasks.exe':     'Task Scheduler CLI — create/modify scheduled tasks for persistence',
    'at.exe':           'Legacy task scheduler — schedule tasks (deprecated but still works)',
    'reg.exe':          'Registry editor CLI — modify Run keys, disable security features',
    'sc.exe':           'Service Control — create/modify services for persistence',
    'wmic.exe':         'WMI CLI — process creation, lateral movement, recon (T1047)',
    'mofcomp.exe':      'MOF compiler — install WMI subscriptions for persistence',
}

# Known-benign filenames/path fragments — never trigger IOC or LOLBin hits.
IOC_EXCLUSIONS = [
    'imprbeacons.dat',
    'beacons.dat',
    'beacon.dat',
    'contentdeliverymanager',
]

EXEC_EXTENSIONS = {
    '.exe','.dll','.sys','.bat','.cmd','.ps1','.vbs','.js','.hta',
    '.scr','.pif','.com','.msi','.jar','.wsf','.wsh','.lnk','.inf',
}

STAGING_EXTENSIONS = {
    '.zip','.7z','.rar','.tar','.gz','.bz2','.xz','.cab','.iso',
    '.img','.wim','.001','.002','.csv','.xlsx','.xls','.docx','.doc',
    '.pdf','.pst','.ost','.mbox','.sql','.bak','.dump','.db','.sqlite',
}

# Path fragments suspicious for executables
SUSPICIOUS_PATH_FRAGS = [
    'temp','tmp','appdata','programdata','public',
    'desktop','downloads','documents','perflogs','intel','recycle',
]

# Path fragments benign for executables — suppress noise from system paths
BENIGN_PATH_FRAGS = [
    'windows\\system32','windows\\syswow64','windows\\winsxs',
    'program files','windows\\servicing','windows\\assembly',
    'windows\\microsoft.net','windows\\installer','windows\\softwaredistribution',
    'windowsapps',
]

BURST_COUNT    = 50
BURST_WINDOW_S = 60

# ── WINDOWS FILETIME ───────────────────────────────────────────────────────────

def filetime_to_dt(ft):
    if ft == 0:
        return None
    try:
        return FILETIME_EPOCH + datetime.timedelta(microseconds=ft // 10)
    except (OverflowError, OSError):
        return None

def ts(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S') if dt else ''

def parse_ts(s):
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d'):
        try:
            return datetime.datetime.strptime(s.strip(), fmt)
        except ValueError:
            continue
    raise ValueError(f'Cannot parse timestamp: {s!r}')

# ── MFT RECORD PARSING ─────────────────────────────────────────────────────────

class MFTRecord:
    __slots__ = (
        'entry_num','in_use','is_dir','sequence',
        'si_created','si_modified','si_mft_mod','si_accessed','si_flags',
        'fn_created','fn_modified','fn_mft_mod','fn_accessed',
        'filename','parent_entry','filesize','alloc_size',
        'has_ads','attr_count','namespace',
    )
    def __init__(self):
        for s in self.__slots__:
            setattr(self, s, None)
        self.has_ads    = False
        self.attr_count = 0

    @property
    def extension(self):
        if not self.filename:
            return ''
        _, ext = os.path.splitext(self.filename)
        return ext.lower()


def _fixup(raw_record):
    record = bytearray(raw_record)
    try:
        usa_offset = struct.unpack_from('<H', record, 4)[0]
        usa_count  = struct.unpack_from('<H', record, 6)[0]
        if usa_offset + usa_count * 2 > len(record):
            return record
        check_word = struct.unpack_from('<H', record, usa_offset)[0]
        for i in range(1, usa_count):
            sector_end = i * 512 - 2
            if sector_end + 2 > len(record):
                break
            fixup_val = struct.unpack_from('<H', record, usa_offset + i * 2)[0]
            struct.pack_into('<H', record, sector_end, fixup_val)
    except Exception:
        pass
    return record


def _parse_resident_attr(record, offset):
    if offset + 8 > len(record):
        return None
    attr_type = struct.unpack_from('<I', record, offset)[0]
    if attr_type == ATTR_END:
        return None
    attr_len = struct.unpack_from('<I', record, offset + 4)[0]
    if attr_len < 16 or offset + attr_len > len(record):
        return None
    non_resident = record[offset + 8]
    if non_resident:
        return (attr_type, b'', offset + attr_len)
    content_off = struct.unpack_from('<H', record, offset + 20)[0]
    content_len = struct.unpack_from('<I', record, offset + 16)[0]
    content_start = offset + content_off
    content_end   = min(content_start + content_len, len(record))
    return (attr_type, bytes(record[content_start:content_end]), offset + attr_len)


def _parse_si(content):
    if len(content) < 48:
        return None
    cr, mod, mft_mod, acc = struct.unpack_from('<QQQQ', content, 0)
    flags = struct.unpack_from('<I', content, 32)[0] if len(content) >= 36 else 0
    return (filetime_to_dt(cr), filetime_to_dt(mod),
            filetime_to_dt(mft_mod), filetime_to_dt(acc), flags)


def _parse_fn(content):
    if len(content) < 66:
        return None
    parent_ref   = struct.unpack_from('<Q', content, 0)[0]
    parent_entry = parent_ref & 0x0000FFFFFFFFFFFF
    cr, mod, mft_mod, acc = struct.unpack_from('<QQQQ', content, 8)
    alloc_size   = struct.unpack_from('<Q', content, 40)[0]
    real_size    = struct.unpack_from('<Q', content, 48)[0]
    flags        = struct.unpack_from('<I', content, 56)[0]
    name_len     = content[64]
    namespace    = content[65]
    name_bytes   = content[66: 66 + name_len * 2]
    try:
        name = name_bytes.decode('utf-16-le', errors='replace')
    except Exception:
        name = ''
    return (parent_entry, filetime_to_dt(cr), filetime_to_dt(mod),
            filetime_to_dt(mft_mod), filetime_to_dt(acc),
            alloc_size, real_size, flags, name, namespace)


def parse_record(raw_record, entry_num):
    if len(raw_record) < MFT_RECORD_SIZE or raw_record[:4] != MFT_RECORD_MAGIC:
        return None
    record = _fixup(raw_record)
    rec = MFTRecord()
    rec.entry_num = entry_num
    try:
        attr_offset = struct.unpack_from('<H', record, 20)[0]
        rec_flags   = struct.unpack_from('<H', record, 22)[0]
        rec.sequence = struct.unpack_from('<H', record, 16)[0]
    except struct.error:
        return None
    rec.in_use  = bool(rec_flags & FLAG_IN_USE)
    rec.is_dir  = bool(rec_flags & FLAG_DIRECTORY)
    if attr_offset < 48 or attr_offset >= MFT_RECORD_SIZE:
        return None

    offset = attr_offset
    fn_priority = -1
    data_count  = 0

    while offset < MFT_RECORD_SIZE:
        result = _parse_resident_attr(record, offset)
        if result is None:
            break
        attr_type, content, next_offset = result
        rec.attr_count += 1

        if attr_type == ATTR_STANDARD_INFORMATION and content:
            parsed = _parse_si(content)
            if parsed:
                rec.si_created, rec.si_modified, rec.si_mft_mod, rec.si_accessed, rec.si_flags = parsed

        elif attr_type == ATTR_FILE_NAME and content:
            parsed = _parse_fn(content)
            if parsed:
                (parent_entry, fn_cr, fn_mod, fn_mft, fn_acc,
                 alloc_size, real_size, flags, name, namespace) = parsed
                priority = {1: 3, 3: 2, 0: 1, 2: 0}.get(namespace, 0)
                if priority > fn_priority and name:
                    fn_priority      = priority
                    rec.filename     = name
                    rec.parent_entry = parent_entry
                    rec.fn_created   = fn_cr
                    rec.fn_modified  = fn_mod
                    rec.fn_mft_mod   = fn_mft
                    rec.fn_accessed  = fn_acc
                    rec.filesize     = real_size
                    rec.alloc_size   = alloc_size
                    rec.namespace    = namespace

        elif attr_type == ATTR_DATA:
            data_count += 1
            if data_count > 1:
                rec.has_ads = True

        offset = next_offset

    return rec if rec.filename else None


def stream_mft(mft_path):
    entry_num = 0
    with open(mft_path, 'rb') as f:
        while True:
            raw = f.read(MFT_RECORD_SIZE)
            if not raw:
                break
            if len(raw) == MFT_RECORD_SIZE:
                rec = parse_record(raw, entry_num)
                if rec is not None:
                    yield entry_num, rec
            entry_num += 1

# ── PATH RESOLUTION ────────────────────────────────────────────────────────────

def build_path_map(mft_path):
    """
    First pass: build {entry_num: (filename, parent_entry, is_dir)} map.
    Used to resolve full paths in the second analysis pass.
    """
    path_map = {}
    entry_num = 0
    with open(mft_path, 'rb') as f:
        while True:
            raw = f.read(MFT_RECORD_SIZE)
            if not raw:
                break
            if len(raw) == MFT_RECORD_SIZE and raw[:4] == MFT_RECORD_MAGIC:
                rec = parse_record(raw, entry_num)
                if rec and rec.filename:
                    path_map[entry_num] = (rec.filename, rec.parent_entry, rec.is_dir)
            entry_num += 1
    return path_map


def resolve_path(entry_num, path_map, _cache=None, _depth=0):
    """
    Walk parent chain to reconstruct full path.
    Cached to avoid redundant traversals on large $MFTs.
    """
    if _cache is None:
        _cache = {}
    if entry_num in _cache:
        return _cache[entry_num]
    if _depth > 32 or entry_num not in path_map:
        return ''
    filename, parent_entry, is_dir = path_map[entry_num]
    # Entry 5 is the root directory
    if entry_num == 5 or parent_entry == 5 or parent_entry == entry_num:
        result = '\\' + filename
    else:
        parent_path = resolve_path(parent_entry, path_map, _cache, _depth + 1)
        result = parent_path + '\\' + filename if parent_path else '\\' + filename
    _cache[entry_num] = result
    return result

# ── ANALYSIS HELPERS ───────────────────────────────────────────────────────────

def shannon_entropy(name):
    stem = os.path.splitext(name)[0] if name else ''
    if len(stem) < 6:
        return 0.0
    freq = defaultdict(int)
    for c in stem.lower():
        freq[c] += 1
    n = len(stem)
    return round(-sum((v/n) * math.log2(v/n) for v in freq.values()), 3)


def looks_random(filename):
    stem = os.path.splitext(filename)[0] if filename else ''
    if len(stem) < 8:
        return False
    hex_ratio = sum(1 for c in stem.lower() if c in '0123456789abcdef') / len(stem)
    if hex_ratio > 0.85:
        return True
    if shannon_entropy(filename) > 3.8 and len(stem) >= 10:
        return True
    return False


def path_is_suspicious(full_path_lower):
    """True if path is a suspicious location for an executable."""
    if not full_path_lower:
        return False
    for frag in BENIGN_PATH_FRAGS:
        if frag in full_path_lower:
            return False
    for frag in SUSPICIOUS_PATH_FRAGS:
        if frag in full_path_lower:
            return True
    return False


def is_excluded(filename_lower):
    for excl in IOC_EXCLUSIONS:
        if excl in filename_lower:
            return True
    return False


def ioc_match(filename_lower, ioc_list):
    if is_excluded(filename_lower):
        return None
    for term in ioc_list:
        if term in filename_lower:
            return term
    return None


def lolbin_match(filename_lower):
    if is_excluded(filename_lower):
        return None
    return LOLBIN_NAMES.get(filename_lower.split('\\')[-1])


def human_delta(seconds):
    if seconds < 60:
        return f'{int(seconds)}s'
    elif seconds < 3600:
        return f'{int(seconds/60)}m {int(seconds%60)}s'
    elif seconds < 86400:
        return f'{int(seconds/3600)}h {int((seconds%3600)/60)}m'
    else:
        d = int(seconds / 86400)
        return f'{d}d {int((seconds%86400)/3600)}h'

# ── DEDUPLICATION / GROUPING ───────────────────────────────────────────────────

def group_by_filename(findings):
    """
    Group findings by (filename, finding_type).
    Returns list of group dicts:
      {filename, type, path, earliest_si, count, occurrences: [...]}
    Sorted by earliest SI timestamp.
    """
    groups = defaultdict(list)
    for f in findings:
        key = (f.get('filename','').lower(), f.get('type',''))
        groups[key].append(f)

    result = []
    for (fname_l, ftype), items in groups.items():
        # Sort occurrences by SI timestamp
        def sort_key(x):
            s = x.get('si_created','')
            return s if s else '9999'
        items_sorted = sorted(items, key=sort_key)
        primary = items_sorted[0]
        result.append({
            'filename':     primary.get('filename',''),
            'type':         ftype,
            'path':         primary.get('path',''),
            'ext':          primary.get('ext',''),
            'earliest_si':  primary.get('si_created',''),
            'fn_created':   primary.get('fn_created',''),
            'filesize':     primary.get('filesize',0),
            'flags':        primary.get('flags',''),
            'in_use':       primary.get('in_use', True),
            'ioc_term':     primary.get('ioc_term',''),
            'lolbin_desc':  primary.get('lolbin_desc',''),
            'delta_readable': primary.get('delta_readable',''),
            'severity':     primary.get('severity',''),
            'entropy':      primary.get('entropy',''),
            'entry':        primary.get('entry',''),
            'count':        len(items_sorted),
            'occurrences':  items_sorted,  # all timestamps
        })

    return sorted(result, key=lambda x: x['earliest_si'] or '9999')

# ── ANALYSER ───────────────────────────────────────────────────────────────────

class Analyser:
    def __init__(self, ioc_list, path_map, window_start=None, window_end=None,
                 large_file_bytes=100*1024*1024):
        self.ioc_list     = [t.lower() for t in ioc_list]
        self.path_map     = path_map
        self._path_cache  = {}
        self.window_start = window_start
        self.window_end   = window_end
        self.large_bytes  = large_file_bytes

        self.ioc_hits        = []
        self.lolbin_observed = []
        self.suspicious_exec = []
        self.timestomp       = []
        self.staging         = []
        self.random_exec     = []
        self.ads_files       = []
        self.deleted         = []
        self.burst_windows   = []

        self._ts_list    = []
        self.total       = 0
        self.dirs_skipped = 0

    def _in_window(self, dt):
        if dt is None:
            return True
        if self.window_start and dt < self.window_start:
            return False
        if self.window_end and dt > self.window_end:
            return False
        return True

    def feed(self, rec):
        self.total += 1
        if rec.is_dir:
            self.dirs_skipped += 1
            return

        fname   = rec.filename or ''
        fname_l = fname.lower()
        ext     = rec.extension
        size    = rec.filesize or 0
        si_cr   = rec.si_created
        fn_cr   = rec.fn_created

        # Resolve full path using parent chain map
        full_path   = resolve_path(rec.entry_num, self.path_map, self._path_cache)
        full_path_l = full_path.lower()

        if not self._in_window(si_cr):
            return

        if si_cr:
            self._ts_list.append((si_cr, fname, full_path))

        base = {
            'entry': rec.entry_num, 'filename': fname, 'ext': ext,
            'path': full_path,
            'si_created': ts(si_cr), 'fn_created': ts(fn_cr),
            'si_modified': ts(rec.si_modified),
            'filesize': size, 'in_use': rec.in_use,
        }

        # 1. IOC MATCH ────────────────────────────────────────────────
        hit = ioc_match(fname_l, self.ioc_list)
        if hit:
            self.ioc_hits.append({**base, 'type': 'IOC_MATCH', 'ioc_term': hit})

        # 2. LOLBIN OBSERVED ──────────────────────────────────────────
        # Only flag LOLBins when found OUTSIDE their expected system paths
        lolbin_desc = lolbin_match(fname_l)
        if lolbin_desc:
            in_system_path = any(frag in full_path_l for frag in BENIGN_PATH_FRAGS)
            if not in_system_path:
                self.lolbin_observed.append({
                    **base, 'type': 'LOLBIN',
                    'lolbin_desc': lolbin_desc,
                })

        # 3. SUSPICIOUS EXECUTABLE LOCATIONS ──────────────────────────
        if ext in EXEC_EXTENSIONS and path_is_suspicious(full_path_l):
            flags = []
            if looks_random(fname):
                flags.append('high-entropy name')
            if rec.has_ads:
                flags.append('ADS present')
            if not rec.in_use:
                flags.append('deleted')
            self.suspicious_exec.append({
                **base, 'type': 'SUSPICIOUS_EXEC',
                'flags': ', '.join(flags),
            })

        # 4. TIMESTAMP STOMPING ───────────────────────────────────────
        if si_cr and fn_cr:
            delta = abs((fn_cr - si_cr).total_seconds())
            if delta > 2:
                severity = 'HIGH' if delta > 3600 else 'MEDIUM'
                self.timestomp.append({
                    **base, 'type': 'TIMESTOMP',
                    'delta_secs': int(delta),
                    'delta_readable': human_delta(delta),
                    'severity': severity,
                })

        # 5. STAGING / EXFIL ──────────────────────────────────────────
        if ext in STAGING_EXTENSIONS:
            stg_flags = []
            if size >= self.large_bytes:
                stg_flags.append(f'large ({size/1024/1024:.1f} MB)')
            if ext in {'.zip','.7z','.rar','.tar','.gz','.cab','.iso'}:
                stg_flags.append('archive')
            if stg_flags:
                self.staging.append({**base, 'type': 'STAGING', 'flags': ', '.join(stg_flags)})

        # 6. HIGH-ENTROPY EXECUTABLE NAMES ────────────────────────────
        if ext in EXEC_EXTENSIONS and looks_random(fname):
            self.random_exec.append({
                **base, 'type': 'RANDOM_NAME_EXEC',
                'entropy': shannon_entropy(fname),
            })

        # 7. ALTERNATE DATA STREAMS ───────────────────────────────────
        if rec.has_ads:
            self.ads_files.append({**base, 'type': 'ADS'})

        # 8. DELETED ENTRIES ──────────────────────────────────────────
        if not rec.in_use and ext in EXEC_EXTENSIONS | STAGING_EXTENSIONS:
            self.deleted.append({**base, 'type': 'DELETED'})

    def finalise(self):
        if len(self._ts_list) < BURST_COUNT:
            return
        sorted_ts = sorted(self._ts_list, key=lambda x: x[0])
        n = len(sorted_ts)
        i = 0
        while i <= n - BURST_COUNT:
            t_start = sorted_ts[i][0]
            t_end   = sorted_ts[i + BURST_COUNT - 1][0]
            delta   = (t_end - t_start).total_seconds()
            if delta <= BURST_WINDOW_S:
                self.burst_windows.append({
                    'type': 'BURST',
                    'window_start': ts(t_start),
                    'window_end':   ts(t_end),
                    'count': BURST_COUNT,
                    'duration_secs': int(delta),
                    'first_file': sorted_ts[i][1],
                    'last_file':  sorted_ts[i + BURST_COUNT - 1][1],
                    'first_path': sorted_ts[i][2],
                    'last_path':  sorted_ts[i + BURST_COUNT - 1][2],
                })
                i += BURST_COUNT
            else:
                i += 1

# ── OUTPUT: SQLITE ──────────────────────────────────────────────────────────────

SCHEMA = '''
CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_type    TEXT,
    entry           INTEGER,
    filename        TEXT,
    path            TEXT,
    ext             TEXT,
    earliest_si     TEXT,
    fn_created      TEXT,
    si_modified     TEXT,
    filesize        INTEGER,
    flags           TEXT,
    in_use          INTEGER,
    ioc_term        TEXT,
    lolbin_desc     TEXT,
    delta_secs      INTEGER,
    delta_readable  TEXT,
    severity        TEXT,
    entropy         REAL,
    occurrence_count INTEGER,
    all_si_timestamps TEXT
);
CREATE TABLE IF NOT EXISTS bursts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    window_start  TEXT,
    window_end    TEXT,
    count         INTEGER,
    duration_secs INTEGER,
    first_file    TEXT,
    last_file     TEXT,
    first_path    TEXT,
    last_path     TEXT
);
CREATE INDEX IF NOT EXISTS idx_type ON findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_si   ON findings(earliest_si);
'''

def write_sqlite(analyser, db_path):
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    c = conn.cursor()

    all_buckets = [
        analyser.ioc_hits, analyser.lolbin_observed, analyser.suspicious_exec,
        analyser.timestomp, analyser.staging, analyser.random_exec,
        analyser.ads_files, analyser.deleted,
    ]

    total = 0
    for bucket in all_buckets:
        grouped = group_by_filename(bucket)
        for g in grouped:
            all_ts = ', '.join(o.get('si_created','') for o in g['occurrences'])
            c.execute('''INSERT INTO findings (
                finding_type, entry, filename, path, ext, earliest_si, fn_created,
                si_modified, filesize, flags, in_use, ioc_term, lolbin_desc,
                delta_secs, delta_readable, severity, entropy,
                occurrence_count, all_si_timestamps
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', (
                g['type'], g['entry'], g['filename'], g['path'], g['ext'],
                g['earliest_si'], g['fn_created'], None,
                g['filesize'], g['flags'], 1 if g['in_use'] else 0,
                g['ioc_term'], g['lolbin_desc'],
                None, g['delta_readable'], g['severity'], g['entropy'],
                g['count'], all_ts,
            ))
            total += 1

    for b in analyser.burst_windows:
        c.execute('''INSERT INTO bursts
            (window_start,window_end,count,duration_secs,first_file,last_file,first_path,last_path)
            VALUES (?,?,?,?,?,?,?,?)''', (
            b['window_start'], b['window_end'], b['count'], b['duration_secs'],
            b['first_file'], b['last_file'], b.get('first_path',''), b.get('last_path',''),
        ))

    conn.commit()
    conn.close()
    return total

# ── OUTPUT: HTML REPORT ────────────────────────────────────────────────────────

def write_html(analyser, html_path, source_file, window_start, window_end):

    def build_grouped_table(bucket, cols, extra_col=None):
        """Build HTML table with expandable grouped rows."""
        grouped = group_by_filename(bucket)
        if not grouped:
            return '<p class="none">No findings.</p>', 0

        # Header
        all_cols = cols + ([extra_col] if extra_col else []) + ['occurrences','path']
        th = ''.join(f'<th>{c}</th>' for c in all_cols)
        tbody = ''

        for g in grouped:
            cls = ''
            ftype = g['type']
            if ftype == 'IOC_MATCH':
                cls = 'high'
            elif g.get('severity') == 'HIGH' or ftype == 'LOLBIN':
                cls = 'high' if ftype == 'IOC_MATCH' else 'medium'
            elif g.get('severity') == 'MEDIUM':
                cls = 'medium'
            elif not g.get('in_use', True):
                cls = 'deleted'

            count = g['count']
            has_dupes = count > 1
            toggle_id = f'grp_{abs(hash(g["filename"]+g["type"]))}'

            # Build cells for configured columns
            def cell(col):
                col_l = col.lower()
                if col_l == 'earliest_si':
                    return g.get('earliest_si','')
                if col_l == 'fn_created':
                    return g.get('fn_created','')
                if col_l == 'filesize':
                    sz = g.get('filesize',0)
                    return f'{sz:,}' if sz else ''
                if col_l == 'in_use':
                    return '✓' if g.get('in_use', True) else '✗ deleted'
                if col_l == 'ioc_term':
                    return g.get('ioc_term','')
                if col_l == 'lolbin_desc':
                    d = g.get('lolbin_desc','')
                    return f'<span title="{d}" style="cursor:help">{d[:60]}{"…" if len(d)>60 else ""}</span>'
                if col_l == 'delta_readable':
                    return g.get('delta_readable','')
                if col_l == 'severity':
                    return g.get('severity','')
                if col_l == 'entropy':
                    return str(g.get('entropy',''))
                if col_l == 'flags':
                    return g.get('flags','')
                if col_l == 'filename':
                    return f'<strong>{g.get("filename","")}</strong>'
                if col_l == 'ext':
                    return g.get('ext','')
                if col_l == 'entry':
                    return str(g.get('entry',''))
                return ''

            tds = ''.join(f'<td>{cell(c)}</td>' for c in cols)
            if extra_col:
                tds += f'<td>{cell(extra_col)}</td>'

            # Occurrences column
            if has_dupes:
                occ_btn = (f'<td><button class="tog" onclick="toggleGroup(\'{toggle_id}\')">'
                           f'{count} occurrences ▾</button></td>')
            else:
                occ_btn = '<td><span style="color:#484f58">1</span></td>'

            # Path cell
            path_val = g.get('path','')
            tds += occ_btn + f'<td class="path">{path_val}</td>'

            tbody += f'<tr class="{cls}">{tds}</tr>'

            # Expandable sub-rows for duplicate occurrences
            if has_dupes:
                for occ in g['occurrences']:
                    occ_si  = occ.get('si_created','')
                    occ_fn  = occ.get('fn_created','')
                    occ_ent = occ.get('entry','')
                    tbody += (
                        f'<tr class="subrow" id="{toggle_id}" style="display:none">'
                        f'<td colspan="2" style="padding-left:32px;color:#8b949e">'
                        f'↳ entry {occ_ent}</td>'
                        f'<td>{occ_si}</td>'
                        f'<td>{occ_fn}</td>'
                        f'<td colspan="{len(all_cols)-4}"></td>'
                        f'</tr>'
                    )

        table = f'<table><thead><tr>{th}</tr></thead><tbody>{tbody}</tbody></table>'
        return table, len(grouped)

    # Section definitions: (title, bucket, columns, extra_col, description)
    sections = [
        ('IOC Filename Matches', analyser.ioc_hits,
         ['filename','ioc_term','ext','earliest_si','fn_created','filesize','in_use'],
         None,
         'Known-bad filename matches against the IOC list. Review immediately.'),

        ('LOLBin Observed Outside System Path', analyser.lolbin_observed,
         ['filename','ext','earliest_si','fn_created','filesize','in_use'],
         'lolbin_desc',
         'Legitimate Windows binaries known to be abusable for proxy execution or defense evasion '
         '(LOLBAS project). These are only flagged when found OUTSIDE expected system paths '
         '(System32/SysWOW64/Program Files). Presence in a user or temp path warrants investigation.'),

        ('Suspicious Executable Locations', analyser.suspicious_exec,
         ['filename','ext','earliest_si','fn_created','filesize','flags','in_use'],
         None,
         'Executables in user-writable or temp paths (AppData, Temp, Desktop, Downloads, etc.).'),

        ('Timestamp Stomping Suspects', analyser.timestomp,
         ['filename','ext','earliest_si','fn_created','delta_readable','severity','in_use'],
         None,
         'SI $STANDARD_INFORMATION timestamps diverge from FN $FILE_NAME timestamps. '
         'SI can be set by an attacker; FN is NTFS-controlled. HIGH = >1 hour divergence.'),

        ('Staging / Exfiltration Indicators', analyser.staging,
         ['filename','ext','earliest_si','fn_created','filesize','flags','in_use'],
         None,
         'Archives and large files consistent with data staging. '
         'Cross-reference with SRUM bytes-sent and firewall outbound logs.'),

        ('High-Entropy Executable Names', analyser.random_exec,
         ['filename','ext','entropy','earliest_si','fn_created','filesize','in_use'],
         None,
         'Executables with randomised or hex-string names — dropper/stager naming pattern.'),

        ('Alternate Data Streams', analyser.ads_files,
         ['filename','ext','earliest_si','filesize','in_use'],
         None,
         'Files with Alternate Data Streams. May conceal payloads or Zone.Identifier markers.'),

        ('Deleted Entry Recovery', analyser.deleted,
         ['filename','ext','earliest_si','fn_created','filesize','in_use'],
         None,
         'Executables and archives in unallocated MFT entries. '
         'Content may be recoverable depending on disk state.'),
    ]

    # Build burst table separately (different structure)
    burst_rows = ''
    for b in analyser.burst_windows:
        burst_rows += (
            f'<tr><td>{b["window_start"]}</td><td>{b["window_end"]}</td>'
            f'<td>{b["count"]}</td><td>{b["duration_secs"]}s</td>'
            f'<td class="path">{b["first_file"]}<br><small>{b.get("first_path","")}</small></td>'
            f'<td class="path">{b["last_file"]}<br><small>{b.get("last_path","")}</small></td></tr>'
        )
    burst_table = (
        '<table><thead><tr>'
        '<th>Window Start</th><th>Window End</th>'
        '<th>Count</th><th>Duration</th>'
        '<th>First File</th><th>Last File</th>'
        '</tr></thead><tbody>' + burst_rows + '</tbody></table>'
        if burst_rows else '<p class="none">No findings.</p>'
    )

    # Build section HTML
    sec_html = ''
    total_unique = 0
    nav_items = []

    for title, bucket, cols, extra_col, desc in sections:
        anchor = title.replace(' ', '_')
        table, count = build_grouped_table(bucket, cols, extra_col)
        total_unique += count
        nav_items.append(f'<a href="#{anchor}">{title} <span>({count})</span></a>')
        sec_html += f'''
<section id="{anchor}">
  <h2>{title} <span class="badge">{count}</span></h2>
  <p class="desc">{desc}</p>
  {table}
</section>'''

    # Burst section
    burst_count = len(analyser.burst_windows)
    nav_items.append(f'<a href="#Burst_Windows">Burst Windows <span>({burst_count})</span></a>')
    sec_html += f'''
<section id="Burst_Windows">
  <h2>Burst Creation Windows <span class="badge">{burst_count}</span></h2>
  <p class="desc">{BURST_COUNT}+ files created within {BURST_WINDOW_S}s.
  Ransomware encryption, mass tool deployment, or bulk staging indicator.</p>
  {burst_table}
</section>'''

    nav = ''.join(nav_items)
    win_str = ''
    if window_start or window_end:
        ws = ts(window_start) if window_start else 'start'
        we = ts(window_end)   if window_end   else 'end'
        win_str = f'<p><strong>Window:</strong> {ws} → {we}</p>'

    generated = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>MFT Direct Analysis — {os.path.basename(source_file)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:"Segoe UI",Arial,sans-serif;background:#0d1117;color:#c9d1d9;font-size:13px}}
header{{background:#161b22;padding:20px 28px;border-bottom:3px solid #2e5f8a}}
header h1{{font-size:20px;color:#58a6ff}}
header .meta{{color:#8b949e;font-size:11.5px;margin-top:5px}}
nav{{background:#0d1117;padding:10px 28px;display:flex;gap:14px;flex-wrap:wrap;
     border-bottom:1px solid #21262d;position:sticky;top:0;z-index:99;background:#0d1117}}
nav a{{color:#58a6ff;text-decoration:none;font-size:11.5px;white-space:nowrap}}
nav a span{{color:#8b949e}}
nav a:hover{{color:#fff}}
.summary{{background:#161b22;margin:20px 28px 0;padding:14px 18px;
          border-left:4px solid #2e5f8a;border-radius:3px;font-size:12px;color:#8b949e;line-height:1.7}}
.summary strong{{color:#c9d1d9}}
section{{margin:28px 28px 0}}
h2{{color:#58a6ff;font-size:15px;padding-bottom:7px;border-bottom:1px solid #21262d;margin-bottom:9px}}
.badge{{background:#1f6feb;color:#fff;font-size:10px;padding:1px 7px;border-radius:9px;margin-left:7px;vertical-align:middle}}
.desc{{color:#8b949e;font-size:11px;margin-bottom:10px;font-style:italic;line-height:1.5}}
.none{{color:#484f58;font-style:italic;padding:6px 0;font-size:12px}}
table{{width:100%;border-collapse:collapse;font-size:11.5px;margin-bottom:8px}}
th{{background:#161b22;color:#58a6ff;text-align:left;padding:6px 9px;
    position:sticky;top:38px;cursor:pointer;border-bottom:1px solid #21262d;
    user-select:none;white-space:nowrap}}
th:hover{{background:#1c2128}}
td{{padding:5px 9px;border-bottom:1px solid #161b22;word-break:break-all;vertical-align:top}}
td.path{{font-family:"Courier New",monospace;font-size:10.5px;color:#8b949e;word-break:break-all}}
tr:hover td{{background:#161b22}}
tr.high td{{background:#2d1515;border-left:3px solid #f85149}}
tr.medium td{{background:#2d2008;border-left:3px solid #d29922}}
tr.deleted td{{color:#484f58;font-style:italic}}
tr.subrow td{{background:#0d1117;border-left:3px solid #30363d;font-size:11px}}
tr.subrow:hover td{{background:#161b22}}
button.tog{{background:#21262d;color:#8b949e;border:1px solid #30363d;
            padding:2px 8px;border-radius:4px;cursor:pointer;font-size:11px}}
button.tog:hover{{background:#2d333b;color:#c9d1d9}}
footer{{margin:36px 28px 28px;color:#484f58;font-size:11px;padding-bottom:20px}}
</style>
<script>
function toggleGroup(id){{
  const rows=document.querySelectorAll('#'+id);
  const btn=event.target;
  const visible=rows[0]&&rows[0].style.display!=='none';
  rows.forEach(r=>r.style.display=visible?'none':'table-row');
  btn.textContent=visible?btn.textContent.replace('▴','▾'):btn.textContent.replace('▾','▴');
}}
document.addEventListener('DOMContentLoaded',()=>{{
  document.querySelectorAll('th').forEach((th,idx)=>{{
    th.addEventListener('click',()=>{{
      const tbody=th.closest('table').querySelector('tbody');
      const rows=[...tbody.querySelectorAll('tr:not(.subrow)')];
      const asc=th.dataset.asc!=='true';
      rows.sort((a,b)=>{{
        const av=a.cells[idx]?.textContent.trim()||'';
        const bv=b.cells[idx]?.textContent.trim()||'';
        return asc?av.localeCompare(bv,undefined,{{numeric:true}}):bv.localeCompare(av,undefined,{{numeric:true}});
      }});
      rows.forEach(r=>tbody.appendChild(r));
      th.dataset.asc=asc;
    }});
  }});
}});
</script>
</head>
<body>
<header>
  <h1>$MFT Direct Analysis Report</h1>
  <div class="meta">
    Source: {os.path.basename(source_file)} &nbsp;|&nbsp;
    Records parsed: {analyser.total:,} &nbsp;|&nbsp;
    Unique findings: {total_unique} &nbsp;|&nbsp;
    Generated: {generated} UTC
  </div>
</header>
<nav>{nav}</nav>
<div class="summary">
  <strong>{total_unique} unique findings</strong> across active categories.
  {win_str}
  <br>Duplicate entries for the same filename are grouped — click <em>N occurrences ▾</em> to expand all timestamps.
  <br>Full paths resolved via parent chain walk from raw $MFT.
  <br><strong style="color:#f85149">Red</strong> = IOC match &nbsp;|&nbsp;
  <strong style="color:#d29922">Orange</strong> = LOLBin outside system path / MEDIUM stomp &nbsp;|&nbsp;
  <em>Italic</em> = deleted/unallocated.
  <br>SI timestamps ($STANDARD_INFORMATION) can be manipulated. FN ($FILE_NAME) are NTFS-controlled.
</div>
{sec_html}
<footer>mft_direct.py v2.0 &nbsp;|&nbsp; Raw $MFT parser — no third-party dependencies &nbsp;|&nbsp;
SQLite DB available for unrestricted querying</footer>
</body>
</html>'''

    with open(html_path, 'w', encoding='utf-8') as fh:
        fh.write(html)

    return total_unique

# ── CONSOLE SUMMARY ────────────────────────────────────────────────────────────

def print_summary(analyser, source):
    w = 68
    print('\n' + '='*w)
    print('  $MFT DIRECT ANALYST v2.0 — RESULTS')
    print('='*w)
    print(f'  Source  : {os.path.basename(source)}')
    print(f'  Records : {analyser.total:,}  (dirs skipped: {analyser.dirs_skipped:,})')
    print('-'*w)
    cats = [
        ('IOC Matches',                    analyser.ioc_hits,        True),
        ('LOLBin Outside System Path',     analyser.lolbin_observed, False),
        ('Suspicious Exec Locations',      analyser.suspicious_exec, False),
        ('Timestamp Stomp Suspects',       analyser.timestomp,       False),
        ('Staging/Exfil Indicators',       analyser.staging,         False),
        ('High-Entropy Exec Names',        analyser.random_exec,     False),
        ('Alternate Data Streams',         analyser.ads_files,       False),
        ('Deleted Entry Recovery',         analyser.deleted,         False),
        ('Burst Creation Windows',         analyser.burst_windows,   False),
    ]
    total = 0
    for label, bucket, urgent in cats:
        grouped = group_by_filename(bucket) if bucket and hasattr(bucket[0] if bucket else {}, 'get') else bucket
        count = len(grouped) if isinstance(grouped, list) else len(bucket)
        raw   = len(bucket)
        dupes = raw - count if raw > count else 0
        marker = '  [!]' if urgent and raw else '     '
        suffix = '  *** REVIEW IMMEDIATELY' if urgent and raw else (f'  ({dupes} dupes grouped)' if dupes else '')
        print(f'{marker} {label:<40} {count:>5}{suffix}')
        total += count
    print('-'*w)
    print(f'       {"TOTAL UNIQUE FINDINGS":<40} {total:>5}')
    print('='*w + '\n')

# ── MAIN ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description='Raw $MFT binary parser and targeted forensic analyser v2.0.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument('-f','--file',      required=True,  help='Path to raw $MFT file')
    ap.add_argument('-o','--output',    required=True,  help='Output directory')
    ap.add_argument('--window-start',   help='Analysis window start (YYYY-MM-DD HH:MM:SS)')
    ap.add_argument('--window-end',     help='Analysis window end  (YYYY-MM-DD HH:MM:SS)')
    ap.add_argument('--ioc-file',       help='IOC terms file — one term per line')
    ap.add_argument('--large-file-mb',  type=int, default=100,
                                        help='Flag files larger than N MB (default: 100)')
    ap.add_argument('--no-html',        action='store_true')
    ap.add_argument('--no-sqlite',      action='store_true')
    args = ap.parse_args()

    if not os.path.isfile(args.file):
        sys.exit(f'[ERROR] File not found: {args.file}')

    file_size = os.path.getsize(args.file)
    if file_size % MFT_RECORD_SIZE != 0:
        print(f'[WARN] File size {file_size:,} is not a multiple of 1024 — '
              'may not be a raw $MFT or may be padded.')

    os.makedirs(args.output, exist_ok=True)

    window_start = parse_ts(args.window_start) if args.window_start else None
    window_end   = parse_ts(args.window_end)   if args.window_end   else None

    ioc_list = list(DEFAULT_IOC_TERMS)
    if args.ioc_file:
        if os.path.isfile(args.ioc_file):
            with open(args.ioc_file, encoding='utf-8-sig', errors='replace') as fh:
                custom = [l.strip() for l in fh if l.strip() and not l.startswith('#')]
            ioc_list.extend(custom)
            print(f'[*] Loaded {len(custom)} custom IOC terms from {args.ioc_file}')
        else:
            print(f'[WARN] IOC file not found: {args.ioc_file}')

    print(f'[*] $MFT       : {file_size:,} bytes (~{file_size//MFT_RECORD_SIZE:,} records)')
    print(f'[*] IOC terms  : {len(ioc_list)}')
    print(f'[*] LOLBins    : {len(LOLBIN_NAMES)} tracked')
    if window_start or window_end:
        print(f'[*] Window     : {ts(window_start) or "start"} → {ts(window_end) or "end"}')

    # Pass 1: build parent chain map for path resolution
    print('[*] Pass 1/2   : Building path map...')
    path_map = build_path_map(args.file)
    print(f'[*]              {len(path_map):,} entries mapped')

    # Pass 2: analysis
    print('[*] Pass 2/2   : Analysing records...')
    analyser = Analyser(
        ioc_list=ioc_list,
        path_map=path_map,
        window_start=window_start,
        window_end=window_end,
        large_file_bytes=args.large_file_mb * 1024 * 1024,
    )

    processed = 0
    for entry_num, rec in stream_mft(args.file):
        analyser.feed(rec)
        processed += 1
        if processed % 200_000 == 0:
            print(f'[*]              {processed:,} records analysed...')

    analyser.finalise()

    base = os.path.join(args.output, 'mft_analysis')

    if not args.no_sqlite:
        db_path = base + '.db'
        n = write_sqlite(analyser, db_path)
        print(f'[+] SQLite     : {db_path}  ({n} unique findings)')

    if not args.no_html:
        html_path = base + '_report.html'
        n = write_html(analyser, html_path, args.file, window_start, window_end)
        print(f'[+] HTML       : {html_path}')

    print_summary(analyser, args.file)


if __name__ == '__main__':
    main()


# ── MODULE API (used by case_triage.py) ────────────────────────────────────────

def run(mft_path, output_dir, ioc_list=None, window_start=None, window_end=None,
        large_file_mb=100, write_output=True):
    """
    Run MFT analysis programmatically. Returns (analyser, path_map) for caller use.
    If write_output=True, writes SQLite and HTML to output_dir.
    """
    if ioc_list is None:
        ioc_list = list(DEFAULT_IOC_TERMS)

    path_map = build_path_map(mft_path)
    analyser = Analyser(
        ioc_list=ioc_list,
        path_map=path_map,
        window_start=window_start,
        window_end=window_end,
        large_file_bytes=large_file_mb * 1024 * 1024,
    )
    for entry_num, rec in stream_mft(mft_path):
        analyser.feed(rec)
    analyser.finalise()

    if write_output:
        os.makedirs(output_dir, exist_ok=True)
        base = os.path.join(output_dir, 'mft_analysis')
        write_sqlite(analyser, base + '.db')
        write_html(analyser, base + '_report.html', mft_path, window_start, window_end)

    return analyser, path_map
