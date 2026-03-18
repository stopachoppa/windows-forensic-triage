#!/usr/bin/env python3
"""
attack_timeline.py — Attack Pattern Analysis & Timeline Builder
Version: 1.0

Ingests multiple Windows log sources, normalises events to UTC,
detects attack patterns and MITRE ATT&CK technique sequences,
and produces a condensed narrative + visual HTML timeline.

Supported input sources (auto-detected by filename):
  Security.evtx.xml                                    — Event IDs 4624/4625/4648/4688/4698/4656/4657
  System.evtx.xml                                      — Event IDs 7045/7040
  Microsoft-Windows-PowerShell_Operational.evtx.xml    — Event ID 4104 (Script Block Logging)
  Microsoft-Windows-TaskScheduler_Operational.evtx.xml — Event IDs 106/141/200
  Microsoft-Windows-TerminalServices-*.evtx.xml        — RDP session events
  prefetch.csv                                         — PECmd output (LastRun,RunCount,ExecutableName,FullPath)
  firewall.csv                                         — Windows Firewall log or export

Output:
  attack_timeline.html   — Visual timeline with attack phase grouping
  attack_timeline.db     — SQLite database of all normalised events
  attack_summary.txt     — Plain-text narrative (drop into report)

Usage:
  python attack_timeline.py -i ./logs/ -o ./results/
  python attack_timeline.py -i ./logs/ -o ./results/ --host DESKTOP-W7K2MNX
  python attack_timeline.py -i ./logs/ -o ./results/ --start "2024-03-15 08:00:00" --end "2024-03-15 12:00:00"
"""

import os
import sys
import re
import csv
import json
import sqlite3
import argparse
import datetime
import xml.etree.ElementTree as ET
from collections import defaultdict

# ── MITRE ATT&CK PHASE DEFINITIONS ────────────────────────────────────────────

PHASES = [
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Defense Evasion',
    'Credential Access',
    'Discovery',
    'Lateral Movement',
    'Collection',
    'Exfiltration',
    'Command and Control',
    'Impact',
]

PHASE_COLORS = {
    'Initial Access':        '#c0392b',
    'Execution':             '#e67e22',
    'Persistence':           '#8e44ad',
    'Privilege Escalation':  '#d35400',
    'Defense Evasion':       '#7f8c8d',
    'Credential Access':     '#2980b9',
    'Discovery':             '#27ae60',
    'Lateral Movement':      '#f39c12',
    'Collection':            '#16a085',
    'Exfiltration':          '#c0392b',
    'Command and Control':   '#2c3e50',
    'Impact':                '#e74c3c',
    'Unknown':               '#484f58',
}

# ── EVENT NORMALISATION ────────────────────────────────────────────────────────

NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

def parse_ts(s):
    if not s:
        return None
    s = s.strip().rstrip('Z').replace('T',' ')
    for fmt in (
        '%Y-%m-%d %H:%M:%S.%f000',
        '%Y-%m-%d %H:%M:%S.%f',
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d %H:%M',
    ):
        try:
            return datetime.datetime.strptime(s[:26], fmt)
        except ValueError:
            continue
    return None

def ts_str(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S') if dt else ''

def get_data(event_elem, name):
    """Extract a named Data element from EventData."""
    for d in event_elem.findall('.//e:Data', NS):
        if d.get('Name','').lower() == name.lower():
            return (d.text or '').strip()
    # fallback: search without namespace
    for d in event_elem.findall('.//Data'):
        if d.get('Name','').lower() == name.lower():
            return (d.text or '').strip()
    return ''

def parse_evtx_xml(filepath):
    """Parse EVTX XML export. Returns list of normalised event dicts."""
    events = []
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f'  [WARN] XML parse error in {os.path.basename(filepath)}: {e}')
        return events

    for event in root.findall('.//Event') + root.findall('.//e:Event', NS):
        try:
            # System block
            sys_block = event.find('s')
            if sys_block is None:
                sys_block = event.find('e:System', NS)
            if sys_block is None:
                sys_block = event.find('System')
            if sys_block is None:
                continue

            def sys_val(tag):
                el = sys_block.find(tag) or sys_block.find(f'e:{tag}', NS)
                return (el.text or '').strip() if el is not None else ''

            def sys_attr(tag, attr):
                el = sys_block.find(tag) or sys_block.find(f'e:{tag}', NS)
                return el.get(attr, '') if el is not None else ''

            event_id_raw = sys_val('EventID')
            try:
                event_id = int(event_id_raw)
            except ValueError:
                continue

            time_str = sys_attr('TimeCreated', 'SystemTime')
            dt = parse_ts(time_str)
            if dt is None:
                continue

            channel  = sys_val('Channel')
            computer = sys_val('Computer')
            level    = sys_val('Level')

            ev = {
                'time':     dt,
                'event_id': event_id,
                'channel':  channel,
                'computer': computer,
                'level':    level,
                'source':   os.path.basename(filepath),
                'raw':      event,
            }
            events.append(ev)
        except Exception:
            continue

    return events


def parse_prefetch_csv(filepath):
    """Parse PECmd CSV output."""
    events = []
    try:
        with open(filepath, encoding='utf-8-sig', errors='replace') as f:
            reader = csv.DictReader(f)
            reader.fieldnames = [h.strip() for h in (reader.fieldnames or [])]
            for row in reader:
                row = {k.strip(): (v or '').strip() for k, v in row.items()}
                # Handle both PECmd and our synthetic format
                last_run = row.get('LastRun') or row.get('Last Run') or ''
                dt = parse_ts(last_run)
                if not dt:
                    continue
                exe  = row.get('ExecutableName') or row.get('Executable Name') or ''
                path = row.get('FullPath') or row.get('Full Path') or ''
                events.append({
                    'time':     dt,
                    'event_id': 'PREFETCH',
                    'channel':  'Prefetch',
                    'computer': '',
                    'source':   os.path.basename(filepath),
                    'exe':      exe,
                    'path':     path,
                    'run_count': row.get('RunCount','1'),
                    'raw':      row,
                })
    except Exception as e:
        print(f'  [WARN] Prefetch parse error: {e}')
    return events


def parse_firewall_csv(filepath):
    """Parse Windows Firewall log CSV."""
    events = []
    try:
        with open(filepath, encoding='utf-8-sig', errors='replace') as f:
            reader = csv.DictReader(f)
            for row in reader:
                row = {(k or '').strip(): (v or '').strip() for k, v in row.items()}
                date = row.get('date','')
                time = row.get('time','')
                dt = parse_ts(f'{date} {time}')
                if not dt:
                    continue
                events.append({
                    'time':      dt,
                    'event_id':  'FIREWALL',
                    'channel':   'Firewall',
                    'computer':  '',
                    'source':    os.path.basename(filepath),
                    'action':    row.get('action',''),
                    'protocol':  row.get('protocol',''),
                    'src_ip':    row.get('src-ip',''),
                    'src_port':  row.get('src-port',''),
                    'dst_ip':    row.get('dst-ip',''),
                    'dst_port':  row.get('dst-port',''),
                    'size':      row.get('size','0'),
                    'direction': row.get('direction',''),
                    'path':      row.get('path',''),
                    'raw':       row,
                })
    except Exception as e:
        print(f'  [WARN] Firewall parse error: {e}')
    return events

# ── INGESTION ROUTER ───────────────────────────────────────────────────────────

def ingest_directory(input_dir):
    """Auto-detect and parse all supported log files in a directory."""
    all_events = []
    files = sorted(os.listdir(input_dir))
    for fname in files:
        fpath = os.path.join(input_dir, fname)
        flower = fname.lower()
        if flower.endswith('.xml') or flower.endswith('.evtx.xml'):
            print(f'  [*] {fname}')
            evts = parse_evtx_xml(fpath)
            print(f'      → {len(evts)} events')
            all_events.extend(evts)
        elif flower == 'prefetch.csv' or 'prefetch' in flower:
            print(f'  [*] {fname}')
            evts = parse_prefetch_csv(fpath)
            print(f'      → {len(evts)} entries')
            all_events.extend(evts)
        elif flower == 'firewall.csv' or 'firewall' in flower or 'pfirewall' in flower:
            print(f'  [*] {fname}')
            evts = parse_firewall_csv(fpath)
            print(f'      → {len(evts)} entries')
            all_events.extend(evts)
        elif flower.endswith('.json') and 'groundtruth' not in flower:
            pass  # skip
    all_events.sort(key=lambda x: x['time'])
    return all_events

# ── PATTERN DETECTION ──────────────────────────────────────────────────────────

class PatternDetector:
    """
    Analyses normalised event stream and identifies attack patterns.
    Each pattern produces a Finding with phase, confidence, description,
    and supporting evidence.
    """

    def __init__(self, events):
        self.events   = events
        self.findings = []
        self._by_id   = defaultdict(list)
        for ev in events:
            self._by_id[ev['event_id']].append(ev)

    def _cmdline(self, ev):
        return get_data(ev['raw'], 'CommandLine').lower() if hasattr(ev.get('raw'), 'find') else ''

    def _procname(self, ev):
        return get_data(ev['raw'], 'NewProcessName').lower() if hasattr(ev.get('raw'), 'find') else ''

    def _parent(self, ev):
        return get_data(ev['raw'], 'ParentProcessName').lower() if hasattr(ev.get('raw'), 'find') else ''

    def _field(self, ev, name):
        raw = ev.get('raw')
        if raw is None:
            return ''
        if hasattr(raw, 'find'):
            return get_data(raw, name).lower()
        if isinstance(raw, dict):
            return raw.get(name, '').lower()
        return ''

    def _add(self, phase, technique, confidence, time, description, evidence, host=''):
        self.findings.append({
            'phase':       phase,
            'technique':   technique,
            'confidence':  confidence,   # HIGH / MEDIUM / LOW
            'time':        time,
            'description': description,
            'evidence':    evidence,     # list of supporting event descriptions
            'host':        host,
        })

    def run_all(self):
        self._detect_phishing_macro()
        self._detect_encoded_powershell()
        self._detect_stager_download()
        self._detect_suspicious_child_process()
        self._detect_lsass_access()
        self._detect_credential_tools()
        self._detect_domain_recon()
        self._detect_bloodhound()
        self._detect_new_service()
        self._detect_scheduled_task_persistence()
        self._detect_explicit_credential_use()
        self._detect_rdp_lateral_movement()
        self._detect_lolbin_execution()
        self._detect_staging_tools()
        self._detect_exfil_tools()
        self._detect_c2_beaconing()
        self._detect_large_outbound()
        self._detect_logon_failures()
        self._detect_defender_alert()
        self._detect_ps_scriptblock_ioc()
        # Sort findings by time
        self.findings.sort(key=lambda x: x['time'])

    # ── INITIAL ACCESS ──────────────────────────────────────────────────────

    def _detect_phishing_macro():
        pass  # handled by suspicious child process below

    def _detect_phishing_macro(self):
        for ev in self._by_id.get(4688, []):
            parent = self._parent(ev)
            proc   = self._procname(ev)
            cmdline = self._cmdline(ev)
            # Office app spawning cmd/powershell/wscript
            office = any(o in parent for o in ['winword','excel','outlook','powerpnt','mspub'])
            shell  = any(s in proc for s in ['cmd.exe','powershell','wscript','cscript','mshta'])
            if office and shell:
                self._add(
                    'Initial Access', 'T1566.001 — Phishing: Malicious Attachment',
                    'HIGH', ev['time'],
                    f'Office application spawned a shell process — macro execution likely.',
                    [
                        f'Parent: {self._field(ev,"ParentProcessName")}',
                        f'Child:  {self._field(ev,"NewProcessName")}',
                        f'Cmd:    {self._field(ev,"CommandLine")[:120]}',
                    ],
                    ev.get('computer','')
                )

    # ── EXECUTION ───────────────────────────────────────────────────────────

    def _detect_encoded_powershell(self):
        for ev in self._by_id.get(4688, []):
            cmdline = self._cmdline(ev)
            proc    = self._procname(ev)
            if 'powershell' in proc and (
                '-encodedcommand' in cmdline or '-enc ' in cmdline or
                '-nop' in cmdline or '-w hidden' in cmdline or
                'downloadstring' in cmdline or 'downloadfile' in cmdline
            ):
                flags = []
                if '-encodedcommand' in cmdline or '-enc ' in cmdline:
                    flags.append('EncodedCommand')
                if '-nop' in cmdline:
                    flags.append('NoProfile')
                if 'hidden' in cmdline:
                    flags.append('WindowHidden')
                if 'downloadstring' in cmdline or 'downloadfile' in cmdline:
                    flags.append('Download')
                self._add(
                    'Execution', 'T1059.001 — PowerShell',
                    'HIGH', ev['time'],
                    f'Suspicious PowerShell execution with flags: {", ".join(flags)}.',
                    [f'Cmd: {self._field(ev,"CommandLine")[:200]}'],
                    ev.get('computer','')
                )

    def _detect_stager_download(self):
        for ev in self._by_id.get(4104, []):
            block = self._field(ev, 'ScriptBlockText')
            if any(x in block for x in ['downloadstring','downloadfile','webclient','invoke-webrequest','iwr ','curl ']):
                urls = re.findall(r'https?://[\w\.\-\:/]+', block, re.I)
                self._add(
                    'Execution', 'T1059.001 — PowerShell Download Cradle',
                    'HIGH', ev['time'],
                    f'PowerShell script block contains download cradle.',
                    [f'Block: {block[:200]}'] + ([f'URL: {u}' for u in urls[:3]]),
                    ev.get('computer','')
                )

    def _detect_suspicious_child_process(self):
        suspicious_parents = ['svchost32','pd.exe','sharphound','rclone','winupdatesvc']
        for ev in self._by_id.get(4688, []):
            parent = self._parent(ev)
            proc   = self._procname(ev)
            if any(sp in parent for sp in suspicious_parents):
                self._add(
                    'Execution', 'T1106 — Native API / Malware Process Chain',
                    'HIGH', ev['time'],
                    f'Suspicious parent process spawned child.',
                    [
                        f'Parent: {self._field(ev,"ParentProcessName")}',
                        f'Child:  {self._field(ev,"NewProcessName")}',
                        f'Cmd:    {self._field(ev,"CommandLine")[:120]}',
                    ],
                    ev.get('computer','')
                )

    # ── CREDENTIAL ACCESS ───────────────────────────────────────────────────

    def _detect_lsass_access(self):
        for ev in self._by_id.get(4656, []):
            obj = self._field(ev, 'ObjectName')
            if 'lsass' in obj:
                proc = self._field(ev,'ProcessName')
                self._add(
                    'Credential Access', 'T1003.001 — LSASS Memory',
                    'HIGH', ev['time'],
                    f'Handle requested to LSASS process — memory dump likely.',
                    [
                        f'Accessing process: {proc}',
                        f'Access mask: {self._field(ev,"AccessMask")}',
                    ],
                    ev.get('computer','')
                )

    def _detect_credential_tools(self):
        cred_tools = {
            'mimikatz': 'Mimikatz credential harvesting tool',
            'pd.exe':   'Procdump — LSASS dump utility',
            'wce':      'Windows Credential Editor',
            'nanodump': 'NanoDump LSASS dumper',
            'lsassy':   'Lsassy remote credential extraction',
        }
        for ev in self._by_id.get(4688, []):
            proc    = self._procname(ev)
            cmdline = self._cmdline(ev)
            for tool, desc in cred_tools.items():
                if tool in proc or tool in cmdline:
                    self._add(
                        'Credential Access', 'T1003 — OS Credential Dumping',
                        'HIGH', ev['time'],
                        f'Known credential tool executed: {desc}.',
                        [f'Process: {self._field(ev,"NewProcessName")}',
                         f'Cmd: {self._field(ev,"CommandLine")[:150]}'],
                        ev.get('computer','')
                    )
                    break

    def _detect_ps_scriptblock_ioc(self):
        cred_patterns = ['sekurlsa','invoke-mimikatz','dcsync','invoke-bloodhound',
                         'get-gpppassword','find-localadminaccess']
        for ev in self._by_id.get(4104, []):
            block = self._field(ev, 'ScriptBlockText')
            for pat in cred_patterns:
                if pat in block:
                    self._add(
                        'Credential Access', 'T1059.001 — Malicious Script Block',
                        'HIGH', ev['time'],
                        f'PowerShell script block contains credential harvesting pattern: {pat}.',
                        [f'Block: {block[:200]}'],
                        ev.get('computer','')
                    )
                    break

    # ── DISCOVERY ───────────────────────────────────────────────────────────

    def _detect_domain_recon(self):
        recon_patterns = [
            ('net.exe', ['group "domain admins"','user /domain','localgroup','accounts /dom'],
             'Domain group/user enumeration via net.exe'),
            ('nltest.exe', ['/domain_trusts','/dclist','/dsgetdc'],
             'Domain trust and DC enumeration via nltest.exe'),
            ('dsquery.exe', ['*'], 'Active Directory query via dsquery'),
            ('adfind.exe', ['*'], 'Active Directory enumeration via AdFind'),
        ]
        for ev in self._by_id.get(4688, []):
            proc    = self._procname(ev)
            cmdline = self._cmdline(ev)
            for tool, patterns, desc in recon_patterns:
                if tool in proc:
                    if tool == 'dsquery.exe' or tool == 'adfind.exe' or \
                       any(p in cmdline for p in patterns):
                        self._add(
                            'Discovery', 'T1069/T1087 — Account/Group Discovery',
                            'HIGH', ev['time'],
                            desc,
                            [f'Cmd: {self._field(ev,"CommandLine")[:150]}'],
                            ev.get('computer','')
                        )
                        break

    def _detect_bloodhound(self):
        for ev in self._by_id.get(4688, []):
            proc    = self._procname(ev)
            cmdline = self._cmdline(ev)
            if 'sharphound' in proc or 'bloodhound' in proc or \
               'invoke-bloodhound' in cmdline or 'sharphound' in cmdline:
                self._add(
                    'Discovery', 'T1087/T1482 — BloodHound AD Collection',
                    'HIGH', ev['time'],
                    'BloodHound/SharpHound executed — full AD object collection for attack path analysis.',
                    [f'Cmd: {self._field(ev,"CommandLine")[:150]}'],
                    ev.get('computer','')
                )

    # ── PERSISTENCE ─────────────────────────────────────────────────────────

    def _detect_new_service(self):
        for ev in self._by_id.get(7045, []):
            name    = self._field(ev, 'ServiceName')
            imgpath = self._field(ev, 'ImagePath')
            # Flag services running from suspicious paths
            suspicious = any(x in imgpath for x in ['temp','appdata','roaming','users\\'])
            self._add(
                'Persistence', 'T1543.003 — New Windows Service',
                'HIGH' if suspicious else 'MEDIUM', ev['time'],
                f'New service installed: {name}.',
                [
                    f'Service: {name}',
                    f'Binary:  {self._field(ev,"ImagePath")}',
                    f'Start:   {self._field(ev,"StartType")}',
                ],
                ev.get('computer','')
            )

    def _detect_scheduled_task_persistence(self):
        for ev in self._by_id.get(4698, []):
            task = self._field(ev, 'TaskName')
            content = self._field(ev, 'TaskContent')
            # Flag tasks pointing to suspicious paths
            suspicious = any(x in content for x in ['appdata','temp','roaming','users\\'])
            self._add(
                'Persistence', 'T1053.005 — Scheduled Task',
                'HIGH' if suspicious else 'MEDIUM', ev['time'],
                f'Scheduled task created: {task}.',
                [
                    f'Task: {task}',
                    f'Action path hint: {"suspicious user path" if suspicious else "review task content"}',
                ],
                ev.get('computer','')
            )
        # Also catch from Task Scheduler operational log
        for ev in self._by_id.get(106, []):
            task = self._field(ev, 'TaskName')
            if task:
                self._add(
                    'Persistence', 'T1053.005 — Scheduled Task Registered',
                    'MEDIUM', ev['time'],
                    f'Scheduled task registered: {task}.',
                    [f'Task: {task}', f'User: {self._field(ev,"UserName")}'],
                    ev.get('computer','')
                )

    # ── LATERAL MOVEMENT ────────────────────────────────────────────────────

    def _detect_explicit_credential_use(self):
        for ev in self._by_id.get(4648, []):
            target_user   = self._field(ev, 'TargetUserName')
            target_server = self._field(ev, 'TargetServerName')
            proc          = self._field(ev, 'ProcessName')
            self._add(
                'Lateral Movement', 'T1550.002 — Use of Alternate Credentials',
                'HIGH', ev['time'],
                f'Explicit credential logon to {target_server} as {target_user}.',
                [
                    f'Target user:   {target_user}',
                    f'Target host:   {target_server}',
                    f'Process used:  {proc}',
                ],
                ev.get('computer','')
            )

    def _detect_rdp_lateral_movement(self):
        rdp_events = (
            self._by_id.get(21, []) +
            self._by_id.get(22, []) +
            self._by_id.get(1149, [])
        )
        for ev in rdp_events:
            user    = self._field(ev, 'User') or self._field(ev, 'Param1')
            address = self._field(ev, 'Address') or self._field(ev, 'Param3')
            self._add(
                'Lateral Movement', 'T1021.001 — Remote Desktop Protocol',
                'HIGH', ev['time'],
                f'RDP session from {address} as {user}.',
                [
                    f'User:    {user}',
                    f'Source:  {address}',
                    f'EventID: {ev["event_id"]}',
                ],
                ev.get('computer','')
            )

    # ── DEFENSE EVASION ─────────────────────────────────────────────────────

    def _detect_lolbin_execution(self):
        lolbins = {
            'mshta.exe':       'T1218.005 — Mshta proxy execution',
            'regsvr32.exe':    'T1218.010 — Regsvr32 Squiblydoo',
            'installutil.exe': 'T1218.004 — InstallUtil bypass',
            'rundll32.exe':    'T1218.011 — Rundll32 proxy execution',
            'certutil.exe':    'T1140 — Certutil decode/download',
            'bitsadmin.exe':   'T1197 — BITSAdmin persistence/download',
            'odbcconf.exe':    'T1218.008 — ODBCConf DLL load',
            'msiexec.exe':     'T1218.007 — Msiexec remote payload',
            'wmic.exe':        'T1047 — WMIC process creation',
            'cmstp.exe':       'T1218.003 — CMSTP UAC bypass',
            'ttdinject.exe':   'T1218 — TTDInject proxy execution',
        }
        for ev in self._by_id.get(4688, []):
            proc = self._procname(ev)
            for lb, desc in lolbins.items():
                if lb in proc:
                    self._add(
                        'Defense Evasion', desc,
                        'MEDIUM', ev['time'],
                        f'LOLBin {lb} executed — may be used for proxy execution or defense bypass.',
                        [f'Cmd: {self._field(ev,"CommandLine")[:150]}'],
                        ev.get('computer','')
                    )
                    break

    # ── COLLECTION ──────────────────────────────────────────────────────────

    def _detect_staging_tools(self):
        staging = {
            'robocopy.exe': 'T1074 — Robocopy used for bulk file staging',
            'xcopy.exe':    'T1074 — Xcopy used for bulk file staging',
        }
        for ev in self._by_id.get(4688, []):
            proc    = self._procname(ev)
            cmdline = self._cmdline(ev)
            for tool, desc in staging.items():
                if tool in proc:
                    self._add(
                        'Collection', desc,
                        'HIGH', ev['time'],
                        f'File staging tool {tool} executed.',
                        [f'Cmd: {self._field(ev,"CommandLine")[:200]}'],
                        ev.get('computer','')
                    )
                    break

    # ── EXFILTRATION ────────────────────────────────────────────────────────

    def _detect_exfil_tools(self):
        exfil = {
            'rclone.exe':   'T1567 — Rclone cloud exfiltration tool',
            'megasync.exe': 'T1567 — MegaSync cloud exfiltration',
            'winscp.exe':   'T1048 — WinSCP file transfer (exfil possible)',
        }
        for ev in self._by_id.get(4688, []):
            proc = self._procname(ev)
            for tool, desc in exfil.items():
                if tool in proc:
                    self._add(
                        'Exfiltration', desc,
                        'HIGH', ev['time'],
                        f'Data exfiltration tool detected: {tool}.',
                        [f'Cmd: {self._field(ev,"CommandLine")[:200]}'],
                        ev.get('computer','')
                    )
                    break

        # Also check prefetch
        for ev in self.events:
            if ev.get('event_id') == 'PREFETCH':
                exe = ev.get('exe','').lower()
                for tool, desc in exfil.items():
                    if tool in exe:
                        self._add(
                            'Exfiltration', desc + ' (Prefetch)',
                            'MEDIUM', ev['time'],
                            f'Exfiltration tool execution evidence in Prefetch: {exe}.',
                            [f'Path: {ev.get("path","")}', f'Run count: {ev.get("run_count","?")}'],
                            ev.get('computer','')
                        )
                        break

    # ── C2 ───────────────────────────────────────────────────────────────────

    def _detect_c2_beaconing(self):
        """Detect periodic outbound connections suggesting C2 beaconing."""
        # Group firewall SEND events by (src_proc, dst_ip, dst_port)
        fw_events = [e for e in self.events if e.get('event_id') == 'FIREWALL'
                     and e.get('direction','').upper() == 'SEND']
        by_dest = defaultdict(list)
        for ev in fw_events:
            key = (ev.get('path',''), ev.get('dst_ip',''), ev.get('dst_port',''))
            by_dest[key].append(ev)

        for (proc, dst_ip, dst_port), evs in by_dest.items():
            if len(evs) < 4:
                continue
            # Calculate intervals
            times = sorted(e['time'] for e in evs)
            intervals = [(times[i+1]-times[i]).total_seconds() for i in range(len(times)-1)]
            if not intervals:
                continue
            avg_interval = sum(intervals) / len(intervals)
            std_dev = (sum((x-avg_interval)**2 for x in intervals)/len(intervals))**0.5
            # Low std dev = very regular = beaconing
            if avg_interval > 0 and std_dev / avg_interval < 0.3:
                proc_name = os.path.basename(proc) if proc else 'unknown'
                self._add(
                    'Command and Control', 'T1071 — Application Layer C2 Beaconing',
                    'HIGH', times[0],
                    f'Regular outbound connections from {proc_name} to {dst_ip}:{dst_port} '
                    f'suggest C2 beaconing (avg interval: {avg_interval:.0f}s, {len(evs)} connections).',
                    [
                        f'Process:  {proc}',
                        f'Dest:     {dst_ip}:{dst_port}',
                        f'Count:    {len(evs)} connections',
                        f'Interval: ~{avg_interval:.0f}s (σ={std_dev:.1f}s)',
                    ]
                )

    def _detect_large_outbound(self):
        """Flag large outbound transfers suggesting exfiltration."""
        # Group by dst_ip, sum bytes sent
        totals = defaultdict(lambda: {'bytes': 0, 'count': 0, 'proc': '', 'first': None})
        for ev in self.events:
            if ev.get('event_id') == 'FIREWALL' and ev.get('direction','').upper() == 'SEND':
                try:
                    size = int(ev.get('size', 0))
                except ValueError:
                    size = 0
                dst = ev.get('dst_ip','')
                totals[dst]['bytes'] += size
                totals[dst]['count'] += 1
                totals[dst]['proc']   = ev.get('path','')
                if totals[dst]['first'] is None:
                    totals[dst]['first'] = ev['time']

        for dst_ip, data in totals.items():
            mb = data['bytes'] / 1024 / 1024
            if mb >= 5:  # flag anything over 5MB outbound to single IP
                proc_name = os.path.basename(data['proc']) if data['proc'] else 'unknown'
                self._add(
                    'Exfiltration', 'T1048 — Exfiltration Over Alternative Protocol',
                    'HIGH' if mb > 50 else 'MEDIUM',
                    data['first'],
                    f'{mb:.1f} MB sent to {dst_ip} via {proc_name} across {data["count"]} connections.',
                    [
                        f'Destination: {dst_ip}',
                        f'Total sent:  {mb:.1f} MB',
                        f'Connections: {data["count"]}',
                        f'Process:     {data["proc"]}',
                    ]
                )

    # ── IMPACT / DETECTION ──────────────────────────────────────────────────

    def _detect_logon_failures(self):
        """Detect burst of logon failures suggesting brute force / scanning."""
        failures = sorted(self._by_id.get(4625, []), key=lambda x: x['time'])
        if len(failures) >= 3:
            window = (failures[-1]['time'] - failures[0]['time']).total_seconds()
            if window <= 120:
                ips = list({self._field(e,'IpAddress') for e in failures})
                self._add(
                    'Lateral Movement', 'T1110 — Brute Force / Credential Scanning',
                    'MEDIUM', failures[0]['time'],
                    f'{len(failures)} logon failures in {int(window)}s — possible credential scanning.',
                    [f'Target IPs: {", ".join(ips[:5])}',
                     f'Failure count: {len(failures)}'],
                    failures[0].get('computer','')
                )

    def _detect_defender_alert(self):
        for ev in self._by_id.get(1116, []) + self._by_id.get(1117, []):
            label = 'Warning' if ev['event_id'] == 1116 else 'Quarantine'
            self._add(
                'Defense Evasion', f'T1562.001 — AV {label} (Defender)',
                'HIGH', ev['time'],
                f'Windows Defender generated a {label.lower()} notification — review threat name.',
                [f'EventID: {ev["event_id"]}', f'Host: {ev.get("computer","")}'],
                ev.get('computer','')
            )

# ── NARRATIVE BUILDER ──────────────────────────────────────────────────────────

def build_narrative(findings, events):
    """Build a plain-text attack narrative from findings."""
    if not findings:
        return 'No significant attack patterns detected.'

    lines = []
    lines.append('ATTACK PATTERN ANALYSIS — EXECUTIVE SUMMARY')
    lines.append('=' * 60)
    lines.append('')

    # Time span
    times = [f['time'] for f in findings]
    lines.append(f'Incident Window: {ts_str(min(times))} → {ts_str(max(times))} UTC')
    lines.append(f'Total Indicators: {len(findings)}')
    lines.append('')

    # Group by phase
    by_phase = defaultdict(list)
    for f in findings:
        by_phase[f['phase']].append(f)

    phase_order = [p for p in PHASES if p in by_phase]

    lines.append('ATTACK PHASES IDENTIFIED:')
    for phase in phase_order:
        count = len(by_phase[phase])
        lines.append(f'  • {phase} ({count} indicator{"s" if count > 1 else ""})')
    lines.append('')
    lines.append('-' * 60)
    lines.append('')

    for phase in phase_order:
        phase_findings = sorted(by_phase[phase], key=lambda x: x['time'])
        lines.append(f'[ {phase.upper()} ]')
        lines.append('')
        for f in phase_findings:
            lines.append(f'  {ts_str(f["time"])}  [{f["confidence"]}]  {f["technique"]}')
            lines.append(f'  {f["description"]}')
            for ev_line in f['evidence'][:3]:
                lines.append(f'    → {ev_line}')
            lines.append('')
        lines.append('')

    lines.append('-' * 60)
    lines.append('NOTE: Timestamps are as recorded in source logs (UTC assumed).')
    lines.append('Cross-reference all findings against raw artifacts before reporting.')

    return '\n'.join(lines)

# ── OUTPUT: SQLITE ──────────────────────────────────────────────────────────────

def write_sqlite(findings, all_events, db_path):
    conn = sqlite3.connect(db_path)
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phase TEXT, technique TEXT, confidence TEXT,
            time TEXT, description TEXT, evidence TEXT, host TEXT
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT, event_id TEXT, channel TEXT,
            computer TEXT, source TEXT, summary TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_f_time ON findings(time);
        CREATE INDEX IF NOT EXISTS idx_e_time ON events(time);
    ''')
    c = conn.cursor()
    for f in findings:
        c.execute('INSERT INTO findings (phase,technique,confidence,time,description,evidence,host) VALUES (?,?,?,?,?,?,?)',
            (f['phase'], f['technique'], f['confidence'], ts_str(f['time']),
             f['description'], '\n'.join(f['evidence']), f['host']))

    for ev in all_events:
        # Build a short summary string
        raw = ev.get('raw')
        if hasattr(raw, 'find'):
            summary = (get_data(raw,'CommandLine') or get_data(raw,'TaskName') or
                       get_data(raw,'ServiceName') or get_data(raw,'ScriptBlockText') or '')[:200]
        elif isinstance(raw, dict):
            summary = str(raw)[:200]
        else:
            summary = ''
        c.execute('INSERT INTO events (time,event_id,channel,computer,source,summary) VALUES (?,?,?,?,?,?)',
            (ts_str(ev['time']), str(ev['event_id']), ev.get('channel',''),
             ev.get('computer',''), ev.get('source',''), summary))

    conn.commit()
    conn.close()

# ── OUTPUT: HTML TIMELINE ──────────────────────────────────────────────────────

def write_html(findings, all_events, html_path, input_dir):
    if not findings:
        return

    by_phase = defaultdict(list)
    for f in findings:
        by_phase[f['phase']].append(f)

    phase_order = [p for p in PHASES if p in by_phase]
    times = [f['time'] for f in findings]
    incident_start = ts_str(min(times))
    incident_end   = ts_str(max(times))

    # Phase summary badges
    phase_badges = ''
    for phase in phase_order:
        color = PHASE_COLORS.get(phase, '#484f58')
        count = len(by_phase[phase])
        phase_badges += f'<span class="badge" style="background:{color}">{phase} ({count})</span> '

    # Timeline rows — all findings sorted by time
    timeline_rows = ''
    for f in sorted(findings, key=lambda x: x['time']):
        color   = PHASE_COLORS.get(f['phase'], '#484f58')
        conf_cls = f['confidence'].lower()
        evidence_html = ''.join(f'<div class="ev-line">→ {e}</div>' for e in f['evidence'])
        host = f.get('host','')
        host_tag = f'<span class="host-tag">{host}</span>' if host else ''
        fid = abs(hash(str(f['time']) + f['technique']))
        timeline_rows += f'''
<div class="tl-item conf-{conf_cls}">
  <div class="tl-time">{ts_str(f["time"])}</div>
  <div class="tl-dot" style="background:{color}"></div>
  <div class="tl-content">
    <div class="tl-phase" style="color:{color}">{f["phase"]}</div>
    <div class="tl-tech">{f["technique"]} {host_tag}
      <span class="conf-badge conf-{conf_cls}">{f["confidence"]}</span>
    </div>
    <div class="tl-desc">{f["description"]}</div>
    <div class="tl-evidence" id="ev-{fid}" style="display:none">{evidence_html}</div>
    <button class="ev-btn" onclick="toggleEv('ev-{fid}',this)">show evidence ▾</button>
  </div>
</div>'''

    # Phase detail sections
    phase_sections = ''
    for phase in phase_order:
        color   = PHASE_COLORS.get(phase, '#484f58')
        anchor  = phase.replace(' ','_')
        p_findings = sorted(by_phase[phase], key=lambda x: x['time'])
        rows = ''
        for f in p_findings:
            evidence_html = ''.join(f'<li>{e}</li>' for e in f['evidence'])
            rows += f'''
<div class="finding">
  <div class="f-time">{ts_str(f["time"])}</div>
  <div class="f-tech">{f["technique"]}
    <span class="conf-badge conf-{f["confidence"].lower()}">{f["confidence"]}</span>
  </div>
  <div class="f-desc">{f["description"]}</div>
  <ul class="f-evidence">{evidence_html}</ul>
</div>'''
        phase_sections += f'''
<section id="{anchor}">
  <h2 style="border-left:4px solid {color};padding-left:12px">{phase}
    <span class="badge" style="background:{color}">{len(p_findings)}</span>
  </h2>
  {rows}
</section>'''

    generated = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Attack Timeline — {os.path.basename(input_dir)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:"Segoe UI",Arial,sans-serif;background:#0d1117;color:#c9d1d9;font-size:13px}}
header{{background:#161b22;padding:20px 28px;border-bottom:3px solid #c0392b}}
header h1{{font-size:20px;color:#f85149}}
header .meta{{color:#8b949e;font-size:11.5px;margin-top:6px;line-height:1.8}}
nav{{background:#0d1117;padding:10px 28px;display:flex;gap:12px;flex-wrap:wrap;
     border-bottom:1px solid #21262d;position:sticky;top:0;z-index:99}}
nav a{{color:#58a6ff;text-decoration:none;font-size:11px;white-space:nowrap}}
nav a:hover{{color:#fff}}
.badge{{display:inline-block;font-size:10.5px;padding:2px 9px;border-radius:10px;
        color:#fff;margin:2px;font-weight:600}}
.main{{display:grid;grid-template-columns:340px 1fr;gap:0;min-height:100vh}}
.timeline-col{{background:#0d1117;border-right:1px solid #21262d;padding:20px 16px;
               position:sticky;top:42px;height:calc(100vh - 42px);overflow-y:auto}}
.timeline-col h3{{color:#8b949e;font-size:11px;text-transform:uppercase;
                  letter-spacing:.08em;margin-bottom:14px}}
.tl-item{{display:grid;grid-template-columns:130px 16px 1fr;gap:0 10px;
           margin-bottom:14px;align-items:start}}
.tl-time{{color:#8b949e;font-size:10.5px;padding-top:2px;white-space:nowrap}}
.tl-dot{{width:12px;height:12px;border-radius:50%;margin-top:3px;flex-shrink:0}}
.tl-content{{}}
.tl-phase{{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.06em}}
.tl-tech{{font-size:11.5px;font-weight:600;color:#c9d1d9;margin:1px 0}}
.tl-desc{{font-size:11px;color:#8b949e;line-height:1.4}}
.tl-evidence{{font-size:10.5px;color:#8b949e;margin-top:4px;line-height:1.5}}
.ev-line{{padding:1px 0}}
.ev-btn{{background:none;border:none;color:#58a6ff;font-size:10px;cursor:pointer;
         padding:2px 0;margin-top:2px}}
.ev-btn:hover{{color:#fff}}
.host-tag{{background:#21262d;color:#8b949e;font-size:9.5px;padding:1px 5px;
           border-radius:3px;margin-left:4px}}
.conf-badge{{font-size:9.5px;padding:1px 5px;border-radius:3px;font-weight:700}}
.conf-high{{background:#2d1515;color:#f85149;border:1px solid #f85149}}
.conf-medium{{background:#2d2008;color:#d29922;border:1px solid #d29922}}
.conf-low{{background:#1a2a1a;color:#3fb950;border:1px solid #3fb950}}
.detail-col{{padding:24px 28px;overflow-y:auto}}
section{{margin-bottom:36px}}
h2{{font-size:15px;color:#c9d1d9;margin-bottom:14px;padding-bottom:8px;
    border-bottom:1px solid #21262d}}
.finding{{background:#161b22;border-radius:6px;padding:14px 16px;margin-bottom:10px;
          border-left:3px solid #21262d}}
.f-time{{color:#8b949e;font-size:10.5px;margin-bottom:4px}}
.f-tech{{font-size:13px;font-weight:600;color:#c9d1d9;margin-bottom:5px}}
.f-desc{{font-size:12px;color:#8b949e;line-height:1.5;margin-bottom:6px}}
.f-evidence{{margin-left:16px;font-size:11.5px;color:#8b949e;line-height:1.6}}
</style>
<script>
function toggleEv(id,btn){{
  const el=document.getElementById(id);
  const vis=el.style.display!=='none';
  el.style.display=vis?'none':'block';
  btn.textContent=vis?'show evidence ▾':'hide evidence ▴';
}}
</script>
</head>
<body>
<header>
  <h1>Attack Pattern Analysis &amp; Timeline</h1>
  <div class="meta">
    Source: {os.path.basename(input_dir)} &nbsp;|&nbsp;
    Incident window: {incident_start} → {incident_end} UTC &nbsp;|&nbsp;
    {len(findings)} indicators across {len(phase_order)} phases &nbsp;|&nbsp;
    Generated: {generated} UTC
    <br>{phase_badges}
  </div>
</header>
<nav>
  <a href="#timeline">Timeline</a>
  {''.join(f'<a href="#{p.replace(" ","_")}">{p}</a>' for p in phase_order)}
</nav>
<div class="main">
  <div class="timeline-col" id="timeline">
    <h3>Chronological Timeline</h3>
    {timeline_rows}
  </div>
  <div class="detail-col">
    {phase_sections}
  </div>
</div>
</body>
</html>'''

    with open(html_path, 'w', encoding='utf-8') as fh:
        fh.write(html)

# ── MAIN ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description='Attack pattern analysis and timeline builder.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument('-i','--input',   required=True, help='Input directory containing log files')
    ap.add_argument('-o','--output',  required=True, help='Output directory')
    ap.add_argument('--host',         help='Filter events to specific hostname')
    ap.add_argument('--start',        help='Window start (YYYY-MM-DD HH:MM:SS)')
    ap.add_argument('--end',          help='Window end   (YYYY-MM-DD HH:MM:SS)')
    ap.add_argument('--no-html',      action='store_true')
    ap.add_argument('--no-sqlite',    action='store_true')
    ap.add_argument('--no-narrative', action='store_true')
    args = ap.parse_args()

    if not os.path.isdir(args.input):
        sys.exit(f'[ERROR] Input directory not found: {args.input}')
    os.makedirs(args.output, exist_ok=True)

    window_start = parse_ts(args.start) if args.start else None
    window_end   = parse_ts(args.end)   if args.end   else None

    print(f'[*] Ingesting logs from: {args.input}')
    all_events = ingest_directory(args.input)
    print(f'[*] Total events ingested: {len(all_events):,}')

    # Apply filters
    if args.host:
        all_events = [e for e in all_events
                      if not e.get('computer') or args.host.lower() in e.get('computer','').lower()]
    if window_start:
        all_events = [e for e in all_events if e['time'] >= window_start]
    if window_end:
        all_events = [e for e in all_events if e['time'] <= window_end]

    print(f'[*] Events after filtering: {len(all_events):,}')
    print(f'[*] Running pattern detection...')

    detector = PatternDetector(all_events)
    detector.run_all()
    findings = detector.findings

    print(f'[*] Findings: {len(findings)} indicators detected')
    by_phase = defaultdict(int)
    for f in findings:
        by_phase[f['phase']] += 1
    for phase, count in sorted(by_phase.items()):
        print(f'    {phase:<30} {count}')

    base = os.path.join(args.output, 'attack_timeline')

    if not args.no_sqlite:
        db_path = base + '.db'
        write_sqlite(findings, all_events, db_path)
        print(f'[+] SQLite:    {db_path}')

    if not args.no_html:
        html_path = base + '.html'
        write_html(findings, all_events, html_path, args.input)
        print(f'[+] HTML:      {html_path}')

    if not args.no_narrative:
        narrative = build_narrative(findings, all_events)
        txt_path = base + '_summary.txt'
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write(narrative)
        print(f'[+] Summary:   {txt_path}')
        print()
        print(narrative)


if __name__ == '__main__':
    main()


# ── MODULE API (used by case_triage.py) ────────────────────────────────────────

def run(input_dir, output_dir, host_filter=None, window_start=None, window_end=None,
        write_output=True):
    """
    Run timeline analysis programmatically. Returns (findings, all_events).
    If write_output=True, writes SQLite, HTML, and summary txt to output_dir.
    """
    all_events = ingest_directory(input_dir)

    if host_filter:
        all_events = [e for e in all_events
                      if not e.get('computer') or
                      host_filter.lower() in e.get('computer','').lower()]
    if window_start:
        all_events = [e for e in all_events if e['time'] >= window_start]
    if window_end:
        all_events = [e for e in all_events if e['time'] <= window_end]

    detector = PatternDetector(all_events)
    detector.run_all()
    findings = detector.findings

    if write_output:
        os.makedirs(output_dir, exist_ok=True)
        base = os.path.join(output_dir, 'attack_timeline')
        write_sqlite(findings, all_events, base + '.db')
        write_html(findings, all_events, base + '.html', input_dir)
        narrative = build_narrative(findings, all_events)
        with open(base + '_summary.txt', 'w', encoding='utf-8') as f:
            f.write(narrative)

    return findings, all_events
