#!/usr/bin/env python3
"""
generate_test_mft.py — Synthetic $MFT Binary Generator
Version: 1.0

Generates a realistic synthetic $MFT file containing a Trickbot-style
intrusion artifact set. Designed for testing mft_direct.py and case_triage.py
without needing a real case image.

Artifacts included:
  - mimikatz.exe          (IOC match, AppDataLocal\Temp)
  - svchost32.exe         (suspicious exec, AppDataLocal\Temp)
  - a3f9e2b1c4d5.exe      (high-entropy name, AppData\Roaming)
  - legit_svc.exe         (timestamp stomped — SI 2022, FN 2024)
  - backup_docs.zip       (large archive staging, Desktop)
  - rclone.exe            (exfil tool, AppDataLocal\Temp)
  - SharpHound.exe        (IOC match, AppDataLocal\Temp)
  - WinUpdateSvc.exe      (persistence, AppData\Roaming)
  - pd.exe                (procdump, AppDataLocal\Temp)
  - dropper.exe           (deleted/unallocated entry)
  - lsass.dmp             (credential dump output, Temp)
  - 60x encrypted_NNNN.docx (burst creation — ransomware pattern)
  - Normal system files   (explorer.exe, notepad.exe — should NOT be flagged)

Directory structure created:
  Entry 5   = root (\)
  Entry 6   = Users
  Entry 7   = Users\jsmith
  Entry 8   = Users\jsmith\AppData
  Entry 9   = Users\jsmith\AppDataLocal
  Entry 10  = Users\jsmith\AppDataLocal\Temp
  Entry 11  = Users\jsmith\AppData\Roaming
  Entry 12  = Users\jsmith\Desktop
  Entry 13  = Windows
  Entry 14  = Windows\System32

Usage:
    python generate_test_mft.py -o C:\\Tools\\test_dataset\\
    python generate_test_mft.py -o C:\\Tools\\test_dataset\\ --verbose
"""

import struct
import os
import sys
import argparse
import datetime

# ── CONSTANTS ──────────────────────────────────────────────────────────────────

RECORD_SIZE   = 1024
FILETIME_EPOCH = datetime.datetime(1601, 1, 1)

# ── HELPERS ────────────────────────────────────────────────────────────────────

def filetime(dt):
    """Convert datetime to Windows FILETIME (100ns ticks since 1601-01-01)."""
    return int((dt - FILETIME_EPOCH).total_seconds() * 10_000_000)

def t(y, mo, d, h=0, mi=0, s=0):
    return datetime.datetime(y, mo, d, h, mi, s)

def make_si(cr, mod, flags=0x20):
    """Build $STANDARD_INFORMATION attribute content (72 bytes, v1)."""
    return (struct.pack('<QQQQ', filetime(cr), filetime(mod), filetime(mod), filetime(mod)) +
            struct.pack('<IIIIIIQ', flags, 0, 0, 0, 0, 0, 0))

def make_fn(parent_entry, cr, mod, alloc, real, filename, namespace=1):
    """Build $FILE_NAME attribute content."""
    name_bytes  = filename.encode('utf-16-le')
    parent_ref  = parent_entry | (1 << 48)  # seq=1
    body  = struct.pack('<Q', parent_ref)
    body += struct.pack('<QQQQ', filetime(cr), filetime(mod), filetime(mod), filetime(mod))
    body += struct.pack('<QQ', alloc, real)
    body += struct.pack('<II', 0x20, 0)
    body += struct.pack('<BB', len(filename), namespace)
    body += name_bytes
    return body

def resident_attr(attr_type, content, attr_id=0):
    """Wrap content in a resident MFT attribute header."""
    content_off = 24
    raw_len     = content_off + len(content)
    attr_len    = (raw_len + 7) & ~7
    pad         = attr_len - raw_len
    hdr  = struct.pack('<I', attr_type)
    hdr += struct.pack('<I', attr_len)
    hdr += struct.pack('<B', 0)           # resident
    hdr += struct.pack('<B', 0)           # name length
    hdr += struct.pack('<H', content_off)
    hdr += struct.pack('<H', 0)           # flags
    hdr += struct.pack('<H', attr_id)
    hdr += struct.pack('<I', len(content))
    hdr += struct.pack('<H', content_off)
    hdr += struct.pack('<H', 0)           # indexed
    assert len(hdr) == 24
    return hdr + content + b'\x00' * pad

def make_record(entry_num, parent_entry, filename,
                si_cr, si_mod, fn_cr, fn_mod,
                filesize=4096, in_use=True, is_dir=False):
    """Build a complete 1024-byte MFT record."""
    ATTR_OFFSET = 56   # 48 byte header + 6 byte USA + 2 byte pad

    si_data  = make_si(si_cr, si_mod)
    fn_data  = make_fn(parent_entry, fn_cr, fn_mod, filesize, filesize, filename)
    si_attr  = resident_attr(0x10, si_data, attr_id=0)
    fn_attr  = resident_attr(0x30, fn_data, attr_id=1)
    end_mark = struct.pack('<I', 0xFFFFFFFF) + b'\x00\x00\x00\x00'

    attrs    = si_attr + fn_attr + end_mark
    used     = ATTR_OFFSET + len(attrs)

    rec_flags = 0x01 if in_use else 0x00
    if is_dir:
        rec_flags |= 0x02

    hdr  = b'FILE'
    hdr += struct.pack('<H', 48)            # update seq offset
    hdr += struct.pack('<H', 3)             # update seq size
    hdr += struct.pack('<Q', entry_num)     # LSN
    hdr += struct.pack('<H', 1)             # sequence number
    hdr += struct.pack('<H', 1)             # hard link count
    hdr += struct.pack('<H', ATTR_OFFSET)   # first attribute offset
    hdr += struct.pack('<H', rec_flags)
    hdr += struct.pack('<I', used)
    hdr += struct.pack('<I', RECORD_SIZE)
    hdr += struct.pack('<Q', 0)             # base record ref
    hdr += struct.pack('<H', 2)             # next attr ID
    hdr += struct.pack('<H', 0)             # pad
    hdr += struct.pack('<I', entry_num)
    assert len(hdr) == 48

    usa     = struct.pack('<HHH', 0x0001, 0x0000, 0x0000)
    pad_hdr = b'\x00' * (ATTR_OFFSET - 48 - len(usa))

    record = bytearray(hdr + usa + pad_hdr + attrs)
    record += b'\x00' * (RECORD_SIZE - len(record))

    # Apply USA fixup to sector ends
    for sector in range(RECORD_SIZE // 512):
        pos = (sector + 1) * 512 - 2
        record[pos:pos+2] = struct.pack('<H', 0x0001)

    return bytes(record)

# ── SCENARIO BUILDER ───────────────────────────────────────────────────────────

def build_mft():
    """Build the complete synthetic $MFT record list."""
    records = []

    # Helper to append and track
    def add(eid, parent, name, si_cr, si_mod, fn_cr, fn_mod,
            size=4096, in_use=True, is_dir=False):
        rec = make_record(eid, parent, name, si_cr, si_mod, fn_cr, fn_mod,
                          size, in_use, is_dir)
        records.append((eid, rec))

    # ── MFT metadata entries (0-4) ──────────────────────────────────────────
    epoch = t(2020, 1, 1)
    for i in range(5):
        add(i, 5, f'$MFTMeta{i}', epoch, epoch, epoch, epoch)

    # ── Root and directory structure ─────────────────────────────────────────
    # Entry 5 = root
    add(5,  5,  '.',             epoch, epoch, epoch, epoch, is_dir=True)
    # Users tree
    add(6,  5,  'Users',         epoch, epoch, epoch, epoch, is_dir=True)
    add(7,  6,  'jsmith',        epoch, epoch, epoch, epoch, is_dir=True)
    add(8,  7,  'AppData',       epoch, epoch, epoch, epoch, is_dir=True)
    add(9,  8,  'Local',         epoch, epoch, epoch, epoch, is_dir=True)
    add(10, 9,  'Temp',          epoch, epoch, epoch, epoch, is_dir=True)
    add(11, 8,  'Roaming',       epoch, epoch, epoch, epoch, is_dir=True)
    add(12, 7,  'Desktop',       epoch, epoch, epoch, epoch, is_dir=True)
    add(13, 7,  'Downloads',     epoch, epoch, epoch, epoch, is_dir=True)
    # Windows tree
    add(14, 5,  'Windows',       epoch, epoch, epoch, epoch, is_dir=True)
    add(15, 14, 'System32',      epoch, epoch, epoch, epoch, is_dir=True)

    # ── Legit system files (should NOT be flagged) ───────────────────────────
    sys_ts = t(2020, 6, 1)
    add(20, 15, 'explorer.exe',  sys_ts, sys_ts, sys_ts, sys_ts, size=4_000_000)
    add(21, 15, 'notepad.exe',   sys_ts, sys_ts, sys_ts, sys_ts, size=204_800)
    add(22, 15, 'cmd.exe',       sys_ts, sys_ts, sys_ts, sys_ts, size=323_584)
    add(23, 15, 'net.exe',       sys_ts, sys_ts, sys_ts, sys_ts, size=98_304)
    add(24, 15, 'nltest.exe',    sys_ts, sys_ts, sys_ts, sys_ts, size=174_080)
    add(25, 15, 'robocopy.exe',  sys_ts, sys_ts, sys_ts, sys_ts, size=512_000)
    add(26, 15, 'mstsc.exe',     sys_ts, sys_ts, sys_ts, sys_ts, size=1_048_576)

    # ── Incident timeline artifacts ──────────────────────────────────────────

    # 08:47 — Word opens phishing doc (Downloads)
    add(30, 13, 'Invoice_March2024.docm',
        t(2024,3,15,8,47,0), t(2024,3,15,8,47,0),
        t(2024,3,15,8,47,0), t(2024,3,15,8,47,0), size=245_760)

    # 08:48 — Stager dropped to Temp
    add(31, 10, 'svchost32.exe',
        t(2024,3,15,8,48,10), t(2024,3,15,8,48,10),
        t(2024,3,15,8,48,10), t(2024,3,15,8,48,10), size=524_288)

    # 08:52 — Procdump dropped to Temp
    add(32, 10, 'pd.exe',
        t(2024,3,15,8,52,0), t(2024,3,15,8,52,0),
        t(2024,3,15,8,52,0), t(2024,3,15,8,52,0), size=471_040)

    # 08:52 — LSASS dump output
    add(33, 10, 'lsass.dmp',
        t(2024,3,15,8,52,35), t(2024,3,15,8,52,35),
        t(2024,3,15,8,52,35), t(2024,3,15,8,52,35), size=42_000_000)

    # 08:55 — SharpHound dropped to Temp (IOC)
    add(34, 10, 'SharpHound.exe',
        t(2024,3,15,8,55,0), t(2024,3,15,8,55,0),
        t(2024,3,15,8,55,0), t(2024,3,15,8,55,0), size=1_048_576)

    # 08:55 — BloodHound output zip (staging)
    add(35, 10, 'bloodhound_acme.zip',
        t(2024,3,15,9,3,45), t(2024,3,15,9,3,45),
        t(2024,3,15,9,3,45), t(2024,3,15,9,3,45), size=3_145_728)

    # 09:03 — High-entropy name (dropper/loader)
    add(36, 11, 'a3f9e2b1c4d5.exe',
        t(2024,3,15,9,3,0), t(2024,3,15,9,3,0),
        t(2024,3,15,9,3,0), t(2024,3,15,9,3,0), size=102_400)

    # 09:22 — Persistence binary in Roaming
    add(37, 11, 'WinUpdateSvc.exe',
        t(2024,3,15,9,22,0), t(2024,3,15,9,22,0),
        t(2024,3,15,9,22,0), t(2024,3,15,9,22,0), size=81_920)

    # 09:35 — Large staging archive on Desktop
    add(38, 12, 'backup_docs.zip',
        t(2024,3,15,9,35,30), t(2024,3,15,9,35,30),
        t(2024,3,15,9,35,30), t(2024,3,15,9,35,30), size=524_288_000)

    # 09:41 — Rclone exfil tool in Temp (IOC + exfil)
    add(39, 10, 'rclone.exe',
        t(2024,3,15,9,41,0), t(2024,3,15,9,41,0),
        t(2024,3,15,9,41,0), t(2024,3,15,9,41,0), size=47_185_920)

    # 09:41 — Rclone config in Temp
    add(40, 10, 'rclone.conf',
        t(2024,3,15,9,41,0), t(2024,3,15,9,41,0),
        t(2024,3,15,9,41,0), t(2024,3,15,9,41,0), size=512)

    # 09:45 — Mimikatz dropped (IOC — timestamp stomped)
    # SI says 2022 (attacker backdated it), FN says 2024 (NTFS truth)
    add(41, 10, 'mimikatz.exe',
        t(2022,1,1,0,0,0),       t(2022,1,1,0,0,0),   # SI — backdated
        t(2024,3,15,9,45,0),     t(2024,3,15,9,45,0),  # FN — real
        size=1_355_776)

    # 09:47 — Deleted dropper (unallocated — in_use=False)
    add(42, 10, 'dropper.exe',
        t(2024,3,15,8,47,50), t(2024,3,15,8,47,50),
        t(2024,3,15,8,47,50), t(2024,3,15,8,47,50),
        size=32_768, in_use=False)

    # 09:22 — Scheduled task PowerShell script
    add(43, 11, 'update_check.ps1',
        t(2024,3,15,9,22,5), t(2024,3,15,9,22,5),
        t(2024,3,15,9,22,5), t(2024,3,15,9,22,5), size=4_096)

    # ── Burst creation (60 files in 30 seconds — ransomware/staging pattern) ─
    base_time = t(2024, 3, 15, 11, 0, 0)
    import datetime as _dt
    for i in range(60):
        burst_ts = base_time + _dt.timedelta(seconds=i * 0.5)
        add(100 + i, 10, f'encrypted_{i:04d}.docx',
            burst_ts, burst_ts, burst_ts, burst_ts, size=20_480)

    return records


# ── WRITER ─────────────────────────────────────────────────────────────────────

def write_mft(records, output_path, verbose=False):
    """Write sorted records to a binary $MFT file."""
    # Sort by entry number, pad gaps with zero records
    record_dict = {eid: data for eid, data in records}
    max_entry   = max(record_dict.keys())

    written = 0
    with open(output_path, 'wb') as f:
        for i in range(max_entry + 1):
            if i in record_dict:
                f.write(record_dict[i])
                written += 1
            else:
                f.write(b'\x00' * RECORD_SIZE)

    size = os.path.getsize(output_path)
    print(f'  [+] {os.path.basename(output_path)}')
    print(f'      Records   : {written} populated + {max_entry + 1 - written} gap entries')
    print(f'      File size : {size:,} bytes ({size / 1024:.1f} KB)')

    if verbose:
        print()
        print('  Artifact summary:')
        for eid, data in sorted(record_dict.items()):
            if eid < 5:
                continue
            # Quick peek at filename from record
            try:
                fn_off = 56 + 24 + len(make_si(datetime.datetime.now(), datetime.datetime.now())) + (8 - (len(make_si(datetime.datetime.now(), datetime.datetime.now())) % 8 or 8))
            except Exception:
                pass


def main():
    ap = argparse.ArgumentParser(
        description='Generate synthetic $MFT binary for forensic tool testing.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument('-o','--output',  required=True, help='Output directory')
    ap.add_argument('--verbose',      action='store_true', help='Verbose output')
    ap.add_argument('--filename',     default='$MFT', help='Output filename (default: $MFT)')
    args = ap.parse_args()

    os.makedirs(args.output, exist_ok=True)
    output_path = os.path.join(args.output, args.filename)

    print(f'[*] Generating synthetic $MFT → {output_path}')
    print(f'[*] Scenario: Trickbot-style intrusion artifact set')
    print()

    records = build_mft()
    write_mft(records, output_path, args.verbose)

    print()
    print('[*] Key artifacts included:')
    artifacts = [
        ('mimikatz.exe',            'IOC match + HIGH timestomp (SI backdated ~2 years)'),
        ('svchost32.exe',           'Suspicious exec in Temp + IOC match'),
        ('pd.exe',                  'Procdump — credential tool'),
        ('lsass.dmp',               'LSASS dump output (large file, Temp)'),
        ('SharpHound.exe',          'IOC match — BloodHound collector'),
        ('bloodhound_acme.zip',     'Staging archive (Temp)'),
        ('a3f9e2b1c4d5.exe',        'High-entropy name (Roaming)'),
        ('WinUpdateSvc.exe',        'Persistence binary (Roaming)'),
        ('backup_docs.zip',         'Large staging archive ~500MB (Desktop)'),
        ('rclone.exe',              'Exfil tool IOC match (Temp)'),
        ('dropper.exe',             'Deleted/unallocated entry'),
        ('encrypted_0000-0059.docx','Burst creation — 60 files in 30 seconds'),
        ('explorer.exe / notepad.exe', 'Benign System32 files — should NOT be flagged'),
    ]
    for name, desc in artifacts:
        print(f'  {name:<35} {desc}')

    print()
    print(f'[*] Run mft_direct.py against it:')
    print(f'    python mft_direct_v2.py -f "{{output_path}}" -o ./results/')
    print()
    print(f'[*] Or run the full case triage:')
    print(f'    python case_triage.py --case "TEST-001" --mft "{output_path}" \\')
    print(f'      --logs ./test_dataset/ --output ./results/ --examiner "Your Name"')


if __name__ == '__main__':
    main()
