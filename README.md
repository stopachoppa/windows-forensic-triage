# windows-forensic-triage

Raw $MFT parser, attack pattern analyser, and unified triage launcher for Windows incident response. Interactive HTML reports, pure Python, zero dependencies.

---

## Tools

| Script | Purpose |
|--------|---------|
| `case_triage.py` | Unified launcher -- runs all analysis and produces consolidated case report |
| `mft_direct_v2.py` | Raw `$MFT` binary parser and targeted forensic analyser |
| `attack_timeline.py` | Multi-source log ingestor, ATT&CK pattern detection, timeline builder |
| `generate_test_mft.py` | Synthetic `$MFT` generator (Trickbot-style intrusion artifacts) |
| `generate_test_data.py` | Synthetic log dataset generator (EVTX XML, Prefetch CSV, firewall log) |

---

## Quick Start

Step 1 -- Generate a synthetic test dataset (no real case needed):

```
python generate_test_mft.py -o C:\Tools\test_dataset\
python generate_test_data.py -o C:\Tools\test_dataset\
```

Step 2 -- Run the full triage:

```
python case_triage.py --case "CASE-2024-001" --mft "C:\Tools\test_dataset\$MFT" --logs "C:\Tools\test_dataset" --output "C:\Tools\results" --examiner "L. Mitchell"
```

Step 3 -- Open the report:

```
C:\Tools\results\case_report_CASE-2024-001.html
```

---

## case_triage.py -- Unified Launcher

The primary entry point. Runs MFT analysis and attack timeline detection in sequence, cross-references findings across both sources, and produces a single consolidated HTML case report.

```
python case_triage.py
  --case          Case number or name (required)
  --mft           Path to raw $MFT file (required)
  --logs          Directory containing log files (required)
  --output        Output directory (required)
  --examiner      Examiner name for report header
  --host          Filter events to specific hostname
  --window-start  Analysis window start "YYYY-MM-DD HH:MM:SS"
  --window-end    Analysis window end   "YYYY-MM-DD HH:MM:SS"
  --ioc-file      Custom IOC terms file (one term per line)
  --large-file-mb Flag files larger than N MB (default: 100)
  --mft-script    Path to mft_direct_v2.py (auto-detected if omitted)
  --tl-script     Path to attack_timeline.py (auto-detected if omitted)
```

Output files:

| File | Description |
|------|-------------|
| `case_report_[CASE].html` | Consolidated case report -- open in any browser |
| `case_[CASE].db` | SQLite database with all findings |
| `case_summary_[CASE].txt` | Plain-text executive summary (report-ready) |
| `mft_analysis_report.html` | Standalone MFT report |
| `attack_timeline.html` | Standalone attack timeline report |

Report features:
- Computer filter sidebar -- click any hostname to filter all findings to that machine
- Source log panel -- confirms which log files were ingested
- Global search bar -- real-time keyword filter across all findings simultaneously
- Event viewer -- flat chronological table of all events, filterable by computer and keyword
- Cross-referenced artifacts -- findings corroborated across MFT and log sources elevated to the top
- Sortable columns throughout
- Color-coded severity -- red = HIGH/IOC, orange = MEDIUM/LOLBin, italic = deleted/unallocated

---

## mft_direct_v2.py -- Raw $MFT Parser

Points directly at a raw $MFT binary file. No MFTECmd required. Streams record by record -- handles $MFT files of any size without memory issues.

```
python mft_direct_v2.py
  -f / --file         Path to raw $MFT file (required)
  -o / --output       Output directory (required)
  --window-start      Analysis window start
  --window-end        Analysis window end
  --ioc-file          Custom IOC terms file
  --large-file-mb     Large file threshold in MB (default: 100)
  --no-html           Skip HTML report
  --no-sqlite         Skip SQLite output
```

Analysis modules:

| Module | What it finds |
|--------|--------------|
| IOC Filename Matching | Known-bad filenames (46 built-in terms + custom list) |
| LOLBin Detection | 61 Windows LOLBins flagged only when outside expected system paths |
| Suspicious Exec Locations | Executables in user-writable/temp paths |
| Timestamp Stomping | SI $STANDARD_INFORMATION vs FN $FILE_NAME divergence |
| Staging / Exfil Indicators | Archives and large files in staging-consistent paths |
| High-Entropy Names | Random/generated executable names (Shannon entropy + hex ratio) |
| Alternate Data Streams | Files with ADS flags |
| Deleted Entry Recovery | Executables and archives in unallocated MFT entries |
| Burst Creation Windows | 50+ files created within 60 seconds (ransomware/mass staging) |

Two-pass design:
- Pass 1 builds a parent chain map across the entire $MFT
- Pass 2 performs analysis with full path resolution via parent chain walk
- Results in C:\Users\jsmith\AppData\Local\Temp\svchost32.exe rather than just svchost32.exe

Why SI vs FN timestamp comparison matters:

$STANDARD_INFORMATION timestamps can be modified by an attacker using tools like timestomp. $FILE_NAME timestamps are maintained by NTFS itself and are significantly harder to manipulate from userland. A file where SI Created is two years earlier than FN Created is a strong indicator of anti-forensic timestamp manipulation.

Acquiring $MFT without removing from a live system:

```
# CyLR (recommended for triage -- collects $MFT automatically)
CyLR.exe -of output.zip

# FTK Imager
File > Add Evidence Item > Logical Drive > [root] > right-click $MFT > Export Files
```

---

## attack_timeline.py -- Attack Pattern Analysis and Timeline Builder

Ingests multiple Windows log sources, normalises to UTC, detects attack patterns mapped to MITRE ATT&CK, and produces a condensed narrative and visual timeline.

```
python attack_timeline.py
  -i / --input    Input directory containing log files (required)
  -o / --output   Output directory (required)
  --host          Filter to specific hostname
  --start         Window start "YYYY-MM-DD HH:MM:SS"
  --end           Window end   "YYYY-MM-DD HH:MM:SS"
  --no-html       Skip HTML report
  --no-sqlite     Skip SQLite output
  --no-narrative  Skip plain-text summary
```

Supported log sources (auto-detected by filename):

| Source | Detection |
|--------|-----------|
| `Security.evtx.xml` | Logon/logoff, account events, process creation (4624/4625/4648/4688/4698/4656) |
| `System.evtx.xml` | Service installation (7045) |
| `Microsoft-Windows-PowerShell_Operational.evtx.xml` | Script Block Logging (4104) |
| `Microsoft-Windows-TaskScheduler_Operational.evtx.xml` | Task creation/execution (106/200) |
| `Microsoft-Windows-TerminalServices-*.evtx.xml` | RDP session events (21/22/23/1149) |
| `prefetch.csv` | PECmd output (LastRun, ExecutableName, FullPath) |
| `firewall.csv` | Windows Firewall log |

Exporting EVTX files for ingestion:

In Event Viewer, right-click a log, select Save All Events As, choose XML (*.xml) format. Name the file to match the source (e.g. Security.evtx.xml) and place all files in a single directory.

Detection patterns include:
- Phishing macro execution (Office spawning cmd/PowerShell)
- Encoded and obfuscated PowerShell (-EncodedCommand, download cradles)
- C2 beaconing -- statistical interval analysis on firewall connections, low-jitter periodic traffic
- LSASS handle access (Event 4656)
- Credential tool execution (procdump, mimikatz, nanodump by name)
- Domain recon via net.exe, nltest.exe, dsquery, AdFind
- BloodHound/SharpHound collection
- New service and scheduled task persistence in suspicious paths
- Explicit credential use (Event 4648) -- lateral movement indicator
- RDP lateral movement (Terminal Services events)
- File staging via robocopy/xcopy
- Exfiltration tool detection (rclone, megasync)
- Large outbound transfer volume from firewall logs
- Brute force/credential scanning (burst of Event 4625)
- Windows Defender alerts (Event 1116/1117)

---

## Test Dataset Generators

### generate_test_mft.py

Generates a realistic binary $MFT containing a Trickbot-style intrusion artifact set with a proper directory structure for full path resolution testing.

```
python generate_test_mft.py -o C:\Tools\test_dataset\
```

Artifacts included:
- mimikatz.exe -- IOC match + HIGH timestamp stomp (SI backdated ~2 years)
- svchost32.exe -- Suspicious exec in Temp
- pd.exe -- Procdump credential tool
- lsass.dmp -- LSASS dump output (large file)
- SharpHound.exe -- BloodHound collector IOC
- a3f9e2b1c4d5.exe -- High-entropy name
- WinUpdateSvc.exe -- Persistence binary in Roaming
- backup_docs.zip -- 500MB staging archive on Desktop
- rclone.exe -- Exfil tool
- dropper.exe -- Deleted/unallocated entry
- 60x encrypted_NNNN.docx -- Burst creation pattern (ransomware simulation)
- explorer.exe, notepad.exe -- Benign System32 files (correctly ignored)

### generate_test_data.py

Generates a matching synthetic log dataset covering the same Trickbot scenario across all supported log sources.

```
python generate_test_data.py -o C:\Tools\test_dataset\
```

Generates:
- Security.evtx.xml -- 22 events covering phishing through exfil
- System.evtx.xml -- Malicious service installation
- Microsoft-Windows-PowerShell_Operational.evtx.xml -- Download cradles, credential patterns
- Microsoft-Windows-TaskScheduler_Operational.evtx.xml -- Persistence task
- Microsoft-Windows-TerminalServices-*.evtx.xml -- RDP lateral movement
- prefetch.csv -- Execution evidence for all key binaries
- firewall.csv -- C2 beaconing and large exfil transfers
- scenario_groundtruth.json -- Ground truth for validating tool output

---

## IOC Customisation

Both mft_direct_v2.py and case_triage.py accept a custom IOC file via --ioc-file. Format is plain text, one term per line, # for comments:

```
# Case-specific IOCs
rclone
tuckerbackup
c2domain.xyz
```

Terms are case-insensitive substring matches against filenames. Built-in terms are listed at the top of mft_direct_v2.py under DEFAULT_IOC_TERMS.

To suppress false positives from legitimate files that match IOC substrings (e.g. imprbeacons.dat matching beacon), add entries to IOC_FALSE_POSITIVE_EXCLUSIONS at the top of mft_direct_v2.py.

---

## Design Philosophy

These tools were built around a core principle: understand the artifact at the binary level, do not trust tool output blindly.

Key decisions that reflect this:

- Raw $MFT parsing -- MFTECmd is excellent but paid tools can silently fail or produce incomplete output. Parsing the binary directly means you know exactly what was and was not parsed.
- SI vs FN timestamp comparison -- Most tools surface SI timestamps only. FN timestamps are NTFS-controlled and significantly harder to manipulate. Comparing both catches timestomping that a surface-level review misses.
- LOLBin path context -- ttdinject.exe in System32 is legitimate. ttdinject.exe in C:\Users\jsmith\AppData\ is a finding. Path context is what makes the difference between signal and noise.
- Streaming design -- Enterprise $MFT files routinely exceed 1GB. Loading them into memory causes the kind of CSV truncation problems that motivated these tools in the first place. Every parser streams record by record.
- Zero dependencies -- IR environments are often locked down. A tool that requires pip installs is a tool that will not run when you need it.

---

## Output Structure

After running case_triage.py, your output directory will contain:

```
results/
├── case_report_CASE-2024-001.html     (open this first)
├── case_CASE-2024-001.db              (SQLite -- query freely)
├── case_summary_CASE-2024-001.txt     (draft narrative for report)
├── mft_analysis_report.html           (standalone MFT report)
├── mft_analysis.db                    (MFT findings SQLite)
├── attack_timeline.html               (standalone timeline report)
├── attack_timeline.db                 (timeline findings SQLite)
└── attack_timeline_summary.txt        (timeline narrative)
```

The SQLite databases accept any standard SQL queries -- no row limits, no Excel truncation.

---

## Requirements

- Python 3.6 or higher
- No third-party packages required
- Windows or Linux
- All scripts in the same directory (case_triage.py auto-detects siblings)

---

## Disclaimer

These tools are intended for use by qualified digital forensic examiners and incident responders on systems and data they are authorised to examine. Always follow proper chain of custody procedures. Tool output should be validated against raw artifacts before inclusion in any formal report or legal proceeding.

---

## License

MIT License -- see LICENSE file for full terms.
