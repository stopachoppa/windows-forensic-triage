#!/usr/bin/env python3
"""
case_triage.py — Unified Digital Forensic Triage Launcher
Version: 1.0

Runs MFT analysis and attack timeline/pattern detection in sequence,
cross-references findings across both sources, and produces a single
consolidated HTML case report with executive summary.

Required files in same directory (or specify paths):
  mft_direct_v2.py     — raw $MFT parser
  attack_timeline.py   — log ingestion and pattern detection

Usage:
    python case_triage.py \\
        --case "CASE-2024-001" \\
        --mft "C:\\cases\\tucker\\$MFT" \\
        --logs "C:\\cases\\tucker\\logs\\" \\
        --output "C:\\cases\\tucker\\results\\" \\
        --examiner "L. Mitchell" \\
        --host DESKTOP-W7K2MNX

    python case_triage.py \\
        --case "CASE-2024-001" \\
        --mft "C:\\cases\\tucker\\$MFT" \\
        --logs "C:\\cases\\tucker\\logs\\" \\
        --output "C:\\cases\\tucker\\results\\" \\
        --window-start "2024-03-15 08:00:00" \\
        --window-end   "2024-03-15 18:00:00" \\
        --ioc-file     "C:\\cases\\tucker\\iocs.txt" \\
        --examiner     "L. Mitchell"
"""

import os
import sys
import json
import sqlite3
import argparse
import datetime
import importlib.util
from collections import defaultdict

# ── MODULE LOADER ──────────────────────────────────────────────────────────────

def load_module(name, filepath):
    """Load a sibling script as a module by file path."""
    if not os.path.isfile(filepath):
        sys.exit(f'[ERROR] Required module not found: {filepath}\n'
                 f'        Ensure {os.path.basename(filepath)} is in the same directory.')
    spec = importlib.util.spec_from_file_location(name, filepath)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

# ── HELPERS ────────────────────────────────────────────────────────────────────

def ts(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S') if dt else ''

def parse_ts(s):
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d'):
        try:
            return datetime.datetime.strptime(s.strip(), fmt)
        except ValueError:
            continue
    raise ValueError(f'Cannot parse timestamp: {s!r}')

def now_str():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

# ── CROSS-REFERENCE ENGINE ─────────────────────────────────────────────────────

def cross_reference(mft_analyser, tl_findings, tl_events):
    """
    Find artifacts that appear in BOTH MFT findings and timeline findings.
    Returns list of cross-reference hit dicts for elevated reporting.
    """
    hits = []

    # Build lookup sets from MFT findings
    mft_filenames = set()
    mft_by_name   = defaultdict(list)
    for bucket in [
        mft_analyser.ioc_hits, mft_analyser.lolbin_observed,
        mft_analyser.suspicious_exec, mft_analyser.random_exec,
        mft_analyser.deleted, mft_analyser.staging,
    ]:
        for f in bucket:
            fname = (f.get('filename') or '').lower()
            if fname:
                mft_filenames.add(fname)
                mft_by_name[fname].append(f)

    # Build lookup from timeline findings — extract filenames from evidence/descriptions
    tl_filenames = set()
    tl_by_name   = defaultdict(list)
    for f in tl_findings:
        desc = (f.get('description','') + ' ' + ' '.join(f.get('evidence',[]))).lower()
        # Extract executable names from description text
        import re
        exes = re.findall(r'[\w\-\.]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta)', desc)
        for exe in exes:
            tl_filenames.add(exe.lower())
            tl_by_name[exe.lower()].append(f)

    # Also check prefetch and firewall events for filenames
    for ev in tl_events:
        exe = os.path.basename(ev.get('path','') or ev.get('exe','')).lower()
        if exe:
            tl_filenames.add(exe)
            tl_by_name[exe].append(ev)

    # Find intersection
    common = mft_filenames & tl_filenames
    for fname in sorted(common):
        mft_types = list({f.get('type','') for f in mft_by_name[fname]})
        tl_phases  = list({f.get('phase','') for f in tl_by_name[fname] if 'phase' in f})
        mft_ts     = min((f.get('earliest_si') or f.get('si_created','') or '9999'
                          for f in mft_by_name[fname]), default='')
        tl_ts      = min((ts(f.get('time')) if hasattr(f.get('time'), 'strftime')
                          else f.get('time','') or '9999'
                          for f in tl_by_name[fname] if f.get('time')), default='')
        mft_path   = next((f.get('path','') for f in mft_by_name[fname] if f.get('path')), '')

        hits.append({
            'filename':  fname,
            'mft_types': mft_types,
            'tl_phases': tl_phases,
            'mft_ts':    mft_ts,
            'tl_ts':     tl_ts,
            'path':      mft_path,
            'confidence': 'HIGH' if any(t in ('IOC_MATCH','TIMESTOMP') for t in mft_types) else 'MEDIUM',
        })

    return sorted(hits, key=lambda x: x['mft_ts'] or '9999')


def build_executive_summary(mft_analyser, tl_findings, xref_hits, case_meta):
    """Build a plain-text executive summary."""
    lines = []
    lines.append(f'CASE: {case_meta["case_number"]}')
    lines.append(f'EXAMINER: {case_meta["examiner"]}')
    lines.append(f'DATE: {case_meta["date"]}')
    if case_meta.get('host'):
        lines.append(f'SUBJECT HOST: {case_meta["host"]}')
    lines.append('')
    lines.append('EXECUTIVE SUMMARY')
    lines.append('=' * 60)
    lines.append('')

    # MFT summary
    mft_total = (len(mft_analyser.ioc_hits) + len(mft_analyser.suspicious_exec) +
                 len(mft_analyser.timestomp) + len(mft_analyser.lolbin_observed) +
                 len(mft_analyser.staging) + len(mft_analyser.random_exec) +
                 len(mft_analyser.deleted))
    lines.append(f'MFT ANALYSIS: {mft_total} findings from {mft_analyser.total:,} records')
    if mft_analyser.ioc_hits:
        lines.append(f'  IOC Matches          : {len(mft_analyser.ioc_hits)}  *** REVIEW IMMEDIATELY')
    if mft_analyser.timestomp:
        lines.append(f'  Timestamp Stomping   : {len(mft_analyser.timestomp)}')
    if mft_analyser.lolbin_observed:
        lines.append(f'  LOLBins Outside Path : {len(mft_analyser.lolbin_observed)}')
    if mft_analyser.suspicious_exec:
        lines.append(f'  Suspicious Executables: {len(mft_analyser.suspicious_exec)}')
    if mft_analyser.staging:
        lines.append(f'  Staging/Exfil Clues  : {len(mft_analyser.staging)}')
    lines.append('')

    # Timeline summary
    by_phase = defaultdict(int)
    for f in tl_findings:
        by_phase[f['phase']] += 1
    lines.append(f'ATTACK PATTERN ANALYSIS: {len(tl_findings)} indicators')
    for phase, count in sorted(by_phase.items()):
        lines.append(f'  {phase:<30} {count}')
    lines.append('')

    # Cross-reference
    if xref_hits:
        lines.append(f'CROSS-REFERENCED ARTIFACTS: {len(xref_hits)} artifacts confirmed across both sources')
        for h in xref_hits[:10]:
            lines.append(f'  {h["filename"]:<35} MFT: {", ".join(h["mft_types"])}')
            if h["tl_phases"]:
                lines.append(f'  {"":35} ATT&CK: {", ".join(h["tl_phases"])}')
        if len(xref_hits) > 10:
            lines.append(f'  ... and {len(xref_hits)-10} more (see full report)')
    lines.append('')
    lines.append('See full HTML report for complete findings, timeline, and evidence detail.')
    return '\n'.join(lines)

# ── CONSOLIDATED HTML REPORT ───────────────────────────────────────────────────

def write_consolidated_report(
    case_meta, mft_analyser, tl_findings, tl_events,
    xref_hits, executive_summary, html_path, dataset_meta=None
):
    """Build single consolidated HTML report combining all tool outputs."""

    from collections import defaultdict as _dd
    import re as _re
    import json as _json

    if dataset_meta is None:
        dataset_meta = {'computers': [], 'sources': []}

    computers   = dataset_meta.get('computers', [])
    sources     = dataset_meta.get('sources', [])

    # ── Serialise events for JS (computer filter + search) ──
    # Build a compact event list for the JS layer
    # Each entry: {time, computer, source, channel, summary, phase, technique}
    js_events = []
    for ev in tl_events:
        raw = ev.get('raw')
        if hasattr(raw, 'find'):
            from attack_timeline import get_data as _get_data
            summary = (_get_data(raw,'CommandLine') or _get_data(raw,'TaskName') or
                       _get_data(raw,'ServiceName') or _get_data(raw,'ScriptBlockText') or
                       _get_data(raw,'User') or '')[:200]
        elif isinstance(raw, dict):
            summary = ' | '.join(f'{k}={v}' for k,v in list(raw.items())[:4])[:200]
        else:
            summary = ev.get('exe','') or ev.get('path','') or ''
        js_events.append({
            't': ts(ev['time']),
            'c': ev.get('computer',''),
            's': ev.get('source',''),
            'ch': ev.get('channel',''),
            'eid': str(ev.get('event_id','')),
            'sum': summary,
        })

    # Also include MFT findings in search index
    js_mft = []
    for bucket in [mft_analyser.ioc_hits, mft_analyser.lolbin_observed,
                   mft_analyser.suspicious_exec, mft_analyser.timestomp,
                   mft_analyser.staging, mft_analyser.random_exec,
                   mft_analyser.deleted, mft_analyser.ads_files]:
        for f in bucket:
            js_mft.append({
                't': f.get('earliest_si') or f.get('si_created',''),
                'fn': f.get('filename',''),
                'p': f.get('path',''),
                'type': f.get('type',''),
                'ioc': f.get('ioc_term',''),
                'flags': f.get('flags',''),
            })

    js_tl = []
    for f in tl_findings:
        js_tl.append({
            't': ts(f['time']),
            'phase': f['phase'],
            'tech': f['technique'],
            'conf': f['confidence'],
            'desc': f['description'],
            'ev': ' | '.join(f['evidence'][:3]),
            'host': f.get('host',''),
        })

    events_json = _json.dumps(js_events,   separators=(',',':'))
    mft_json    = _json.dumps(js_mft,      separators=(',',':'))
    tl_json     = _json.dumps(js_tl,       separators=(',',':'))
    computers_json = _json.dumps(sorted(computers), separators=(',',':'))

    # ── MFT findings grouped section ──
    def mft_grouped_table(bucket, cols):
        if not bucket:
            return '<p class="none">No findings.</p>'
        groups = _dd(list)
        for f in bucket:
            key = (f.get('filename','') or '').lower()
            groups[key].append(f)

        rows = ''
        for fname_l, items in sorted(groups.items(),
                key=lambda x: min(i.get('earliest_si') or i.get('si_created','9999') for i in x[1])):
            primary = min(items, key=lambda x: x.get('earliest_si') or x.get('si_created','9999'))
            count = len(items)
            cls = ''
            ftype = primary.get('type','')
            if ftype == 'IOC_MATCH':
                cls = 'high'
            elif ftype == 'TIMESTOMP' and primary.get('severity') == 'HIGH':
                cls = 'high'
            elif ftype in ('LOLBIN','TIMESTOMP'):
                cls = 'medium'
            elif not primary.get('in_use', True):
                cls = 'deleted'

            # Build search-data attribute from all meaningful fields
            search_str = ' '.join([
                primary.get('filename',''), primary.get('path',''),
                primary.get('ioc_term',''), primary.get('lolbin_desc',''),
                primary.get('flags',''), ftype,
            ]).lower()

            def cell(col):
                c = col.lower()
                if c == 'filename':   return f'<strong>{primary.get("filename","")}</strong>'
                if c == 'path':       return f'<span class="mono">{primary.get("path","")}</span>'
                if c in ('earliest_si','si_created'):
                    return primary.get('earliest_si') or primary.get('si_created','')
                if c == 'fn_created': return primary.get('fn_created','')
                if c == 'filesize':
                    s = primary.get('filesize',0)
                    return f'{s:,}' if s else ''
                if c == 'in_use':     return '✓' if primary.get('in_use',True) else '✗ deleted'
                if c == 'ioc_term':   return primary.get('ioc_term','')
                if c == 'lolbin_desc':
                    d = primary.get('lolbin_desc','')
                    return f'<span title="{d}">{d[:55]}{"…" if len(d)>55 else ""}</span>'
                if c == 'delta_readable': return primary.get('delta_readable','')
                if c == 'severity':   return primary.get('severity','')
                if c == 'entropy':    return str(primary.get('entropy',''))
                if c == 'flags':      return primary.get('flags','')
                return ''

            tds = ''.join(f'<td>{cell(c)}</td>' for c in cols)
            count_td = (f'<td><span class="occ">{count}×</span></td>' if count > 1 else '<td></td>')
            rows += f'<tr class="{cls}" data-search="{search_str}">{tds}{count_td}</tr>'

        th = ''.join(f'<th>{c}</th>' for c in cols) + '<th>#</th>'
        return f'<table class="searchable"><thead><tr>{th}</tr></thead><tbody>{rows}</tbody></table>'

    # ── Timeline findings section ──
    by_phase = _dd(list)
    for f in tl_findings:
        by_phase[f['phase']].append(f)

    from_triage = [
        'Initial Access','Execution','Persistence','Privilege Escalation',
        'Defense Evasion','Credential Access','Discovery','Lateral Movement',
        'Collection','Exfiltration','Command and Control','Impact'
    ]
    COLORS = {
        'Initial Access':'#c0392b','Execution':'#e67e22','Persistence':'#8e44ad',
        'Privilege Escalation':'#d35400','Defense Evasion':'#7f8c8d',
        'Credential Access':'#2980b9','Discovery':'#27ae60',
        'Lateral Movement':'#f39c12','Collection':'#16a085',
        'Exfiltration':'#c0392b','Command and Control':'#2c3e50','Impact':'#e74c3c',
    }

    phase_html = ''
    for phase in from_triage:
        if phase not in by_phase:
            continue
        color   = COLORS.get(phase,'#484f58')
        p_items = sorted(by_phase[phase], key=lambda x: x['time'])
        item_html = ''
        for f in p_items:
            conf_cls  = f['confidence'].lower()
            ev_lines  = ''.join(f'<li>{e}</li>' for e in f['evidence'])
            host_tag  = f'<span class="host-tag">{f["host"]}</span>' if f.get('host') else ''
            search_str = (f['phase'] + ' ' + f['technique'] + ' ' +
                          f['description'] + ' ' + f.get('host','')).lower()
            item_html += f'''
<div class="tl-finding" data-host="{f.get("host","").lower()}" data-search="{search_str}">
  <span class="tl-ts">{ts(f["time"])}</span>
  <span class="conf-badge conf-{conf_cls}">{f["confidence"]}</span>
  {host_tag}
  <div class="tl-tech">{f["technique"]}</div>
  <div class="tl-desc">{f["description"]}</div>
  <ul class="tl-ev">{ev_lines}</ul>
</div>'''
        phase_html += f'''
<div class="phase-block" data-phase="{phase}">
  <h3 style="border-left:4px solid {color};padding-left:10px;color:{color}">{phase}
    <span class="badge" style="background:{color}">{len(p_items)}</span>
  </h3>
  {item_html}
</div>'''

    # ── Cross-reference section ──
    xref_rows = ''
    for h in xref_hits:
        conf_cls = h['confidence'].lower()
        search_str = (h['filename'] + ' ' + h['path'] + ' ' +
                      ' '.join(h['mft_types']) + ' ' + ' '.join(h['tl_phases'])).lower()
        xref_rows += f'''
<tr class="{'high' if h['confidence']=='HIGH' else 'medium'}" data-search="{search_str}">
  <td><strong>{h['filename']}</strong></td>
  <td class="mono">{h['path']}</td>
  <td>{', '.join(h['mft_types'])}</td>
  <td>{', '.join(h['tl_phases'])}</td>
  <td>{h['mft_ts']}</td>
  <td><span class="conf-badge conf-{conf_cls}">{h['confidence']}</span></td>
</tr>'''
    xref_table = f'''
<table class="searchable">
  <thead><tr>
    <th>Filename</th><th>Path</th><th>MFT Finding</th>
    <th>ATT&amp;CK Phase</th><th>Earliest SI</th><th>Confidence</th>
  </tr></thead>
  <tbody>{xref_rows}</tbody>
</table>''' if xref_hits else '<p class="none">No cross-referenced artifacts.</p>'

    # ── Dashboard stats ──
    mft_cats = [
        ('IOC Matches',          len(mft_analyser.ioc_hits),        'high'),
        ('LOLBin Outside Path',  len(mft_analyser.lolbin_observed),  'medium'),
        ('Suspicious Exec',      len(mft_analyser.suspicious_exec),  'medium'),
        ('Timestamp Stomping',   len(mft_analyser.timestomp),        'medium'),
        ('Staging/Exfil Clues',  len(mft_analyser.staging),          ''),
        ('High-Entropy Names',   len(mft_analyser.random_exec),      ''),
        ('Deleted Recovery',     len(mft_analyser.deleted),          ''),
        ('ADS Files',            len(mft_analyser.ads_files),        ''),
        ('Burst Windows',        len(mft_analyser.burst_windows),    ''),
    ]
    tl_cats  = [(p, len(v)) for p, v in sorted(by_phase.items())]
    xref_count = len(xref_hits)

    def stat_card(label, value, cls=''):
        bg     = {'high':'#2d1515','medium':'#2d2008','':''}.get(cls,'')
        border = {'high':'#f85149','medium':'#d29922','':' #21262d'}.get(cls,'#21262d')
        return (f'<div class="stat-card" style="background:{bg};border-color:{border}">'
                f'<div class="stat-val">{value}</div>'
                f'<div class="stat-lbl">{label}</div></div>')

    mft_cards = ''.join(stat_card(l, v, c) for l, v, c in mft_cats if v > 0)
    tl_cards  = ''.join(stat_card(p, v) for p, v in tl_cats if v > 0)

    # ── Computer list panel ──
    comp_items = ''.join(
        f'<div class="comp-item" onclick="filterByComputer(\'{c.replace("'","")}\', this)">'
        f'{c}</div>'
        for c in sorted(computers)
    ) if computers else '<div style="color:#484f58;font-size:11px">No computer names found in logs</div>'

    # ── Source log list panel ──
    src_items = ''.join(
        f'<div class="src-item">{s}</div>'
        for s in sorted(sources)
    ) if sources else '<div style="color:#484f58;font-size:11px">No sources detected</div>'

    # ── Event viewer (by computer) ──
    ev_rows = ''
    for ev in sorted(js_events, key=lambda x: x['t']):
        ev_rows += (f'<tr data-computer="{ev["c"].lower()}" data-search="{(ev["c"]+" "+ev["ch"]+" "+ev["sum"]).lower()}">'
                    f'<td>{ev["t"]}</td>'
                    f'<td>{ev["c"]}</td>'
                    f'<td>{ev["ch"] or ev["s"]}</td>'
                    f'<td>{ev["eid"]}</td>'
                    f'<td class="mono">{ev["sum"][:120]}</td>'
                    f'</tr>')

    nav_items = [
        '<a href="#summary">Summary</a>',
        '<a href="#xref">Cross-Ref</a>',
        '<a href="#mft">MFT</a>',
        '<a href="#timeline">Timeline</a>',
        '<a href="#events">Event Viewer</a>',
    ]
    nav = ''.join(nav_items)

    host_str   = case_meta.get('host','')
    window_str = ''
    ws = case_meta.get('window_start')
    we = case_meta.get('window_end')
    if ws or we:
        window_str = f'Window: {ts(ws) if ws else "start"} → {ts(we) if we else "end"}'

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Case Report — {case_meta["case_number"]}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:"Segoe UI",Arial,sans-serif;background:#0d1117;color:#c9d1d9;font-size:13px}}
header{{background:#161b22;padding:20px 28px;border-bottom:3px solid #f85149}}
header h1{{font-size:22px;color:#f85149;letter-spacing:.02em}}
header .meta{{color:#8b949e;font-size:11.5px;margin-top:6px;line-height:2}}
nav{{background:#0d1117;padding:10px 28px;display:flex;gap:16px;flex-wrap:wrap;align-items:center;
     border-bottom:1px solid #21262d;position:sticky;top:0;z-index:99}}
nav a{{color:#58a6ff;text-decoration:none;font-size:12px;font-weight:600}}
nav a:hover{{color:#fff}}
.search-wrap{{margin-left:auto;display:flex;gap:8px;align-items:center}}
#global-search{{background:#161b22;border:1px solid #30363d;color:#c9d1d9;
               padding:5px 12px;border-radius:20px;font-size:12px;width:220px;outline:none}}
#global-search:focus{{border-color:#58a6ff}}
#global-search::placeholder{{color:#484f58}}
#search-clear{{background:none;border:none;color:#484f58;cursor:pointer;font-size:14px;padding:0 4px}}
#search-clear:hover{{color:#c9d1d9}}
#search-status{{color:#8b949e;font-size:11px;white-space:nowrap}}
.layout{{display:grid;grid-template-columns:220px 1fr;min-height:calc(100vh - 90px)}}
.sidebar{{background:#161b22;border-right:1px solid #21262d;padding:16px;
          position:sticky;top:42px;height:calc(100vh - 42px);overflow-y:auto}}
.sidebar h4{{color:#8b949e;font-size:10px;text-transform:uppercase;letter-spacing:.08em;
             margin:0 0 8px;padding-bottom:6px;border-bottom:1px solid #21262d}}
.sidebar-block{{margin-bottom:20px}}
.comp-item{{padding:5px 8px;border-radius:4px;cursor:pointer;font-size:11.5px;
            color:#c9d1d9;margin-bottom:2px;border:1px solid transparent}}
.comp-item:hover{{background:#21262d}}
.comp-item.active{{background:#1f3352;border-color:#58a6ff;color:#58a6ff}}
.comp-all{{padding:5px 8px;border-radius:4px;cursor:pointer;font-size:11px;
           color:#8b949e;margin-bottom:8px;text-decoration:underline}}
.comp-all:hover{{color:#c9d1d9}}
.src-item{{padding:3px 6px;font-size:10.5px;color:#8b949e;
           border-left:2px solid #30363d;margin-bottom:3px}}
.content{{padding:24px 28px;overflow-x:auto}}
section{{margin-bottom:40px}}
h2{{font-size:16px;color:#58a6ff;padding-bottom:8px;
    border-bottom:2px solid #21262d;margin-bottom:16px}}
h3{{font-size:13.5px;color:#c9d1d9;margin:16px 0 10px}}
.badge{{display:inline-block;font-size:10px;padding:2px 8px;
        border-radius:9px;color:#fff;margin-left:6px;font-weight:700}}
.conf-badge{{font-size:9.5px;padding:1px 5px;border-radius:3px;font-weight:700}}
.conf-high{{background:#2d1515;color:#f85149;border:1px solid #f85149}}
.conf-medium{{background:#2d2008;color:#d29922;border:1px solid #d29922}}
.conf-low{{background:#1a2a1a;color:#3fb950;border:1px solid #3fb950}}
.stat-grid{{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:20px}}
.stat-card{{background:#161b22;border:1px solid #21262d;border-radius:6px;
            padding:12px 16px;min-width:140px;text-align:center}}
.stat-val{{font-size:28px;font-weight:700;color:#c9d1d9}}
.stat-lbl{{font-size:10.5px;color:#8b949e;margin-top:4px}}
.summary-box{{background:#161b22;border-left:4px solid #f85149;
              padding:16px 20px;border-radius:3px;white-space:pre-wrap;
              font-family:"Courier New",monospace;font-size:11.5px;
              color:#c9d1d9;line-height:1.7}}
table{{width:100%;border-collapse:collapse;font-size:11.5px;margin-bottom:4px}}
th{{background:#161b22;color:#58a6ff;text-align:left;padding:6px 9px;
    border-bottom:1px solid #21262d;white-space:nowrap;cursor:pointer;user-select:none}}
th:hover{{background:#1c2128}}
td{{padding:5px 9px;border-bottom:1px solid #161b22;vertical-align:top}}
.mono{{font-family:"Courier New",monospace;font-size:10.5px;color:#8b949e;word-break:break-all}}
tr:hover td{{background:#161b22}}
tr.high td{{background:#2d1515;border-left:3px solid #f85149}}
tr.medium td{{background:#2d2008;border-left:3px solid #d29922}}
tr.deleted td{{color:#484f58;font-style:italic}}
tr.hidden{{display:none!important}}
.occ{{background:#1f6feb;color:#fff;font-size:10px;padding:1px 6px;border-radius:8px}}
.none{{color:#484f58;font-style:italic;padding:8px 0;font-size:12px}}
.phase-block{{margin-bottom:24px}}
.phase-block.hidden{{display:none}}
.tl-finding{{background:#161b22;border-radius:5px;padding:12px 14px;
             margin-bottom:8px;border-left:3px solid #21262d}}
.tl-finding.hidden{{display:none}}
.tl-ts{{color:#8b949e;font-size:10.5px;margin-right:8px}}
.tl-tech{{font-size:13px;font-weight:600;color:#c9d1d9;margin:5px 0 4px}}
.tl-desc{{font-size:12px;color:#8b949e;line-height:1.5;margin-bottom:5px}}
.tl-ev{{margin-left:16px;font-size:11px;color:#8b949e;line-height:1.6}}
.host-tag{{background:#21262d;color:#8b949e;font-size:9.5px;padding:1px 5px;
           border-radius:3px;margin-left:4px}}
.subsection{{margin-bottom:28px}}
.filter-bar{{display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap}}
.filter-info{{font-size:11px;color:#8b949e;font-style:italic}}
.no-results{{color:#484f58;font-size:12px;font-style:italic;padding:10px 0;display:none}}
footer{{padding:20px 28px;color:#484f58;font-size:11px;
        border-top:1px solid #21262d;margin-top:20px}}
</style>

<script>
// ── DATA ──────────────────────────────────────────────────────────────────────
const ALL_EVENTS  = {events_json};
const ALL_MFT     = {mft_json};
const ALL_TL      = {tl_json};
const COMPUTERS   = {computers_json};

let activeComputer = '';
let searchTerm     = '';

// ── SEARCH ────────────────────────────────────────────────────────────────────
function doSearch() {{
  searchTerm = document.getElementById('global-search').value.trim().toLowerCase();
  applyFilters();
  const status = document.getElementById('search-status');
  if (searchTerm) {{
    const vis = document.querySelectorAll('tr[data-search]:not(.hidden), .tl-finding[data-search]:not(.hidden)').length;
    status.textContent = `${{vis}} matching`;
  }} else {{
    status.textContent = '';
  }}
}}

function clearSearch() {{
  document.getElementById('global-search').value = '';
  searchTerm = '';
  applyFilters();
  document.getElementById('search-status').textContent = '';
}}

// ── COMPUTER FILTER ───────────────────────────────────────────────────────────
function filterByComputer(computer, el) {{
  if (activeComputer === computer) {{
    activeComputer = '';
    document.querySelectorAll('.comp-item').forEach(e => e.classList.remove('active'));
  }} else {{
    activeComputer = computer;
    document.querySelectorAll('.comp-item').forEach(e => e.classList.remove('active'));
    if (el) el.classList.add('active');
  }}
  applyFilters();
}}

function clearComputerFilter() {{
  activeComputer = '';
  document.querySelectorAll('.comp-item').forEach(e => e.classList.remove('active'));
  applyFilters();
}}

// ── COMBINED FILTER ───────────────────────────────────────────────────────────
function applyFilters() {{
  const st = searchTerm;
  const ac = activeComputer;

  // Table rows with data-search
  document.querySelectorAll('tr[data-search]').forEach(row => {{
    const matchSearch = !st || row.dataset.search.includes(st);
    const matchComp   = !ac || row.dataset.computer === ac ||
                        row.dataset.search.includes(ac);
    row.classList.toggle('hidden', !(matchSearch && matchComp));
  }});

  // Timeline findings
  document.querySelectorAll('.tl-finding[data-search]').forEach(el => {{
    const matchSearch = !st || el.dataset.search.includes(st);
    const matchComp   = !ac || el.dataset.host === ac ||
                        el.dataset.search.includes(ac);
    el.classList.toggle('hidden', !(matchSearch && matchComp));
  }});

  // Hide phase blocks where all findings are hidden
  document.querySelectorAll('.phase-block').forEach(block => {{
    const visible = block.querySelectorAll('.tl-finding:not(.hidden)').length;
    block.classList.toggle('hidden', visible === 0 && (st || ac));
  }});

  // Update event viewer active filter label
  const label = document.getElementById('ev-filter-label');
  if (label) {{
    const parts = [];
    if (ac) parts.push(`Computer: ${{ac}}`);
    if (st) parts.push(`Search: "${{st}}"`);
    label.textContent = parts.length ? `Active filters: ${{parts.join(' | ')}}` : '';
  }}
}}

// ── TABLE SORT ────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {{
  document.querySelectorAll('th').forEach((th, idx) => {{
    th.addEventListener('click', () => {{
      const tbody = th.closest('table').querySelector('tbody');
      const rows  = [...tbody.querySelectorAll('tr')];
      const asc   = th.dataset.asc !== 'true';
      rows.sort((a, b) => {{
        const av = a.cells[idx]?.textContent.trim() || '';
        const bv = b.cells[idx]?.textContent.trim() || '';
        return asc ? av.localeCompare(bv, undefined, {{numeric:true}})
                   : bv.localeCompare(av, undefined, {{numeric:true}});
      }});
      rows.forEach(r => tbody.appendChild(r));
      th.dataset.asc = asc;
    }});
  }});

  // Search on input
  document.getElementById('global-search').addEventListener('input', doSearch);
  document.getElementById('global-search').addEventListener('keydown', e => {{
    if (e.key === 'Escape') clearSearch();
  }});
}});
</script>
</head>
<body>

<header>
  <h1>Digital Forensic Case Report</h1>
  <div class="meta">
    <strong style="color:#c9d1d9">Case:</strong> {case_meta["case_number"]} &nbsp;|&nbsp;
    <strong style="color:#c9d1d9">Examiner:</strong> {case_meta["examiner"]} &nbsp;|&nbsp;
    <strong style="color:#c9d1d9">Generated:</strong> {case_meta["date"]} UTC
    {f'&nbsp;|&nbsp;<strong style="color:#c9d1d9">Host:</strong> {host_str}' if host_str else ''}
    {f'<br><strong style="color:#c9d1d9">{window_str}</strong>' if window_str else ''}
    <br>MFT records: {mft_analyser.total:,} &nbsp;|&nbsp;
    Timeline indicators: {len(tl_findings)} &nbsp;|&nbsp;
    Cross-referenced: {xref_count} &nbsp;|&nbsp;
    Log sources: {len(sources)} &nbsp;|&nbsp;
    Computers: {len(computers)}
  </div>
</header>

<nav>
  <a href="#summary">Summary</a>
  <a href="#xref">Cross-Ref</a>
  <a href="#mft">MFT</a>
  <a href="#timeline">Timeline</a>
  <a href="#events">Event Viewer</a>
  <div class="search-wrap">
    <input id="global-search" type="text" placeholder="🔍  Search all findings...">
    <button id="search-clear" onclick="clearSearch()" title="Clear search">✕</button>
    <span id="search-status"></span>
  </div>
</nav>

<div class="layout">

<!-- SIDEBAR -->
<div class="sidebar">
  <div class="sidebar-block">
    <h4>Computers in Dataset</h4>
    <div class="comp-all" onclick="clearComputerFilter()">Show all</div>
    {comp_items}
  </div>
  <div class="sidebar-block">
    <h4>Log Sources</h4>
    {src_items}
  </div>
</div>

<!-- MAIN CONTENT -->
<div class="content">

<!-- EXECUTIVE SUMMARY -->
<section id="summary">
  <h2>Executive Summary</h2>
  <div class="stat-grid">
    {stat_card("Cross-Referenced", xref_count, "high" if xref_count else "")}
    {stat_card("IOC Matches", len(mft_analyser.ioc_hits), "high" if mft_analyser.ioc_hits else "")}
    {stat_card("ATT&CK Indicators", len(tl_findings))}
    {stat_card("Attack Phases", len(by_phase))}
    {stat_card("MFT Records", f"{mft_analyser.total:,}")}
    {stat_card("Log Sources", len(sources))}
    {stat_card("Computers", len(computers))}
  </div>
  <div class="summary-box">{executive_summary}</div>
</section>

<!-- CROSS-REFERENCE -->
<section id="xref">
  <h2>Cross-Referenced Artifacts
    <span class="badge" style="background:#f85149">{xref_count}</span>
  </h2>
  <p style="color:#8b949e;font-size:11.5px;margin-bottom:12px">
    Artifacts confirmed across both MFT analysis and attack timeline/log sources.
    Corroboration across independent evidence sources increases confidence.
  </p>
  {xref_table}
</section>

<!-- MFT ANALYSIS -->
<section id="mft">
  <h2>MFT Analysis</h2>
  <div class="stat-grid">{mft_cards}</div>

  <div class="subsection">
    <h3>IOC Matches</h3>
    {mft_grouped_table(mft_analyser.ioc_hits,
      ['filename','ioc_term','ext','earliest_si','fn_created','filesize','in_use','path'])}
  </div>
  <div class="subsection">
    <h3>LOLBin Observed Outside System Path</h3>
    {mft_grouped_table(mft_analyser.lolbin_observed,
      ['filename','ext','earliest_si','fn_created','filesize','in_use','lolbin_desc','path'])}
  </div>
  <div class="subsection">
    <h3>Timestamp Stomping Suspects</h3>
    {mft_grouped_table(mft_analyser.timestomp,
      ['filename','ext','earliest_si','fn_created','delta_readable','severity','path'])}
  </div>
  <div class="subsection">
    <h3>Suspicious Executable Locations</h3>
    {mft_grouped_table(mft_analyser.suspicious_exec,
      ['filename','ext','earliest_si','fn_created','filesize','flags','path'])}
  </div>
  <div class="subsection">
    <h3>Staging / Exfiltration Indicators</h3>
    {mft_grouped_table(mft_analyser.staging,
      ['filename','ext','earliest_si','fn_created','filesize','flags','path'])}
  </div>
  <div class="subsection">
    <h3>High-Entropy Executable Names</h3>
    {mft_grouped_table(mft_analyser.random_exec,
      ['filename','ext','entropy','earliest_si','fn_created','path'])}
  </div>
  <div class="subsection">
    <h3>Deleted Entry Recovery</h3>
    {mft_grouped_table(mft_analyser.deleted,
      ['filename','ext','earliest_si','fn_created','filesize','path'])}
  </div>
  <div class="subsection">
    <h3>Alternate Data Streams</h3>
    {mft_grouped_table(mft_analyser.ads_files,
      ['filename','ext','earliest_si','filesize','path'])}
  </div>
</section>

<!-- ATTACK TIMELINE -->
<section id="timeline">
  <h2>Attack Pattern Analysis &amp; Timeline</h2>
  <div class="stat-grid">{tl_cards}</div>
  {phase_html if phase_html else '<p class="none">No attack patterns detected.</p>'}
</section>

<!-- EVENT VIEWER -->
<section id="events">
  <h2>Event Viewer</h2>
  <div class="filter-bar">
    <span class="filter-info" id="ev-filter-label"></span>
    <span style="color:#484f58;font-size:11px">
      Click a computer in the sidebar to filter · Use search bar to filter by keyword
    </span>
  </div>
  <table>
    <thead><tr>
      <th>Time</th><th>Computer</th><th>Channel / Source</th>
      <th>Event ID</th><th>Summary</th>
    </tr></thead>
    <tbody>
      {ev_rows if ev_rows else '<tr><td colspan="5" class="none">No events loaded.</td></tr>'}
    </tbody>
  </table>
</section>

</div><!-- .content -->
</div><!-- .layout -->

<footer>
  case_triage.py v1.0 &nbsp;|&nbsp;
  mft_direct.py v2.0 + attack_timeline.py v1.0 &nbsp;|&nbsp;
  No third-party dependencies
</footer>
</body>
</html>'''

    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html)



# ── CONSOLIDATED SQLITE ────────────────────────────────────────────────────────

def write_consolidated_sqlite(mft_analyser, tl_findings, tl_events, xref_hits, db_path):
    conn = sqlite3.connect(db_path)
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS mft_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_type TEXT, filename TEXT, path TEXT, ext TEXT,
            earliest_si TEXT, fn_created TEXT, filesize INTEGER,
            flags TEXT, in_use INTEGER, ioc_term TEXT, lolbin_desc TEXT,
            delta_readable TEXT, severity TEXT, entropy REAL
        );
        CREATE TABLE IF NOT EXISTS timeline_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phase TEXT, technique TEXT, confidence TEXT,
            time TEXT, description TEXT, evidence TEXT, host TEXT
        );
        CREATE TABLE IF NOT EXISTS cross_reference (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT, path TEXT, mft_types TEXT,
            tl_phases TEXT, mft_ts TEXT, tl_ts TEXT, confidence TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_mft_type ON mft_findings(finding_type);
        CREATE INDEX IF NOT EXISTS idx_tl_phase ON timeline_findings(phase);
        CREATE INDEX IF NOT EXISTS idx_xref_conf ON cross_reference(confidence);
    ''')
    c = conn.cursor()

    # MFT findings
    all_mft = (mft_analyser.ioc_hits + mft_analyser.lolbin_observed +
               mft_analyser.suspicious_exec + mft_analyser.timestomp +
               mft_analyser.staging + mft_analyser.random_exec +
               mft_analyser.ads_files + mft_analyser.deleted)
    for f in all_mft:
        c.execute('''INSERT INTO mft_findings
            (finding_type,filename,path,ext,earliest_si,fn_created,filesize,
             flags,in_use,ioc_term,lolbin_desc,delta_readable,severity,entropy)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', (
            f.get('type'), f.get('filename'), f.get('path'), f.get('ext'),
            f.get('earliest_si') or f.get('si_created'),
            f.get('fn_created'), f.get('filesize',0),
            f.get('flags'), 1 if f.get('in_use',True) else 0,
            f.get('ioc_term'), f.get('lolbin_desc'),
            f.get('delta_readable'), f.get('severity'), f.get('entropy'),
        ))

    # Timeline findings
    for f in tl_findings:
        c.execute('''INSERT INTO timeline_findings
            (phase,technique,confidence,time,description,evidence,host)
            VALUES (?,?,?,?,?,?,?)''', (
            f['phase'], f['technique'], f['confidence'],
            ts(f['time']), f['description'],
            '\n'.join(f['evidence']), f.get('host',''),
        ))

    # Cross-reference
    for h in xref_hits:
        c.execute('''INSERT INTO cross_reference
            (filename,path,mft_types,tl_phases,mft_ts,tl_ts,confidence)
            VALUES (?,?,?,?,?,?,?)''', (
            h['filename'], h['path'],
            ', '.join(h['mft_types']), ', '.join(h['tl_phases']),
            h['mft_ts'], h['tl_ts'], h['confidence'],
        ))

    conn.commit()
    conn.close()

# ── MAIN ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description='Unified digital forensic triage launcher.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument('--case',         required=True,  help='Case number/name')
    ap.add_argument('--mft',          required=True,  help='Path to raw $MFT file')
    ap.add_argument('--logs',         required=True,  help='Directory containing log files')
    ap.add_argument('--output',       required=True,  help='Output directory')
    ap.add_argument('--examiner',     default='',     help='Examiner name for report header')
    ap.add_argument('--host',         default='',     help='Subject hostname filter')
    ap.add_argument('--window-start', help='Analysis window start (YYYY-MM-DD HH:MM:SS)')
    ap.add_argument('--window-end',   help='Analysis window end   (YYYY-MM-DD HH:MM:SS)')
    ap.add_argument('--ioc-file',     help='Custom IOC terms file')
    ap.add_argument('--large-file-mb',type=int, default=100)
    ap.add_argument('--mft-script',   default='',     help='Path to mft_direct_v2.py (auto-detected if blank)')
    ap.add_argument('--tl-script',    default='',     help='Path to attack_timeline.py (auto-detected if blank)')
    args = ap.parse_args()

    # Validate inputs
    if not os.path.isfile(args.mft):
        sys.exit(f'[ERROR] $MFT not found: {args.mft}')
    if not os.path.isdir(args.logs):
        sys.exit(f'[ERROR] Logs directory not found: {args.logs}')

    os.makedirs(args.output, exist_ok=True)

    window_start = parse_ts(args.window_start) if args.window_start else None
    window_end   = parse_ts(args.window_end)   if args.window_end   else None

    # Locate sibling scripts
    here = os.path.dirname(os.path.abspath(__file__))
    mft_script = args.mft_script or os.path.join(here, 'mft_direct_v2.py')
    tl_script  = args.tl_script  or os.path.join(here, 'attack_timeline.py')

    # Try alternate names
    if not os.path.isfile(mft_script):
        mft_script = os.path.join(here, 'mft_direct.py')

    print()
    print('╔══════════════════════════════════════════════════════════╗')
    print('║         CASE TRIAGE LAUNCHER  v1.0                      ║')
    print('╚══════════════════════════════════════════════════════════╝')
    print(f'  Case     : {args.case}')
    print(f'  Examiner : {args.examiner or "not specified"}')
    print(f'  $MFT     : {args.mft}')
    print(f'  Logs     : {args.logs}')
    print(f'  Output   : {args.output}')
    if window_start or window_end:
        print(f'  Window   : {ts(window_start) or "start"} → {ts(window_end) or "end"}')
    print()

    # Load modules
    print('[1/4] Loading analysis modules...')
    mft_mod = load_module('mft_direct', mft_script)
    tl_mod  = load_module('attack_timeline', tl_script)
    print(f'      mft_direct     : {os.path.basename(mft_script)}')
    print(f'      attack_timeline: {os.path.basename(tl_script)}')
    print()

    # Build IOC list
    ioc_list = list(mft_mod.DEFAULT_IOC_TERMS)
    if args.ioc_file:
        if os.path.isfile(args.ioc_file):
            with open(args.ioc_file, encoding='utf-8-sig', errors='replace') as f:
                custom = [l.strip() for l in f if l.strip() and not l.startswith('#')]
            ioc_list.extend(custom)
            print(f'      Custom IOCs: {len(custom)} terms loaded from {args.ioc_file}')

    # ── PHASE 1: MFT ANALYSIS ──
    print('[2/4] Running MFT analysis...')
    mft_size = os.path.getsize(args.mft)
    print(f'      $MFT size : {mft_size:,} bytes '
          f'(~{mft_size//mft_mod.MFT_RECORD_SIZE:,} records)')
    print('      Pass 1/2  : Building path map...')

    mft_analyser, path_map = mft_mod.run(
        mft_path      = args.mft,
        output_dir    = args.output,
        ioc_list      = ioc_list,
        window_start  = window_start,
        window_end    = window_end,
        large_file_mb = args.large_file_mb,
        write_output  = True,
    )

    print(f'      Records   : {mft_analyser.total:,}')
    print(f'      IOC hits  : {len(mft_analyser.ioc_hits)}')
    print(f'      LOLBins   : {len(mft_analyser.lolbin_observed)}')
    print(f'      Timestomp : {len(mft_analyser.timestomp)}')
    print()

    # ── PHASE 2: TIMELINE ANALYSIS ──
    print('[3/4] Running attack pattern analysis...')
    tl_findings, tl_events = tl_mod.run(
        input_dir    = args.logs,
        output_dir   = args.output,
        host_filter  = args.host or None,
        window_start = window_start,
        window_end   = window_end,
        write_output = True,
    )
    from collections import defaultdict as _dd
    by_phase = _dd(int)
    for f in tl_findings:
        by_phase[f['phase']] += 1
    print(f'      Events ingested : {len(tl_events):,}')
    print(f'      Indicators found: {len(tl_findings)}')
    for phase, count in sorted(by_phase.items()):
        print(f'        {phase:<30} {count}')
    print()

    # ── PHASE 3: CROSS-REFERENCE ──
    print('[4/4] Cross-referencing findings...')
    xref_hits = cross_reference(mft_analyser, tl_findings, tl_events)
    print(f'      Corroborated artifacts: {len(xref_hits)}')
    for h in xref_hits[:5]:
        print(f'        {h["filename"]:<35} [{h["confidence"]}]')
    if len(xref_hits) > 5:
        print(f'        ... and {len(xref_hits)-5} more')
    print()

    # ── OUTPUT ──
    case_meta = {
        'case_number':  args.case,
        'examiner':     args.examiner or 'Not specified',
        'date':         now_str(),
        'host':         args.host,
        'window_start': window_start,
        'window_end':   window_end,
    }

    executive_summary = build_executive_summary(
        mft_analyser, tl_findings, xref_hits, case_meta)

    # Build dataset metadata for the report UI
    computers = sorted({e.get('computer','') for e in tl_events if e.get('computer','')})
    sources   = sorted({e.get('source','')   for e in tl_events if e.get('source','')})
    dataset_meta = {'computers': computers, 'sources': sources}

    # Consolidated report
    report_path = os.path.join(args.output, f'case_report_{args.case}.html')
    write_consolidated_report(
        case_meta, mft_analyser, tl_findings, tl_events,
        xref_hits, executive_summary, report_path, dataset_meta
    )

    # Consolidated SQLite
    db_path = os.path.join(args.output, f'case_{args.case}.db')
    write_consolidated_sqlite(mft_analyser, tl_findings, tl_events, xref_hits, db_path)

    # Plain text summary
    txt_path = os.path.join(args.output, f'case_summary_{args.case}.txt')
    with open(txt_path, 'w', encoding='utf-8') as f:
        f.write(executive_summary)

    print('═' * 60)
    print(f'  CASE REPORT  : {report_path}')
    print(f'  SQLITE DB    : {db_path}')
    print(f'  SUMMARY TXT  : {txt_path}')
    print(f'  MFT REPORT   : {os.path.join(args.output, "mft_analysis_report.html")}')
    print(f'  TIMELINE     : {os.path.join(args.output, "attack_timeline.html")}')
    print('═' * 60)
    print()
    print(executive_summary)


if __name__ == '__main__':
    main()
