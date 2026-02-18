import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

def run_powershell(ps_cmd: str, timeout: int = 25) -> tuple[int, str, str]:
    """Run a PowerShell command and return (code, stdout, stderr)."""
    # Use -NoProfile for speed and repeatability
    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError:
        return 127, "", "PowerShell not found."
    except subprocess.TimeoutExpired:
        return 124, "", "PowerShell command timed out."

def safe_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", errors="ignore")

def now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def get_basic_system_info() -> dict:
    return {
        "hostname": platform.node(),
        "os": platform.platform(),
        "python_version": sys.version.split()[0],
        "timestamp_utc": now_iso(),
    }

def get_uptime_seconds() -> int | None:
    # Windows: use Get-CimInstance Win32_OperatingSystem LastBootUpTime
    code, out, err = run_powershell(
        "(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime | "
        "Select-Object -ExpandProperty TotalSeconds"
    )
    if code == 0 and out:
        try:
            return int(float(out))
        except ValueError:
            return None
    return None

def get_defender_status() -> dict:
    # Requires Defender cmdlets to exist; on Windows 10/11 they usually do.
    ps = "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntispywareEnabled,AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Json"
    code, out, err = run_powershell(ps)
    if code == 0 and out:
        try:
            data = json.loads(out)
            return {"available": True, "data": data, "error": ""}
        except json.JSONDecodeError:
            return {"available": True, "data": {}, "error": "Failed to parse Defender output."}
    return {"available": False, "data": {}, "error": err or "Defender status unavailable."}

def get_firewall_profiles() -> dict:
    ps = "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json"
    code, out, err = run_powershell(ps)
    if code == 0 and out:
        try:
            data = json.loads(out)
            # Can be dict or list depending on count
            profiles = data if isinstance(data, list) else [data]
            return {"available": True, "profiles": profiles, "error": ""}
        except json.JSONDecodeError:
            return {"available": True, "profiles": [], "error": "Failed to parse firewall output."}
    return {"available": False, "profiles": [], "error": err or "Firewall status unavailable."}


def get_bitlocker_status() -> dict:
    exe = shutil.which("manage-bde")
    if not exe:
        return {"available": False, "volumes": [], "error": "manage-bde not found."}

    code, output = subprocess.getstatusoutput("manage-bde -status")

    if code == 0 and output:
        return {"available": True, "raw": output, "error": ""}
    else:
        return {"available": False, "raw": "", "error": output or "BitLocker status unavailable."}


def get_recent_updates(limit: int = 10) -> dict:
    # Quick, readable update history
    ps = f"Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First {limit} HotFixID,Description,InstalledOn | ConvertTo-Json"
    code, out, err = run_powershell(ps, timeout=40)
    if code == 0 and out:
        try:
            data = json.loads(out)
            updates = data if isinstance(data, list) else [data]
            return {"available": True, "updates": updates, "error": ""}
        except json.JSONDecodeError:
            return {"available": True, "updates": [], "error": "Failed to parse update output."}
    return {"available": False, "updates": [], "error": err or "Update history unavailable."}

def get_local_users(limit: int = 20) -> dict:
    ps = f"Get-LocalUser | Select-Object -First {limit} Name,Enabled,LastLogon | ConvertTo-Json"
    code, out, err = run_powershell(ps)
    if code == 0 and out:
        try:
            data = json.loads(out)
            users = data if isinstance(data, list) else [data]
            return {"available": True, "users": users, "error": ""}
        except json.JSONDecodeError:
            return {"available": True, "users": [], "error": "Failed to parse local user output."}
    return {"available": False, "users": [], "error": err or "Local users unavailable."}

def score_findings(defender: dict, firewall: dict, updates: dict) -> tuple[int, list[dict]]:
    score = 100
    findings = []

    # Defender checks
    if not defender.get("available"):
        score -= 15
        findings.append({"severity": "medium", "title": "Defender status not readable", "detail": defender.get("error", "")})
    else:
        d = defender.get("data", {})
        if d and not d.get("RealTimeProtectionEnabled", True):
            score -= 25
            findings.append({"severity": "high", "title": "Real-time protection disabled", "detail": "Enable Microsoft Defender real-time protection."})
        if d and not d.get("AntivirusEnabled", True):
            score -= 25
            findings.append({"severity": "high", "title": "Antivirus appears disabled", "detail": "Verify antivirus is enabled and updating."})

    # Firewall checks
    if not firewall.get("available"):
        score -= 10
        findings.append({"severity": "medium", "title": "Firewall status not readable", "detail": firewall.get("error", "")})
    else:
        profiles = firewall.get("profiles", [])
        disabled = [p for p in profiles if str(p.get("Enabled", "")).lower() in ("false", "0")]
        if disabled:
            score -= 20
            names = ", ".join(p.get("Name", "Unknown") for p in disabled)
            findings.append({"severity": "high", "title": "Firewall disabled on profiles", "detail": f"Disabled profiles: {names}."})

    # Update freshness check (simple heuristic)
    if updates.get("available") and updates.get("updates"):
        newest = updates["updates"][0].get("InstalledOn")
        if not newest:
            score -= 5
            findings.append({"severity": "low", "title": "Cannot determine latest update date", "detail": "InstalledOn missing for newest hotfix."})
    else:
        score -= 10
        findings.append({"severity": "medium", "title": "Update history not readable", "detail": updates.get("error", "")})

    score = max(0, min(100, score))
    return score, findings

def render_html(report: dict) -> str:
    hostname = report["system"].get("hostname", "host")
    score = int(report.get("score", 0))
    findings = report.get("findings", [])

    def esc(s: str) -> str:
        return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    score_label = "Excellent" if score >= 90 else "Good" if score >= 75 else "Fair" if score >= 60 else "Needs Work"
    score_class = "s-ex" if score >= 90 else "s-good" if score >= 75 else "s-fair" if score >= 60 else "s-bad"

    uptime = report.get("uptime_seconds")
    defender_ok = report.get("defender", {}).get("available", False)
    firewall_ok = report.get("firewall", {}).get("available", False)
    updates_count = len(report.get("updates", {}).get("updates", []) or [])

    def fmt_bool(v: bool) -> str:
        return "Available" if v else "Unavailable"

    # Findings table rows
    if not findings:
        findings_rows = "<tr><td colspan='3' class='muted'>No major findings detected.</td></tr>"
    else:
        rows = []
        for f in findings:
            sev = esc(f.get("severity", "info")).lower()
            title = esc(f.get("title", ""))
            detail = esc(f.get("detail", ""))
            sev_badge = f"<span class='sev sev-{sev}'>{sev.upper()}</span>"
            rows.append(f"<tr><td>{sev_badge}</td><td><b>{title}</b><div class='muted'>{detail}</div></td><td class='right'>Action</td></tr>")
        findings_rows = "\n".join(rows)

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Compliance Evidence Report - {esc(hostname)}</title>
  <style>
    :root {{
      --bg: #0b0f17;
      --panel: #111827;
      --panel2: #0f172a;
      --text: #e5e7eb;
      --muted: #9ca3af;
      --border: rgba(255,255,255,0.08);
      --shadow: rgba(0,0,0,0.45);
      --good: #22c55e;
      --warn: #f59e0b;
      --bad:  #ef4444;
      --info: #60a5fa;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, "Apple Color Emoji", "Segoe UI Emoji";
      background: radial-gradient(1200px 600px at 20% 0%, rgba(96,165,250,0.18), transparent 55%),
                  radial-gradient(1200px 600px at 80% 10%, rgba(34,197,94,0.12), transparent 55%),
                  var(--bg);
      color: var(--text);
    }}
    .wrap {{ max-width: 1100px; margin: 0 auto; padding: 28px 18px 50px; }}
    .top {{
      display: flex; align-items: flex-start; justify-content: space-between; gap: 14px;
      margin-bottom: 18px;
    }}
    h1 {{ font-size: 26px; margin: 0 0 6px; letter-spacing: 0.2px; }}
    .sub {{ color: var(--muted); font-size: 13px; line-height: 1.35; }}
    .pill {{
      display: inline-flex; align-items: center; gap: 10px;
      background: rgba(255,255,255,0.06);
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 10px 14px;
      box-shadow: 0 8px 24px var(--shadow);
      min-width: 210px;
      justify-content: space-between;
    }}
    .score {{
      font-size: 22px; font-weight: 800; letter-spacing: 0.4px;
    }}
    .slabel {{
      font-size: 12px; padding: 6px 10px; border-radius: 999px; border: 1px solid var(--border);
      background: rgba(255,255,255,0.06);
    }}
    .s-ex .slabel {{ border-color: rgba(34,197,94,0.35); }}
    .s-good .slabel {{ border-color: rgba(34,197,94,0.25); }}
    .s-fair .slabel {{ border-color: rgba(245,158,11,0.35); }}
    .s-bad .slabel {{ border-color: rgba(239,68,68,0.35); }}

    .grid {{
      display: grid;
      grid-template-columns: repeat(12, 1fr);
      gap: 14px;
      margin-top: 14px;
    }}
    .card {{
      background: linear-gradient(180deg, rgba(255,255,255,0.06), rgba(255,255,255,0.03));
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 16px;
      box-shadow: 0 10px 30px var(--shadow);
    }}
    .span-12 {{ grid-column: span 12; }}
    .span-8 {{ grid-column: span 8; }}
    .span-4 {{ grid-column: span 4; }}
    .span-6 {{ grid-column: span 6; }}
    .title {{ font-size: 14px; font-weight: 700; margin: 0 0 10px; color: #f3f4f6; }}
    .muted {{ color: var(--muted); }}
    .kpi {{
      display: grid; gap: 8px;
    }}
    .krow {{ display: flex; justify-content: space-between; gap: 10px; font-size: 13px; padding: 8px 10px; border-radius: 10px; background: rgba(0,0,0,0.18); border: 1px solid var(--border); }}
    .krow b {{ font-weight: 700; color: #f9fafb; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 10px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }}
    th {{ font-size: 12px; color: var(--muted); font-weight: 700; letter-spacing: 0.3px; }}
    .right {{ text-align: right; color: var(--muted); font-size: 12px; }}
    .sev {{
      display: inline-block; font-size: 11px; font-weight: 800;
      padding: 4px 8px; border-radius: 999px;
      border: 1px solid var(--border);
      background: rgba(255,255,255,0.06);
    }}
    .sev-high {{ border-color: rgba(239,68,68,0.55); }}
    .sev-medium {{ border-color: rgba(245,158,11,0.55); }}
    .sev-low {{ border-color: rgba(96,165,250,0.55); }}
    .sev-info {{ border-color: rgba(96,165,250,0.35); }}

    .footer {{
      margin-top: 16px;
      color: var(--muted);
      font-size: 12px;
    }}
    @media print {{
      body {{ background: #fff; color: #111; }}
      .card {{ box-shadow: none; }}
      .pill {{ box-shadow: none; }}
      .muted {{ color: #444; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div>
        <h1>Compliance Evidence Report</h1>
        <div class="sub">
          Host: <b>{esc(hostname)}</b><br>
          OS: {esc(report["system"].get("os",""))}<br>
          Generated (UTC): {esc(report["system"].get("timestamp_utc",""))}
        </div>
      </div>
      <div class="pill {score_class}">
        <div>
          <div class="muted" style="font-size:12px;">Overall Score</div>
          <div class="score">{score}/100</div>
        </div>
        <div class="slabel">{score_label}</div>
      </div>
    </div>

    <div class="grid">
      <div class="card span-4">
        <div class="title">Quick Summary</div>
        <div class="kpi">
          <div class="krow"><span>Defender</span><b>{fmt_bool(defender_ok)}</b></div>
          <div class="krow"><span>Firewall</span><b>{fmt_bool(firewall_ok)}</b></div>
          <div class="krow"><span>Updates Found</span><b>{updates_count}</b></div>
          <div class="krow"><span>Uptime (sec)</span><b>{uptime if uptime is not None else "N/A"}</b></div>
        </div>
      </div>

      <div class="card span-8">
        <div class="title">Findings</div>
        <table>
          <thead>
            <tr>
              <th style="width:140px;">Severity</th>
              <th>Finding</th>
              <th class="right" style="width:120px;">Next</th>
            </tr>
          </thead>
          <tbody>
            {findings_rows}
          </tbody>
        </table>
        <div class="footer">
          Outputs: <b>report.html</b>, <b>report.pdf</b>, <b>report.json</b>, evidence in <b>raw_logs/</b>
        </div>
      </div>

      <div class="card span-12">
        <div class="title">What’s Included</div>
        <div class="sub">
          This report contains evidence snapshots for Defender, Firewall, update history, local users,
          and BitLocker (when available). Use the JSON output for automation pipelines.
        </div>
      </div>
    </div>
  </div>
</body>
</html>
"""


def render_pdf(report: dict, pdf_path: Path) -> None:
    """
    Professional PDF export using ReportLab:
    - Cover page: header, score badge, summary cards, findings table
    - Page 2: evidence details (Defender/Firewall/Updates)
    """
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        )
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    except Exception as e:
        raise RuntimeError("ReportLab is not installed. Run: pip install reportlab") from e

    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    # ---------- helpers ----------
    def safe_str(v) -> str:
        return "" if v is None else str(v)

    def score_bucket(s: int) -> tuple[str, colors.Color]:
        if s >= 90:
            return "Excellent", colors.HexColor("#16a34a")
        if s >= 75:
            return "Good", colors.HexColor("#22c55e")
        if s >= 60:
            return "Fair", colors.HexColor("#f59e0b")
        return "Needs Work", colors.HexColor("#ef4444")

    def wrap_kv(d: dict, keys: list[str]) -> list[list[str]]:
        rows = []
        for k in keys:
            rows.append([k, safe_str(d.get(k))])
        return rows

    # ---------- extract ----------
    system = report.get("system", {})
    hostname = system.get("hostname", "host")
    os_name = system.get("os", "")
    ts = system.get("timestamp_utc", "")
    score = int(report.get("score", 0))
    label, accent = score_bucket(score)

    uptime = report.get("uptime_seconds")
    defender = report.get("defender", {})
    firewall = report.get("firewall", {})
    updates = report.get("updates", {})
    findings = report.get("findings", []) or []

    defender_ok = bool(defender.get("available"))
    firewall_ok = bool(firewall.get("available"))
    updates_list = updates.get("updates", []) or []
    updates_count = len(updates_list)

    # ---------- document ----------
    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.8 * inch,
        bottomMargin=0.75 * inch,
        title=f"Compliance Evidence Report - {hostname}",
        author="Compliance Evidence Collector",
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="TitleBig",
        parent=styles["Title"],
        fontSize=18,
        leading=22,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="Muted",
        parent=styles["Normal"],
        textColor=colors.HexColor("#6b7280"),
        fontSize=9.5,
        leading=12,
    ))
    styles.add(ParagraphStyle(
        name="H2",
        parent=styles["Heading2"],
        fontSize=12.5,
        leading=15,
        spaceBefore=10,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="Cell",
        parent=styles["Normal"],
        fontSize=9.5,
        leading=12,
    ))
    styles.add(ParagraphStyle(
        name="CellMuted",
        parent=styles["Normal"],
        fontSize=9,
        leading=11,
        textColor=colors.HexColor("#4b5563"),
    ))
    styles.add(ParagraphStyle(
        name="Badge",
        parent=styles["Normal"],
        fontSize=10,
        leading=12,
        textColor=colors.white,
    ))

    story = []

    # ---------- header band (table trick) ----------
    header_tbl = Table(
        [[
            Paragraph("<b>Compliance Evidence Report</b>", styles["Badge"]),
            Paragraph(f"<b>{score}/100</b> &nbsp;&nbsp; {label}", styles["Badge"])
        ]],
        colWidths=[4.9 * inch, 2.1 * inch],
        rowHeights=[0.45 * inch],
    )
    header_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (1, 0), colors.HexColor("#111827")),
        ("BACKGROUND", (1, 0), (1, 0), accent),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("ALIGN", (1, 0), (1, 0), "CENTER"),
        ("LINEBELOW", (0, 0), (-1, 0), 1, colors.HexColor("#0f172a")),
    ]))
    story.append(header_tbl)

    story.append(Spacer(1, 10))
    story.append(Paragraph(f"<b>Host:</b> {hostname} &nbsp;&nbsp; <b>OS:</b> {safe_str(os_name)}", styles["Muted"]))
    story.append(Paragraph(f"<b>Generated (UTC):</b> {safe_str(ts)}", styles["Muted"]))
    story.append(Spacer(1, 14))

    # ---------- summary cards ----------
    card_data = [
        [Paragraph("<b>Defender</b><br/>" + ("Available" if defender_ok else "Unavailable"), styles["Cell"]),
         Paragraph("<b>Firewall</b><br/>" + ("Available" if firewall_ok else "Unavailable"), styles["Cell"]),
         Paragraph("<b>Updates Found</b><br/>" + safe_str(updates_count), styles["Cell"])],
        [Paragraph("<b>Uptime (sec)</b><br/>" + (safe_str(uptime) if uptime is not None else "N/A"), styles["Cell"]),
         Paragraph("<b>Outputs</b><br/>report.html / report.pdf / report.json", styles["Cell"]),
         Paragraph("<b>Evidence</b><br/>raw_logs folder included", styles["Cell"])],
    ]
    cards = Table(card_data, colWidths=[2.33 * inch, 2.33 * inch, 2.33 * inch])
    cards.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e5e7eb")),
        ("INNERGRID", (0, 0), (-1, -1), 1, colors.HexColor("#e5e7eb")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(cards)

    # ---------- findings ----------
    story.append(Spacer(1, 12))
    story.append(Paragraph("Findings", styles["H2"]))

    if not findings:
        story.append(Paragraph("No major findings detected.", styles["Cell"]))
    else:
        # Table: Severity | Finding | Detail
        rows = [[
            Paragraph("<b>Severity</b>", styles["CellMuted"]),
            Paragraph("<b>Finding</b>", styles["CellMuted"]),
            Paragraph("<b>Detail</b>", styles["CellMuted"]),
        ]]

        for f in findings:
            sev = safe_str(f.get("severity", "info")).lower()
            title = safe_str(f.get("title", "")).strip()
            detail = safe_str(f.get("detail", "")).strip()

            sev_color = {
                "high": colors.HexColor("#ef4444"),
                "medium": colors.HexColor("#f59e0b"),
                "low": colors.HexColor("#3b82f6"),
                "info": colors.HexColor("#6b7280"),
            }.get(sev, colors.HexColor("#6b7280"))

            sev_cell = Paragraph(f"<font color='{sev_color.hexval()}'><b>{sev.upper()}</b></font>", styles["Cell"])
            rows.append([
                sev_cell,
                Paragraph(f"<b>{title}</b>", styles["Cell"]),
                Paragraph(detail, styles["CellMuted"]),
            ])

        findings_tbl = Table(rows, colWidths=[1.0 * inch, 2.5 * inch, 3.5 * inch])
        findings_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e5e7eb")),
            ("INNERGRID", (0, 0), (-1, -1), 1, colors.HexColor("#e5e7eb")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(findings_tbl)

    # ---------- page 2: evidence ----------
    story.append(PageBreak())
    story.append(Paragraph("Evidence Details", styles["H2"]))
    story.append(Paragraph(
        "This section provides a structured snapshot of collected evidence. "
        "Raw artifacts are saved in the raw_logs folder.", styles["CellMuted"]
    ))
    story.append(Spacer(1, 10))

    # Defender evidence (selected fields)
    story.append(Paragraph("Microsoft Defender", styles["H2"]))
    if defender_ok and isinstance(defender.get("data", {}), dict):
        d = defender.get("data", {})
        defender_keys = ["AMServiceEnabled", "AntispywareEnabled", "AntivirusEnabled", "RealTimeProtectionEnabled"]
        drows = [["Field", "Value"]] + wrap_kv(d, defender_keys)
        dt = Table(drows, colWidths=[2.6 * inch, 4.4 * inch])
        dt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e5e7eb")),
            ("INNERGRID", (0, 0), (-1, -1), 1, colors.HexColor("#e5e7eb")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(dt)
    else:
        story.append(Paragraph(f"Unavailable: {safe_str(defender.get('error',''))}", styles["CellMuted"]))

    story.append(Spacer(1, 10))

    # Firewall evidence
    story.append(Paragraph("Windows Firewall Profiles", styles["H2"]))
    if firewall_ok:
        profiles = firewall.get("profiles", []) or []
        frows = [[
            Paragraph("<b>Name</b>", styles["CellMuted"]),
            Paragraph("<b>Enabled</b>", styles["CellMuted"]),
        ]]
        for p in profiles:
            frows.append([Paragraph(safe_str(p.get("Name", "")), styles["Cell"]),
                          Paragraph(safe_str(p.get("Enabled", "")), styles["Cell"])])
        ft = Table(frows, colWidths=[4.6 * inch, 2.4 * inch])
        ft.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e5e7eb")),
            ("INNERGRID", (0, 0), (-1, -1), 1, colors.HexColor("#e5e7eb")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(ft)
    else:
        story.append(Paragraph(f"Unavailable: {safe_str(firewall.get('error',''))}", styles["CellMuted"]))

    story.append(Spacer(1, 10))

    # Updates evidence (top N)
    story.append(Paragraph("Recent Windows Updates (Top 10)", styles["H2"]))
    if updates.get("available") and updates_list:
        urows = [[
            Paragraph("<b>HotFixID</b>", styles["CellMuted"]),
            Paragraph("<b>Description</b>", styles["CellMuted"]),
            Paragraph("<b>InstalledOn</b>", styles["CellMuted"]),
        ]]
        for u in updates_list[:10]:
            urows.append([
                Paragraph(safe_str(u.get("HotFixID", "")), styles["Cell"]),
                Paragraph(safe_str(u.get("Description", "")), styles["CellMuted"]),
                Paragraph(safe_str(u.get("InstalledOn", "")), styles["Cell"]),
            ])
        ut = Table(urows, colWidths=[1.4 * inch, 4.2 * inch, 1.4 * inch])
        ut.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e5e7eb")),
            ("INNERGRID", (0, 0), (-1, -1), 1, colors.HexColor("#e5e7eb")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(ut)
    else:
        story.append(Paragraph(f"Unavailable: {safe_str(updates.get('error',''))}", styles["CellMuted"]))

    # ---------- footer on every page ----------
    def on_page(c, d):
        c.saveState()
        c.setFont("Helvetica", 9)
        c.setFillColor(colors.HexColor("#6b7280"))
        c.drawString(doc.leftMargin, 0.55 * inch, "Compliance Evidence Collector (Python) — Generated locally")
        c.drawRightString(letter[0] - doc.rightMargin, 0.55 * inch, f"Page {c.getPageNumber()}")
        c.restoreState()

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)


def main():
    ap = argparse.ArgumentParser(description="Compliance Evidence Collector (Windows-focused)")
    ap.add_argument("--output", default="out", help="Output directory")
    args = ap.parse_args()

    out_dir = Path(args.output).resolve()
    raw_dir = out_dir / "raw_logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)

    system = get_basic_system_info()
    uptime = get_uptime_seconds()
    defender = get_defender_status()
    firewall = get_firewall_profiles()
    bitlocker = get_bitlocker_status()
    updates = get_recent_updates(limit=10)
    users = get_local_users(limit=20)

    score, findings = score_findings(defender, firewall, updates)

    report = {
        "system": system,
        "uptime_seconds": uptime,
        "score": score,
        "findings": findings,
        "defender": defender,
        "firewall": firewall,
        "bitlocker": bitlocker,
        "updates": updates,
        "local_users": users,
    }

    # Save evidence artifacts
    safe_write(raw_dir / "defender.json", json.dumps(defender, indent=2))
    safe_write(raw_dir / "firewall.json", json.dumps(firewall, indent=2))
    safe_write(raw_dir / "updates.json", json.dumps(updates, indent=2))
    safe_write(raw_dir / "local_users.json", json.dumps(users, indent=2))
    if bitlocker.get("available"):
        safe_write(raw_dir / "bitlocker_status.txt", bitlocker.get("raw", ""))

    # Save report outputs
    safe_write(out_dir / "report.json", json.dumps(report, indent=2))
    safe_write(out_dir / "report.html", render_html(report))
    render_pdf(report, out_dir / "report.pdf")

    print(f"[+] Report written to: {out_dir / 'report.html'}")
    print(f"[+] PDF written to:    {out_dir / 'report.pdf'}")
    print(f"[+] JSON written to:   {out_dir / 'report.json'}")
    print(f"[+] Evidence in:       {raw_dir}")

if __name__ == "__main__":
    main()
