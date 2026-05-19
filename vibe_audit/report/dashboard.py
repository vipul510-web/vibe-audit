import html
from datetime import datetime
from ..models import Finding, compute_score, score_grade, SEVERITY_ORDER

SEVERITY_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#65a30d",
    "INFO": "#6b7280",
}

SEVERITY_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH": "#fff7ed",
    "MEDIUM": "#fffbeb",
    "LOW": "#f7fee7",
    "INFO": "#f9fafb",
}

CATEGORIES = [
    "Secrets", ".env Leaks", "Frontend Exposure", "SQL/XSS Injection",
    "Command Injection", "Sensitive Logging", "Security Headers",
    "Rate Limiting", "Dependencies", "Auth Issues",
]


def _severity_badge(severity: str) -> str:
    color = SEVERITY_COLOR.get(severity, "#6b7280")
    return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:0.5px">{severity}</span>'


def _score_color(score: int) -> str:
    if score >= 75:
        return "#16a34a"
    if score >= 50:
        return "#d97706"
    return "#dc2626"


def _category_status(category: str, findings: list[Finding]) -> str:
    cat_findings = [f for f in findings if f.category == category]
    if not cat_findings:
        return "PASS"
    severities = [f.severity for f in cat_findings]
    if "CRITICAL" in severities:
        return "CRITICAL"
    if "HIGH" in severities:
        return "HIGH"
    if "MEDIUM" in severities:
        return "MEDIUM"
    return "LOW"


def _status_dot(status: str) -> str:
    colors = {"PASS": "#16a34a", "CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706", "LOW": "#65a30d"}
    color = colors.get(status, "#6b7280")
    label = "✓ Pass" if status == "PASS" else f"✗ {status.title()}"
    return f'<span style="color:{color};font-weight:600">{label}</span>'


def generate_html(findings: list[Finding], project_path: str) -> str:
    score = compute_score(findings)
    grade = score_grade(score)
    score_col = _score_color(score)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    counts = {s: sum(1 for f in findings if f.severity == s) for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}
    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    # Category grid
    cat_cards = ""
    for cat in CATEGORIES:
        status = _category_status(cat, findings)
        count = sum(1 for f in findings if f.category == cat)
        cat_cards += f"""
        <div style="background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:14px 16px;display:flex;justify-content:space-between;align-items:center">
            <span style="font-size:13px;color:#374151;font-weight:500">{html.escape(cat)}</span>
            <div style="text-align:right">
                {_status_dot(status)}
                {f'<br><span style="font-size:11px;color:#9ca3af">{count} issue{"s" if count!=1 else ""}</span>' if count > 0 else ''}
            </div>
        </div>"""

    # Findings cards
    finding_cards = ""
    if not sorted_findings:
        finding_cards = '<div style="text-align:center;padding:40px;color:#16a34a;font-size:18px;font-weight:600">🎉 No issues found — looking good!</div>'
    else:
        for f in sorted_findings:
            bg = SEVERITY_BG.get(f.severity, "#f9fafb")
            border = SEVERITY_COLOR.get(f.severity, "#e5e7eb")
            file_line = f"{html.escape(f.file)}{f':{f.line}' if f.line else ''}"
            snippet = html.escape(f.code_snippet) if f.code_snippet else ""
            explanation = html.escape(f.ai_explanation) if f.ai_explanation else html.escape(f.description)
            fix = html.escape(f.fix_prompt) if f.fix_prompt else ""

            finding_cards += f"""
            <div style="background:{bg};border-left:4px solid {border};border-radius:8px;padding:16px 20px;margin-bottom:12px">
                <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px">
                    <div>
                        {_severity_badge(f.severity)}
                        <span style="margin-left:8px;font-size:13px;color:#6b7280;background:#f3f4f6;padding:2px 8px;border-radius:4px">{html.escape(f.category)}</span>
                    </div>
                    <code style="font-size:11px;color:#6b7280;background:#f3f4f6;padding:2px 6px;border-radius:4px">{file_line}</code>
                </div>
                <div style="font-weight:600;color:#111827;margin-bottom:6px">{html.escape(f.title)}</div>
                <div style="color:#374151;font-size:14px;margin-bottom:{'10px' if snippet or fix else '0'}">{explanation}</div>
                {f'<pre style="background:#1f2937;color:#f9fafb;padding:10px 14px;border-radius:6px;font-size:12px;overflow-x:auto;margin:8px 0 0">{snippet}</pre>' if snippet else ''}
                {f'''<div style="margin-top:10px">
                    <div style="font-size:11px;font-weight:600;color:#6b7280;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px">Fix prompt for your AI agent</div>
                    <div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:6px;padding:10px 14px;font-size:13px;color:#1e40af;font-family:monospace;cursor:pointer" onclick="navigator.clipboard.writeText(this.innerText)" title="Click to copy">{fix}</div>
                </div>''' if fix else ''}
            </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>vibe-audit — Security Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f8fafc; color: #111827; }}
  .container {{ max-width: 900px; margin: 0 auto; padding: 32px 20px; }}
  .stat-card {{ background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 20px 24px; text-align: center; }}
  .grid-4 {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }}
  .grid-2 {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; }}
  @media (max-width: 600px) {{ .grid-4 {{ grid-template-columns: repeat(2, 1fr); }} .grid-2 {{ grid-template-columns: 1fr; }} }}
  h2 {{ font-size: 16px; font-weight: 600; color: #374151; margin-bottom: 12px; }}
  section {{ margin-bottom: 32px; }}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:28px;padding-bottom:20px;border-bottom:1px solid #e5e7eb">
    <div>
      <div style="font-size:22px;font-weight:700;color:#111827">vibe-audit</div>
      <div style="font-size:13px;color:#6b7280;margin-top:2px">{html.escape(project_path)} &nbsp;·&nbsp; {now}</div>
    </div>
    <div style="text-align:right">
      <div style="font-size:52px;font-weight:800;color:{score_col};line-height:1">{score}</div>
      <div style="font-size:13px;color:#6b7280">/ 100 &nbsp; Grade: <strong style="color:{score_col}">{grade}</strong></div>
    </div>
  </div>

  <!-- Stat cards -->
  <section>
    <div class="grid-4">
      <div class="stat-card">
        <div style="font-size:28px;font-weight:800;color:#dc2626">{counts['CRITICAL']}</div>
        <div style="font-size:12px;color:#6b7280;margin-top:2px;font-weight:600">CRITICAL</div>
      </div>
      <div class="stat-card">
        <div style="font-size:28px;font-weight:800;color:#ea580c">{counts['HIGH']}</div>
        <div style="font-size:12px;color:#6b7280;margin-top:2px;font-weight:600">HIGH</div>
      </div>
      <div class="stat-card">
        <div style="font-size:28px;font-weight:800;color:#d97706">{counts['MEDIUM']}</div>
        <div style="font-size:12px;color:#6b7280;margin-top:2px;font-weight:600">MEDIUM</div>
      </div>
      <div class="stat-card">
        <div style="font-size:28px;font-weight:800;color:#65a30d">{counts['LOW']}</div>
        <div style="font-size:12px;color:#6b7280;margin-top:2px;font-weight:600">LOW</div>
      </div>
    </div>
  </section>

  <!-- Category grid -->
  <section>
    <h2>Checks ({len(CATEGORIES)} categories)</h2>
    <div class="grid-2">{cat_cards}</div>
  </section>

  <!-- Findings -->
  <section>
    <h2>Findings ({len(findings)} total)</h2>
    {finding_cards}
  </section>

  <div style="text-align:center;font-size:12px;color:#9ca3af;padding-top:16px;border-top:1px solid #e5e7eb">
    Generated by <strong>vibe-audit</strong> · github.com/YOUR_USERNAME/vibe-audit
  </div>

</div>
</body>
</html>"""
