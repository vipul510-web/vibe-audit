import re
import uuid
from ._utils import iter_files, read_file, rel
from ..models import Finding

SQL_PATTERNS = [
    (r'(?i)(execute|query|cursor\.execute)\s*\(\s*f["\'].*SELECT', "SQL injection via f-string SELECT", "CRITICAL"),
    (r'(?i)(execute|query|cursor\.execute)\s*\(\s*f["\'].*INSERT', "SQL injection via f-string INSERT", "CRITICAL"),
    (r'(?i)(execute|query|cursor\.execute)\s*\(\s*f["\'].*UPDATE', "SQL injection via f-string UPDATE", "CRITICAL"),
    (r'(?i)(execute|query|cursor\.execute)\s*\(\s*f["\'].*DELETE', "SQL injection via f-string DELETE", "CRITICAL"),
    (r'(?i)(execute|query)\s*\(\s*["\'][^"\']*["\'\s]*\+', "SQL injection via string concatenation", "CRITICAL"),
    (r'(?i)(execute|query)\s*\(.*%\s*\(?\s*(request|params|body|args|form|data)', "SQL injection via % format", "CRITICAL"),
    (r'(?i)raw\s*\(\s*[f"\'].*\{', "Django raw() with f-string", "HIGH"),
    (r'(?i)\.filter\(.*=.*request\.\w+\[', "ORM filter with raw request data", "MEDIUM"),
]

XSS_PATTERNS = [
    (r'dangerouslySetInnerHTML\s*=\s*\{\s*\{', "React dangerouslySetInnerHTML", "HIGH"),
    # Only flag innerHTML when RHS is a variable/expression, not a string literal or empty string
    (r'\.innerHTML\s*=\s*[a-zA-Z_$][a-zA-Z0-9_$.]*(?:\s*\+|\s*;|\s*$)', "Direct innerHTML assignment with variable", "MEDIUM"),
    # Template literals: skip if the interpolated value is wrapped in a known escape function
    (r'\.innerHTML\s*=\s*`[^`]*\$\{(?!(?:_?escape|sanitize|encode|htmlEncode|escHtml|_citEscape|escapeHtml|DOMPurify\.sanitize|textContent)\b)[^}]+\}', "Direct innerHTML assignment with template literal", "MEDIUM"),
    (r'document\.write\s*\(', "document.write usage", "MEDIUM"),
    # Only flag eval when it's a standalone call, not inside a string/comment
    (r'(?<!["\'\w])eval\s*\([^)]+\)', "eval() with argument", "HIGH"),
    (r'(?i)render_template_string\s*\(', "Flask render_template_string", "HIGH"),
    (r'(?i)mark_safe\s*\(.*request', "Django mark_safe with request data", "HIGH"),
    (r'(?i)Markup\s*\(.*request', "Jinja2 Markup with request data", "HIGH"),
    (r'v-html\s*=', "Vue v-html directive", "MEDIUM"),
]

CMD_PATTERNS = [
    (r'(?i)(subprocess\.(run|call|Popen|check_output)|os\.system)\s*\(.*\+', "Command injection via concatenation", "CRITICAL"),
    (r'(?i)(subprocess\.(run|call|Popen|check_output)|os\.system)\s*\(\s*f["\']', "Command injection via f-string", "CRITICAL"),
    (r'(?i)shell\s*=\s*True.*\+', "subprocess shell=True with concatenation", "CRITICAL"),
    # Negative lookbehind: skip regex.exec() — only flag standalone exec calls or child_process context
    (r'(?i)child_process[^)]*exec\s*\(.*\+', "Node.js child_process.exec with concatenation", "CRITICAL"),
    (r'(?i)(?<![.\w])execSync\s*\(.*\+', "Node.js execSync with concatenation", "CRITICAL"),
    (r'(?i)(?<![.\w])execFile\s*\(.*\+', "Node.js execFile with concatenation", "CRITICAL"),
]


def scan_injection(root: str, limit: int = 500) -> list[Finding]:
    findings = []
    for fpath in iter_files(root, limit):
        content = read_file(fpath)
        if not content:
            continue
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            for pattern, label, severity in SQL_PATTERNS + XSS_PATTERNS + CMD_PATTERNS:
                if re.search(pattern, line):
                    category = "SQL/XSS Injection" if "SQL" in label or "XSS" in label or "innerHTML" in label or "eval" in label or "dangerously" in label or "v-html" in label or "template" in label or "mark_safe" in label or "Markup" in label or "document.write" in label else "Command Injection"
                    findings.append(Finding(
                        id=str(uuid.uuid4())[:8],
                        category=category,
                        severity=severity,
                        title=label,
                        description=f"Potential {label} found. User-controlled data may reach a dangerous function.",
                        file=rel(fpath, root),
                        line=i,
                        code_snippet=stripped[:200],
                    ))
                    break
    return findings
