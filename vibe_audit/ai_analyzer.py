import os
import json
from .models import Finding

MODEL = "gpt-4o"

SYSTEM_PROMPT = """You are a security expert helping non-technical founders understand and fix security issues in their apps.

For each finding, write:
1. "explanation": 2-3 plain-English sentences. No jargon. Explain the real-world risk (data breach, account takeover, API bill, etc.).
2. "fix_prompt": A specific, copy-paste prompt the user can send directly to their AI coding agent (Claude, Cursor, Copilot). Start with "In [filename], " and describe exactly what to change. Be specific about the file and line number.

Return ONLY a valid JSON array with one object per finding, each with keys: "id", "explanation", "fix_prompt".
If you believe a finding is a false positive, still include it but note that in the explanation."""

USER_PROMPT_TEMPLATE = """Here are the security findings from scanning the project. Provide explanations and fix prompts for each.

Findings:
{findings_json}"""


def enrich_with_ai(findings: list[Finding]) -> list[Finding]:
    if not findings:
        return findings

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return findings

    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)

        findings_data = [
            {
                "id": f.id,
                "category": f.category,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "file": f.file,
                "line": f.line,
                "code_snippet": f.code_snippet,
            }
            for f in findings
        ]

        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": USER_PROMPT_TEMPLATE.format(
                    findings_json=json.dumps(findings_data, indent=2)
                )},
            ],
            response_format={"type": "json_object"},
            temperature=0.2,
        )

        raw = response.choices[0].message.content
        parsed = json.loads(raw)

        # Handle both {"findings": [...]} and [...]
        if isinstance(parsed, dict):
            enriched = parsed.get("findings", parsed.get("results", list(parsed.values())[0]))
        else:
            enriched = parsed

        id_to_enriched = {item["id"]: item for item in enriched}

        for finding in findings:
            if finding.id in id_to_enriched:
                item = id_to_enriched[finding.id]
                finding.ai_explanation = item.get("explanation", "")
                finding.fix_prompt = item.get("fix_prompt", "")

    except Exception as e:
        pass  # AI enrichment is best-effort; static findings still shown

    return findings
