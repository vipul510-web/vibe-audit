from dataclasses import dataclass, field


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_SCORE = {"CRITICAL": 20, "HIGH": 12, "MEDIUM": 5, "LOW": 2, "INFO": 0}


@dataclass
class Finding:
    id: str
    category: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    file: str
    line: int
    code_snippet: str
    fix_prompt: str = ""
    ai_explanation: str = ""

    def to_dict(self):
        return {
            "id": self.id,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "file": self.file,
            "line": self.line,
            "code_snippet": self.code_snippet,
            "fix_prompt": self.fix_prompt,
            "ai_explanation": self.ai_explanation,
        }


def compute_score(findings: list) -> int:
    deduction = sum(SEVERITY_SCORE.get(f.severity, 0) for f in findings)
    return max(0, 100 - deduction)


def score_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"
