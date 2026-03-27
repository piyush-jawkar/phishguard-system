from pathlib import Path
from typing import Any


SUSPICIOUS_EXTENSIONS = {
    ".exe": 1.0,
    ".scr": 1.0,
    ".js": 0.9,
    ".vbs": 0.9,
    ".bat": 0.9,
    ".cmd": 0.9,
    ".ps1": 0.9,
    ".jar": 0.85,
    ".msi": 0.85,
    ".hta": 0.85,
    ".iso": 0.8,
    ".dll": 0.8,
    ".docm": 0.75,
    ".xlsm": 0.75,
    ".pptm": 0.75,
    ".zip": 0.55,
    ".rar": 0.55,
    ".7z": 0.55,
}

SUSPICIOUS_NAME_KEYWORDS = (
    "invoice",
    "payment",
    "urgent",
    "verify",
    "account",
    "password",
    "statement",
    "receipt",
    "refund",
    "update",
    "security",
)


def analyze_attachments(attachments: list[dict[str, Any]]) -> tuple[float, list[dict[str, Any]]]:
    if not attachments:
        return 0.0, []

    per_attachment_scores: list[float] = []
    evidence: list[dict[str, Any]] = []

    for item in attachments:
        filename = str(item.get("filename", "") or "")
        extension = Path(filename).suffix.lower() if filename else ""
        name_lower = filename.lower()
        attachment_score = 0.0
        reasons: list[str] = []

        extension_risk = SUSPICIOUS_EXTENSIONS.get(extension, 0.0)
        if extension_risk > 0:
            attachment_score = max(attachment_score, extension_risk)
            reasons.append(f"suspicious_extension:{extension}")

        if any(keyword in name_lower for keyword in SUSPICIOUS_NAME_KEYWORDS):
            attachment_score = max(attachment_score, 0.45)
            reasons.append("suspicious_filename_keyword")

        mime = str(item.get("content_type", "") or "").lower()
        if mime in {"application/x-msdownload", "application/x-ms-installer"}:
            attachment_score = max(attachment_score, 0.9)
            reasons.append("high_risk_mime")

        if filename:
            per_attachment_scores.append(attachment_score)
            evidence.append(
                {
                    "filename": filename,
                    "score": attachment_score,
                    "reasons": reasons,
                }
            )

    if not per_attachment_scores:
        return 0.0, []

    max_score = max(per_attachment_scores)
    avg_score = sum(per_attachment_scores) / len(per_attachment_scores)
    return min((max_score * 0.8) + (avg_score * 0.2), 1.0), evidence
