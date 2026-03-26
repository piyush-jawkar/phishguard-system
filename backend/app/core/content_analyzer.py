SUSPICIOUS_KEYWORDS = [
    "compromised",
    "reset",
    "urgent",
    "verify",
    "login",
    "account",
    "suspended",
    "immediately"
]

def analyze_text(text: str) -> float:

    if not text:
        return 0.0

    lower = text.lower()
    hits = sum(1 for word in SUSPICIOUS_KEYWORDS if word in lower)

    return min(hits * 0.15, 1.0)
