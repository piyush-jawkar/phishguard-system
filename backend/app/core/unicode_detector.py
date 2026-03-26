def analyze_unicode(text: str) -> float:
    if not text:
        return 0.0

    suspicious_count = 0
    total = len(text)

    for char in text:
        if ord(char) > 127:  # Non-ASCII character
            suspicious_count += 1

    ratio = suspicious_count / total if total > 0 else 0

    return min(ratio * 5, 1.0)
