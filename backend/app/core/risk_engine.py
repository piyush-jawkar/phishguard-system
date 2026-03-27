from urllib.parse import urlparse
import difflib


TRUSTED_DOMAINS = [
    "dropbox.com",
    "google.com",
    "microsoft.com",
    "facebook.com",
    "apple.com",
    "amazon.com"
]

SENSITIVE_KEYWORDS = [
    "login", "verify", "reset", "password",
    "account", "secure", "confirm", "update"
]


def is_trusted_domain(url: str) -> bool:
    domain = urlparse(url).netloc.lower()
    return any(td in domain for td in TRUSTED_DOMAINS)


def has_sensitive_path(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(word in path for word in SENSITIVE_KEYWORDS)


def brand_spoofing_score(url: str) -> float:
    domain = urlparse(url).netloc.lower()

    for brand in TRUSTED_DOMAINS:
        similarity = difflib.SequenceMatcher(None, domain, brand).ratio()
        if similarity > 0.75 and brand not in domain:
            return 1.0

    return 0.0


def calculate_risk(
    url_score: float,
    content_score: float,
    link_score: float,
    text_ml_score: float,
    unicode_score: float,
    reputation_score: float,
    brand_spoof_score: float = 0.0,
    attachment_score: float = 0.0,
    vt_score: float = 0.0,
    url: str | None = None
):
    # ------------------------------------------------
    # HARD RULE OVERRIDES (Security First)
    # ------------------------------------------------
    if vt_score >= 0.85:
        return "HIGH"

    if url_score >= 0.82:
        return "HIGH"

    if link_score >= 0.9:
        return "HIGH"

    if reputation_score >= 0.7:
        return "HIGH"

    if brand_spoof_score >= 0.95:
        return "HIGH"

    if attachment_score >= 0.95:
        return "HIGH"

    # ------------------------------------------------
    # Weighted Risk Model
    # ------------------------------------------------
    base_score = (
        (url_score * 0.24) +
        (content_score * 0.12) +
        (link_score * 0.12) +
        (text_ml_score * 0.14) +
        (unicode_score * 0.05) +
        (reputation_score * 0.08) +
        (brand_spoof_score * 0.10) +
        (vt_score * 0.15)
    )
    final_score = base_score if attachment_score <= 0 else ((base_score * 0.88) + (attachment_score * 0.12))

    # ------------------------------------------------
    # Risk Classification
    # ------------------------------------------------
    if final_score >= 0.7:
        return "HIGH"
    elif final_score >= 0.4:
        return "MEDIUM"
    else:
        return "SAFE"
