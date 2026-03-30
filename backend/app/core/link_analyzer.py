import re
from urllib.parse import urlparse

SUSPICIOUS_BRANDS = [
    "facebook", "paypal", "instagram", "amazon", "bank", "google"
]

TRUSTED_DOMAINS = [
    "google.com",
    "c.gle",
    "microsoft.com",
    "amazon.com",
    "twitch.tv",
    "instagram.com",
    "steampowered.com",
    "riotgames.com"
]

IGNORE_PATH_KEYWORDS = [
    "unsubscribe",
    "emailoptout",
    "preferences",
    "privacy",
    "terms",
    "report",
    "support"
]


def _is_trusted_domain(domain: str) -> bool:
    return any(domain == trusted or domain.endswith(f".{trusted}") for trusted in TRUSTED_DOMAINS)


def _normalize_link(link: str) -> str:
    normalized = (link or "").strip()
    # Handle commonly defanged URLs copied from security reports/emails.
    return (
        normalized.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("{.}", ".")
    )


def _should_ignore_link(link: str) -> bool:
    try:
        parsed = urlparse(_normalize_link(link))
    except ValueError:
        return False
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    return _is_trusted_domain(domain) and any(keyword in path for keyword in IGNORE_PATH_KEYWORDS)


def analyze_links(links: list[str]) -> float:
    if not links:
        return 0.0

    per_link_scores: list[float] = []

    for link in links:
        normalized_link = _normalize_link(link)
        try:
            parsed = urlparse(normalized_link)
        except ValueError:
            continue
        domain = parsed.netloc.lower()
        lower = normalized_link.lower()

        if not domain or _should_ignore_link(normalized_link):
            continue

        per_link_risk = 0.0

        # Detect number substitution (faceb00k)
        if re.search(r"faceb0+ok|1nstagram|lnstagram|micr0soft|paypa1|g00gle", lower):
            per_link_risk += 0.7

        # Detect suspicious brand patterns in domain only (avoid query-noise)
        for brand in SUSPICIOUS_BRANDS:
            if brand in domain and not (
                domain == f"{brand}.com" or domain.endswith(f".{brand}.com")
            ):
                per_link_risk += 0.45
                break

        # Very long URL can be suspicious, but keep low weight to reduce newsletter false positives
        if len(normalized_link) > 220:
            per_link_risk += 0.1

        # Multiple subdomains in host
        if domain.count(".") > 3:
            per_link_risk += 0.15

        # Raw IP host
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
            per_link_risk += 0.5

        per_link_scores.append(min(per_link_risk, 1.0))

    if not per_link_scores:
        return 0.0

    max_score = max(per_link_scores)
    avg_score = sum(per_link_scores) / len(per_link_scores)

    return min((max_score * 0.75) + (avg_score * 0.25), 1.0)
