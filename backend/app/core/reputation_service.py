from urllib.parse import urlparse

SAFE_DOMAINS = [
    "dropbox.com",
    "google.com",
    "microsoft.com",
    "github.com",
    "amazon.com",
    "kotak.com",
    "kotak811.com"
]

def check_reputation(url: str) -> float:

    if not url:
        return 0.0

    domain = urlparse(url).netloc.lower()

    for safe in SAFE_DOMAINS:
        if safe in domain:
            return 0.0   # trusted brand

    return 0.2  # mild unknown risk
