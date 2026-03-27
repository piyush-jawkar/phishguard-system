TRUSTED_DOMAINS = [
    "dropbox.com",
    "links.dropbox.com",
    "google.com",
    "mail.google.com",
    "accounts.google.com"
]

from urllib.parse import urlparse

def is_whitelisted_domain(url: str) -> bool:
    domain = urlparse(url).netloc.lower()
    return any(trusted in domain for trusted in TRUSTED_DOMAINS)
