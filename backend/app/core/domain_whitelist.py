TRUSTED_DOMAINS = [
    "dropbox.com",
    "links.dropbox.com",
    "google.com",
    "mail.google.com",
    "accounts.google.com"
]

from app.core.domain_whitelist import TRUSTED_DOMAINS
from urllib.parse import urlparse

domain = urlparse(url).netloc

for trusted in TRUSTED_DOMAINS:
    if trusted in domain:
        return "SAFE"
