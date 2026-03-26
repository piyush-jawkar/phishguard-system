from urllib.parse import urlparse

# Known trusted brands
KNOWN_BRANDS = [
    "google",
    "facebook",
    "microsoft",
    "dropbox",
    "amazon",
    "apple",
    "paypal",
    "instagram",
    "netflix",
    "linkedin"
]


# Simple Levenshtein Distance
def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return levenshtein(b, a)

    if len(b) == 0:
        return len(a)

    previous_row = range(len(b) + 1)
    for i, c1 in enumerate(a):
        current_row = [i + 1]
        for j, c2 in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def detect_brand_spoof(url: str) -> float:
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        if not domain:
            return 0.0

        # Remove subdomains
        domain_parts = domain.split(".")
        if len(domain_parts) >= 2:
            main_domain = domain_parts[-2]
        else:
            main_domain = domain_parts[0]

        for brand in KNOWN_BRANDS:
            distance = levenshtein(main_domain, brand)

            # If domain is very close to brand (like faceb00k)
            if distance <= 2 and main_domain != brand:
                return 1.0

        return 0.0

    except:
        return 0.0
