import tldextract


def extract_domain(email):
    try:
        domain = email.split("@")[1]
        extracted = tldextract.extract(domain)
        return extracted.domain
    except:
        return ""


def validate_sender(sender: str, links: list[str]) -> float:
    sender_domain = extract_domain(sender)

    if not links:
        return 0.0

    mismatch_count = 0

    for link in links:
        extracted = tldextract.extract(link)
        link_domain = extracted.domain

        if sender_domain and link_domain != sender_domain:
            mismatch_count += 1

    ratio = mismatch_count / len(links)

    return min(ratio, 1.0)
