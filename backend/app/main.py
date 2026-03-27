from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse
import heapq
from typing import Optional

# Core Hybrid Engine Imports
from app.core.text_ml_classifier import predict_text
from app.core.unicode_detector import analyze_unicode
from app.core.reputation_service import check_reputation
from app.core.content_analyzer import analyze_text
from app.core.link_analyzer import analyze_links
from app.core.risk_engine import calculate_risk
from app.core.ml_classifier import predict_url
from app.core.brand_detector import detect_brand_spoof
from app.core.vt_service import get_vt_score, get_vt_file_hash_score
from app.core.attachment_analyzer import analyze_attachments


# ------------------------------------------------
# TRUSTED DOMAIN LIST
# ------------------------------------------------
TRUSTED_DOMAINS = [
    "google.com",
    "c.gle",
    "dropbox.com",
    "links.dropbox.com",
    "microsoft.com",
    "amazon.com",
    "kotak.com",
    "kotak811.com",
    "twitch.tv",
    "instagram.com",
    "steampowered.com",
    "riotgames.com"
]


def is_trusted_domain(link: str) -> bool:
    try:
        parsed = urlparse(link)
        domain = parsed.netloc.lower()
        return any(td in domain for td in TRUSTED_DOMAINS)
    except Exception:
        return False


# ------------------------------------------------
# APP INITIALIZATION
# ------------------------------------------------
app = FastAPI(title="PhishGuard API")


# ------------------------------------------------
# CORS (DEV MODE)
# ------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------------------------------------------
# REQUEST MODEL
# ------------------------------------------------
class EmailRequest(BaseModel):
    url: str
    body: str
    links: list[str]
    attachments: Optional[list[dict]] = None


# ------------------------------------------------
# HEALTH CHECK
# ------------------------------------------------
@app.get("/")
def health_check():
    return {"status": "PhishGuard API Running"}


# ------------------------------------------------
# URL QUICK ANALYSIS
# ------------------------------------------------
@app.get("/analyze-url")
def analyze_url(url: str = Query(...)):
    url_score = predict_url(url)
    reputation_score = check_reputation(url)

    vt_score, vt_info = get_vt_score(url)
    brand_spoof_score = detect_brand_spoof(url)

    final_risk = calculate_risk(
        url_score=url_score,
        content_score=0.0,
        link_score=0.0,
        text_ml_score=0.0,
        unicode_score=0.0,
        reputation_score=reputation_score,
        brand_spoof_score=brand_spoof_score,
        attachment_score=0.0,
        vt_score=vt_score,
    )

    return {
        "url": url,
        "risk_level": final_risk,
        "details": {
            "url_score": url_score,
            "reputation_score": reputation_score,
            "brand_spoof_score": brand_spoof_score,
            "vt_score": vt_score,
            "vt_info": vt_info
        }
    }


# ------------------------------------------------
# FULL HYBRID EMAIL ANALYSIS
# ------------------------------------------------
@app.post("/analyze-email")
def analyze_email(data: EmailRequest):
    print("\n========== EMAIL DEBUG ==========")
    print("Tab URL:", data.url)
    print("Extracted Links:", data.links)
    print("Body preview:", data.body[:200])
    print("Attachments:", len(data.attachments or []))
    print("==================================\n")

    # 1️⃣ Content Analysis
    content_score = analyze_text(data.body)

    # 2️⃣ Link Behaviour Score
    link_score = analyze_links(data.links)

    # 3️⃣ Text ML Score
    text_ml_score = predict_text(data.body)

    # 4️⃣ Unicode Detection
    unicode_score = analyze_unicode(data.body)

    # 5️⃣ URL + Reputation + Brand spoof + VT scores
    url_scores = []
    reputation_scores = []
    brand_spoof_scores = []
    vt_scores = []
    vt_evidence = []
    candidate_links: list[tuple[float, str]] = []
    attachment_vt_scores = []
    attachment_vt_evidence = []

    for link in data.links:
        if not link.startswith(("http://", "https://")):
            continue

        if is_trusted_domain(link):
            print("Trusted domain detected:", link)
            url_scores.append(0.1)
            reputation_scores.append(0.0)
            brand_spoof_scores.append(0.0)
            vt_evidence.append({"url": link, "status": "skipped_trusted"})
            continue

        current_url_score = predict_url(link)
        current_reputation_score = check_reputation(link)
        current_brand_spoof_score = detect_brand_spoof(link)

        url_scores.append(current_url_score)
        reputation_scores.append(current_reputation_score)
        brand_spoof_scores.append(current_brand_spoof_score)

        heuristic_priority = (current_url_score * 0.6) + (current_brand_spoof_score * 0.3) + (current_reputation_score * 0.1)
        candidate_links.append((heuristic_priority, link))

    # VT checks are expensive; scan only top risky links per email
    top_links = [link for _, link in heapq.nlargest(3, candidate_links, key=lambda x: x[0])]
    for link in top_links:
        vt_score_value, vt_info = get_vt_score(link)
        vt_scores.append(vt_score_value)
        vt_evidence.append({"url": link, **vt_info})

    url_score = max(url_scores) if url_scores else 0.0
    reputation_score = max(reputation_scores) if reputation_scores else 0.0
    brand_spoof_score = max(brand_spoof_scores) if brand_spoof_scores else 0.0
    vt_score = max(vt_scores) if vt_scores else 0.0

    # 6️⃣ Attachment analysis (local + VT file hash)
    attachments = data.attachments or []
    attachment_local_score, attachment_evidence = analyze_attachments(attachments)
    for item in attachments:
        file_hash = str(item.get("sha256", "") or "").strip()
        filename = str(item.get("filename", "") or "")
        if not file_hash:
            if filename:
                attachment_vt_evidence.append(
                    {"filename": filename, "status": "fallback", "reason": "missing_file_hash"}
                )
            continue
        vt_file_score, vt_file_info = get_vt_file_hash_score(file_hash)
        attachment_vt_scores.append(vt_file_score)
        attachment_vt_evidence.append(
            {"filename": filename, "sha256": file_hash, **vt_file_info}
        )

    attachment_vt_score = max(attachment_vt_scores) if attachment_vt_scores else 0.0
    attachment_score = max(attachment_local_score, attachment_vt_score)

    # 6️⃣ Final Risk Calculation
    final_risk = calculate_risk(
        url_score=url_score,
        content_score=content_score,
        link_score=link_score,
        text_ml_score=text_ml_score,
        unicode_score=unicode_score,
        reputation_score=reputation_score,
        brand_spoof_score=brand_spoof_score,
        attachment_score=attachment_score,
        vt_score=vt_score,
    )

    print("Scores:")
    print("url_score:", url_score)
    print("content_score:", content_score)
    print("link_score:", link_score)
    print("text_ml_score:", text_ml_score)
    print("unicode_score:", unicode_score)
    print("reputation_score:", reputation_score)
    print("brand_spoof_score:", brand_spoof_score)
    print("vt_score:", vt_score)
    print("attachment_score:", attachment_score)
    if vt_evidence:
        compact_vt = []
        for item in vt_evidence[:3]:
            stats = item.get("stats", {})
            compact_vt.append({
                "status": item.get("status"),
                "source": item.get("source"),
                "reason": item.get("reason"),
                "url": item.get("url"),
                "malicious": stats.get("malicious"),
                "suspicious": stats.get("suspicious"),
            })
        print("vt_evidence_summary:", compact_vt)
    if attachment_vt_evidence:
        compact_attachment_vt = []
        for item in attachment_vt_evidence[:3]:
            stats = item.get("stats", {})
            compact_attachment_vt.append(
                {
                    "status": item.get("status"),
                    "source": item.get("source"),
                    "reason": item.get("reason"),
                    "filename": item.get("filename"),
                    "malicious": stats.get("malicious"),
                    "suspicious": stats.get("suspicious"),
                }
            )
        print("attachment_vt_evidence_summary:", compact_attachment_vt)
    print("FINAL RISK:", final_risk)
    print("==================================\n")

    return {
        "risk_level": final_risk,
        "debug": {
            "url_score": url_score,
            "content_score": content_score,
            "link_score": link_score,
            "text_ml_score": text_ml_score,
            "unicode_score": unicode_score,
            "reputation_score": reputation_score,
            "brand_spoof_score": brand_spoof_score,
            "vt_score": vt_score,
            "vt_evidence": vt_evidence[:5],
            "attachment_score": attachment_score,
            "attachment_evidence": attachment_evidence[:5],
            "attachment_vt_evidence": attachment_vt_evidence[:5]
        }
    }
