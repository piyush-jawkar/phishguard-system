import base64
import os
import time
from typing import Any, Dict, Tuple

import requests

VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
VT_BASE = "https://www.virustotal.com/api/v3"
VT_TIMEOUT = 5
VT_POLL_ATTEMPTS = 2
VT_POLL_SLEEP = 1
VT_SUBMIT_ON_UNKNOWN = os.getenv("VT_SUBMIT_ON_UNKNOWN", "false").lower() == "true"

# simple in-memory cache: {"url:<url>"|"file:<sha256>": (timestamp, (score, evidence))}
_CACHE: Dict[str, Tuple[float, Tuple[float, Dict[str, Any]]]] = {}
CACHE_TTL_SECONDS = 24 * 60 * 60


def _default_result(reason: str) -> Tuple[float, Dict[str, Any]]:
    return 0.0, {"status": "fallback", "reason": reason}


def _normalize_stats(stats: Dict[str, int]) -> float:
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    total = max(malicious + suspicious + harmless + undetected, 1)

    if malicious > 0:
        return min(0.85 + min(malicious / total, 0.15), 1.0)
    if suspicious > 0:
        return min(0.55 + min(suspicious / total, 0.2), 0.8)
    return 0.0


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def get_vt_score(url: str) -> Tuple[float, Dict[str, Any]]:
    if not url or not url.startswith(("http://", "https://")):
        return _default_result("invalid_url")
    if not VT_API_KEY:
        return _default_result("missing_api_key")

    now = time.time()
    cache_key = f"url:{url}"
    cached = _CACHE.get(cache_key)
    if cached and (now - cached[0] < CACHE_TTL_SECONDS):
        return cached[1]

    headers = {"x-apikey": VT_API_KEY}

    try:
        # Fast path: try URL report directly
        report_resp = requests.get(
            f"{VT_BASE}/urls/{_url_id(url)}", headers=headers, timeout=VT_TIMEOUT
        )
        if report_resp.status_code == 200:
            attrs = report_resp.json()["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            score = _normalize_stats(stats)
            result = (
                score,
                {
                    "status": "ok",
                    "source": "report",
                    "stats": stats,
                    "last_analysis_date": attrs.get("last_analysis_date"),
                },
            )
            _CACHE[cache_key] = (now, result)
            return result

        if report_resp.status_code in (400, 404) and not VT_SUBMIT_ON_UNKNOWN:
            return _default_result("not_found")

        # If unknown/not ready, optionally submit for analysis
        submit_resp = requests.post(
            f"{VT_BASE}/urls",
            headers=headers,
            data={"url": url},
            timeout=VT_TIMEOUT,
        )
        if submit_resp.status_code not in (200, 202):
            return _default_result(f"submit_failed_{submit_resp.status_code}")

        analysis_id = submit_resp.json()["data"]["id"]

        for _ in range(VT_POLL_ATTEMPTS):
            poll_resp = requests.get(
                f"{VT_BASE}/analyses/{analysis_id}", headers=headers, timeout=VT_TIMEOUT
            )
            if poll_resp.status_code != 200:
                time.sleep(VT_POLL_SLEEP)
                continue

            attrs = poll_resp.json()["data"]["attributes"]
            if attrs.get("status") != "completed":
                time.sleep(VT_POLL_SLEEP)
                continue

            stats = attrs.get("stats", {})
            score = _normalize_stats(stats)
            result = (
                score,
                {
                    "status": "ok",
                    "source": "analysis",
                    "stats": stats,
                    "analysis_id": analysis_id,
                },
            )
            _CACHE[cache_key] = (time.time(), result)
            return result

        return _default_result("analysis_timeout")

    except requests.RequestException as exc:
        return _default_result(f"request_error:{type(exc).__name__}")


def get_vt_file_hash_score(file_hash: str) -> Tuple[float, Dict[str, Any]]:
    normalized_hash = (file_hash or "").strip().lower()
    if not normalized_hash:
        return _default_result("missing_file_hash")
    if not VT_API_KEY:
        return _default_result("missing_api_key")

    now = time.time()
    cache_key = f"file:{normalized_hash}"
    cached = _CACHE.get(cache_key)
    if cached and (now - cached[0] < CACHE_TTL_SECONDS):
        return cached[1]

    headers = {"x-apikey": VT_API_KEY}

    try:
        report_resp = requests.get(
            f"{VT_BASE}/files/{normalized_hash}", headers=headers, timeout=VT_TIMEOUT
        )

        if report_resp.status_code == 200:
            attrs = report_resp.json()["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            score = _normalize_stats(stats)
            result = (
                score,
                {
                    "status": "ok",
                    "source": "file_report",
                    "stats": stats,
                    "sha256": normalized_hash,
                    "meaningful_name": attrs.get("meaningful_name"),
                },
            )
            _CACHE[cache_key] = (now, result)
            return result

        if report_resp.status_code in (400, 404):
            return _default_result("file_not_found")

        return _default_result(f"file_report_failed_{report_resp.status_code}")

    except requests.RequestException as exc:
        return _default_result(f"request_error:{type(exc).__name__}")
