import joblib
import pandas as pd
import os
import re
from urllib.parse import urlparse

# ------------------------------------------------
# LOAD MODEL + FEATURE SCHEMA (LOCAL TO THIS FILE)
# ------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MODEL_PATH = os.path.join(BASE_DIR, "ml", "phishing_model.pkl")
FEATURE_PATH = os.path.join(BASE_DIR, "ml", "feature_columns.pkl")

model = joblib.load(MODEL_PATH)
feature_columns = joblib.load(FEATURE_PATH)


# ------------------------------------------------
# URL FEATURE EXTRACTION + PREDICTION
# ------------------------------------------------

def predict_url(url: str) -> float:

    if not url:
        return 0.0

    parsed = urlparse(url)

    features = {}

    # Basic URL heuristics
    features["UsingIP"] = 1 if re.match(r"\d+\.\d+\.\d+\.\d+", parsed.netloc) else 0
    features["LongURL"] = 1 if len(url) > 75 else 0
    features["ShortURL"] = 1 if len(parsed.netloc) < 7 else 0
    features["Symbol@"] = 1 if "@" in url else 0
    features["Redirecting//"] = 1 if url.count("//") > 1 else 0
    features["PrefixSuffix-"] = 1 if "-" in parsed.netloc else 0
    features["SubDomains"] = 1 if parsed.netloc.count(".") > 2 else 0
    features["HTTPS"] = 1 if parsed.scheme == "https" else 0

    # Fill missing features with 0
    for col in feature_columns:
        if col not in features:
            features[col] = 0

    df = pd.DataFrame([features])
    df = df[feature_columns]

    probability = model.predict_proba(df)[0][1]

    return float(probability)
