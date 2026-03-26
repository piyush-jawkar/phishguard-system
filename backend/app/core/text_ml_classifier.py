import joblib
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MODEL_PATH = os.path.join(BASE_DIR, "ml", "text_model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "ml", "text_vectorizer.pkl")

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)

def predict_text(text: str) -> float:
    X = vectorizer.transform([text])
    return float(model.predict_proba(X)[0][1])
