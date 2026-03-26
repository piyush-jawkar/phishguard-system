from fastapi import FastAPI
import joblib

app = FastAPI()

# Load model
model = joblib.load("model.pkl")

def extract_features(url: str):
    return [
        len(url),
        1 if url.startswith("https") else 0,
        1 if "@" in url else 0,
        1 if "-" in url else 0
    ]

@app.get("/predict")
def predict(url: str):
    features = extract_features(url)
    prediction = model.predict([features])
    return {"url": url, "phishing": bool(prediction[0])}
