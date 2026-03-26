import pandas as pd
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))

DATA_PATH = os.path.join(PROJECT_ROOT, "sms.tsv")

MODEL_PATH = os.path.join(CURRENT_DIR, "text_model.pkl")
VECTORIZER_PATH = os.path.join(CURRENT_DIR, "text_vectorizer.pkl")

print("Loading dataset from:", DATA_PATH)

df = pd.read_csv(DATA_PATH, sep="\t")

df.columns = ["label", "text"]

df["label"] = df["label"].map({
    "spam": 1,
    "ham": 0
})

X_train, X_test, y_train, y_test = train_test_split(
    df["text"], df["label"], test_size=0.2, random_state=42
)

vectorizer = TfidfVectorizer(
    max_features=5000,
    ngram_range=(1,2),
    stop_words="english"
)

X_train_tfidf = vectorizer.fit_transform(X_train)
X_test_tfidf = vectorizer.transform(X_test)

model = LogisticRegression(max_iter=1000)
model.fit(X_train_tfidf, y_train)

y_pred = model.predict(X_test_tfidf)

print(classification_report(y_test, y_pred))

joblib.dump(model, MODEL_PATH)
joblib.dump(vectorizer, VECTORIZER_PATH)

print("Text model saved.")
