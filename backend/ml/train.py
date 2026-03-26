import pandas as pd
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# ------------------------------------------------
# PATH CONFIGURATION
# ------------------------------------------------

# Current file location → backend/ml/train.py
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

# Go to project root (two levels up)
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))

# Dataset path (located in project root)
DATA_PATH = os.path.join(PROJECT_ROOT, "phishing.csv")

# Model + feature schema save location (inside backend/ml)
MODEL_PATH = os.path.join(CURRENT_DIR, "phishing_model.pkl")
FEATURE_PATH = os.path.join(CURRENT_DIR, "feature_columns.pkl")

print("Loading dataset from:", DATA_PATH)

# ------------------------------------------------
# LOAD DATASET (ONLY ONCE)
# ------------------------------------------------
df = pd.read_csv(DATA_PATH)

print("Dataset Shape:", df.shape)
print("Columns:", df.columns.tolist())

# ------------------------------------------------
# CLEAN DATASET
# ------------------------------------------------

# Drop useless Index column if present
if "Index" in df.columns:
    df = df.drop(columns=["Index"])
    print("Dropped 'Index' column")

# ------------------------------------------------
# SPLIT FEATURES & TARGET
# ------------------------------------------------
X = df.drop("class", axis=1)
y = df["class"]

# Convert -1/1 labels to 0/1 if needed
if set(y.unique()) == {-1, 1}:
    y = y.replace({-1: 0, 1: 1})

# ------------------------------------------------
# SAVE FEATURE COLUMN ORDER (CRITICAL)
# ------------------------------------------------
feature_columns = X.columns.tolist()
joblib.dump(feature_columns, FEATURE_PATH)
print("Feature schema saved to:", FEATURE_PATH)

# ------------------------------------------------
# TRAIN / TEST SPLIT
# ------------------------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# ------------------------------------------------
# MODEL TRAINING
# ------------------------------------------------
model = RandomForestClassifier(
    n_estimators=200,
    random_state=42
)

model.fit(X_train, y_train)

# ------------------------------------------------
# EVALUATION
# ------------------------------------------------
y_pred = model.predict(X_test)

print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# ------------------------------------------------
# SAVE MODEL
# ------------------------------------------------
joblib.dump(model, MODEL_PATH)
print("Model saved to:", MODEL_PATH)
