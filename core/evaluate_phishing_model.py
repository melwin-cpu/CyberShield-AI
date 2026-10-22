
from pathlib import Path

import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split

from core.phishing_engine import extract_url_features, FEATURE_NAMES


ROOT = Path(__file__).resolve().parent.parent
DATASET_PATH = ROOT / "dataset" / "phishing" / "phishing_urls.csv"
MODEL_PATH = ROOT / "models" / "phishing_rf_model.joblib"


def main():
    print("Loading saved model and dataset...")

    model = joblib.load(MODEL_PATH)
    df = pd.read_csv(DATASET_PATH)[["url", "label"]].dropna()

    df["url"] = df["url"].astype(str).str.strip()
    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df.dropna(subset=["label"])
    df = df[df["url"] != ""]
    df = df[df["label"].isin([0, 1])]
    df["label"] = df["label"].astype(int)
    df = df.drop_duplicates(subset=["url"])

    print("Preparing features...")
    rows = []
    labels = []
    seen = set()

    for url, label in zip(df["url"], df["label"]):
        try:
            features = extract_url_features(url)
            rows.append([features[name] for name in FEATURE_NAMES])
            labels.append(label)
            seen.add(url)
        except Exception:
            continue

    X = pd.DataFrame(rows, columns=FEATURE_NAMES)
    y = pd.Series(labels)

    _, X_test, _, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    if getattr(model, "n_features_in_", None) != len(FEATURE_NAMES):
        raise ValueError("Model feature count does not match FEATURE_NAMES.")

    predictions = model.predict(X_test)

    print("\n=== SAVED MODEL EVALUATION ===")
    print(f"Test URLs: {len(y_test):,}")
    print(f"Accuracy : {accuracy_score(y_test, predictions) * 100:.2f}%")
    print(f"Precision: {precision_score(y_test, predictions, zero_division=0) * 100:.2f}%")
    print(f"Recall   : {recall_score(y_test, predictions, zero_division=0) * 100:.2f}%")
    print(f"F1-score : {f1_score(y_test, predictions, zero_division=0) * 100:.2f}%")

    print("\nClassification report:")
    print(classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Legitimate", "Phishing"],
        zero_division=0,
    ))

    print("Confusion matrix (actual rows, predicted columns):")
    print(confusion_matrix(y_test, predictions, labels=[0, 1]))


if __name__ == "__main__":
    main()
