import json
from pathlib import Path

import numpy as np

# Compatibility for the installed legacy EMBER package
if not hasattr(np, "int"):
    np.int = int

import lightgbm as lgb
import ember

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)

ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = ROOT / "models" / "ember_model_2018.txt"
DATASET_PATH = Path(r"D:\CyberShieldData\ember2018\test_features.jsonl")

MAX_SAMPLES = 10000


def main():
    if not MODEL_PATH.is_file():
        raise FileNotFoundError(f"Model not found: {MODEL_PATH}")

    if not DATASET_PATH.is_file():
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

    print("Loading EMBER model...")
    model = lgb.Booster(model_file=str(MODEL_PATH))
    extractor = ember.PEFeatureExtractor(
        feature_version=2,
        print_feature_warning=False,
    )

    if model.num_feature() != 2381:
        raise ValueError(
            f"Expected 2381 features, got {model.num_feature()}"
        )

    features = []
    labels = []
    skipped = 0

    print(f"Reading up to {MAX_SAMPLES} labelled records...")

    # Stream the file: never load the complete 1.87 GB dataset.
    with DATASET_PATH.open("r", encoding="utf-8") as file:
        for line in file:
            if len(labels) >= MAX_SAMPLES:
                break

            try:
                record = json.loads(line)
                label = int(record["label"])

                # Ignore records without a reliable binary label.
                if label not in (0, 1):
                    skipped += 1
                    continue

                vector = extractor.process_raw_features(record)

                if len(vector) != model.num_feature():
                    raise ValueError(
                        f"Feature mismatch: {len(vector)}"
                    )

                features.append(vector)
                labels.append(label)

            except Exception as error:
                print("Record skipped:", error)
                skipped += 1

    if not labels:
        raise RuntimeError("No labelled records could be processed.")

    X = np.asarray(features, dtype=np.float32)
    y_true = np.asarray(labels, dtype=np.int32)

    print("Running predictions...")
    scores = model.predict(X)
    y_pred = (scores >= 0.5).astype(np.int32)

    print("\n===== EMBER VALIDATION RESULTS =====")
    print("Samples evaluated:", len(y_true))
    print("Records skipped:", skipped)
    print("Benign labels:", int(np.sum(y_true == 0)))
    print("Malware labels:", int(np.sum(y_true == 1)))
    print("Accuracy:", round(accuracy_score(y_true, y_pred), 4))
    print(
        "Precision:",
        round(precision_score(y_true, y_pred, zero_division=0), 4),
    )
    print(
        "Recall:",
        round(recall_score(y_true, y_pred, zero_division=0), 4),
    )
    print(
        "F1-score:",
        round(f1_score(y_true, y_pred, zero_division=0), 4),
    )
    print("\nConfusion matrix:")
    print(confusion_matrix(y_true, y_pred, labels=[0, 1]))
    print("\nClassification report:")
    print(
        classification_report(
            y_true,
            y_pred,
            labels=[0, 1],
            target_names=["Benign", "Malware"],
            zero_division=0,
        )
    )

    print(
        "Note: This is a preliminary evaluation of the first "
        "labelled records, using a 0.5 threshold."
    )


if __name__ == "__main__":
    main()