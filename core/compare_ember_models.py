
import json
from pathlib import Path

import numpy as np
import lightgbm as lgb
import ember

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

if not hasattr(np, "int"):
    np.int = int

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(r"D:\CyberShieldData\ember2018")
MODEL_DIR = Path(r"D:\CyberShieldData\models")

OFFICIAL_MODEL_PATH = MODEL_DIR / "ember_model_2018.txt"
CUSTOM_MODEL_PATH = MODEL_DIR / "ember_lightgbm_custom.txt"
TEST_PATH = DATA_DIR / "test_features.jsonl"

TEST_LIMIT = 10_000
FEATURE_COUNT = 2381


def main():
    for path in (OFFICIAL_MODEL_PATH, CUSTOM_MODEL_PATH, TEST_PATH):
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {path}")

    print("Loading both models...", flush=True)
    official_model = lgb.Booster(model_file=str(OFFICIAL_MODEL_PATH))
    custom_model = lgb.Booster(model_file=str(CUSTOM_MODEL_PATH))

    extractor = ember.PEFeatureExtractor(feature_version=2)

    actual = []
    features = []

    print("Reading labelled test samples...", flush=True)

    with TEST_PATH.open("r", encoding="utf-8") as source:
        for line in source:
            if not line.strip():
                continue

            record = json.loads(line)
            label = record.get("label")

            if label not in (0, 1):
                continue

            vector = np.asarray(
                extractor.process_raw_features(record),
                dtype=np.float32,
            ).reshape(-1)

            if vector.size != FEATURE_COUNT:
                raise ValueError(
                    f"Expected {FEATURE_COUNT} features, got {vector.size}"
                )

            np.nan_to_num(
                vector,
                copy=False,
                nan=0.0,
                posinf=0.0,
                neginf=0.0,
            )

            features.append(vector)
            actual.append(int(label))

            if len(actual) >= TEST_LIMIT:
                break

    if not actual:
        raise RuntimeError("No labelled test samples found.")

    X = np.vstack(features)
    y = np.asarray(actual, dtype=np.int8)

    del features

    models = {
        "Official EMBER": official_model,
        "Custom LightGBM": custom_model,
    }

    print(f"\nSame test samples for both models: {len(y):,}")

    for name, model in models.items():
        probabilities = model.predict(X)
        predicted = (probabilities >= 0.5).astype(np.int8)

        print(f"\n=== {name} ===")
        print(f"Accuracy:  {accuracy_score(y, predicted):.4f}")
        print(
            f"Precision: {precision_score(y, predicted, zero_division=0):.4f}"
        )
        print(
            f"Recall:    {recall_score(y, predicted, zero_division=0):.4f}"
        )
        print(f"F1-score:  {f1_score(y, predicted, zero_division=0):.4f}")
        print("Confusion matrix:")
        print(confusion_matrix(y, predicted, labels=[0, 1]))

    print(
        "\nNote: Results apply only to this labelled test subset, "
        "not the entire EMBER test set."
    )


if __name__ == "__main__":
    main()
