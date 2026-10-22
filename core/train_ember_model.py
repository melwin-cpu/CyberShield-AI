
import gc
import json
from pathlib import Path

import numpy as np
import lightgbm as lgb

# Compatibility workaround for older EMBER dependencies.
if not hasattr(np, "int"):
    np.int = int

import ember
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)


# Always resolve the project root relative to this script.
ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(r"D:\CyberShieldData\ember2018")
MODEL_DIR = Path(r"D:\CyberShieldData\models")

FEATURE_COUNT = 2381
SAMPLES_PER_CLASS = 50_000
TOTAL_SAMPLES = SAMPLES_PER_CLASS * 2
TEST_LIMIT = 10_000

MODEL_DIR.mkdir(parents=True, exist_ok=True)

# open_memmap below creates these .npy files.
X_PATH = MODEL_DIR / "ember_train_features.npy"
Y_PATH = MODEL_DIR / "ember_train_labels.npy"
MODEL_PATH = MODEL_DIR / "ember_lightgbm_custom.txt"

QUOTAS = {
    "train_features_0.jsonl": {0: 10_000, 1: 0},
    "train_features_1.jsonl": {0: 8_000, 1: 10_000},
    "train_features_2.jsonl": {0: 8_000, 1: 10_000},
    "train_features_3.jsonl": {0: 8_000, 1: 10_000},
    "train_features_4.jsonl": {0: 8_000, 1: 10_000},
    "train_features_5.jsonl": {0: 8_000, 1: 10_000},
}


def main():
    training_files = [DATA_DIR / name for name in QUOTAS]

    missing = [str(path) for path in training_files if not path.is_file()]
    if missing:
        raise FileNotFoundError(
            "Missing training files:\n" + "\n".join(missing)
        )

    test_path = DATA_DIR / "test_features.jsonl"
    if not test_path.is_file():
        raise FileNotFoundError(f"Test file not found: {test_path}")

    print("Loading EMBER feature extractor...", flush=True)
    extractor = ember.PEFeatureExtractor(feature_version=2)
    print(f"Feature count: {extractor.dim}", flush=True)

    if extractor.dim != FEATURE_COUNT:
        raise ValueError(
            f"Expected {FEATURE_COUNT} features, got {extractor.dim}"
        )

    X = None
    y = None
    train_data = None

    try:
        # Disk-backed arrays reduce RAM usage.
        X = np.lib.format.open_memmap(
            str(X_PATH),
            mode="w+",
            dtype=np.float32,
            shape=(TOTAL_SAMPLES, FEATURE_COUNT),
        )
        y = np.lib.format.open_memmap(
            str(Y_PATH),
            mode="w+",
            dtype=np.int8,
            shape=(TOTAL_SAMPLES,),
        )

        position = 0
        collected = {0: 0, 1: 0}

        for path in training_files:
            quota = QUOTAS[path.name]
            file_counts = {0: 0, 1: 0}

            print(f"\nReading {path.name}", flush=True)

            with path.open("r", encoding="utf-8") as source:
                for line in source:
                    if not line.strip():
                        continue

                    record = json.loads(line)
                    label = record.get("label")

                    if label not in (0, 1):
                        continue

                    if file_counts[label] >= quota[label]:
                        continue

                    vector = np.asarray(
                        extractor.process_raw_features(record),
                        dtype=np.float32,
                    ).reshape(-1)

                    if vector.size != FEATURE_COUNT:
                        raise ValueError(
                            f"Unexpected feature count: {vector.size}"
                        )

                    np.nan_to_num(
                        vector,
                        copy=False,
                        nan=0.0,
                        posinf=0.0,
                        neginf=0.0,
                    )

                    X[position] = vector
                    y[position] = label
                    position += 1
                    file_counts[label] += 1
                    collected[label] += 1

                    if position % 5000 == 0:
                        X.flush()
                        y.flush()
                        print(
                            f"Prepared {position:,}/{TOTAL_SAMPLES:,}",
                            flush=True,
                        )

                    if all(
                        file_counts[c] >= quota[c] for c in (0, 1)
                    ):
                        break

            print(
                f"  Benign: {file_counts[0]:,}; "
                f"Malware: {file_counts[1]:,}",
                flush=True,
            )

        if position != TOTAL_SAMPLES:
            raise RuntimeError(
                f"Expected {TOTAL_SAMPLES} records, got {position}. "
                "Check the training shard labels and quotas."
            )

        X.flush()
        y.flush()

        print("\nTraining sample totals:", collected, flush=True)
        print("Training LightGBM on CPU...", flush=True)

        train_data = lgb.Dataset(
            X,
            label=y,
            params={"max_bin": 127},
            free_raw_data=False,
        )

        params = {
            "objective": "binary",
            "metric": ["binary_logloss", "auc"],
            "learning_rate": 0.05,
            "num_leaves": 31,
            "max_depth": -1,
            "max_bin": 127,
            "feature_fraction": 0.8,
            "verbosity": -1,
            "num_threads": 4,
            "force_col_wise": True,
            "seed": 42,
        }

        model = lgb.train(
            params,
            train_data,
            num_boost_round=200,
            callbacks=[lgb.log_evaluation(period=25)],
        )

        model.save_model(str(MODEL_PATH))
        print(f"\nSaved custom model: {MODEL_PATH}", flush=True)

        # Release training data before evaluation.
        del train_data
        train_data = None
        del X, y
        X = None
        y = None
        gc.collect()

        print(
            f"\nEvaluating on up to {TEST_LIMIT:,} labelled test records...",
            flush=True,
        )

        actual = []
        probabilities = []

        with test_path.open("r", encoding="utf-8") as source:
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
                        f"Unexpected test feature count: {vector.size}"
                    )

                np.nan_to_num(
                    vector,
                    copy=False,
                    nan=0.0,
                    posinf=0.0,
                    neginf=0.0,
                )

                probability = float(
                    model.predict(vector.reshape(1, -1))[0]
                )

                actual.append(int(label))
                probabilities.append(probability)

                if len(actual) >= TEST_LIMIT:
                    break

        if not actual:
            raise RuntimeError("No labelled test records were found.")

        predicted = [
            1 if probability >= 0.5 else 0
            for probability in probabilities
        ]

        print("\n=== Preliminary Test Results ===")
        print(f"Test samples: {len(actual):,}")
        print(f"Accuracy:  {accuracy_score(actual, predicted):.4f}")
        print(
            "Precision: "
            f"{precision_score(actual, predicted, zero_division=0):.4f}"
        )
        print(
            "Recall:    "
            f"{recall_score(actual, predicted, zero_division=0):.4f}"
        )
        print(
            "F1-score:  "
            f"{f1_score(actual, predicted, zero_division=0):.4f}"
        )
        print("Confusion matrix:")
        print(confusion_matrix(actual, predicted, labels=[0, 1]))
        print(
            classification_report(
                actual,
                predicted,
                labels=[0, 1],
                target_names=["Benign", "Malware"],
                zero_division=0,
            )
        )

        print(
            "Note: this is a preliminary subset evaluation, "
            "not the full EMBER test-set result."
        )

    finally:
        if train_data is not None:
            del train_data

        if X is not None:
            X.flush()
            del X

        if y is not None:
            y.flush()
            del y

        gc.collect()


if __name__ == "__main__":
    main()
