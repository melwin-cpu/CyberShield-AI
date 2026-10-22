
import os
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "models")

X_PATH = os.path.join(MODEL_DIR, "ember_train_features.npy")
Y_PATH = os.path.join(MODEL_DIR, "ember_train_labels.npy")

OUTPUT_PATH = os.path.join(
    MODEL_DIR, "svm_malware_model_candidate.joblib"
)

RANDOM_STATE = 42


def main():
    print("Loading existing EMBER feature arrays...")

    if not os.path.exists(X_PATH) or not os.path.exists(Y_PATH):
        raise FileNotFoundError(
            "EMBER .npy files not found inside the models folder."
        )

    X = np.load(X_PATH, mmap_mode="r")
    y = np.load(Y_PATH, mmap_mode="r")

    if X.ndim != 2 or y.ndim != 1 or len(X) != len(y):
        raise ValueError(
            f"Unexpected data shapes: X={X.shape}, y={y.shape}"
        )

    if not np.isin(np.unique(y), [0, 1]).all():
        raise ValueError("Labels must contain only 0 and 1.")

    print(f"Features shape: {X.shape}")
    print(f"Labels shape: {y.shape}")

    indices = np.arange(len(y))

    train_idx, test_idx = train_test_split(
        indices,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    print("Preparing train/test arrays...")

    X_train = np.array(X[train_idx], dtype=np.float32, copy=True)
    X_test = np.array(X[test_idx], dtype=np.float32, copy=True)
    y_train = np.asarray(y[train_idx], dtype=np.int8)
    y_test = np.asarray(y[test_idx], dtype=np.int8)

    del X, y, indices, train_idx, test_idx

    print("Training SVM only...")

    model = make_pipeline(
        StandardScaler(),
        LinearSVC(
            C=0.1,
            class_weight="balanced",
            dual="auto",
            max_iter=10000,
            random_state=RANDOM_STATE,
        ),
    )

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("\n--- SVM Candidate Evaluation ---")
    print(f"Accuracy : {accuracy_score(y_test, predictions):.4f}")
    print(f"Precision: {precision_score(y_test, predictions, zero_division=0):.4f}")
    print(f"Recall   : {recall_score(y_test, predictions, zero_division=0):.4f}")
    print(f"F1 Score : {f1_score(y_test, predictions, zero_division=0):.4f}")
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    print("\nSaving candidate model without overwriting existing SVM...")
    joblib.dump(model, OUTPUT_PATH, compress=3)

    print(f"Candidate saved to: {OUTPUT_PATH}")
    print("Existing svm_malware_model.joblib was not modified.")


if __name__ == "__main__":
    main()
