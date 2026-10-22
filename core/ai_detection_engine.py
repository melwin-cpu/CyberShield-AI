import os
import joblib
import pandas as pd

from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

# ------------------------------------------------------------
# Import existing malware feature extraction
# ------------------------------------------------------------

try:
    from ml_engine import (
        extract_features,
        FEATURE_NAMES
    )

except ImportError:

    from core.ml_engine import (
        extract_features,
        FEATURE_NAMES
    )


# ============================================================
# CyberShield AI
# Malware Random Forest ML Engine
# ============================================================

MODEL_DIR = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models")
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "random_forest_malware_model.joblib"
)


# ------------------------------------------------------------
# Create Random Forest model
# ------------------------------------------------------------

def create_model():

    model = Pipeline([
        (
            "imputer",
            SimpleImputer(
                strategy="median"
            )
        ),

        (
            "random_forest",
            RandomForestClassifier(
                n_estimators=300,
                max_depth=15,
                min_samples_split=4,
                min_samples_leaf=2,
                class_weight="balanced",
                random_state=42,
                n_jobs=-1
            )
        )
    ])

    return model


# ------------------------------------------------------------
# Extract feature dataframe from file
# ------------------------------------------------------------

def file_to_features(file_path):

    if not os.path.exists(file_path):

        raise FileNotFoundError(
            f"File not found:\n{file_path}"
        )

    features = extract_features(
        file_path
    )

    return features


# ------------------------------------------------------------
# Predict malware
# ------------------------------------------------------------

def predict_malware(file_path):

    if not os.path.exists(
        MODEL_PATH
    ):

        raise FileNotFoundError(
            "Random Forest malware model not found. "
            "Train the model first."
        )

    model = joblib.load(
        MODEL_PATH
    )

    features = file_to_features(
        file_path
    )

    prediction = model.predict(
        features
    )[0]

    probabilities = model.predict_proba(
        features
    )[0]

    # Probability of class 1 = Malware
    class_list = list(
        model.named_steps[
            "random_forest"
        ].classes_
    )

    if 1 in class_list:

        malware_index = class_list.index(1)

        malware_probability = float(
            probabilities[malware_index]
        )

    else:

        malware_probability = 0.0

    risk_score = round(
        malware_probability * 100,
        2
    )

    if prediction == 1:

        result = "MALWARE"

    else:

        result = "BENIGN"

    return {
        "prediction": result,
        "risk_score": risk_score,
        "probability": round(
            malware_probability,
            4
        )
    }


# ------------------------------------------------------------
# Train Random Forest model
# ------------------------------------------------------------

def train_model(
    dataset_path,
    target_column="label",
    test_size=0.20,
    random_state=42
):

    print("\n========================================")
    print("CyberShield AI")
    print("Malware Random Forest Engine")
    print("========================================")

    # --------------------------------------------------------
    # Dataset check
    # --------------------------------------------------------

    if not os.path.exists(
        dataset_path
    ):

        raise FileNotFoundError(
            f"Dataset not found:\n{dataset_path}"
        )

    print("\nLoading dataset...")

    dataset = pd.read_csv(
        dataset_path
    )

    print(
        f"Dataset rows    : {len(dataset)}"
    )

    print(
        f"Dataset columns : {len(dataset.columns)}"
    )

    # --------------------------------------------------------
    # Validate target
    # --------------------------------------------------------

    if target_column not in dataset.columns:

        raise ValueError(
            f"Missing target column: "
            f"{target_column}"
        )

    # --------------------------------------------------------
    # Check all features
    # --------------------------------------------------------

    missing_features = [
        feature
        for feature in FEATURE_NAMES
        if feature not in dataset.columns
    ]

    if missing_features:

        raise ValueError(
            "Missing required malware features:\n"
            +
            "\n".join(
                missing_features
            )
        )

    # --------------------------------------------------------
    # Prepare X and y
    # --------------------------------------------------------

    X = dataset[
        FEATURE_NAMES
    ].copy()

    y = pd.to_numeric(
        dataset[target_column],
        errors="coerce"
    )

    # Remove invalid labels
    valid_rows = y.notna()

    X = X[
        valid_rows
    ]

    y = y[
        valid_rows
    ].astype(int)

    unique_labels = sorted(
        y.unique()
    )

    print(
        f"Labels found     : {unique_labels}"
    )

    if not set(
        unique_labels
    ).issubset({0, 1}):

        raise ValueError(
            "Labels must contain only 0 and 1."
        )

    if len(unique_labels) < 2:

        raise ValueError(
            "Dataset must contain both "
            "benign (0) and malware (1) samples."
        )

    # --------------------------------------------------------
    # Dataset information
    # --------------------------------------------------------

    print(
        f"\nValid samples    : {len(X)}"
    )

    print(
        f"Feature count    : {len(FEATURE_NAMES)}"
    )

    print(
        f"Benign samples   : "
        f"{int((y == 0).sum())}"
    )

    print(
        f"Malware samples  : "
        f"{int((y == 1).sum())}"
    )

    # --------------------------------------------------------
    # Train / test split
    # --------------------------------------------------------

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y
    )

    print(
        f"\nTraining samples : {len(X_train)}"
    )

    print(
        f"Testing samples  : {len(X_test)}"
    )

    # --------------------------------------------------------
    # Create model
    # --------------------------------------------------------

    model = create_model()

    print(
        "\nTraining Random Forest model..."
    )

    model.fit(
        X_train,
        y_train
    )

    # --------------------------------------------------------
    # Predictions
    # --------------------------------------------------------

    predictions = model.predict(
        X_test
    )

    # --------------------------------------------------------
    # Evaluation
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )

    print("\n========================================")
    print("MODEL PERFORMANCE")
    print("========================================")

    print(
        f"Accuracy  : {accuracy * 100:.2f}%"
    )

    print(
        f"Precision : {precision * 100:.2f}%"
    )

    print(
        f"Recall    : {recall * 100:.2f}%"
    )

    print(
        f"F1 Score  : {f1 * 100:.2f}%"
    )

    print(
        "\nClassification Report:"
    )

    print(
        classification_report(
            y_test,
            predictions,
            zero_division=0
        )
    )

    print(
        "Confusion Matrix:"
    )

    print(
        confusion_matrix(
            y_test,
            predictions
        )
    )

    # --------------------------------------------------------
    # Save model
    # --------------------------------------------------------

    os.makedirs(
        MODEL_DIR,
        exist_ok=True
    )

    joblib.dump(
        model,
        MODEL_PATH
    )

    print("\n========================================")
    print("MODEL SAVED")
    print("========================================")

    print(
        f"Path: {MODEL_PATH}"
    )

    return model


# ------------------------------------------------------------
# Check model availability
# ------------------------------------------------------------

def is_model_available():

    return os.path.exists(
        MODEL_PATH
    )


# ------------------------------------------------------------
# Main test
# ------------------------------------------------------------

if __name__ == "__main__":

    print("\n========================================")
    print("CyberShield AI")
    print("Malware Random Forest ML Engine")
    print("========================================")

    print(
        f"\nFeature count: "
        f"{len(FEATURE_NAMES)}"
    )

    print("\nFeatures:")

    for number, name in enumerate(
        FEATURE_NAMES,
        start=1
    ):

        print(
            f"{number:02d}. {name}"
        )

    print(
        f"\nModel available: "
        f"{is_model_available()}"
    )

    print(
        f"Model path: {MODEL_PATH}"
    )

    print(
        "\nMalware Random Forest Engine ready."
    )