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

try:
    from .phishing_engine import extract_url_features
except ImportError:
    from phishing_engine import extract_url_features


# ============================================================
# CyberShield AI - Phishing Random Forest ML Engine
# ============================================================

MODEL_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..",
        "models"
    )
)

# Correct filename: matches the existing model file
MODEL_PATH = os.path.join(
    MODEL_DIR,
    "phishing_rf_model.joblib"
)


# ------------------------------------------------------------
# Feature names
# ------------------------------------------------------------

FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "path_length",
    "dot_count",
    "slash_count",
    "hyphen_count",
    "underscore_count",
    "at_count",
    "question_count",
    "equal_count",
    "ampersand_count",
    "percent_count",
    "digit_count",
    "letter_count",
    "subdomain_count",
    "uses_https",
    "uses_ip",
    "has_port",
    "has_punycode",
    "has_fragment",
    "has_query",
    "has_login_keyword",
    "has_verify_keyword",
    "has_account_keyword",
    "has_security_keyword",
    "has_password_keyword",
    "has_bank_keyword"
]


# ------------------------------------------------------------
# Create Random Forest model
# ------------------------------------------------------------

def create_model():
    return Pipeline([
        (
            "imputer",
            SimpleImputer(strategy="median")
        ),
        (
            "random_forest",
            RandomForestClassifier(
                n_estimators=300,
                max_depth=12,
                min_samples_split=4,
                min_samples_leaf=2,
                class_weight="balanced",
                random_state=42,
                n_jobs=-1
            )
        )
    ])


# ------------------------------------------------------------
# Convert URL into feature vector
# ------------------------------------------------------------

def url_to_features(url):
    features = extract_url_features(str(url))

    missing_features = [
        name for name in FEATURE_NAMES
        if name not in features
    ]

    if missing_features:
        raise ValueError(
            "Missing URL features: "
            + ", ".join(missing_features)
        )

    return [
        features[name]
        for name in FEATURE_NAMES
    ]


# ------------------------------------------------------------
# Predict a single URL
# ------------------------------------------------------------

def predict_phishing(url):
    if not os.path.isfile(MODEL_PATH):
        raise FileNotFoundError(
            "Random Forest phishing model not found.\n"
            f"Expected path: {MODEL_PATH}\n"
            "Check the model filename or train the model first."
        )

    model = joblib.load(MODEL_PATH)

    feature_vector = url_to_features(url)

    dataframe = pd.DataFrame(
        [feature_vector],
        columns=FEATURE_NAMES
    )

    prediction = int(model.predict(dataframe)[0])

    probabilities = model.predict_proba(dataframe)[0]

    # Find the probability associated with class 1 (phishing)
    classes = list(model.classes_)
    if 1 in classes:
        probability = float(probabilities[classes.index(1)])
    else:
        probability = 0.0

    risk_score = round(probability * 100, 2)

    result = "PHISHING" if prediction == 1 else "LEGITIMATE"

    return {
        "prediction": result,
        "risk_score": risk_score,
        "probability": round(probability, 4)
    }


# ------------------------------------------------------------
# Train Random Forest model
# ------------------------------------------------------------

def train_model(
    dataset_path,
    url_column="url",
    target_column="label",
    test_size=0.20,
    random_state=42
):
    print("\n========================================")
    print("CyberShield AI - Phishing Random Forest")
    print("========================================")

    if not os.path.isfile(dataset_path):
        raise FileNotFoundError(
            f"Dataset not found:\n{dataset_path}"
        )

    print("\nLoading dataset...")

    dataset = pd.read_csv(dataset_path)

    print(f"Dataset rows    : {len(dataset)}")
    print(f"Dataset columns : {len(dataset.columns)}")

    # Validate required columns
    if url_column not in dataset.columns:
        raise ValueError(
            f"Missing URL column: {url_column}"
        )

    if target_column not in dataset.columns:
        raise ValueError(
            f"Missing target column: {target_column}"
        )

    # Remove missing values
    dataset = dataset.dropna(
        subset=[url_column, target_column]
    ).copy()

    # Convert labels to numeric
    dataset[target_column] = pd.to_numeric(
        dataset[target_column],
        errors="coerce"
    )

    dataset = dataset.dropna(
        subset=[target_column]
    ).copy()

    if dataset.empty:
        raise ValueError("Dataset contains no valid rows.")

    dataset[target_column] = dataset[target_column].astype(int)

    unique_labels = sorted(
        dataset[target_column].unique()
    )

    print(f"Labels found    : {unique_labels}")

    if not set(unique_labels).issubset({0, 1}):
        raise ValueError(
            "Labels must contain only 0 and 1."
        )

    if len(unique_labels) != 2:
        raise ValueError(
            "Dataset must contain both legitimate and phishing URLs."
        )

    # Extract features
    print("\nExtracting URL features...")

    feature_rows = []
    valid_indices = []

    for index, url in dataset[url_column].items():
        try:
            features = url_to_features(str(url))
            feature_rows.append(features)
            valid_indices.append(index)

        except Exception as error:
            print(f"Skipping invalid URL at row {index}: {error}")

    if not feature_rows:
        raise ValueError(
            "No valid URLs found in dataset."
        )

    X = pd.DataFrame(
        feature_rows,
        columns=FEATURE_NAMES
    )

    y = dataset.loc[
        valid_indices,
        target_column
    ].to_numpy()

    print(f"\nValid URLs      : {len(X)}")
    print(f"Feature count   : {len(FEATURE_NAMES)}")

    # Train/test split
    # Note: this is a stratified row split, not a domain-separated
    # evaluation. Related domains may appear in both sets.
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y
    )

    print(f"Training samples: {len(X_train)}")
    print(f"Testing samples : {len(X_test)}")

    # Train
    model = create_model()

    print("\nTraining Random Forest model...")

    model.fit(X_train, y_train)

    # Predict
    predictions = model.predict(X_test)

    # Evaluate
    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(
        y_test, predictions, zero_division=0
    )
    recall = recall_score(
        y_test, predictions, zero_division=0
    )
    f1 = f1_score(
        y_test, predictions, zero_division=0
    )

    print("\n========================================")
    print("MODEL PERFORMANCE")
    print("========================================")
    print(f"Accuracy  : {accuracy * 100:.2f}%")
    print(f"Precision : {precision * 100:.2f}%")
    print(f"Recall    : {recall * 100:.2f}%")
    print(f"F1 Score  : {f1 * 100:.2f}%")

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            zero_division=0
        )
    )

    print("Confusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    # Save the trained model
    os.makedirs(MODEL_DIR, exist_ok=True)

    # Back up the existing model before replacing it
    if os.path.isfile(MODEL_PATH):
        backup_path = MODEL_PATH + ".backup"
        joblib.copy if False else None

        import shutil
        shutil.copy2(MODEL_PATH, backup_path)

        print(f"\nPrevious model backup: {backup_path}")

    joblib.dump(model, MODEL_PATH)

    print("\n========================================")
    print("MODEL SAVED")
    print("========================================")
    print(f"Path: {MODEL_PATH}")

    return model


# ------------------------------------------------------------
# Check model availability
# ------------------------------------------------------------

def is_model_available():
    return os.path.isfile(MODEL_PATH)


# ------------------------------------------------------------
# Main test
# ------------------------------------------------------------

if __name__ == "__main__":
    print("\n========================================")
    print("CyberShield AI")
    print("Phishing Random Forest ML Engine")
    print("========================================")

    print(f"\nFeature count: {len(FEATURE_NAMES)}")

    print("\nFeatures:")
    for number, name in enumerate(FEATURE_NAMES, start=1):
        print(f"{number:02d}. {name}")

    print(f"\nModel available: {is_model_available()}")
    print(f"Model path: {MODEL_PATH}")

    if is_model_available():
        print("\nTesting a sample URL...")

        try:
            result = predict_phishing("https://www.wikipedia.org/")
            print(result)
        except Exception as error:
            print(f"Prediction test failed: {error}")

    print("\nPhishing Random Forest Engine ready.")
