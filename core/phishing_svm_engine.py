import os
import joblib
import pandas as pd

from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
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
# CyberShield AI - Phishing SVM ML Engine
# ============================================================

MODEL_DIR = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models")
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "svm_phishing_model.joblib"
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
# Create SVM model
# ------------------------------------------------------------

def create_model():

    model = Pipeline([
        (
            "imputer",
            SimpleImputer(strategy="median")
        ),

        (
            "scaler",
            StandardScaler()
        ),

        (
            "svm",
            SVC(
                kernel="rbf",
                C=2.0,
                gamma="scale",
                probability=True,
                class_weight="balanced",
                random_state=42
            )
        )
    ])

    return model


# ------------------------------------------------------------
# Convert URL into feature vector
# ------------------------------------------------------------

def url_to_features(url):

    features = extract_url_features(url)

    return [
        features[name]
        for name in FEATURE_NAMES
    ]


# ------------------------------------------------------------
# Predict a single URL
# ------------------------------------------------------------

def predict_phishing(url):

    if not os.path.exists(MODEL_PATH):

        raise FileNotFoundError(
            "SVM phishing model not found. "
            "Train the model first."
        )

    model = joblib.load(
        MODEL_PATH
    )

    feature_vector = url_to_features(
        url
    )

    dataframe = pd.DataFrame(
        [feature_vector],
        columns=FEATURE_NAMES
    )

    prediction = model.predict(
        dataframe
    )[0]

    probability = model.predict_proba(
        dataframe
    )[0][1]

    risk_score = round(
        float(probability) * 100,
        2
    )

    if prediction == 1:

        result = "PHISHING"

    else:

        result = "LEGITIMATE"

    return {
        "prediction": result,
        "risk_score": risk_score,
        "probability": round(
            float(probability),
            4
        )
    }


# ------------------------------------------------------------
# Train SVM model
# ------------------------------------------------------------

def train_model(
    dataset_path,
    url_column="url",
    target_column="label",
    test_size=0.20,
    random_state=42
):

    print("\n========================================")
    print("CyberShield AI - Phishing SVM")
    print("========================================")

    if not os.path.exists(dataset_path):

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
    # Validate columns
    # --------------------------------------------------------

    if url_column not in dataset.columns:

        raise ValueError(
            f"Missing URL column: {url_column}"
        )

    if target_column not in dataset.columns:

        raise ValueError(
            f"Missing target column: {target_column}"
        )

    # --------------------------------------------------------
    # Remove missing values
    # --------------------------------------------------------

    dataset = dataset[
        dataset[url_column].notna()
    ]

    dataset = dataset[
        dataset[target_column].notna()
    ]

    # --------------------------------------------------------
    # Convert labels
    # --------------------------------------------------------

    dataset[target_column] = pd.to_numeric(
        dataset[target_column],
        errors="coerce"
    )

    dataset = dataset.dropna(
        subset=[target_column]
    )

    dataset[target_column] = dataset[
        target_column
    ].astype(int)

    unique_labels = sorted(
        dataset[target_column].unique()
    )

    print(
        f"Labels found     : {unique_labels}"
    )

    if not set(unique_labels).issubset({0, 1}):

        raise ValueError(
            "Labels must contain only 0 and 1."
        )

    if len(unique_labels) < 2:

        raise ValueError(
            "Dataset must contain both "
            "legitimate and phishing URLs."
        )

    # --------------------------------------------------------
    # Feature extraction
    # --------------------------------------------------------

    print("\nExtracting URL features...")

    feature_rows = []
    valid_indices = []

    for index, url in dataset[url_column].items():

        try:

            features = extract_url_features(
                str(url)
            )

            feature_rows.append(
                [
                    features[name]
                    for name in FEATURE_NAMES
                ]
            )

            valid_indices.append(
                index
            )

        except Exception as error:

            print(
                f"Skipping invalid URL: {url}"
            )

            print(
                f"Reason: {error}"
            )

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
    ].values

    print(
        f"\nValid URLs       : {len(X)}"
    )

    print(
        f"Feature count    : {len(FEATURE_NAMES)}"
    )

    # --------------------------------------------------------
    # Train / Test split
    # --------------------------------------------------------

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y
    )

    print(
        f"Training samples : {len(X_train)}"
    )

    print(
        f"Testing samples  : {len(X_test)}"
    )

    # --------------------------------------------------------
    # Create model
    # --------------------------------------------------------

    model = create_model()

    print("\nTraining SVM model...")

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

    print("\nClassification Report:")

    print(
        classification_report(
            y_test,
            predictions,
            zero_division=0
        )
    )

    print("Confusion Matrix:")

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
    print("Phishing SVM ML Engine")
    print("========================================")

    print(
        f"\nFeature count: {len(FEATURE_NAMES)}"
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

    print("\nPhishing SVM Engine ready.")