# core/phishing_ml_engine.py

import os
import json
import shutil
import ipaddress
from urllib.parse import urlparse, parse_qs, unquote

import joblib
import pandas as pd
from xgboost import XGBClassifier

from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)

from core.phishing_engine import extract_url_features


# =========================================================
# PATHS
# =========================================================

ROOT_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

MODEL_DIR = os.path.join(ROOT_DIR, "models")

DATASET_PATH = os.path.join(
    ROOT_DIR,
    "dataset",
    "phishing",
    "phishing_urls.csv",
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "xgboost_phishing_model.joblib",
)

FEATURE_PATH = os.path.join(
    MODEL_DIR,
    "xgboost_phishing_feature_names.json",
)

BACKUP_PATH = os.path.join(
    MODEL_DIR,
    "xgboost_phishing_model_backup.joblib",
)


# =========================================================
# FEATURE NAMES
# Must match the trained model and phishing_engine.py
# =========================================================

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
    "has_bank_keyword",
]


# =========================================================
# DOMAIN AND URL RULES
# =========================================================

TRUSTED_DOMAINS = {
    "google.com",
    "youtube.com",
    "wikipedia.org",
    "github.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "baidu.com",
    "yahoo.com",
    "example.com",
}

SUSPICIOUS_KEYWORDS = (
    "login",
    "verify",
    "account",
    "security",
    "password",
    "bank",
    "signin",
    "confirm",
    "wallet",
)

REDIRECT_PATHS = {
    "/url",
    "/redirect",
    "/out",
    "/away",
    "/external",
    "/go",
    "/link",
}

DESTINATION_PARAMETERS = {
    "url",
    "q",
    "target",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "next",
    "destination",
    "continue",
    "return",
    "return_url",
    "to",
}


# =========================================================
# URL PARSING
# =========================================================

def parse_url(url):
    """Normalize and parse a URL."""

    if not isinstance(url, str) or not url.strip():
        raise ValueError("Please enter a valid URL.")

    normalized_url = url.strip()

    if not normalized_url.startswith(("http://", "https://")):
        normalized_url = "https://" + normalized_url

    try:
        parsed = urlparse(normalized_url)
        hostname = parsed.hostname
        port = parsed.port

    except ValueError as exc:
        raise ValueError(f"Invalid URL: {exc}") from exc

    if not hostname:
        raise ValueError(
            "The URL does not contain a valid hostname."
        )

    hostname = hostname.lower().rstrip(".")

    return normalized_url, parsed, hostname, port


# =========================================================
# REGISTERED DOMAIN
# =========================================================

def get_registered_domain(hostname):
    """
    Approximate registered-domain extraction.

    This is not a complete Public Suffix List implementation.
    """

    hostname = hostname.lower().strip(".")

    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass

    parts = hostname.split(".")

    special_suffixes = {
        "co.uk",
        "org.uk",
        "ac.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.in",
        "net.in",
        "org.in",
        "ac.in",
        "co.jp",
        "co.nz",
        "com.br",
        "com.sg",
    }

    if len(parts) <= 2:
        return hostname

    last_two = ".".join(parts[-2:])

    if last_two in special_suffixes and len(parts) >= 3:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


# =========================================================
# TRUSTED DOMAIN CHECK
# =========================================================

def is_trusted_hostname(hostname):
    registered_domain = get_registered_domain(hostname)
    return registered_domain in TRUSTED_DOMAINS


# =========================================================
# URL INSPECTION
# =========================================================

def inspect_url(url):
    """
    Inspect URL structure and identify warning signals.

    A warning is not proof of phishing.
    A trusted hostname is not proof of safety.
    """

    normalized_url, parsed, hostname, port = parse_url(url)

    try:
        ipaddress.ip_address(hostname)
        uses_ip = True
    except ValueError:
        uses_ip = False

    lower_hostname = hostname.lower()
    lower_path = unquote(parsed.path or "/").lower()
    lower_url = normalized_url.lower()

    registered_domain = get_registered_domain(hostname)
    trusted = is_trusted_hostname(hostname)

    has_userinfo = (
        parsed.username is not None
        or parsed.password is not None
    )

    suspicious_signals = []

    # IP address instead of a hostname
    if uses_ip:
        suspicious_signals.append(
            "URL uses an IP address"
        )

    # Internationalized hostname encoded as punycode
    if "xn--" in lower_hostname:
        suspicious_signals.append(
            "Hostname contains punycode"
        )

    # Credentials embedded in URL syntax
    if has_userinfo:
        suspicious_signals.append(
            "URL contains user-info syntax"
        )

    # Non-standard port
    if port not in (None, 80, 443):
        suspicious_signals.append(
            "URL uses a non-standard port"
        )

    # Security-sensitive words
    keyword_hits = [
        word
        for word in SUSPICIOUS_KEYWORDS
        if word in lower_url
    ]

    if keyword_hits:
        suspicious_signals.append(
            "Contains security-sensitive words: "
            + ", ".join(keyword_hits)
        )

    # Redirect-style paths
    normalized_path = lower_path.rstrip("/") or "/"

    if normalized_path in REDIRECT_PATHS:
        suspicious_signals.append(
            "URL uses a redirect-style endpoint"
        )

    # Check common redirect destination parameters
    query_parameters = parse_qs(
        parsed.query,
        keep_blank_values=True,
    )

    redirect_destinations = []

    for parameter_name, values in query_parameters.items():
        if parameter_name.lower() not in DESTINATION_PARAMETERS:
            continue

        for value in values:
            decoded_value = value.strip()

            # Decode URL-encoded values up to two times
            for _ in range(2):
                decoded_value = unquote(decoded_value)

            if decoded_value.startswith(("http://", "https://")):
                redirect_destinations.append(decoded_value)

    # Remove duplicate destinations
    redirect_destinations = list(dict.fromkeys(
        redirect_destinations
    ))

    if redirect_destinations:
        suspicious_signals.append(
            "URL contains an external redirect destination"
        )

    return {
        "normalized_url": normalized_url,
        "hostname": hostname,
        "registered_domain": registered_domain,
        "is_trusted_domain": trusted,
        "has_userinfo": has_userinfo,
        "suspicious_signals": suspicious_signals,
        "redirect_destinations": redirect_destinations,
    }


# =========================================================
# MODEL CREATION
# =========================================================

def create_model():
    return XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )


# =========================================================
# LOAD TRAINED MODEL
# =========================================================

def load_model():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Trained model not found: {MODEL_PATH}"
        )

    if not os.path.exists(FEATURE_PATH):
        raise FileNotFoundError(
            f"Feature names file not found: {FEATURE_PATH}"
        )

    model = joblib.load(MODEL_PATH)

    with open(
        FEATURE_PATH,
        "r",
        encoding="utf-8",
    ) as file:
        feature_names = json.load(file)

    if feature_names != FEATURE_NAMES:
        raise ValueError(
            "Feature order mismatch. Check the trained model "
            "and feature names JSON file."
        )

    if hasattr(model, "n_features_in_"):
        if model.n_features_in_ != len(feature_names):
            raise ValueError(
                "The model expects a different number of features."
            )

    return model, feature_names


# =========================================================
# URL TO FEATURES
# =========================================================

def url_to_features(url):
    inspection = inspect_url(url)

    features = extract_url_features(
        inspection["normalized_url"]
    )

    missing_features = [
        name
        for name in FEATURE_NAMES
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


# =========================================================
# PHISHING PREDICTION
# =========================================================

def predict_phishing(url):
    """
    Predict phishing risk using the trained XGBoost model
    and inspect URL structure.

    risk_score is the model's phishing-class probability
    expressed as a percentage. It is not a guarantee of
    real-world phishing probability.
    """

    model, feature_names = load_model()

    inspection = inspect_url(url)

    features = extract_url_features(
        inspection["normalized_url"]
    )

    missing_features = [
        name
        for name in feature_names
        if name not in features
    ]

    if missing_features:
        raise ValueError(
            "Missing URL features: "
            + ", ".join(missing_features)
        )

    dataframe = pd.DataFrame(
        [[features[name] for name in feature_names]],
        columns=feature_names,
    )

    classes = list(model.classes_)

    if 1 not in classes:
        raise ValueError(
            "The trained model does not contain phishing label 1."
        )

    phishing_index = classes.index(1)

    probabilities = model.predict_proba(dataframe)[0]

    phishing_probability = float(
        probabilities[phishing_index]
    )

    model_prediction = int(
        model.predict(dataframe)[0]
    )

    model_verdict = (
        "PHISHING"
        if model_prediction == 1
        else "LEGITIMATE"
    )

    trusted = inspection["is_trusted_domain"]
    signals = inspection["suspicious_signals"]

    parsed = urlparse(inspection["normalized_url"])

    is_root_page = parsed.path in ("", "/")

    has_query_or_fragment = bool(
        parsed.query or parsed.fragment
    )

    # Trusted root homepage without warning signals.
    # This is a heuristic, not a guarantee of safety.
    if (
        trusted
        and is_root_page
        and not has_query_or_fragment
        and not signals
    ):
        final_verdict = "LIKELY LEGITIMATE"

        decision_reason = (
            "Hostname matches the configured trusted-domain "
            "list and no inspection warning was found. "
            "This does not guarantee the URL is safe."
        )

    # Trusted host with warning signals:
    # require review rather than automatically trusting it.
    elif trusted and signals:
        final_verdict = "REVIEW REQUIRED"

        decision_reason = (
            "The hostname matches the trusted-domain list, "
            "but warning indicators were detected. Review "
            "the complete URL and any redirect destination."
        )

    elif model_prediction == 1:
        final_verdict = "SUSPICIOUS"

        decision_reason = (
            "The machine-learning model classified this URL "
            "as phishing. Verify it before opening."
        )

    else:
        final_verdict = "NO PHISHING SIGNAL DETECTED"

        decision_reason = (
            "The model did not classify this URL as phishing. "
            "This does not guarantee safety."
        )

    return {
        "prediction": final_verdict,
        "model_prediction": model_verdict,
        "risk_score": round(
            phishing_probability * 100, 2
        ),
        "probability": round(
            phishing_probability, 4
        ),
        "hostname": inspection["hostname"],
        "registered_domain": inspection["registered_domain"],
        "trusted_domain_match": trusted,
        "suspicious_signals": signals,
        "redirect_destinations": inspection[
            "redirect_destinations"
        ],
        "decision_reason": decision_reason,
    }


# =========================================================
# DATASET DOMAIN GROUPING
# =========================================================

def get_domain_group(url):
    try:
        inspection = inspect_url(url)
        return inspection["registered_domain"]
    except (ValueError, TypeError):
        return None


# =========================================================
# TRAIN MODEL
# =========================================================

def train_model():
    """
    Train a new XGBoost model using domain-grouped splitting.

    Expected CSV columns:
        url   -> URL string
        label -> 0 for legitimate, 1 for phishing

    This function replaces the saved model after training.
    """

    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_PATH}"
        )

    os.makedirs(MODEL_DIR, exist_ok=True)

    dataset = pd.read_csv(DATASET_PATH)

    if (
        "url" not in dataset.columns
        or "label" not in dataset.columns
    ):
        raise ValueError(
            "Dataset must contain 'url' and 'label' columns. "
            f"Found: {list(dataset.columns)}"
        )

    dataset = dataset[["url", "label"]].copy()

    dataset = dataset.dropna(
        subset=["url", "label"]
    )

    dataset["url"] = (
        dataset["url"].astype(str).str.strip()
    )

    dataset["label"] = pd.to_numeric(
        dataset["label"],
        errors="coerce",
    )

    dataset = dataset.dropna(
        subset=["label"]
    )

    dataset = dataset[
        dataset["label"].isin([0, 1])
    ].copy()

    dataset = dataset[
        dataset["url"].str.len() > 0
    ].copy()

    if dataset["label"].nunique() != 2:
        raise ValueError(
            "Training dataset must contain both labels 0 and 1."
        )

    feature_rows = []
    valid_indices = []
    domain_groups = []

    for index, row in dataset.iterrows():
        try:
            features = extract_url_features(
                row["url"]
            )

            if not all(
                name in features
                for name in FEATURE_NAMES
            ):
                continue

            group = get_domain_group(row["url"])

            if not group:
                continue

            feature_rows.append(
                [
                    features[name]
                    for name in FEATURE_NAMES
                ]
            )

            valid_indices.append(index)
            domain_groups.append(group)

        except (ValueError, TypeError):
            continue

    if len(feature_rows) < 10:
        raise ValueError(
            "Not enough valid URLs to train the model."
        )

    X = pd.DataFrame(
        feature_rows,
        columns=FEATURE_NAMES,
    )

    y = (
        dataset.loc[valid_indices, "label"]
        .astype(int)
        .reset_index(drop=True)
    )

    groups = pd.Series(
        domain_groups
    ).reset_index(drop=True)

    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=0.2,
        random_state=42,
    )

    train_indices, test_indices = next(
        splitter.split(
            X,
            y,
            groups=groups,
        )
    )

    X_train = X.iloc[train_indices]
    X_test = X.iloc[test_indices]

    y_train = y.iloc[train_indices]
    y_test = y.iloc[test_indices]

    if y_train.nunique() < 2:
        raise ValueError(
            "Training split contains only one label. "
            "More domain diversity is needed."
        )

    if y_test.nunique() < 2:
        raise ValueError(
            "Test split contains only one label. "
            "More domain diversity is needed for evaluation."
        )

    model = create_model()

    model.fit(
        X_train,
        y_train,
    )

    predictions = model.predict(X_test)

    accuracy = accuracy_score(
        y_test,
        predictions,
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0,
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0,
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0,
    )

    # Back up the previous model before replacing it.
    if os.path.exists(MODEL_PATH):
        shutil.copy2(
            MODEL_PATH,
            BACKUP_PATH,
        )

    joblib.dump(
        model,
        MODEL_PATH,
    )

    with open(
        FEATURE_PATH,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            FEATURE_NAMES,
            file,
            indent=4,
        )

    results = {
        "samples_used": len(X),
        "training_samples": len(train_indices),
        "testing_samples": len(test_indices),
        "unique_domains": int(groups.nunique()),
        "accuracy": round(float(accuracy), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1_score": round(float(f1), 4),
        "model_path": MODEL_PATH,
        "feature_path": FEATURE_PATH,
    }

    print("\n===== XGBoost Phishing Model Results =====")

    for key, value in results.items():
        print(f"{key}: {value}")

    print(
        "\nThese metrics describe this test split only; "
        "they do not guarantee real-world accuracy."
    )

    return results


# =========================================================
# MANUAL TEST
# =========================================================

if __name__ == "__main__":

    test_urls = [
        "https://www.google.com/",
        "https://www.wikipedia.org/",
        "https://github.com/",
        "https://www.google.com/url?q=https://example.com",
        "http://192.0.2.1/login",
    ]

    for test_url in test_urls:
        print("\n" + "=" * 60)
        print("URL:", test_url)

        try:
            result = predict_phishing(test_url)

            for key, value in result.items():
                print(f"{key}: {value}")

        except Exception as error:
            print("ERROR:", error)
