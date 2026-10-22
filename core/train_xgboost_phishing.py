
from pathlib import Path
import json
import shutil

import joblib
import pandas as pd

from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)

from xgboost import XGBClassifier

from core.phishing_engine import extract_url_features, FEATURE_NAMES


ROOT = Path(__file__).resolve().parent.parent

DATASET_PATH = ROOT / "dataset" / "phishing" / "phishing_urls.csv"
MODEL_DIR = ROOT / "models"

MODEL_PATH = MODEL_DIR / "xgboost_phishing_model.joblib"
FEATURE_PATH = MODEL_DIR / "xgboost_phishing_feature_names.json"
BACKUP_PATH = MODEL_DIR / "xgboost_phishing_model_backup.joblib"


# Common multi-part public suffixes. This is a simplified list,
# not a complete replacement for the Public Suffix List.
MULTIPART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk",
    "com.au", "net.au", "org.au",
    "co.in", "net.in", "org.in", "ac.in",
    "co.jp", "co.nz", "com.br", "com.sg",
}


def get_domain_group(url):
    """Group subdomains under a common registrable-domain approximation."""
    from urllib.parse import urlparse
    import ipaddress

    value = str(url).strip()

    if not value.startswith(("http://", "https://")):
        value = "http://" + value

    parsed = urlparse(value)
    hostname = (parsed.hostname or "").lower().rstrip(".")

    if not hostname:
        raise ValueError(f"Could not parse hostname from URL: {url}")

    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass

    parts = hostname.split(".")

    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTIPART_SUFFIXES:
        return ".".join(parts[-3:])

    if len(parts) >= 2:
        return ".".join(parts[-2:])

    return hostname


def main():
    print("\n========================================")
    print("CyberShield AI - XGBoost Training")
    print("========================================")

    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

    print("\nLoading dataset...")
    df = pd.read_csv(DATASET_PATH)

    if not {"url", "label"}.issubset(df.columns):
        raise ValueError("Dataset must contain 'url' and 'label' columns.")

    df = df[["url", "label"]].dropna().copy()
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"] != ""].copy()

    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df.dropna(subset=["label"]).copy()
    df = df[df["label"].isin([0, 1])].copy()
    df["label"] = df["label"].astype(int)

    # Drop exact duplicate URLs. Conflicting labels are excluded rather
    # than choosing one label arbitrarily.
    conflicting = (
        df.groupby("url")["label"].nunique().loc[lambda x: x > 1].index
    )

    if len(conflicting):
        print(f"Removing URLs with conflicting labels: {len(conflicting)}")
        df = df[~df["url"].isin(conflicting)].copy()

    df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)

    if df["label"].nunique() != 2:
        raise ValueError("Dataset must contain both labels 0 and 1.")

    print(f"Usable URLs: {len(df):,}")
    print("\nLabel counts (0=legitimate, 1=phishing):")
    print(df["label"].value_counts().sort_index().to_string())

    print("\nExtracting features and domain groups...")
    rows = []
    labels = []
    groups = []
    valid_urls = []

    for url, label in zip(df["url"], df["label"]):
        try:
            features = extract_url_features(url)
            group = get_domain_group(url)

            rows.append([features[name] for name in FEATURE_NAMES])
            labels.append(int(label))
            groups.append(group)
            valid_urls.append(url)

        except Exception as exc:
            print(f"Skipping URL {url!r}: {exc}")

    if not rows:
        raise ValueError("No valid URL features were extracted.")

    X = pd.DataFrame(rows, columns=FEATURE_NAMES)
    y = pd.Series(labels, name="label")
    groups = pd.Series(groups, name="domain_group")
    valid_urls = pd.Series(valid_urls, name="url")

    print(f"\nFeature matrix: {X.shape}")
    print(f"Unique domain groups: {groups.nunique():,}")

    diagnostic = X.copy()
    diagnostic["label"] = y

    print("\n--- FEATURE CHECK BY LABEL ---")
    print(
        diagnostic.groupby("label")[
            ["slash_count", "path_length", "url_length", "domain_length"]
        ].mean().round(2)
    )

    # Group split: URLs assigned to the same approximate registrable
    # domain should not occur in both training and testing sets.
    splitter = GroupShuffleSplit(
        n_splits=30,
        test_size=0.20,
        random_state=42,
    )

    selected_split = None

    for train_idx, test_idx in splitter.split(X, y, groups):
        if y.iloc[train_idx].nunique() == 2 and y.iloc[test_idx].nunique() == 2:
            selected_split = (train_idx, test_idx)
            break

    if selected_split is None:
        raise ValueError(
            "Could not create a domain-group split containing both labels. "
            "Inspect the dataset and domain grouping."
        )

    train_idx, test_idx = selected_split

    X_train = X.iloc[train_idx]
    X_test = X.iloc[test_idx]
    y_train = y.iloc[train_idx]
    y_test = y.iloc[test_idx]

    train_groups = set(groups.iloc[train_idx])
    test_groups = set(groups.iloc[test_idx])
    overlap = train_groups.intersection(test_groups)

    if overlap:
        raise RuntimeError("Domain leakage detected between train and test.")

    print(f"\nTraining samples: {len(X_train):,}")
    print(f"Testing samples: {len(X_test):,}")
    print(f"Training domain groups: {len(train_groups):,}")
    print(f"Testing domain groups: {len(test_groups):,}")
    print(f"Overlapping domain groups: {len(overlap)}")

    model = XGBClassifier(
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

    print("\nTraining XGBoost model...")
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("\n========== XGBOOST RESULTS ==========")
    print(f"Accuracy : {accuracy_score(y_test, predictions) * 100:.2f}%")
    print(
        f"Precision: "
        f"{precision_score(y_test, predictions, zero_division=0) * 100:.2f}%"
    )
    print(
        f"Recall   : "
        f"{recall_score(y_test, predictions, zero_division=0) * 100:.2f}%"
    )
    print(
        f"F1-score : "
        f"{f1_score(y_test, predictions, zero_division=0) * 100:.2f}%"
    )

    print("\nClassification report:")
    print(
        classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["Legitimate", "Phishing"],
            zero_division=0,
        )
    )

    print("Confusion matrix (rows=actual, columns=predicted):")
    print(confusion_matrix(y_test, predictions, labels=[0, 1]))

    print("\n--- TOP 10 FEATURE IMPORTANCES ---")
    importance = pd.Series(
        model.feature_importances_,
        index=FEATURE_NAMES,
    ).sort_values(ascending=False)

    print(importance.head(10).to_string())

    # Sanity checks are separate from the held-out evaluation.
    test_urls = [
        "https://wikipedia.org",
        "https://www.wikipedia.org/",
        "https://en.wikipedia.org/",
        "https://www.google.com/",
        "https://www.google.com/search?q=test",
        "https://www.youtube.com/",
        "https://github.com/",
        "https://www.microsoft.com/",
        "https://example.com",
        "http://example.com",
    ]

    print("\n--- URL SANITY CHECK ---")

    for url in test_urls:
        try:
            features = extract_url_features(url)
            test_X = pd.DataFrame(
                [[features[name] for name in FEATURE_NAMES]],
                columns=FEATURE_NAMES,
            )

            predicted = int(model.predict(test_X)[0])
            probabilities = model.predict_proba(test_X)[0]
            phishing_index = list(model.classes_).index(1)
            phishing_probability = float(probabilities[phishing_index])

            verdict = "PHISHING" if predicted == 1 else "LEGITIMATE"

            print(
                f"\nURL: {url}\n"
                f"Prediction: {verdict}\n"
                f"Phishing probability: {phishing_probability:.2%}"
            )

        except Exception as exc:
            print(f"\nCould not test {url}: {exc}")

    # Backup before replacing the current model.
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    if MODEL_PATH.exists():
        shutil.copy2(MODEL_PATH, BACKUP_PATH)
        print(f"\nPrevious model backed up to:\n{BACKUP_PATH}")

    # Save the model and its matching feature list.
    joblib.dump(model, MODEL_PATH)

    FEATURE_PATH.write_text(
        json.dumps(FEATURE_NAMES, indent=2),
        encoding="utf-8",
    )

    print(f"\nXGBoost model saved to:\n{MODEL_PATH}")
    print(f"Feature list saved to:\n{FEATURE_PATH}")
    print("\nTraining completed successfully.")


if __name__ == "__main__":
    main()
