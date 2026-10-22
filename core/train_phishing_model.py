
from pathlib import Path
from urllib.parse import urlparse
import json
import shutil
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)

from core.phishing_engine import extract_url_features, FEATURE_NAMES


ROOT = Path(__file__).resolve().parent.parent
DATASET_PATH = ROOT / "dataset" / "phishing" / "phishing_urls.csv"
MODEL_DIR = ROOT / "models"
MODEL_PATH = MODEL_DIR / "phishing_rf_model.joblib"
FEATURE_PATH = MODEL_DIR / "phishing_feature_names.json"
BACKUP_PATH = MODEL_DIR / "phishing_rf_model_backup.joblib"


def get_hostname(url):
    """Extract hostname safely from a URL."""
    try:
        value = url.strip()

        if not value.startswith(("http://", "https://")):
            value = "http://" + value

        return (urlparse(value).hostname or "").lower().strip(".")
    except Exception:
        return ""


def get_domain_group(hostname):
    """
    Group common subdomains with their parent domain.

    This simple helper handles common multi-part suffixes.
    It is not a complete public-suffix database.
    """
    parts = hostname.split(".")

    if len(parts) <= 2:
        return hostname

    common_two_part_suffixes = {
        "co.uk", "org.uk", "ac.uk",
        "com.au", "net.au", "org.au",
        "co.in", "firm.in", "net.in",
        "org.in", "gen.in", "ind.in",
        "com.br", "com.cn", "com.sg",
        "co.jp", "co.nz", "com.mx",
    }

    suffix = ".".join(parts[-2:])

    if suffix in common_two_part_suffixes and len(parts) >= 3:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def main():
    print("=" * 45)
    print("CyberShield AI - Random Forest Training")
    print("=" * 45)

    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_PATH}"
        )

    print("\nLoading dataset...")
    df = pd.read_csv(DATASET_PATH)

    if not {"url", "label"}.issubset(df.columns):
        raise ValueError(
            "Dataset must contain 'url' and 'label' columns."
        )

    df = df[["url", "label"]].dropna().copy()
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"] != ""].copy()

    df["label"] = pd.to_numeric(
        df["label"], errors="coerce"
    )
    df = df.dropna(subset=["label"])
    df = df[df["label"].isin([0, 1])].copy()
    df["label"] = df["label"].astype(int)

    # Remove exact duplicate URLs.
    df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)

    if df["label"].nunique() != 2:
        raise ValueError("Both labels 0 and 1 are required.")

    # Extract hostname and domain grouping.
    df["hostname"] = df["url"].apply(get_hostname)
    df = df[df["hostname"] != ""].copy()

    df["domain_group"] = df["hostname"].apply(get_domain_group)

    print(f"Usable URLs: {len(df):,}")
    print("\nLabel counts:")
    print(df["label"].value_counts().sort_index().to_string())

    print("\n--- DOMAIN LABEL DIAGNOSTIC ---")
    print("Unique hostnames:", df["hostname"].nunique())
    print("Unique domain groups:", df["domain_group"].nunique())

    domain_label_counts = df.groupby("domain_group")["label"].nunique()
    mixed_domains = domain_label_counts[domain_label_counts > 1]

    print("Domain groups with both labels:", len(mixed_domains))

    if len(mixed_domains):
        print("\nExample mixed-label domain groups:")
        print(mixed_domains.head(10).to_string())

    print("\nExtracting URL features...")
    X_rows = []
    valid_indices = []

    for index, url in zip(df.index, df["url"]):
        try:
            features = extract_url_features(url)
            X_rows.append([features[name] for name in FEATURE_NAMES])
            valid_indices.append(index)
        except Exception as exc:
            print(f"Skipping URL at row {index}: {exc}")

    if not X_rows:
        raise ValueError("No URLs could be converted into features.")

    X = pd.DataFrame(X_rows, columns=FEATURE_NAMES)
    valid_df = df.loc[valid_indices].copy().reset_index(drop=True)
    y = valid_df["label"].to_numpy()
    groups = valid_df["domain_group"].to_numpy()

    if len(set(y)) != 2:
        raise ValueError("Both classes must remain after feature extraction.")

    print("\nFeature matrix:", X.shape)
    print("Splitting by domain groups (80% / 20% target)...")

    # Keep related domain groups out of both train and test sets.
    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=0.20,
        random_state=42,
    )

    train_indices, test_indices = next(
        splitter.split(X, y, groups=groups)
    )

    X_train = X.iloc[train_indices]
    X_test = X.iloc[test_indices]
    y_train = y[train_indices]
    y_test = y[test_indices]

    train_groups = set(groups[train_indices])
    test_groups = set(groups[test_indices])

    overlap = train_groups.intersection(test_groups)

    print("Training samples:", len(X_train))
    print("Testing samples:", len(X_test))
    print("Training domain groups:", len(train_groups))
    print("Testing domain groups:", len(test_groups))
    print("Overlapping domain groups:", len(overlap))

    if overlap:
        raise RuntimeError(
            "Domain leakage detected: train/test groups overlap."
        )

    if len(set(y_train)) != 2 or len(set(y_test)) != 2:
        raise ValueError(
            "A split contains only one class. "
            "Try a different random_state or review the dataset."
        )

    print("\nTraining Random Forest model...")

    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    model.fit(X_train, y_train)

    print("\nEvaluating on unseen domain groups...")
    predictions = model.predict(X_test)

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

    print("\n========== RANDOM FOREST RESULTS ==========")
    print(f"Accuracy : {accuracy * 100:.2f}%")
    print(f"Precision: {precision * 100:.2f}%")
    print(f"Recall   : {recall * 100:.2f}%")
    print(f"F1-score : {f1 * 100:.2f}%")

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

    # Inspect feature importance.
    importance = pd.Series(
        model.feature_importances_,
        index=FEATURE_NAMES,
    ).sort_values(ascending=False)

    print("\nTop 10 feature importances:")
    print(importance.head(10).to_string())

    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    # Back up the current model before replacing it.
    if MODEL_PATH.exists():
        shutil.copy2(MODEL_PATH, BACKUP_PATH)
        print("\nPrevious model backed up to:", BACKUP_PATH)

    joblib.dump(model, MODEL_PATH)

    FEATURE_PATH.write_text(
        json.dumps(FEATURE_NAMES, indent=2),
        encoding="utf-8",
    )

    print("\nModel saved to:", MODEL_PATH)
    print("Feature list saved to:", FEATURE_PATH)
    print("\nTraining completed successfully.")


if __name__ == "__main__":
    main()
