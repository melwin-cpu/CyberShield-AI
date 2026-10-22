
import pandas as pd
from urllib.parse import urlparse
from pathlib import Path

# Dataset location
BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "dataset" / "phishing" / "phishing_urls.csv"

print("=" * 55)
print("CyberShield AI - Phishing Dataset Validation")
print("=" * 55)

# 1. Check dataset file
if not DATASET_PATH.exists():
    raise FileNotFoundError(
        f"Dataset not found: {DATASET_PATH}"
    )

df = pd.read_csv(DATASET_PATH)

# 2. Check required columns
required_columns = {"url", "label"}

if not required_columns.issubset(df.columns):
    raise ValueError(
        "CSV must contain 'url' and 'label' columns."
    )

# 3. Validate rows and labels
print("\n[1] BASIC DATASET CHECK")

print("Total rows:", len(df))
print("Missing URLs:", df["url"].isna().sum())
print("Missing labels:", df["label"].isna().sum())

df = df[["url", "label"]].dropna().copy()
df["url"] = df["url"].astype(str).str.strip()
df = df[df["url"] != ""].copy()

df["label"] = pd.to_numeric(
    df["label"], errors="coerce"
)

invalid_labels = df[
    ~df["label"].isin([0, 1])
]

print("Invalid labels:", len(invalid_labels))

df = df[df["label"].isin([0, 1])].copy()
df["label"] = df["label"].astype(int)

# 4. Check duplicate URLs
print("\n[2] DUPLICATE CHECK")

print("Duplicate URLs:", df["url"].duplicated().sum())

conflicting = (
    df.groupby("url")["label"].nunique() > 1
)

conflicting_urls = conflicting[conflicting].index

print("URLs with conflicting labels:", len(conflicting_urls))

# 5. Label distribution
print("\n[3] LABEL DISTRIBUTION")

counts = df["label"].value_counts().sort_index()

print("Legitimate (0):", counts.get(0, 0))
print("Phishing (1):", counts.get(1, 0))

# 6. Inspect popular domains and their labels
print("\n[4] DOMAIN LABEL CHECK")

def get_host(url):
    try:
        value = str(url).strip()

        if "://" not in value:
            value = "https://" + value

        return (urlparse(value).hostname or "").lower()
    except Exception:
        return ""

df["host"] = df["url"].apply(get_host)

domains_to_check = [
    "google.com",
    "wikipedia.org",
    "microsoft.com",
    "github.com",
    "youtube.com",
]

for domain in domains_to_check:
    matches = df[
        df["host"].apply(
            lambda host: host == domain
            or host.endswith("." + domain)
        )
    ]

    print(f"\n{domain}: {len(matches)} URLs")

    if not matches.empty:
        print(
            matches["label"]
            .value_counts()
            .sort_index()
            .rename(index={
                0: "Legitimate",
                1: "Phishing"
            })
            .to_string()
        )

# 7. Save a report without changing the dataset/model
report_path = BASE_DIR / "phishing_dataset_validation_report.txt"

with open(report_path, "w", encoding="utf-8") as report:
    report.write("CyberShield AI Dataset Validation Report\n")
    report.write("=" * 45 + "\n")
    report.write(f"Usable rows: {len(df)}\n")
    report.write(f"Legitimate URLs: {counts.get(0, 0)}\n")
    report.write(f"Phishing URLs: {counts.get(1, 0)}\n")
    report.write(
        f"Duplicate URLs: {df['url'].duplicated().sum()}\n"
    )
    report.write(
        f"Conflicting-label URLs: {len(conflicting_urls)}\n"
    )

print("\nReport saved to:")
print(report_path)

print("\nDataset validation completed.")
print("No model was retrained or modified.")
