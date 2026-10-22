
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent

RAW_DIR = ROOT / "dataset" / "phishing" / "raw"
OUTPUT_FILE = ROOT / "dataset" / "phishing" / "phishing_urls.csv"

PHISHING_FILE = RAW_DIR / "urlsfish.csv"
LEGITIMATE_FILE = RAW_DIR / "urlsgood.csv"


def load_urls(file_path, label):
    if not file_path.exists():
        raise FileNotFoundError(f"Dataset file not found: {file_path}")

    df = pd.read_csv(file_path)

    if "URLs" not in df.columns:
        raise ValueError(
            f"Expected column 'URLs' in {file_path.name}. "
            f"Found columns: {df.columns.tolist()}"
        )

    result = df[["URLs"]].rename(columns={"URLs": "url"})
    result["label"] = label
    return result


def main():
    print("Loading phishing URLs...")
    phishing = load_urls(PHISHING_FILE, 1)

    print("Loading legitimate URLs...")
    legitimate = load_urls(LEGITIMATE_FILE, 0)

    combined = pd.concat(
        [phishing, legitimate],
        ignore_index=True
    )

    combined["url"] = combined["url"].astype(str).str.strip()
    combined = combined.dropna(subset=["url"])
    combined = combined[combined["url"] != ""]
    combined = combined.drop_duplicates(subset=["url"])

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    combined.to_csv(OUTPUT_FILE, index=False)

    print("\nDataset preparation complete!")
    print(f"Saved to: {OUTPUT_FILE}")
    print(f"Total URLs: {len(combined):,}")
    print("\nLabel counts:")
    print(combined["label"].value_counts().sort_index().to_string())
    print("\nFirst 5 rows:")
    print(combined.head().to_string(index=False))


if __name__ == "__main__":
    main()
