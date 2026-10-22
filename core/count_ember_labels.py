import json
from pathlib import Path
from collections import Counter


def main():
    data_dir = Path("ember2018")
    files = sorted(data_dir.glob("train_features_*.jsonl"))

    if not files:
        print("ERROR: EMBER training files not found.")
        return

    total = Counter()

    for file_path in files:
        counts = Counter()
        print(f"\nReading: {file_path.name}", flush=True)

        with file_path.open("r", encoding="utf-8") as file:
            for line in file:
                if not line.strip():
                    continue

                try:
                    record = json.loads(line)
                    label = int(record.get("label", -1))
                    counts[label] += 1
                except (json.JSONDecodeError, TypeError, ValueError):
                    counts["invalid"] += 1

        total.update(counts)

        print(f"  Benign (0):     {counts[0]:,}")
        print(f"  Malware (1):    {counts[1]:,}")
        print(f"  Unlabeled (-1): {counts[-1]:,}")
        print(f"  Invalid:        {counts['invalid']:,}")

    print("\n" + "=" * 35)
    print("TOTAL TRAINING DATA")
    print("=" * 35)
    print(f"Benign (0):     {total[0]:,}")
    print(f"Malware (1):    {total[1]:,}")
    print(f"Unlabeled (-1): {total[-1]:,}")
    print(f"Invalid:        {total['invalid']:,}")
    print(f"Total records:  {sum(total.values()):,}")


if __name__ == "__main__":
    main()