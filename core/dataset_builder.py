# ============================================================
# CyberShield AI
# Dataset Builder
# Static PE/File Feature Extraction
# ============================================================

import os
import sys
import pandas as pd

# ------------------------------------------------------------
# Project root
# ------------------------------------------------------------

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ------------------------------------------------------------
# Import our existing feature extractor
# ------------------------------------------------------------

from core.ml_engine import (
    extract_features,
    FEATURE_NAMES
)


# ============================================================
# CONFIGURATION
# ============================================================

DATASET_DIR = os.path.join(
    PROJECT_ROOT,
    "dataset"
)

BENIGN_DIR = os.path.join(
    DATASET_DIR,
    "benign"
)

MALWARE_DIR = os.path.join(
    DATASET_DIR,
    "malware"
)

OUTPUT_FILE = os.path.join(
    DATASET_DIR,
    "malware_dataset.csv"
)


# ============================================================
# SUPPORTED FILE TYPES
# ============================================================

SUPPORTED_EXTENSIONS = (
    ".exe",
    ".dll",
    ".sys",
    ".scr"
)


# ============================================================
# COLLECT FILES
# ============================================================

def collect_files(folder):

    files = []

    if not os.path.isdir(folder):
        return files

    for root, directories, filenames in os.walk(folder):

        for filename in filenames:

            file_path = os.path.join(
                root,
                filename
            )

            if filename.lower().endswith(
                SUPPORTED_EXTENSIONS
            ):
                files.append(file_path)

    return files


# ============================================================
# BUILD DATASET
# ============================================================

def build_dataset():

    print("\n========================================")
    print("CyberShield AI - Dataset Builder")
    print("========================================")

    # --------------------------------------------------------
    # Create folders
    # --------------------------------------------------------

    os.makedirs(
        BENIGN_DIR,
        exist_ok=True
    )

    os.makedirs(
        MALWARE_DIR,
        exist_ok=True
    )

    # --------------------------------------------------------
    # Collect files
    # --------------------------------------------------------

    benign_files = collect_files(
        BENIGN_DIR
    )

    malware_files = collect_files(
        MALWARE_DIR
    )

    print("\nBenign files :", len(benign_files))
    print("Malware files:", len(malware_files))

    if len(benign_files) == 0:
        print("\n⚠ No benign files found.")
        print("Add legitimate EXE/DLL samples to:")
        print(BENIGN_DIR)

    if len(malware_files) == 0:
        print("\n⚠ No malware files found.")
        print("Add an appropriate malware dataset to:")
        print(MALWARE_DIR)

    if not benign_files or not malware_files:

        print("\nDataset cannot be built yet.")
        return

    # --------------------------------------------------------
    # Store rows
    # --------------------------------------------------------

    rows = []

    # --------------------------------------------------------
    # Process benign files
    # --------------------------------------------------------

    print("\nProcessing benign files...")

    for index, file_path in enumerate(
        benign_files,
        start=1
    ):

        try:

            features = extract_features(
                file_path
            )

            row = features.iloc[0].to_dict()

            row["label"] = 0

            rows.append(row)

            print(
                f"[BENIGN {index}/{len(benign_files)}] "
                f"{os.path.basename(file_path)}"
            )

        except Exception as error:

            print(
                f"⚠ Failed: {file_path}"
            )

            print(
                "  Reason:",
                error
            )

    # --------------------------------------------------------
    # Process malware files
    # --------------------------------------------------------

    print("\nProcessing malware files...")

    for index, file_path in enumerate(
        malware_files,
        start=1
    ):

        try:

            features = extract_features(
                file_path
            )

            row = features.iloc[0].to_dict()

            row["label"] = 1

            rows.append(row)

            print(
                f"[MALWARE {index}/{len(malware_files)}] "
                f"{os.path.basename(file_path)}"
            )

        except Exception as error:

            print(
                f"⚠ Failed: {file_path}"
            )

            print(
                "  Reason:",
                error
            )

    # --------------------------------------------------------
    # Check results
    # --------------------------------------------------------

    if not rows:

        print("\n❌ No features were extracted.")
        return

    # --------------------------------------------------------
    # Create DataFrame
    # --------------------------------------------------------

    dataframe = pd.DataFrame(
        rows
    )

    # --------------------------------------------------------
    # Ensure correct feature order
    # --------------------------------------------------------

    dataframe = dataframe[
        FEATURE_NAMES + ["label"]
    ]

    # --------------------------------------------------------
    # Save CSV
    # --------------------------------------------------------

    dataframe.to_csv(
        OUTPUT_FILE,
        index=False
    )

    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    benign_count = int(
        (dataframe["label"] == 0).sum()
    )

    malware_count = int(
        (dataframe["label"] == 1).sum()
    )

    print("\n========================================")
    print("DATASET CREATED")
    print("========================================")

    print(
        f"\nTotal samples  : {len(dataframe)}"
    )

    print(
        f"Benign samples : {benign_count}"
    )

    print(
        f"Malware samples: {malware_count}"
    )

    print(
        "\nSaved to:"
    )

    print(
        OUTPUT_FILE
    )

    print("\n✅ Dataset builder completed.")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    build_dataset()