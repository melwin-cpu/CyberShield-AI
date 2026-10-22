# ============================================================
# CyberShield AI
# XGBoost Malware Detection - Model Training Script
# ============================================================

import os
import sys

# ------------------------------------------------------------
# Add project root to Python path
# ------------------------------------------------------------

CURRENT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

PROJECT_ROOT = os.path.dirname(
    CURRENT_DIR
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ------------------------------------------------------------
# Import ML engine
# ------------------------------------------------------------

from core.ml_engine import (
    train_model,
    FEATURE_NAMES
)


# ============================================================
# CONFIGURATION
# ============================================================

DATASET_DIR = os.path.join(
    PROJECT_ROOT,
    "dataset"
)

DATASET_PATH = os.path.join(
    DATASET_DIR,
    "malware_dataset.csv"
)


# ============================================================
# CHECK DATASET
# ============================================================

def check_dataset():

    print("\n========================================")
    print("CyberShield AI - Dataset Check")
    print("========================================")

    print("\nDataset location:")
    print(DATASET_PATH)

    # --------------------------------------------------------
    # Check dataset folder
    # --------------------------------------------------------

    if not os.path.isdir(DATASET_DIR):

        print("\n❌ Dataset folder not found.")

        print("\nPlease create:")
        print("dataset/")

        return False

    # --------------------------------------------------------
    # Check CSV
    # --------------------------------------------------------

    if not os.path.isfile(DATASET_PATH):

        print("\n❌ Dataset file not found.")

        print("\nExpected file:")
        print("dataset/malware_dataset.csv")

        return False

    print("\n✅ Dataset file found.")

    return True


# ============================================================
# DISPLAY REQUIRED FEATURES
# ============================================================

def show_required_features():

    print("\n========================================")
    print("Required Dataset Features")
    print("========================================")

    print("\nYour CSV must contain these columns:\n")

    for number, feature in enumerate(
        FEATURE_NAMES,
        start=1
    ):

        print(
            f"{number:02d}. {feature}"
        )

    print("\n31 feature columns are required.")

    print("\nAdditional target column:")

    print("label")

    print("\nLabel values:")

    print("0 = Benign")
    print("1 = Malware")


# ============================================================
# TRAIN MODEL
# ============================================================

def start_training():

    print("\n========================================")
    print("CyberShield AI")
    print("XGBoost Malware Detection Training")
    print("========================================")

    # --------------------------------------------------------
    # Check dataset
    # --------------------------------------------------------

    if not check_dataset():

        show_required_features()

        return

    # --------------------------------------------------------
    # Start training
    # --------------------------------------------------------

    print("\n🚀 Starting XGBoost training...")

    try:

        result = train_model(
            dataset_path=DATASET_PATH,
            target_column="label",
            test_size=0.20,
            random_state=42
        )

        # ----------------------------------------------------
        # Training successful
        # ----------------------------------------------------

        print("\n========================================")
        print("TRAINING COMPLETED")
        print("========================================")

        print(
            f"\nAccuracy  : "
            f"{result['accuracy'] * 100:.2f}%"
        )

        print(
            f"Precision : "
            f"{result['precision'] * 100:.2f}%"
        )

        print(
            f"Recall    : "
            f"{result['recall'] * 100:.2f}%"
        )

        print(
            f"F1 Score  : "
            f"{result['f1_score'] * 100:.2f}%"
        )

        print("\nModel saved at:")

        print(
            result["model_path"]
        )

        print("\n✅ XGBoost malware model is ready.")

    except Exception as error:

        print("\n========================================")
        print("TRAINING ERROR")
        print("========================================")

        print("\n❌", error)

        print("\nPlease check:")
        print("1. Dataset format")
        print("2. Feature column names")
        print("3. label column")
        print("4. Label values (0 or 1)")
        print("5. Dataset contains both benign and malware samples")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    start_training()