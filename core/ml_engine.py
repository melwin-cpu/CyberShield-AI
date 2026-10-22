# ============================================================
# CyberShield AI
# ML Engine - XGBoost + Scikit-learn + PE/File Feature Extraction
# ============================================================

import os
import math
import hashlib
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

from xgboost import XGBClassifier

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


# ============================================================
# CONFIGURATION
# ============================================================

MODEL_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..",
    "models"
)

MODEL_DIR = os.path.abspath(MODEL_DIR)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "xgboost_malware_model.joblib"
)

# Entropy / string scans only look at the first 32 MB of a file
MAX_READ_BYTES = 32 * 1024 * 1024


# ============================================================
# FEATURE NAMES
# ============================================================

FEATURE_NAMES = [
    # -------------------------
    # General file features
    # -------------------------
    "file_size",
    "entropy",

    # -------------------------
    # PE header features
    # -------------------------
    "is_pe",
    "machine",
    "number_of_sections",
    "time_date_stamp",
    "characteristics",
    "optional_header_size",
    "subsystem",
    "dll_characteristics",
    "size_of_code",
    "size_of_initialized_data",
    "size_of_uninitialized_data",
    "address_of_entry_point",
    "base_of_code",
    "image_base",
    "section_alignment",
    "file_alignment",
    "size_of_image",
    "size_of_headers",

    # -------------------------
    # PE section features
    # -------------------------
    "total_section_size",
    "mean_section_entropy",
    "max_section_entropy",
    "min_section_entropy",
    "executable_sections",
    "writable_sections",

    # -------------------------
    # Import/export features
    # -------------------------
    "number_of_import_dlls",
    "number_of_imports",
    "number_of_exports",

    # -------------------------
    # String indicators
    # -------------------------
    "suspicious_string_count",
]


# ============================================================
# DIRECTORY CREATION
# ============================================================

def ensure_model_directory():
    """
    Create the models directory if it does not exist.
    """

    os.makedirs(MODEL_DIR, exist_ok=True)


# ============================================================
# SHA256
# ============================================================

def calculate_sha256(file_path):
    """
    Calculate SHA-256 hash of a file.
    """

    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:

            while True:

                data = file.read(8192)

                if not data:
                    break

                sha256.update(data)

        return sha256.hexdigest()

    except Exception:
        return ""


# ============================================================
# FILE ENTROPY
# ============================================================

def calculate_entropy(file_path):
    """
    Calculate Shannon entropy of the complete file.

    Higher entropy can sometimes indicate compressed,
    packed or encrypted content.

    This feature alone is NOT a malware verdict.
    """

    try:

        with open(file_path, "rb") as file:
            data = file.read(MAX_READ_BYTES)

        if not data:
            return 0.0

        byte_array = np.frombuffer(data, dtype=np.uint8)

        counts = np.bincount(
            byte_array,
            minlength=256
        )

        probabilities = counts / len(byte_array)

        entropy = 0.0

        for probability in probabilities:

            if probability > 0:
                entropy -= probability * math.log2(probability)

        return float(entropy)

    except Exception:
        return 0.0


# ============================================================
# SHA256 NUMERIC REPRESENTATION
# ============================================================

def hash_to_numeric(sha256_hash):
    """
    Convert SHA-256 into a deterministic numeric value.

    This is included only as a lightweight file fingerprint
    feature. It should not be treated as a meaningful malware
    classifier by itself.
    """

    if not sha256_hash:
        return 0.0

    try:

        value = int(
            sha256_hash[:16],
            16
        )

        return float(
            value / float(0xFFFFFFFFFFFFFFFF)
        )

    except Exception:
        return 0.0


# ============================================================
# SUSPICIOUS STRING DETECTION
# ============================================================

SUSPICIOUS_STRINGS = [
    b"powershell",
    b"cmd.exe",
    b"wscript",
    b"cscript",
    b"rundll32",
    b"regsvr32",
    b"mshta",
    b"certutil",
    b"bitsadmin",
    b"downloadstring",
    b"invoke-expression",
    b"virtualalloc",
    b"virtualprotect",
    b"writeprocessmemory",
    b"createremotethread",
]


def count_suspicious_strings(file_path):
    """
    Count simple suspicious string indicators.

    This is a heuristic feature, not a malware verdict.
    """

    count = 0

    try:

        with open(file_path, "rb") as file:
            data = file.read(MAX_READ_BYTES)

        data_lower = data.lower()

        for suspicious_string in SUSPICIOUS_STRINGS:

            if suspicious_string.lower() in data_lower:
                count += 1

    except Exception:
        pass

    return count


# ============================================================
# DEFAULT FEATURE VECTOR
# ============================================================

def get_default_features(file_path):
    """
    Create a default feature dictionary.

    Used when PE parsing is unavailable or the selected
    file is not a valid PE executable.
    """

    file_size = 0

    try:
        file_size = os.path.getsize(file_path)

    except Exception:
        pass

    features = {
        name: 0.0
        for name in FEATURE_NAMES
    }

    features["file_size"] = float(file_size)

    features["entropy"] = calculate_entropy(file_path)

    features["suspicious_string_count"] = float(
        count_suspicious_strings(file_path)
    )

    return features


# ============================================================
# PE FEATURE EXTRACTION
# ============================================================

def extract_pe_features(file_path):
    """
    Extract static PE features from an EXE/DLL file.

    Returns:
        dict containing FEATURE_NAMES
    """

    features = get_default_features(file_path)

    # --------------------------------------------------------
    # Check pefile
    # --------------------------------------------------------

    if not PEFILE_AVAILABLE:
        return features

    try:

        pe = pefile.PE(
            file_path,
            fast_load=False
        )

    except Exception:

        # File is not a valid PE
        return features

    # --------------------------------------------------------
    # Basic PE information
    # --------------------------------------------------------

    features["is_pe"] = 1.0

    try:
        features["machine"] = float(
            pe.FILE_HEADER.Machine
        )
    except Exception:
        pass

    try:
        features["number_of_sections"] = float(
            pe.FILE_HEADER.NumberOfSections
        )
    except Exception:
        pass

    try:
        features["time_date_stamp"] = float(
            pe.FILE_HEADER.TimeDateStamp
        )
    except Exception:
        pass

    try:
        features["characteristics"] = float(
            pe.FILE_HEADER.Characteristics
        )
    except Exception:
        pass

    # --------------------------------------------------------
    # Optional Header
    # --------------------------------------------------------

    try:
        optional_header = pe.OPTIONAL_HEADER

        features["optional_header_size"] = float(
            pe.FILE_HEADER.SizeOfOptionalHeader
        )

        features["subsystem"] = float(
            optional_header.Subsystem
        )

        features["dll_characteristics"] = float(
            optional_header.DllCharacteristics
        )

        features["size_of_code"] = float(
            optional_header.SizeOfCode
        )

        features["size_of_initialized_data"] = float(
            optional_header.SizeOfInitializedData
        )

        features["size_of_uninitialized_data"] = float(
            optional_header.SizeOfUninitializedData
        )

        features["address_of_entry_point"] = float(
            optional_header.AddressOfEntryPoint
        )

        features["base_of_code"] = float(
            optional_header.BaseOfCode
        )

        features["image_base"] = float(
            optional_header.ImageBase
        )

        features["section_alignment"] = float(
            optional_header.SectionAlignment
        )

        features["file_alignment"] = float(
            optional_header.FileAlignment
        )

        features["size_of_image"] = float(
            optional_header.SizeOfImage
        )

        features["size_of_headers"] = float(
            optional_header.SizeOfHeaders
        )

    except Exception:
        pass

    # --------------------------------------------------------
    # Section information
    # --------------------------------------------------------

    section_sizes = []
    section_entropies = []

    executable_sections = 0
    writable_sections = 0

    try:

        for section in pe.sections:

            # Section size
            try:

                section_size = float(
                    section.SizeOfRawData
                )

                section_sizes.append(
                    section_size
                )

            except Exception:
                pass

            # Section entropy
            try:

                entropy = float(
                    section.get_entropy()
                )

                section_entropies.append(
                    entropy
                )

            except Exception:
                pass

            # Executable section
            try:

                if section.Characteristics & 0x20000000:
                    executable_sections += 1

            except Exception:
                pass

            # Writable section
            try:

                if section.Characteristics & 0x80000000:
                    writable_sections += 1

            except Exception:
                pass

    except Exception:
        pass

    if section_sizes:

        features["total_section_size"] = float(
            sum(section_sizes)
        )

    if section_entropies:

        features["mean_section_entropy"] = float(
            np.mean(section_entropies)
        )

        features["max_section_entropy"] = float(
            np.max(section_entropies)
        )

        features["min_section_entropy"] = float(
            np.min(section_entropies)
        )

    features["executable_sections"] = float(
        executable_sections
    )

    features["writable_sections"] = float(
        writable_sections
    )

    # --------------------------------------------------------
    # Import information
    # --------------------------------------------------------

    number_of_import_dlls = 0
    number_of_imports = 0

    try:

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):

            for entry in pe.DIRECTORY_ENTRY_IMPORT:

                number_of_import_dlls += 1

                for imported_function in entry.imports:

                    number_of_imports += 1

    except Exception:
        pass

    features["number_of_import_dlls"] = float(
        number_of_import_dlls
    )

    features["number_of_imports"] = float(
        number_of_imports
    )

    # --------------------------------------------------------
    # Export information
    # --------------------------------------------------------

    number_of_exports = 0

    try:

        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):

            number_of_exports = len(
                pe.DIRECTORY_ENTRY_EXPORT.symbols
            )

    except Exception:
        pass

    features["number_of_exports"] = float(
        number_of_exports
    )

    # --------------------------------------------------------
    # Cleanup
    # --------------------------------------------------------

    try:
        pe.close()
    except Exception:
        pass

    return features


# ============================================================
# FEATURE VECTOR
# ============================================================

def extract_features(file_path):
    """
    Extract all ML features and return them as a pandas DataFrame.

    This format matches the training pipeline.
    """

    if not os.path.isfile(file_path):
        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    features = extract_pe_features(file_path)

    # Make sure every expected feature exists
    for feature_name in FEATURE_NAMES:

        if feature_name not in features:
            features[feature_name] = 0.0

    # Keep exact feature order
    feature_vector = [
        features[name]
        for name in FEATURE_NAMES
    ]

    dataframe = pd.DataFrame(
        [feature_vector],
        columns=FEATURE_NAMES
    )

    return dataframe


# ============================================================
# CREATE XGBOOST PIPELINE
# ============================================================

def create_model():
    """
    Create the XGBoost classification pipeline.

    The pipeline contains:
        - Missing value imputation
        - Feature scaling
        - XGBoost classifier
    """

    model = Pipeline(
        steps=[

            (
                "imputer",
                SimpleImputer(
                    strategy="median"
                )
            ),

            (
                "scaler",
                StandardScaler()
            ),

            (
                "classifier",
                XGBClassifier(
                    n_estimators=200,
                    max_depth=6,
                    learning_rate=0.05,
                    subsample=0.8,
                    colsample_bytree=0.8,
                    objective="binary:logistic",
                    eval_metric="logloss",
                    random_state=42,
                    n_jobs=-1
                )
            )
        ]
    )

    return model


# ============================================================
# TRAIN MODEL
# ============================================================

def train_model(
    dataset_path,
    target_column="label",
    test_size=0.2,
    random_state=42
):
    """
    Train XGBoost malware classifier from a CSV dataset.

    Dataset requirements:

        - CSV file
        - FEATURE_NAMES columns
        - label column

    Label format:
        0 = Benign
        1 = Malware
    """

    if not os.path.isfile(dataset_path):

        raise FileNotFoundError(
            f"Dataset not found: {dataset_path}"
        )

    dataframe = pd.read_csv(
        dataset_path
    )

    # --------------------------------------------------------
    # Check required columns
    # --------------------------------------------------------

    missing_features = [
        feature
        for feature in FEATURE_NAMES
        if feature not in dataframe.columns
    ]

    if missing_features:

        raise ValueError(
            "Dataset is missing required features:\n"
            + ", ".join(missing_features)
        )

    if target_column not in dataframe.columns:

        raise ValueError(
            f"Target column '{target_column}' "
            "was not found in the dataset."
        )

    # --------------------------------------------------------
    # Prepare X and y
    # --------------------------------------------------------

    X = dataframe[FEATURE_NAMES]

    y = dataframe[target_column]

    # Convert labels to integers
    y = pd.to_numeric(
        y,
        errors="coerce"
    )

    # Remove invalid labels
    valid_rows = y.notna()

    X = X.loc[valid_rows]

    y = y.loc[valid_rows].astype(int)

    # --------------------------------------------------------
    # Validate labels
    # --------------------------------------------------------

    unique_labels = sorted(
        y.unique().tolist()
    )

    if not set(unique_labels).issubset({0, 1}):

        raise ValueError(
            "Labels must contain only 0 and 1.\n"
            "0 = Benign\n"
            "1 = Malware"
        )

    if len(unique_labels) < 2:

        raise ValueError(
            "Training requires both classes:\n"
            "0 = Benign and 1 = Malware."
        )

    class_counts = y.value_counts()

    if class_counts.min() < 10:

        raise ValueError(
            "Each class needs at least 10 samples.\n"
            f"Current counts: {class_counts.to_dict()}"
        )

    # --------------------------------------------------------
    # Train/Test split
    # --------------------------------------------------------

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y
    )

    # --------------------------------------------------------
    # Create model
    # --------------------------------------------------------

    model = create_model()

    # --------------------------------------------------------
    # Train
    # --------------------------------------------------------

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
    # Metrics
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

    # --------------------------------------------------------
    # Save model
    # --------------------------------------------------------

    ensure_model_directory()

    joblib.dump(
        model,
        MODEL_PATH
    )

    # --------------------------------------------------------
    # Print report
    # --------------------------------------------------------

    print("\n========================================")
    print("CyberShield AI - XGBoost Training")
    print("========================================")

    print(f"Training samples : {len(X_train)}")
    print(f"Testing samples  : {len(X_test)}")

    print("\nPerformance:")
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
    print(
        confusion_matrix(
            y_test,
            predictions
        )
    )

    print("\nModel saved to:")
    print(MODEL_PATH)

    print("========================================\n")

    return {
        "model": model,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "model_path": MODEL_PATH
    }


# ============================================================
# LOAD MODEL
# ============================================================


def load_model():
    """
    Load the trained XGBoost malware model.
    Returns None when the model file is missing
    or cannot be loaded.
    """
    if not os.path.isfile(MODEL_PATH):
        print("ML Model File Missing:", MODEL_PATH)
        return None

    try:
        model = joblib.load(MODEL_PATH)
        print("ML Model Loaded Successfully:", MODEL_PATH)
        return model

    except Exception as error:
        print("ML Model Load Error:", repr(error))
        return None



# ============================================================
# MALWARE PREDICTION
# ============================================================

def predict_malware(file_path):
    """
    Predict whether a file is benign or malware.

    Returns a dictionary containing:

        status
        prediction
        label
        probability
        features

    If no trained model exists, status is:
        model_not_trained
    """

    if not os.path.isfile(file_path):

        return {
            "status": "error",
            "prediction": None,
            "label": "File not found",
            "probability": 0.0,
            "features": None
        }

    model = load_model()

    # --------------------------------------------------------
    # Model does not exist yet
    # --------------------------------------------------------

    if model is None:

        return {
            "status": "model_not_trained",
            "prediction": None,
            "label": "ML model not trained yet",
            "probability": 0.0,
            "features": extract_features(file_path)
        }

    # --------------------------------------------------------
    # Extract features
    # --------------------------------------------------------

    features = extract_features(
        file_path
    )

    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    try:

        prediction = int(
            model.predict(features)[0]
        )

        probabilities = model.predict_proba(
            features
        )[0]

        malware_probability = float(
            probabilities[1]
        )

        # ----------------------------------------------------
        # Result label
        # ----------------------------------------------------

        if prediction == 1:

            label = "Malware"

        else:

            label = "Benign"

        return {
            "status": "success",
            "prediction": prediction,
            "label": label,
            "probability": malware_probability,
            "probability_percent": malware_probability * 100,
            "features": features
        }

    except Exception as error:

        return {
            "status": "error",
            "prediction": None,
            "label": "Prediction failed",
            "probability": 0.0,
            "features": features,
            "error": str(error)
        }


# ============================================================
# FEATURE INFORMATION
# ============================================================

def get_feature_summary(file_path):
    """
    Return extracted features as a normal dictionary.

    Useful for displaying features in the GUI.
    """

    dataframe = extract_features(
        file_path
    )

    return dataframe.iloc[0].to_dict()


# ============================================================
# MODEL STATUS
# ============================================================

def is_model_available():
    """
    Check whether a trained XGBoost model exists.
    """

    return os.path.isfile(
        MODEL_PATH
    )


# ============================================================
# QUICK TEST
# ============================================================

if __name__ == "__main__":

    print("========================================")
    print("CyberShield AI - ML Engine")
    print("========================================")

    print(
        "PEFile available:",
        PEFILE_AVAILABLE
    )

    print(
        "Model available:",
        is_model_available()
    )

    print(
        "Model path:",
        MODEL_PATH
    )

    print("\nFeature count:")
    print(
        len(FEATURE_NAMES)
    )

    print("\nFeatures:")

    for index, feature in enumerate(
        FEATURE_NAMES,
        start=1
    ):
        print(
            f"{index:02d}. {feature}"
        )

    print("\nML Engine ready.")