# ============================================================
# CyberShield AI - Official EMBER Malware Detector
# ============================================================

import os
from pathlib import Path

import numpy as np

# Compatibility for the legacy EMBER feature extractor.
if not hasattr(np, "int"):
    np.int = int

import lightgbm as lgb
import ember


# Project paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = PROJECT_ROOT / "models" / "ember_lightgbm_custom.txt"

_model = None
_extractor = None


def load_ember_model():
    """Load the official EMBER model once and reuse it."""
    global _model, _extractor

    if _model is not None and _extractor is not None:
        return _model, _extractor
    print(f"[EMBER DEBUG] Project root: {PROJECT_ROOT}")
    print(f"[EMBER DEBUG] Model path: {MODEL_PATH}")
    print(f"[EMBER DEBUG] Model exists: {MODEL_PATH.is_file()}")

    if not MODEL_PATH.is_file():
        raise FileNotFoundError(
            f"EMBER model not found: {MODEL_PATH}"
        )

    model = lgb.Booster(model_file=str(MODEL_PATH))
    extractor = ember.PEFeatureExtractor(feature_version=2)

    if model.num_feature() != 2381:
        raise ValueError(
            f"Expected 2381 model features, got {model.num_feature()}"
        )

    _model = model
    _extractor = extractor

    return _model, _extractor


def predict_ember(file_path):
    """
    Return the EMBER model score for a Windows PE file.

    Label convention: 0 = benign, 1 = malware.
    This is a model prediction, not a guaranteed security verdict.
    """
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    with path.open("rb") as file:
        bytez = file.read()

    if len(bytez) < 2 or bytez[:2] != b"MZ":
        raise ValueError(
            "EMBER v2 detector currently accepts Windows PE files only."
        )

    model, extractor = load_ember_model()

    features = extractor.feature_vector(bytez)

    if len(features) != model.num_feature():
        raise ValueError(
            f"Feature mismatch: extracted {len(features)}, "
            f"expected {model.num_feature()}"
        )

    score = float(model.predict(
        np.asarray(features, dtype=np.float32).reshape(1, -1)
    )[0])

    # EMBER training labels: 0 = benign, 1 = malware.
    return {
        "status": "success",
        "model": "EMBER v2 LightGBM",
        "probability": score,
        "probability_percent": score * 100,
        "label": "Malware" if score >= 0.5 else "Benign",
        "features_count": len(features),
        "warning": (
            "LIEF version differs from the original EMBER v2 "
            "feature-extraction version. Validate before relying "
            "on this prediction."
        ),
    }


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print(
            'Usage: python -m core.ember_detector "C:\\path\\file.exe"'
        )
        raise SystemExit(2)

    try:
        result = predict_ember(sys.argv[1])

        print("\nEMBER Prediction Result")
        print("-----------------------")
        print("Model:", result["model"])
        print("Label:", result["label"])
        print(
            "Score:",
            f'{result["probability_percent"]:.4f}%'
        )
        print("Features:", result["features_count"])
        print("Warning:", result["warning"])

    except Exception as error:
        print("EMBER prediction failed:", error)
        raise SystemExit(1)