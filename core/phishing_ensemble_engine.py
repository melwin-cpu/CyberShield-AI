import json
from pathlib import Path

import joblib
import pandas as pd

# ============================================================
# CYBERSHIELD AI - PHISHING ENSEMBLE ENGINE
# Uses the trained Random Forest model that actually exists.
# ============================================================

ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = ROOT / "models" / "phishing_rf_model.joblib"
FEATURE_NAMES_PATH = ROOT / "models" / "phishing_feature_names.json"

MODEL_WEIGHTS = {
    "Random Forest": 1.0,
}

phishing_model = None
FEATURE_NAMES = []
FEATURE_ENGINE_AVAILABLE = False
MODEL_LOAD_ERROR = None

# ============================================================
# LOAD FEATURE ENGINE
# ============================================================

try:
    from core.phishing_engine import extract_url_features

    FEATURE_ENGINE_AVAILABLE = True

except Exception as exc:
    extract_url_features = None
    MODEL_LOAD_ERROR = f"Feature engine error: {exc}"
    print("Phishing feature engine error:", exc)


# ============================================================
# LOAD TRAINED MODEL
# ============================================================

try:
    if not MODEL_PATH.is_file():
        raise FileNotFoundError(f"Model not found: {MODEL_PATH}")

    if not FEATURE_NAMES_PATH.is_file():
        raise FileNotFoundError(
            f"Feature list not found: {FEATURE_NAMES_PATH}"
        )

    with open(FEATURE_NAMES_PATH, "r", encoding="utf-8") as file:
        FEATURE_NAMES = json.load(file)

    if not isinstance(FEATURE_NAMES, list) or not FEATURE_NAMES:
        raise ValueError("The saved feature list is empty or invalid.")

    phishing_model = joblib.load(MODEL_PATH)

    if not hasattr(phishing_model, "predict_proba"):
        raise TypeError("The loaded model does not support predict_proba().")

    print("Trained phishing Random Forest model loaded.")

except Exception as exc:
    phishing_model = None
    MODEL_LOAD_ERROR = str(exc)
    print("Phishing model loading error:", exc)


# ============================================================
# ENGINE STATUS
# ============================================================

def get_available_models():
    if (
        phishing_model is not None
        and FEATURE_ENGINE_AVAILABLE
        and FEATURE_NAMES
    ):
        return ["Random Forest"]

    return []


def get_engine_status():
    available = get_available_models()

    return {
        "total_models": 1,
        "available_models": len(available),
        "models": available,
        "model_weights": MODEL_WEIGHTS,
        "error": MODEL_LOAD_ERROR,
    }


def get_ensemble_status():
    """
    Status format expected by ui/phishing_scanner.py.
    Only report models that are actually available.
    """
    available = get_available_models()

    return {
        "Heuristic Engine": False,
        "Random Forest": "Random Forest" in available,
        "XGBoost": False,
        "SVM": False,
    }


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def _extract_features(url):
    if not FEATURE_ENGINE_AVAILABLE or extract_url_features is None:
        raise RuntimeError("The phishing feature engine is unavailable.")

    features = extract_url_features(url)

    if not isinstance(features, dict):
        raise TypeError(
            "extract_url_features(url) must return a dictionary."
        )

    missing = [name for name in FEATURE_NAMES if name not in features]

    if missing:
        raise ValueError(
            "Required URL features are missing: " + ", ".join(missing)
        )

    return features


# ============================================================
# MODEL PREDICTION
# ============================================================

def predict_phishing_ensemble(url):
    if phishing_model is None:
        return {
            "success": False,
            "message": MODEL_LOAD_ERROR or "No trained model is available.",
            "url": url,
            "risk_score": None,
            "model_scores": {},
            "reasons": ["Phishing prediction could not be completed."],
            "features": {},
            "models_used": [],
        }

    try:
        features = _extract_features(url)

        row = pd.DataFrame(
            [[features[name] for name in FEATURE_NAMES]],
            columns=FEATURE_NAMES,
        )

        probabilities = phishing_model.predict_proba(row)
        classes = list(phishing_model.classes_)

        if 1 not in classes:
            raise ValueError("The trained model has no phishing class (1).")

        phishing_index = classes.index(1)
        risk_score = float(probabilities[0][phishing_index]) * 100
        risk_score = max(0.0, min(100.0, risk_score))

        if risk_score >= 70:
            threat_level = "HIGH RISK - PHISHING"
            recommendation = (
                "The model assigns a high phishing probability. "
                "Avoid entering passwords or personal information."
            )
        elif risk_score >= 40:
            threat_level = "SUSPICIOUS"
            recommendation = (
                "Verify the website and its domain before entering "
                "sensitive information."
            )
        else:
            threat_level = "LOWER MODEL SCORE"
            recommendation = (
                "The model assigned a lower phishing probability. "
                "This does not guarantee the website is safe."
            )

        return {
            "success": True,
            "url": url,
            "prediction": int(risk_score >= 70),
            "risk_score": round(risk_score, 2),
            "phishing_score": round(risk_score, 2),
            "threat_level": threat_level,
            "recommendation": recommendation,
            "model_scores": {
                "Random Forest": round(risk_score, 2)
            },
            "reasons": [
                f"Random Forest phishing probability: {risk_score:.2f}%."
            ],
            "features": features,
            "models_used": ["Random Forest"],
            "model_agreement": None,
        }

    except Exception as exc:
        print("Phishing prediction error:", exc)

        return {
            "success": False,
            "message": str(exc),
            "url": url,
            "risk_score": None,
            "model_scores": {},
            "reasons": [f"Prediction failed: {exc}"],
            "features": {},
            "models_used": [],
        }


# ============================================================
# COMPATIBILITY HELPERS
# ============================================================

def calculate_ensemble_risk(predictions):
    if not predictions:
        return 0.0

    weighted_sum = 0.0
    total_weight = 0.0

    for name, data in predictions.items():
        if name not in MODEL_WEIGHTS:
            continue

        try:
            score = float(data["risk_score"])
            weight = MODEL_WEIGHTS[name]
        except (KeyError, TypeError, ValueError):
            continue

        weighted_sum += score * weight
        total_weight += weight

    return weighted_sum / total_weight if total_weight else 0.0


def get_threat_level(risk_score):
    if risk_score >= 70:
        return "HIGH RISK - PHISHING"
    if risk_score >= 40:
        return "SUSPICIOUS"
    return "LOWER MODEL SCORE"


def get_final_prediction(risk_score):
    return int(risk_score >= 70)


def calculate_model_agreement(predictions):
    if not predictions:
        return 0.0

    votes = [
        int(data.get("prediction", 0) == 1)
        for data in predictions.values()
    ]

    phishing_votes = sum(votes)
    return max(phishing_votes, len(votes) - phishing_votes) / len(votes) * 100


def get_recommendation(risk_score):
    if risk_score >= 70:
        return (
            "Avoid opening this URL or entering sensitive information."
        )
    if risk_score >= 40:
        return "Verify the website before continuing."
    return (
        "The model assigned a lower phishing probability; "
        "this is not a guarantee of safety."
    )


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":
    print("\nCyberShield AI - Phishing Engine")
    print("=" * 40)
    print("Status:", get_engine_status())

    if get_available_models():
        test_url = "https://example.com/login"
        print("\nTest URL:", test_url)
        print(json.dumps(
            predict_phishing_ensemble(test_url),
            indent=2,
            default=str,
        ))
    else:
        print("No usable phishing model is loaded.")