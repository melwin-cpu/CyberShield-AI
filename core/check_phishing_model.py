
from pathlib import Path
import joblib

ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = ROOT / "models" / "phishing_rf_model.joblib"
FEATURE_PATH = ROOT / "models" / "phishing_feature_names.json"

print("Checking saved phishing model...")

if not MODEL_PATH.exists():
    print("ERROR: Saved model file not found.")
    raise SystemExit(1)

model = joblib.load(MODEL_PATH)

print("Model type:", type(model).__name__)
print("Expected features:", model.n_features_in_)
print("Classes:", model.classes_)

if FEATURE_PATH.exists():
    import json
    features = json.loads(FEATURE_PATH.read_text(encoding="utf-8"))
    print("Saved feature names:", len(features))
    print("Feature count matches:", len(features) == model.n_features_in_)
else:
    print("WARNING: Feature names file not found.")

print("\nCheck completed. No model was changed.")
