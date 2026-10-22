import customtkinter as ctk
from tkinter import messagebox, filedialog
import threading
import queue
import traceback
import json
import re
import ipaddress
import joblib
import pandas as pd

from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
from database.scan_history_db import save_scan

from core.phishing_ml_engine import (
    predict_phishing as predict_xgboost_phishing
)

# ============================================================
# CYBERSHIELD AI - PHISHING SCANNER
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PHISHING_MODEL_PATH = PROJECT_ROOT / "models" / "phishing_rf_model.joblib"

BG = "#02070D"
CARD = "#06111C"
CARD_2 = "#081725"
BORDER = "#123451"

TEXT = "#F4F7FB"
MUTED = "#7FA0BA"

CYAN = "#12C8FF"
BLUE = "#168BDB"
GREEN = "#19D6A0"
RED = "#FF405A"
ORANGE = "#F4A62A"
PURPLE = "#884DFF"

FONT = "Times New Roman"
MONO = "Consolas"

MODEL_ORDER = [
    "Heuristic Engine",
    "Random Forest",
    "XGBoost",
    "SVM"
]

UI_QUEUE = queue.Queue()

STATE = {
    "url": "",
    "result": None
}


# ============================================================
# LOAD ENGINES
# ============================================================

try:
    from core.phishing_ensemble_engine import (
        predict_phishing_ensemble,
        get_ensemble_status
    )
    ENSEMBLE_AVAILABLE = True
except Exception as exc:
    ENSEMBLE_AVAILABLE = False
    predict_phishing_ensemble = None
    get_ensemble_status = None
    print("Ensemble engine not loaded:", exc)


try:
    from core.phishing_engine import (
        extract_url_features,
        FEATURE_NAMES
    )
    FEATURE_ENGINE_AVAILABLE = True
except Exception as exc:
    FEATURE_ENGINE_AVAILABLE = False
    extract_url_features = None
    FEATURE_NAMES = []
    print("Feature engine not loaded:", exc)


phishing_model = None

try:
    if PHISHING_MODEL_PATH.exists():
        phishing_model = joblib.load(PHISHING_MODEL_PATH)
        print("Random Forest model loaded.")
    else:
        print("Random Forest model not found:", PHISHING_MODEL_PATH)
except Exception as exc:
    print("Random Forest loading failed:", exc)


# ============================================================
# MODEL STATUS
# ============================================================

def xgboost_is_available():
    """Check whether the XGBoost engine and saved model are available."""
    model_path = PROJECT_ROOT / "models" / "xgboost_phishing_model.joblib"

    try:
        from core.phishing_ml_engine import is_model_available
        return bool(is_model_available()) and model_path.exists()
    except Exception:
        return model_path.exists()


def safe_status():
    status = {
        "Random Forest": phishing_model is not None,
        "XGBoost": xgboost_is_available(),
        "Heuristic Engine": False,
        "SVM": False,
    }

    if ENSEMBLE_AVAILABLE and get_ensemble_status is not None:
        try:
            result = get_ensemble_status()

            if isinstance(result, dict):
                models = result.get("models")

                if isinstance(models, list):
                    for name in models:
                        status[str(name)] = True
                else:
                    for name, value in result.items():
                        if isinstance(value, bool):
                            status[str(name)] = value

        except Exception as exc:
            print("Model status error:", exc)

    # Always reflect the actual status of these direct model files.
    status["Random Forest"] = phishing_model is not None
    status["XGBoost"] = xgboost_is_available()

    return status

# ============================================================
# RANDOM FOREST PREDICTION
# ============================================================

def predict_phishing_ml(url):
    """Return Random Forest phishing probability from 0 to 100."""

    if phishing_model is None:
        return None

    if not FEATURE_ENGINE_AVAILABLE:
        raise RuntimeError("URL feature engine is unavailable.")

    if not FEATURE_NAMES:
        raise ValueError("Model feature names are unavailable.")

    features = extract_url_features(url)

    if not isinstance(features, dict):
        raise ValueError(
            "extract_url_features() must return a dictionary."
        )

    missing = [
        name for name in FEATURE_NAMES
        if name not in features
    ]

    if missing:
        raise ValueError(
            "Missing model features: " + ", ".join(missing)
        )

    row = pd.DataFrame(
        [[features[name] for name in FEATURE_NAMES]],
        columns=FEATURE_NAMES
    )

    if not hasattr(phishing_model, "predict_proba"):
        raise RuntimeError("Random Forest does not support predict_proba().")

    probabilities = phishing_model.predict_proba(row)
    classes = list(phishing_model.classes_)

    if 1 not in classes:
        raise ValueError("Phishing class 1 was not found in the model.")

    score = float(probabilities[0][classes.index(1)]) * 100.0

    return max(0.0, min(100.0, score))


# ============================================================
# SHARED HELPERS
# ============================================================

def post(callback):
    UI_QUEUE.put(callback)


def start_ui_pump(widget):
    def pump():
        try:
            if not widget.winfo_exists():
                return
        except Exception:
            return

        while True:
            try:
                callback = UI_QUEUE.get_nowait()
            except queue.Empty:
                break

            try:
                callback()
            except Exception:
                traceback.print_exc()

        try:
            widget.after(40, pump)
        except Exception:
            pass

    pump()


def level_color(score):
    if score >= 70:
        return RED
    if score >= 40:
        return ORANGE
    return GREEN


def level_text(score):
    if score >= 70:
        return "HIGH PHISHING RISK"
    if score >= 40:
        return "SUSPICIOUS URL"
    return "LOWER MODEL RISK"


def make_card(parent):
    return ctk.CTkFrame(
        parent,
        fg_color=CARD,
        corner_radius=15,
        border_width=1,
        border_color=BORDER
    )


def make_heading(parent, title, subtitle=None):
    ctk.CTkLabel(
        parent,
        text=title,
        font=(FONT, 18, "bold"),
        text_color=TEXT
    ).pack(anchor="w", padx=20, pady=(18, 2))

    if subtitle:
        ctk.CTkLabel(
            parent,
            text=subtitle,
            font=(FONT, 12),
            text_color=MUTED
        ).pack(anchor="w", padx=20, pady=(0, 8))


def create_info_row(parent, title, value):
    row = ctk.CTkFrame(parent, fg_color="transparent")
    row.pack(fill="x", padx=15, pady=5)

    ctk.CTkLabel(
        row,
        text=title,
        width=150,
        anchor="w",
        font=(FONT, 10, "bold"),
        text_color=MUTED
    ).pack(side="left")

    label = ctk.CTkLabel(
        row,
        text=value,
        anchor="w",
        font=(FONT, 11),
        text_color=TEXT
    )
    label.pack(side="left", fill="x", expand=True)

    return label


# ============================================================
# MAIN PAGE
# ============================================================

def show_phishing_scanner(parent):
    ui = {"parent": parent, "scanning": False}

    while True:
        try:
            UI_QUEUE.get_nowait()
        except queue.Empty:
            break

    for widget in parent.winfo_children():
        widget.destroy()

    parent.configure(fg_color=BG)

    main = ctk.CTkScrollableFrame(
        parent,
        fg_color=BG,
        scrollbar_button_color=BORDER,
        scrollbar_button_hover_color=CYAN
    )
    main.pack(fill="both", expand=True, padx=18, pady=12)

    # Header
    header = ctk.CTkFrame(main, fg_color="transparent")
    header.pack(fill="x", pady=(5, 18))

    title_frame = ctk.CTkFrame(header, fg_color="transparent")
    title_frame.pack(side="left", fill="x", expand=True)

    ctk.CTkLabel(
        title_frame,
        text="PHISHING SCANNER",
        font=(FONT, 30, "bold"),
        text_color=TEXT
    ).pack(anchor="w")

    ctk.CTkLabel(
        title_frame,
        text="AI-powered malicious URL and phishing detection",
        font=(FONT, 15),
        text_color=MUTED
    ).pack(anchor="w", pady=(2, 0))

    status = safe_status()
    engine_ready = any(status.values())

    header_color = GREEN if engine_ready else ORANGE
    header_text = "MODEL AVAILABLE" if engine_ready else "NO PREDICTION MODEL"

    status_frame = ctk.CTkFrame(
        header,
        fg_color=CARD,
        corner_radius=12,
        border_width=1,
        border_color=BORDER
    )
    status_frame.pack(side="right")

    ctk.CTkLabel(
        status_frame,
        text="●",
        font=(FONT, 17),
        text_color=header_color
    ).pack(side="left", padx=(12, 5), pady=9)

    ctk.CTkLabel(
        status_frame,
        text=header_text,
        font=(FONT, 11, "bold"),
        text_color=header_color
    ).pack(side="left", padx=(0, 12))

    # URL input card
    input_card = make_card(main)
    input_card.pack(fill="x", pady=(0, 18))

    make_heading(
        input_card,
        "URL ANALYSIS",
        "Enter or paste a website URL to analyze its phishing risk."
    )

    url_row = ctk.CTkFrame(input_card, fg_color="transparent")
    url_row.pack(fill="x", padx=20, pady=18)

    url_entry = ctk.CTkEntry(
        url_row,
        height=46,
        placeholder_text="Enter a website URL",
        fg_color=CARD_2,
        border_color=BORDER,
        text_color=TEXT,
        placeholder_text_color=MUTED,
        font=(FONT, 13)
    )
    url_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
    url_entry.insert(0, "https://example.com/login")
    url_entry.icursor("end")
    ui["url_entry"] = url_entry

    scan_button = ctk.CTkButton(
        url_row,
        text="ANALYZE URL",
        width=145,
        height=46,
        fg_color=CYAN,
        hover_color=BLUE,
        text_color="#001018",
        font=(FONT, 12, "bold"),
        command=lambda: start_phishing_scan(ui)
    )
    scan_button.pack(side="right")
    ui["scan_button"] = scan_button

    ctk.CTkButton(
        url_row,
        text="CLEAR",
        width=75,
        height=46,
        fg_color=CARD_2,
        hover_color=BORDER,
        border_width=1,
        border_color=BORDER,
        text_color=TEXT,
        font=(FONT, 11, "bold"),
        command=lambda: clear_scan(ui)
    ).pack(side="right", padx=(0, 8))

    ctk.CTkButton(
        url_row,
        text="PASTE",
        width=75,
        height=46,
        fg_color=CARD_2,
        hover_color=BORDER,
        border_width=1,
        border_color=BORDER,
        text_color=TEXT,
        font=(FONT, 11, "bold"),
        command=lambda: paste_url(ui)
    ).pack(side="right", padx=(0, 8))

    info_frame = ctk.CTkFrame(
        input_card,
        fg_color=CARD_2,
        corner_radius=10
    )
    info_frame.pack(fill="x", padx=20, pady=(0, 20))

    ui["domain_label"] = create_info_row(info_frame, "DOMAIN", "-")
    ui["registered_label"] = create_info_row(
        info_frame, "REGISTERED DOMAIN", "-"
    )
    ui["protocol_label"] = create_info_row(info_frame, "PROTOCOL", "-")
    ui["length_label"] = create_info_row(info_frame, "URL LENGTH", "-")
    ui["status_label"] = create_info_row(
        info_frame, "STATUS", "Waiting for URL..."
    )

    url_entry.bind("<Return>", lambda event: start_phishing_scan(ui))

    # Progress card
    progress_card = make_card(main)
    progress_card.pack(fill="x", pady=(0, 18))

    make_heading(
        progress_card,
        "THREAT ANALYSIS",
        "Extracting URL features and running available prediction models."
    )

    ui["progress"] = ctk.CTkProgressBar(
        progress_card,
        height=12,
        corner_radius=8,
        fg_color="#10202E",
        progress_color=CYAN
    )
    ui["progress"].pack(fill="x", padx=20, pady=(14, 5))
    ui["progress"].set(0)

    ui["progress_label"] = ctk.CTkLabel(
        progress_card,
        text="0%",
        font=(FONT, 11, "bold"),
        text_color=CYAN
    )
    ui["progress_label"].pack(anchor="e", padx=20, pady=(0, 18))

    # Result card
    result_card = make_card(main)
    result_card.pack(fill="x", pady=(0, 18))

    make_heading(
        result_card,
        "PHISHING DETECTION RESULT",
        "Model output is an estimate, not proof that a website is safe."
    )

    ui["score_label"] = ctk.CTkLabel(
        result_card,
        text="--%",
        font=(FONT, 46, "bold"),
        text_color=CYAN
    )
    ui["score_label"].pack(pady=(15, 0))

    ctk.CTkLabel(
        result_card,
        text="PHISHING RISK ESTIMATE",
        font=(FONT, 11, "bold"),
        text_color=MUTED
    ).pack()

    ui["risk_bar"] = ctk.CTkProgressBar(
        result_card,
        height=10,
        corner_radius=6,
        width=420,
        fg_color="#10202E",
        progress_color=CYAN
    )
    ui["risk_bar"].pack(pady=(12, 0))
    ui["risk_bar"].set(0)

    ui["threat_label"] = ctk.CTkLabel(
        result_card,
        text="WAITING FOR ANALYSIS",
        font=(FONT, 19, "bold"),
        text_color=TEXT
    )
    ui["threat_label"].pack(pady=(12, 5))

    ui["recommendation_label"] = ctk.CTkLabel(
        result_card,
        text="Enter a URL and start the analysis.",
        font=(FONT, 12),
        text_color=MUTED,
        wraplength=900
    )
    ui["recommendation_label"].pack(pady=(0, 12))

    action_row = ctk.CTkFrame(result_card, fg_color="transparent")
    action_row.pack(pady=(0, 20))

    ctk.CTkButton(
        action_row,
        text="EXPORT REPORT",
        width=150,
        height=34,
        fg_color=CARD_2,
        hover_color=BORDER,
        border_width=1,
        border_color=BORDER,
        text_color=TEXT,
        font=(FONT, 11, "bold"),
        command=lambda: export_report(ui)
    ).pack(side="left", padx=4)

    ctk.CTkButton(
        action_row,
        text="COPY SUMMARY",
        width=150,
        height=34,
        fg_color=CARD_2,
        hover_color=BORDER,
        border_width=1,
        border_color=BORDER,
        text_color=TEXT,
        font=(FONT, 11, "bold"),
        command=lambda: copy_summary(ui)
    ).pack(side="left", padx=4)

    # Red flags
    flags_card = make_card(main)
    flags_card.pack(fill="x", pady=(0, 18))

    make_heading(
        flags_card,
        "RED FLAGS",
        "Reasons returned by the prediction engine."
    )

    ui["flags_frame"] = ctk.CTkFrame(
        flags_card,
        fg_color="transparent"
    )
    ui["flags_frame"].pack(fill="x", padx=20, pady=(8, 18))
    set_flags(ui, None)

    # Feature analysis
    feature_card = make_card(main)
    feature_card.pack(fill="x", pady=(0, 18))

    make_heading(
        feature_card,
        "URL FEATURE ANALYSIS",
        "Features extracted from the submitted URL."
    )

    ui["feature_label"] = ctk.CTkLabel(
        feature_card,
        text="No URL analyzed yet.",
        font=(MONO, 12),
        text_color=MUTED,
        justify="left",
        anchor="w",
        wraplength=1100
    )
    ui["feature_label"].pack(fill="x", padx=20, pady=18)

    # Model list
    engine_card = make_card(main)
    engine_card.pack(fill="x", pady=(0, 18))

    make_heading(
        engine_card,
        "AI DETECTION ENGINES",
        "Per-model phishing probability when available."
    )

    model_frame = ctk.CTkFrame(engine_card, fg_color="transparent")
    model_frame.pack(fill="x", padx=20, pady=(8, 18))

    ui["model_rows"] = {}

    for name in MODEL_ORDER:
        row = ctk.CTkFrame(model_frame, fg_color="transparent")
        row.pack(fill="x", pady=6)

        ctk.CTkLabel(
            row,
            text=name,
            width=150,
            anchor="w",
            font=(FONT, 12, "bold"),
            text_color=TEXT
        ).pack(side="left")

        loaded = status.get(name, False)

        value_label = ctk.CTkLabel(
            row,
            text="ready" if loaded else "not loaded",
            width=90,
            anchor="e",
            font=(FONT, 11, "bold"),
            text_color=GREEN if loaded else MUTED
        )
        value_label.pack(side="right")

        bar = ctk.CTkProgressBar(
            row,
            height=10,
            corner_radius=6,
            fg_color="#10202E",
            progress_color=CYAN
        )
        bar.pack(side="left", fill="x", expand=True, padx=10)
        bar.set(0)

        ui["model_rows"][name] = (bar, value_label)

    ctk.CTkLabel(
        main,
        text="CyberShield AI  •  AI-Powered Phishing Detection",
        font=(FONT, 11),
        text_color=MUTED
    ).pack(pady=(0, 20))

    start_ui_pump(main)


# ============================================================
# URL ACTIONS
# ============================================================

def paste_url(ui):
    try:
        value = ui["parent"].clipboard_get().strip()

        if not value:
            messagebox.showwarning(
                "Clipboard Empty",
                "No URL found in clipboard."
            )
            return

        ui["url_entry"].delete(0, "end")
        ui["url_entry"].insert(0, value)
        ui["url_entry"].icursor("end")

    except Exception as exc:
        messagebox.showwarning("Paste Failed", str(exc))


def clear_scan(ui):
    if ui.get("scanning"):
        return

    ui["url_entry"].delete(0, "end")

    for key in (
        "domain_label",
        "registered_label",
        "protocol_label",
        "length_label"
    ):
        ui[key].configure(text="-", text_color=TEXT)

    ui["status_label"].configure(
        text="Waiting for URL...",
        text_color=TEXT
    )

    ui["progress"].set(0)
    ui["progress_label"].configure(text="0%")
    ui["score_label"].configure(text="--%", text_color=CYAN)
    ui["risk_bar"].set(0)
    ui["risk_bar"].configure(progress_color=CYAN)

    ui["threat_label"].configure(
        text="WAITING FOR ANALYSIS",
        text_color=TEXT
    )

    ui["recommendation_label"].configure(
        text="Enter a URL and start the analysis.",
        text_color=MUTED
    )

    ui["feature_label"].configure(
        text="No URL analyzed yet.",
        text_color=MUTED
    )

    reset_model_rows(ui)
    set_flags(ui, None)

    STATE["url"] = ""
    STATE["result"] = None


def reset_model_rows(ui):
    status = safe_status()

    for name, (bar, value_label) in ui["model_rows"].items():
        loaded = status.get(name, False)

        bar.set(0)
        bar.configure(progress_color=CYAN)

        value_label.configure(
            text="ready" if loaded else "not loaded",
            text_color=GREEN if loaded else MUTED
        )


# ============================================================
# URL VALIDATION AND INFORMATION
# ============================================================

def normalize_url(value):
    value = value.strip()

    if value and "://" not in value:
        value = "https://" + value

    return value


def is_valid_url(url):
    try:
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False

        if not parsed.hostname:
            return False

        if any(char.isspace() for char in url):
            return False

        try:
            parsed.port
        except ValueError:
            return False

        hostname = parsed.hostname.rstrip(".")

        if not hostname:
            return False

        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            pass

        if "." not in hostname:
            return False

        labels = hostname.split(".")

        if any(not label for label in labels):
            return False

        for label in labels:
            if len(label) > 63:
                return False

            if label.startswith("-") or label.endswith("-"):
                return False

            if not re.fullmatch(r"[A-Za-z0-9-]+", label):
                return False

        return True

    except Exception:
        return False


def get_registered_domain(hostname):
    """
    Simple display helper, not a Public Suffix List implementation.
    Avoid claiming this is always the registrable domain.
    """
    if not hostname:
        return "-"

    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass

    parts = hostname.rstrip(".").split(".")

    if len(parts) >= 2:
        return ".".join(parts[-2:])

    return hostname


def update_url_information(ui, url):
    parsed = urlparse(url)
    hostname = parsed.hostname or "-"

    ui["domain_label"].configure(text=hostname)

    ui["registered_label"].configure(
        text=get_registered_domain(hostname)
    )

    ui["protocol_label"].configure(
        text=parsed.scheme.upper(),
        text_color=GREEN if parsed.scheme == "https" else ORANGE
    )

    ui["length_label"].configure(text=f"{len(url)} characters")


# ============================================================
# FEATURE EXTRACTION AND FORMATTING
# ============================================================

def extract_features(url):
    if FEATURE_ENGINE_AVAILABLE:
        try:
            result = extract_url_features(url)

            if isinstance(result, dict):
                return result

            if hasattr(result, "iloc"):
                return result.iloc[0].to_dict()

            if hasattr(result, "to_dict"):
                converted = result.to_dict()

                if isinstance(converted, dict):
                    if converted and all(
                        isinstance(value, dict)
                        for value in converted.values()
                    ):
                        return {
                            key: value.get(0)
                            for key, value in converted.items()
                        }

                    return converted

        except Exception as exc:
            print("Feature extraction failed:", exc)

    parsed = urlparse(url)

    try:
        port = parsed.port
    except ValueError:
        port = None

    hostname = parsed.hostname or ""
    low = url.lower()

    try:
        ipaddress.ip_address(hostname)
        uses_ip = 1
    except ValueError:
        uses_ip = 0

    return {
        "url_length": len(url),
        "domain_length": len(parsed.netloc),
        "path_length": len(parsed.path),
        "dot_count": url.count("."),
        "slash_count": url.count("/"),
        "hyphen_count": url.count("-"),
        "underscore_count": url.count("_"),
        "at_count": url.count("@"),
        "question_count": url.count("?"),
        "equal_count": url.count("="),
        "ampersand_count": url.count("&"),
        "percent_count": url.count("%"),
        "digit_count": sum(char.isdigit() for char in url),
        "letter_count": sum(char.isalpha() for char in url),
        "subdomain_count": max(0, len(hostname.split(".")) - 2),
        "uses_https": int(parsed.scheme == "https"),
        "uses_ip": uses_ip,
        "has_port": int(port is not None and port not in (80, 443)),
        "has_punycode": int("xn--" in low),
        "has_fragment": int(bool(parsed.fragment)),
        "has_query": int(bool(parsed.query)),
        "has_login_keyword": int("login" in low),
        "has_verify_keyword": int("verify" in low),
        "has_account_keyword": int("account" in low),
        "has_security_keyword": int("security" in low),
        "has_password_keyword": int("password" in low),
        "has_bank_keyword": int("bank" in low),
        "_registered_domain": get_registered_domain(hostname)
    }


def format_features(features):
    if not features:
        return "No URL features available."

    priority = [
        "url_length", "domain_length", "path_length",
        "dot_count", "slash_count", "hyphen_count",
        "underscore_count", "at_count", "question_count",
        "equal_count", "ampersand_count", "percent_count",
        "digit_count", "letter_count", "subdomain_count",
        "uses_https", "uses_ip", "has_port",
        "has_punycode", "has_fragment", "has_query",
        "has_login_keyword", "has_verify_keyword",
        "has_account_keyword", "has_security_keyword",
        "has_password_keyword", "has_bank_keyword"
    ]

    keys = [key for key in priority if key in features]

    keys += [
        key for key in features
        if key not in keys and not str(key).startswith("_")
    ]

    cells = [
        f"{key.replace('_', ' ').upper():<26}: {str(features[key]):<8}"
        for key in keys
    ]

    lines = []

    for index in range(0, len(cells), 2):
        right = cells[index + 1] if index + 1 < len(cells) else ""
        lines.append(f"{cells[index]}   {right}".rstrip())

    return "\n".join(lines)


# ============================================================
# PREDICTION
# ============================================================

def run_phishing_prediction(url):
    features = extract_features(url)
    model_scores = {}
    reasons = []
    errors = []

    xgb_score = None
    rf_score = None
    ensemble_score = None

    # --------------------------------------------------------
    # XGBoost
    # --------------------------------------------------------
    try:
        xgb_result = predict_xgboost_phishing(url)

        if isinstance(xgb_result, dict):
            raw_score = xgb_result.get("risk_score")

            if raw_score is not None:
                xgb_score = max(
                    0.0,
                    min(100.0, float(raw_score))
                )
                model_scores["XGBoost"] = xgb_score

                prediction = str(
                    xgb_result.get("prediction", "UNKNOWN")
                ).upper()

                reasons.append(
                    f"XGBoost prediction: {prediction}; "
                    f"risk estimate: {xgb_score:.1f}%."
                )

            else:
                errors.append("XGBoost returned no risk score.")

        else:
            errors.append("XGBoost returned an unexpected result.")

    except Exception as exc:
        errors.append(f"XGBoost: {exc}")
        print("XGBoost prediction failed:", exc)

    # --------------------------------------------------------
    # Random Forest
    # --------------------------------------------------------
    try:
        rf_score = predict_phishing_ml(url)

        if rf_score is not None:
            rf_score = max(0.0, min(100.0, float(rf_score)))
            model_scores["Random Forest"] = rf_score

            reasons.append(
                f"Random Forest risk estimate: {rf_score:.1f}%."
            )

    except Exception as exc:
        errors.append(f"Random Forest: {exc}")
        print("Random Forest prediction failed:", exc)

    # --------------------------------------------------------
    # Optional ensemble engine
    # --------------------------------------------------------
    if ENSEMBLE_AVAILABLE and predict_phishing_ensemble is not None:
        try:
            ensemble_result = predict_phishing_ensemble(url)

            if (
                isinstance(ensemble_result, dict)
                and ensemble_result.get("success", True) is not False
            ):
                raw_score = ensemble_result.get(
                    "risk_score",
                    ensemble_result.get(
                        "score",
                        ensemble_result.get("phishing_score")
                    )
                )

                if raw_score is not None:
                    ensemble_score = max(
                        0.0,
                        min(100.0, float(raw_score))
                    )

                ensemble_models = ensemble_result.get("model_scores", {})

                if isinstance(ensemble_models, dict):
                    for name, value in ensemble_models.items():
                        try:
                            value = max(
                                0.0,
                                min(100.0, float(value))
                            )
                            model_scores.setdefault(str(name), value)
                        except (TypeError, ValueError):
                            continue

                ensemble_reasons = ensemble_result.get("reasons", [])

                if isinstance(ensemble_reasons, list):
                    reasons.extend(str(item) for item in ensemble_reasons)

        except Exception as exc:
            errors.append(f"Ensemble: {exc}")
            print("Ensemble prediction failed:", exc)

    # --------------------------------------------------------
    # Final risk estimate
    # --------------------------------------------------------
    if ensemble_score is not None:
        score = ensemble_score

    else:
        available_scores = [
            value for value in (xgb_score, rf_score)
            if value is not None
        ]

        if not available_scores:
            message = (
                "No usable phishing prediction model could analyze this URL."
            )

            if errors:
                message += " Details: " + " | ".join(errors)

            raise RuntimeError(message)

        # Average the available direct model scores.
        score = sum(available_scores) / len(available_scores)

    if score >= 70:
        recommendation = (
            "High phishing risk estimate. Avoid entering credentials "
            "or payment details until the website is independently verified."
        )
    elif score >= 40:
        recommendation = (
            "Suspicious URL risk estimate. Verify the domain through "
            "a trusted source before entering sensitive information."
        )
    else:
        recommendation = (
            "The available model or models assigned a lower phishing "
            "risk estimate. This does not guarantee that the website is safe."
        )

    if not reasons:
        reasons.append(
            f"Final phishing risk estimate: {score:.1f}%."
        )

    return {
        "score": max(0.0, min(100.0, score)),
        "recommendation": recommendation,
        "model_scores": model_scores,
        "reasons": reasons,
        "features": features,
        "demo": False
    }


# ============================================================
# START SCAN
# ============================================================

def start_phishing_scan(ui):
    if ui.get("scanning"):
        return

    raw_url = ui["url_entry"].get()
    url = normalize_url(raw_url)

    if not url:
        messagebox.showwarning(
            "URL Required",
            "Please enter a website URL."
        )
        return

    if not is_valid_url(url):
        messagebox.showwarning(
            "Invalid URL",
            "Please enter a valid URL.\n\nExample:\nhttps://example.com"
        )
        return

    try:
        update_url_information(ui, url)
    except Exception as exc:
        messagebox.showerror("URL Error", str(exc))
        return

    STATE["url"] = url
    STATE["result"] = None

    ui["progress"].set(0)
    ui["progress_label"].configure(text="0%")

    ui["status_label"].configure(
        text="Initializing phishing analysis...",
        text_color=CYAN
    )

    ui["score_label"].configure(text="--%", text_color=CYAN)
    ui["risk_bar"].set(0)
    ui["risk_bar"].configure(progress_color=CYAN)

    ui["threat_label"].configure(
        text="ANALYZING...",
        text_color=CYAN
    )

    ui["recommendation_label"].configure(
        text="Extracting URL features and running prediction models...",
        text_color=MUTED
    )

    reset_model_rows(ui)
    set_flags(ui, None)

    ui["scan_button"].configure(
        state="disabled",
        text="ANALYZING..."
    )

    ui["scanning"] = True

    threading.Thread(
        target=perform_phishing_scan,
        args=(url, ui),
        daemon=True
    ).start()


def perform_phishing_scan(url, ui):
    try:
        post(lambda: set_stage(
            ui, 15, "Validating URL structure...", CYAN
        ))

        features = extract_features(url)

        post(lambda: set_stage(
            ui, 45, "Running available prediction models...", CYAN
        ))

        result = run_phishing_prediction(url)

        if not result.get("features"):
            result["features"] = features

        post(lambda: set_stage(
            ui, 85, "Preparing analysis result...", PURPLE
        ))

        post(lambda: display_phishing_result(ui, url, result))

    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        traceback.print_exc()

        post(lambda error=error: phishing_scan_error(ui, error))


# ============================================================
# PROGRESS AND RESULTS
# ============================================================

def set_stage(ui, value, text, color):
    try:
        if not ui["parent"].winfo_exists():
            return

        ui["progress"].set(value / 100)
        ui["progress_label"].configure(text=f"{value}%")
        ui["status_label"].configure(text=text, text_color=color)

    except Exception:
        pass


def display_phishing_result(ui, url, result):
    ui["scanning"] = False

    try:
        score = max(
            0.0,
            min(100.0, float(result["score"]))
        )

        color = level_color(score)

        STATE["url"] = url
        STATE["result"] = result

        # Save completed phishing scan to SQLite
        try:
            if score >= 70:
                scan_risk = "HIGH"
                scan_result = "Phishing Detected"
            elif score >= 40:
                scan_risk = "MEDIUM"
                scan_result = "Suspicious URL"
            else:
                scan_risk = "LOW"
                scan_result = "Lower Model Risk"

            save_scan(
                scan_type="Phishing",
                target=url,
                result=scan_result,
                risk=scan_risk,
                score=score
            )

            print(f"Phishing scan saved: {url}")

        except Exception as exc:
            print(f"Unable to save phishing scan history: {exc}")
        
        ui["progress"].set(1)
        ui["progress_label"].configure(text="100%")

        ui["score_label"].configure(
            text=f"{score:.1f}%",
            text_color=color
        )

        ui["risk_bar"].set(score / 100)
        ui["risk_bar"].configure(progress_color=color)

        ui["threat_label"].configure(
            text=level_text(score),
            text_color=color
        )

        ui["recommendation_label"].configure(
            text=result.get("recommendation", ""),
            text_color=TEXT
        )

        ui["status_label"].configure(
            text="Analysis completed. Treat the score as an estimate.",
            text_color=GREEN
        )

        features = result.get("features", {})

        if not isinstance(features, dict):
            features = {}

        ui["registered_label"].configure(
            text=features.get("_registered_domain")
            or get_registered_domain(urlparse(url).hostname or "")
        )

        ui["feature_label"].configure(
            text=format_features(features),
            text_color=TEXT
        )

        scores = result.get("model_scores", {})

        for name, (bar, value_label) in ui["model_rows"].items():
            if name in scores:
                value = max(
                    0.0,
                    min(100.0, float(scores[name]))
                )

                model_color = level_color(value)

                bar.set(value / 100)
                bar.configure(progress_color=model_color)

                value_label.configure(
                    text=f"{value:.1f}%",
                    text_color=model_color
                )

            else:
                bar.set(0)
                value_label.configure(
                    text="not used",
                    text_color=MUTED
                )

        set_flags(ui, result.get("reasons", []))

    except Exception as exc:
        traceback.print_exc()

        ui["status_label"].configure(
            text=f"Unable to display result: {exc}",
            text_color=RED
        )

        ui["threat_label"].configure(
            text="RESULT DISPLAY ERROR",
            text_color=RED
        )

    finally:
        ui["scan_button"].configure(
            state="normal",
            text="ANALYZE URL"
        )


def phishing_scan_error(ui, error):
    ui["scanning"] = False
    STATE["result"] = None

    ui["progress"].set(0)
    ui["progress_label"].configure(text="0%")

    ui["status_label"].configure(
        text="Scan failed. Check the model and feature engine.",
        text_color=RED
    )

    ui["threat_label"].configure(
        text="SCAN FAILED - NO VALID PREDICTION",
        text_color=RED
    )

    ui["score_label"].configure(
        text="N/A",
        text_color=RED
    )

    ui["risk_bar"].set(0)
    ui["risk_bar"].configure(progress_color=RED)

    ui["recommendation_label"].configure(
        text=(
            "No valid prediction was produced. This does not mean the "
            "URL is safe. Check the terminal error and model files."
        ),
        text_color=TEXT
    )

    for bar, value_label in ui["model_rows"].values():
        bar.set(0)
        bar.configure(progress_color=CYAN)
        value_label.configure(
            text="prediction failed",
            text_color=RED
        )

    set_flags(
        ui,
        ["Prediction failed. Check the terminal for details."]
    )

    ui["scan_button"].configure(
        state="normal",
        text="ANALYZE URL"
    )

    print("Phishing scan failed:", error)


# ============================================================
# RED FLAGS
# ============================================================

def set_flags(ui, reasons):
    frame = ui["flags_frame"]

    for widget in frame.winfo_children():
        widget.destroy()

    if reasons is None:
        text = "No URL analyzed yet."
        color = MUTED
    elif not reasons:
        text = "No red flags were returned by the model."
        color = GREEN
    else:
        text = None
        color = TEXT

    if text:
        ctk.CTkLabel(
            frame,
            text=text,
            font=(FONT, 12),
            text_color=color
        ).pack(anchor="w")
        return

    for reason in reasons:
        row = ctk.CTkFrame(
            frame,
            fg_color=CARD_2,
            corner_radius=8
        )
        row.pack(fill="x", pady=3)

        ctk.CTkLabel(
            row,
            text="⚑",
            font=(FONT, 14),
            text_color=ORANGE
        ).pack(side="left", padx=(12, 6), pady=7)

        ctk.CTkLabel(
            row,
            text=str(reason),
            anchor="w",
            justify="left",
            font=(FONT, 12),
            text_color=TEXT,
            wraplength=1000
        ).pack(side="left", fill="x", expand=True, padx=(0, 12))


# ============================================================
# REPORTS
# ============================================================

def summary_text():
    result = STATE.get("result")

    if not isinstance(result, dict):
        return "No completed phishing scan is available."

    score = float(result["score"])

    lines = [
        "CyberShield AI - Phishing Report",
        f"URL     : {STATE.get('url', '')}",
        f"Time    : {datetime.now():%Y-%m-%d %H:%M:%S}",
        f"Score   : {score:.1f}%",
        f"Verdict : {level_text(score)}",
        "Models  : " + (
            ", ".join(
                f"{key} {float(value):.1f}%"
                for key, value in result.get("model_scores", {}).items()
            ) or "n/a"
        ),
        "Red flags:"
    ]

    reasons = result.get("reasons", [])

    if reasons:
        lines.extend(f"  - {reason}" for reason in reasons)
    else:
        lines.append("  none")

    lines.extend([
        "",
        "Disclaimer: A model score is an estimate, not a guarantee of safety."
    ])

    return "\n".join(lines)


def copy_summary(ui):
    if not STATE.get("result"):
        messagebox.showinfo("Nothing to copy", "Run a scan first.")
        return

    try:
        ui["parent"].clipboard_clear()
        ui["parent"].clipboard_append(summary_text())

        ui["status_label"].configure(
            text="Summary copied to clipboard.",
            text_color=GREEN
        )

    except Exception as exc:
        messagebox.showerror("Copy Failed", str(exc))


def export_report(ui):
    if not STATE.get("result"):
        messagebox.showinfo("Nothing to export", "Run a scan first.")
        return

    path = filedialog.asksaveasfilename(
        defaultextension=".json",
        filetypes=[
            ("JSON report", "*.json"),
            ("Text report", "*.txt")
        ],
        initialfile="phishing_report"
    )

    if not path:
        return

    result = STATE["result"]

    try:
        if path.lower().endswith(".txt"):
            data = summary_text()

        else:
            features = result.get("features", {})

            data = json.dumps(
                {
                    "url": STATE["url"],
                    "time": datetime.now().isoformat(timespec="seconds"),
                    "risk_score_estimate": result["score"],
                    "verdict": level_text(result["score"]),
                    "model_scores": result.get("model_scores", {}),
                    "reasons": result.get("reasons", []),
                    "features": {
                        key: value
                        for key, value in features.items()
                        if not str(key).startswith("_")
                    },
                    "disclaimer": (
                        "A model score is an estimate, not a guarantee of safety."
                    )
                },
                indent=2,
                default=str
            )

        with open(path, "w", encoding="utf-8") as file:
            file.write(data)

        ui["status_label"].configure(
            text=f"Report saved: {path}",
            text_color=GREEN
        )

        messagebox.showinfo(
            "Report Saved",
            f"Report saved successfully:\n{path}"
        )

    except Exception as exc:
        messagebox.showerror("Export Failed", str(exc))


# ============================================================
# TEST MODE
# ============================================================

if __name__ == "__main__":
    app = ctk.CTk()
    app.title("CyberShield AI - Phishing Scanner")
    app.geometry("1450x900")
    app.configure(fg_color=BG)

    show_phishing_scanner(app)
    app.mainloop()