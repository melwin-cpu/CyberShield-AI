import customtkinter as ctk
from tkinter import messagebox, filedialog
import threading
import queue
import traceback
import json
import re
import time
from datetime import datetime
from urllib.parse import urlparse

# ============================================================
# CYBERSHIELD AI - PHISHING SCANNER
# ============================================================

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

# Thread -> UI messages (widgets are only touched from the main thread)
UI_QUEUE = queue.Queue()

# Last result (used by export / copy)
STATE = {
    "url": "",
    "result": None
}


# ============================================================
# AI ENSEMBLE
# ============================================================

try:

    from core.phishing_ensemble_engine import (
        predict_phishing_ensemble,
        get_ensemble_status
    )

    ENSEMBLE_AVAILABLE = True

except Exception as e:

    ENSEMBLE_AVAILABLE = False

    print("Phishing ensemble engine not loaded:", e)


# ============================================================
# URL FEATURE ENGINE
# ============================================================

try:

    from core.phishing_engine import extract_url_features

    FEATURE_ENGINE_AVAILABLE = True

except Exception as e:

    FEATURE_ENGINE_AVAILABLE = False

    print("Phishing feature engine not loaded:", e)


# ============================================================
# SMALL HELPERS
# ============================================================

def post(fn):
    """Queue a function to run on the UI thread."""
    UI_QUEUE.put(fn)


def start_ui_pump(widget):
    """Runs queued UI functions every 40 ms on the main thread."""

    def pump():

        try:

            if not widget.winfo_exists():
                return

        except Exception:
            return

        while True:

            try:
                fn = UI_QUEUE.get_nowait()
            except queue.Empty:
                break

            try:
                fn()
            except Exception:
                traceback.print_exc()

        try:
            widget.after(40, pump)
        except Exception:
            pass

    pump()


def safe_status():

    if not ENSEMBLE_AVAILABLE:
        return {}

    try:

        status = get_ensemble_status()

        if isinstance(status, dict):
            return {k: bool(v) for k, v in status.items()}

    except Exception:
        pass

    return {}


def level_color(score):

    if score >= 70:
        return RED

    if score >= 40:
        return ORANGE

    return GREEN


def level_text(score):

    if score >= 70:
        return "🚨 PHISHING DETECTED"

    if score >= 40:
        return "⚠ SUSPICIOUS URL"

    return "✓ LOW RISK - LEGITIMATE"


# ============================================================
# MAIN PAGE
# ============================================================

def show_phishing_scanner(parent):

    # All widgets that need updating later live in this dict
    ui = {}

    # drop callbacks left over from a scan on a previous (destroyed) page
    while not UI_QUEUE.empty():
        try:
            UI_QUEUE.get_nowait()
        except queue.Empty:
            break

    # Clear old page
    for widget in parent.winfo_children():
        widget.destroy()

    parent.configure(
        fg_color=BG
    )

    ui["parent"] = parent

    # ========================================================
    # MAIN SCROLL AREA
    # ========================================================

    main = ctk.CTkScrollableFrame(
        parent,
        fg_color=BG,
        scrollbar_button_color=BORDER,
        scrollbar_button_hover_color=CYAN
    )

    main.pack(
        fill="both",
        expand=True,
        padx=18,
        pady=12
    )

    # ========================================================
    # HEADER
    # ========================================================

    header = ctk.CTkFrame(
        main,
        fg_color="transparent"
    )

    header.pack(
        fill="x",
        pady=(5, 18)
    )

    title_frame = ctk.CTkFrame(
        header,
        fg_color="transparent"
    )

    title_frame.pack(
        side="left",
        fill="x",
        expand=True
    )

    ctk.CTkLabel(
        title_frame,
        text="PHISHING SCANNER",
        font=(FONT, 30, "bold"),
        text_color=TEXT
    ).pack(
        anchor="w"
    )

    ctk.CTkLabel(
        title_frame,
        text="AI-powered malicious URL and phishing detection",
        font=(FONT, 15),
        text_color=MUTED
    ).pack(
        anchor="w",
        pady=(2, 0)
    )

    # Status (real: shows demo mode if the engine is missing)
    status_frame = ctk.CTkFrame(
        header,
        fg_color=CARD,
        corner_radius=12,
        border_width=1,
        border_color=BORDER
    )

    status_frame.pack(
        side="right"
    )

    header_color = GREEN if ENSEMBLE_AVAILABLE else ORANGE

    header_text = (
        "URL SCANNER READY"
        if ENSEMBLE_AVAILABLE
        else "DEMO MODE - ENGINE NOT FOUND"
    )

    ctk.CTkLabel(
        status_frame,
        text="●",
        font=(FONT, 17),
        text_color=header_color
    ).pack(
        side="left",
        padx=(12, 5),
        pady=9
    )

    ctk.CTkLabel(
        status_frame,
        text=header_text,
        font=(FONT, 11, "bold"),
        text_color=header_color
    ).pack(
        side="left",
        padx=(0, 12)
    )

    # ========================================================
    # URL INPUT CARD
    # ========================================================

    input_card = ctk.CTkFrame(
        main,
        fg_color=CARD,
        corner_radius=15,
        border_width=1,
        border_color=BORDER
    )

    input_card.pack(
        fill="x",
        pady=(0, 18)
    )

    ctk.CTkLabel(
        input_card,
        text="URL ANALYSIS",
        font=(FONT, 18, "bold"),
        text_color=TEXT
    ).pack(
        anchor="w",
        padx=20,
        pady=(18, 2)
    )

    ctk.CTkLabel(
        input_card,
        text="Enter a website URL to analyze its phishing risk",
        font=(FONT, 12),
        text_color=MUTED
    ).pack(
        anchor="w",
        padx=20
    )

    # URL entry
    url_row = ctk.CTkFrame(
        input_card,
        fg_color="transparent"
    )

    url_row.pack(
        fill="x",
        padx=20,
        pady=18
    )

    url_entry = ctk.CTkEntry(
        url_row,
        height=46,
        placeholder_text="https://example.com/login",
        fg_color=CARD_2,
        border_color=BORDER,
        text_color=TEXT,
        placeholder_text_color=MUTED,
        font=(FONT, 13)
    )

    url_entry.pack(
        side="left",
        fill="x",
        expand=True,
        padx=(0, 10)
    )

    # Enter key starts the scan
    url_entry.bind(
        "<Return>",
        lambda event: start_phishing_scan(ui)
    )

    ui["url_entry"] = url_entry

    scan_button = ctk.CTkButton(
        url_row,
        text="🔍  ANALYZE URL",
        width=170,
        height=46,
        fg_color=CYAN,
        hover_color=BLUE,
        text_color="#001018",
        font=(FONT, 12, "bold"),
        command=lambda: start_phishing_scan(ui)
    )

    scan_button.pack(
        side="right"
    )

    ui["scan_button"] = scan_button

    clear_button = ctk.CTkButton(
        url_row,
        text="✕ CLEAR",
        width=90,
        height=46,
        fg_color=CARD_2,
        hover_color=BORDER,
        border_width=1,
        border_color=BORDER,
        text_color=TEXT,
        font=(FONT, 12, "bold"),
        command=lambda: clear_scan(ui)
    )

    clear_button.pack(
        side="right",
        padx=(0, 8)
    )

    paste_button = ctk.CTkButton(
        url_row,
        text="📋 PASTE",
        width=90,
        height=46,
        fg_color=CARD_2,
        hover_color=BORDER,
        border_width=1,
        border_color=BORDER,
        text_color=TEXT,
        font=(FONT, 12, "bold"),
        command=lambda: paste_url(ui)
    )

    paste_button.pack(
        side="right",
        padx=(0, 8)
    )

    # ========================================================
    # URL INFORMATION
    # ========================================================

    info_frame = ctk.CTkFrame(
        input_card,
        fg_color=CARD_2,
        corner_radius=10
    )

    info_frame.pack(
        fill="x",
        padx=20,
        pady=(0, 20)
    )

    ui["domain_label"] = create_info_row(
        info_frame,
        "DOMAIN",
        "-"
    )

    ui["registered_label"] = create_info_row(
        info_frame,
        "REGISTERED DOMAIN",
        "-"
    )

    ui["protocol_label"] = create_info_row(
        info_frame,
        "PROTOCOL",
        "-"
    )

    ui["length_label"] = create_info_row(
        info_frame,
        "URL LENGTH",
        "-"
    )

    ui["status_label"] = create_info_row(
        info_frame,
        "STATUS",
        "Waiting for URL..."
    )

    # ========================================================
    # SCAN PROGRESS
    # ========================================================

    progress_card = ctk.CTkFrame(
        main,
        fg_color=CARD,
        corner_radius=15,
        border_width=1,
        border_color=BORDER
    )

    progress_card.pack(
        fill="x",
        pady=(0, 18)
    )

    ctk.CTkLabel(
        progress_card,
        text="THREAT ANALYSIS",
        font=(FONT, 18, "bold"),
        text_color=TEXT
    ).pack(
        anchor="w",
        padx=20,
        pady=(18, 2)
    )

    ctk.CTkLabel(
        progress_card,
        text="Extracting URL features and running AI detection models",
        font=(FONT, 12),
        text_color=MUTED
    ).pack(
        anchor="w",
        padx=20
    )

    progress = ctk.CTkProgressBar(
        progress_card,
        height=12,
        corner_radius=8,
        fg_color="#10202E",
        progress_color=CYAN
    )

    progress.pack(
        fill="x",
        padx=20,
        pady=(20, 5)
    )

    progress.set(0)

    ui["progress"] = progress

    progress_label = ctk.CTkLabel(
        progress_card,
        text="0%",
        font=(FONT, 11, "bold"),
        text_color=CYAN
    )

    progress_label.pack(
        anchor="e",
        padx=20,
        pady=(0, 18)
    )

    ui["progress_label"] = progress_label

    # ========================================================
    # RESULT CARD
    # ========================================================

    result_card = ctk.CTkFrame(
        main,
        fg_color=CARD,
        corner_radius=15,
        border_width=1,
        border_color=BORDER
    )

    result_card.pack(
        fill="x",
        pady=(0, 18)
    )

    ctk.CTkLabel(
        result_card,
        text="PHISHING DETECTION RESULT",
        font=(FONT, 18, "bold"),
        text_color=TEXT
    ).pack(
        anchor="w",
        padx=20,
        pady=(18, 2)
    )

    ctk.CTkLabel(
        result_card,
        text="Unified AI URL analysis",
        font=(FONT, 12),
        text_color=MUTED
    ).pack(
        anchor="w",
        padx=20
    )

    # Risk score
    score_label = ctk.CTkLabel(
        result_card,
        text="--%",
        font=(FONT, 46, "bold"),
        text_color=CYAN
    )

    score_label.pack(
        pady=(20, 0)
    )

    ui["score_label"] = score_label

    ctk.CTkLabel(
        result_card,
        text="PHISHING RISK SCORE",
        font=(FONT, 11, "bold"),
        text_color=MUTED
    ).pack()

    # Risk meter (colour follows the score)
    risk_bar = ctk.CTkProgressBar(
        result_card,
        height=10,
        corner_radius=6,
        width=420,
        fg_color="#10202E",
        progress_color=CYAN
    )

    risk_bar.pack(
        pady=(12, 0)
    )

    risk_bar.set(0)

    ui["risk_bar"] = risk_bar

    # Threat
    threat_label = ctk.CTkLabel(
        result_card,
        text="WAITING FOR ANALYSIS",
        font=(FONT, 19, "bold"),
        text_color=TEXT
    )

    threat_label.pack(
        pady=(12, 5)
    )

    ui["threat_label"] = threat_label

    # Recommendation
    recommendation_label = ctk.CTkLabel(
        result_card,
        text="Enter a URL and start the analysis.",
        font=(FONT, 12),
        text_color=MUTED,
        wraplength=900
    )

    recommendation_label.pack(
        pady=(0, 12)
    )

    ui["recommendation_label"] = recommendation_label

    # Export / copy
    action_row = ctk.CTkFrame(
        result_card,
        fg_color="transparent"
    )

    action_row.pack(
        pady=(0, 20)
    )

    ctk.CTkButton(
        action_row,
        text="💾 EXPORT REPORT",
        width=150,
        height=34,
        fg_color=CARD_2,
        hover_color=BORDER,
        border_width=1,
        border_color=BORDER,
        text_color=TEXT,
        font=(FONT, 11, "bold"),
        command=lambda: export_report(ui)
    ).pack(
        side="left",
        padx=4
    )

    ctk.CTkButton(
        action_row,
        text="📄 COPY SUMMARY",
        width=150,
        height=34,
        fg_color=CARD_2,
        hover_color=BORDER,
        border_width=1,
        border_color=BORDER,
        text_color=TEXT,
        font=(FONT, 11, "bold"),
        command=lambda: copy_summary(ui)
    ).pack(
        side="left",
        padx=4
    )

    # ========================================================
    # RED FLAGS
    # ========================================================

    flags_card = ctk.CTkFrame(
        main,
        fg_color=CARD,
        corner_radius=15,
        border_width=1,
        border_color=BORDER
    )

    flags_card.pack(
        fill="x",
        pady=(0, 18)
    )

    ctk.CTkLabel(
        flags_card,
        text="RED FLAGS",
        font=(FONT, 18, "bold"),
        text_color=TEXT
    ).pack(
        anchor="w",
        padx=20,
        pady=(18, 2)
    )

    ctk.CTkLabel(
        flags_card,
        text="Why this URL received its score",
        font=(FONT, 12),
        text_color=MUTED
    ).pack(
        anchor="w",
        padx=20
    )

    flags_frame = ctk.CTkFrame(
        flags_card,
        fg_color="transparent"
    )

    flags_frame.pack(
        fill="x",
        padx=20,
        pady=(12, 18)
    )

    ui["flags_frame"] = flags_frame

    set_flags(ui, None)

    # ========================================================
    # URL FEATURES
    # ========================================================

    feature_card = ctk.CTkFrame(
        main,
        fg_color=CARD,
        corner_radius=15,
        border_width=1,
        border_color=BORDER
    )

    feature_card.pack(
        fill="x",
        pady=(0, 18)
    )

    ctk.CTkLabel(
        feature_card,
        text="URL FEATURE ANALYSIS",
        font=(FONT, 18, "bold"),
        text_color=TEXT
    ).pack(
        anchor="w",
        padx=20,
        pady=(18, 2)
    )

    ctk.CTkLabel(
        feature_card,
        text="Features extracted from the submitted URL",
        font=(FONT, 12),
        text_color=MUTED
    ).pack(
        anchor="w",
        padx=20
    )

    feature_label = ctk.CTkLabel(
        feature_card,
        text="No URL analyzed yet.",
        font=(MONO, 12),
        text_color=MUTED,
        justify="left",
        anchor="w",
        wraplength=1100
    )

    feature_label.pack(
        fill="x",
        padx=20,
        pady=18
    )

    ui["feature_label"] = feature_label

    # ========================================================
    # AI MODELS
    # ========================================================

    engine_card = ctk.CTkFrame(
        main,
        fg_color=CARD,
        corner_radius=15,
        border_width=1,
        border_color=BORDER
    )

    engine_card.pack(
        fill="x",
        pady=(0, 18)
    )

    ctk.CTkLabel(
        engine_card,
        text="AI DETECTION ENGINES",
        font=(FONT, 18, "bold"),
        text_color=TEXT
    ).pack(
        anchor="w",
        padx=20,
        pady=(18, 2)
    )

    ctk.CTkLabel(
        engine_card,
        text="Per-model phishing probability (only loaded models are used)",
        font=(FONT, 12),
        text_color=MUTED
    ).pack(
        anchor="w",
        padx=20
    )

    model_frame = ctk.CTkFrame(
        engine_card,
        fg_color="transparent"
    )

    model_frame.pack(
        fill="x",
        padx=20,
        pady=(14, 18)
    )

    ui["model_rows"] = {}

    status = safe_status()

    for name in MODEL_ORDER:

        row = ctk.CTkFrame(
            model_frame,
            fg_color="transparent"
        )

        row.pack(
            fill="x",
            pady=6
        )

        ctk.CTkLabel(
            row,
            text=name,
            width=150,
            anchor="w",
            font=(FONT, 12, "bold"),
            text_color=TEXT
        ).pack(
            side="left"
        )

        loaded = status.get(name, False)

        value_label = ctk.CTkLabel(
            row,
            text="ready" if loaded else "not loaded",
            width=90,
            anchor="e",
            font=(FONT, 11, "bold"),
            text_color=GREEN if loaded else MUTED
        )

        value_label.pack(
            side="right"
        )

        bar = ctk.CTkProgressBar(
            row,
            height=10,
            corner_radius=6,
            fg_color="#10202E",
            progress_color=CYAN
        )

        bar.pack(
            side="left",
            fill="x",
            expand=True,
            padx=10
        )

        bar.set(0)

        ui["model_rows"][name] = (bar, value_label)

    # ========================================================
    # FOOTER
    # ========================================================

    ctk.CTkLabel(
        main,
        text="CyberShield AI  •  AI-Powered Phishing Detection",
        font=(FONT, 11),
        text_color=MUTED
    ).pack(
        pady=(0, 20)
    )

    # Start the UI queue pump for this page
    start_ui_pump(main)


# ============================================================
# INFO ROW
# ============================================================

def create_info_row(parent, title, value):

    row = ctk.CTkFrame(
        parent,
        fg_color="transparent"
    )

    row.pack(
        fill="x",
        padx=15,
        pady=5
    )

    ctk.CTkLabel(
        row,
        text=title,
        width=150,
        anchor="w",
        font=(FONT, 10, "bold"),
        text_color=MUTED
    ).pack(
        side="left"
    )

    label = ctk.CTkLabel(
        row,
        text=value,
        anchor="w",
        font=(FONT, 11),
        text_color=TEXT
    )

    label.pack(
        side="left",
        fill="x",
        expand=True
    )

    return label


# ============================================================
# BUTTON ACTIONS
# ============================================================

def paste_url(ui):

    try:

        text = ui["parent"].clipboard_get().strip()

    except Exception:

        return

    ui["url_entry"].delete(0, "end")
    ui["url_entry"].insert(0, text)


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

        ui[key].configure(
            text="-",
            text_color=TEXT
        )

    ui["status_label"].configure(
        text="Waiting for URL...",
        text_color=TEXT
    )

    ui["progress"].set(0)

    ui["progress_label"].configure(
        text="0%"
    )

    ui["score_label"].configure(
        text="--%",
        text_color=CYAN
    )

    ui["risk_bar"].set(0)

    ui["risk_bar"].configure(
        progress_color=CYAN
    )

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

    STATE["result"] = None


def reset_model_rows(ui):

    status = safe_status()

    for name, (bar, value_label) in ui["model_rows"].items():

        loaded = status.get(name, False)

        bar.set(0)

        bar.configure(
            progress_color=CYAN
        )

        value_label.configure(
            text="ready" if loaded else "not loaded",
            text_color=GREEN if loaded else MUTED
        )


def summary_text():

    result = STATE["result"]

    score = result["score"]

    lines = [
        "CyberShield AI - Phishing Report",
        f"URL     : {STATE['url']}",
        f"Time    : {datetime.now():%Y-%m-%d %H:%M:%S}",
        f"Score   : {score:.0f}%",
        f"Verdict : {level_text(score)}",
        "Models  : " + (
            ", ".join(
                f"{k} {v:.0f}%"
                for k, v in result["model_scores"].items()
            ) or "n/a"
        ),
        "Red flags:"
    ]

    flags = result["reasons"]

    if flags:
        lines += [f"  - {r}" for r in flags]
    else:
        lines.append("  none")

    return "\n".join(lines)


def copy_summary(ui):

    if not STATE["result"]:

        messagebox.showinfo(
            "Nothing to copy",
            "Run a scan first."
        )

        return

    ui["parent"].clipboard_clear()
    ui["parent"].clipboard_append(summary_text())

    ui["status_label"].configure(
        text="Summary copied to clipboard.",
        text_color=GREEN
    )


def export_report(ui):

    if not STATE["result"]:

        messagebox.showinfo(
            "Nothing to export",
            "Run a scan first."
        )

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

    if path.lower().endswith(".txt"):

        data = summary_text()

    else:

        data = json.dumps(
            {
                "url": STATE["url"],
                "time": datetime.now().isoformat(timespec="seconds"),
                "risk_score": result["score"],
                "verdict": level_text(result["score"]),
                "model_scores": result["model_scores"],
                "reasons": result["reasons"],
                "features": {
                    k: v
                    for k, v in result["features"].items()
                    if not str(k).startswith("_")
                }
            },
            indent=2,
            default=str
        )

    with open(path, "w", encoding="utf-8") as f:
        f.write(data)

    ui["status_label"].configure(
        text=f"Report saved: {path}",
        text_color=GREEN
    )


# ============================================================
# START SCAN
# ============================================================

def start_phishing_scan(ui):

    if ui.get("scanning"):
        return

    url = normalize_url(
        ui["url_entry"].get()
    )

    # --------------------------------------------------------
    # Empty URL
    # --------------------------------------------------------

    if not url:

        messagebox.showwarning(
            "URL Required",
            "Please enter a website URL."
        )

        return

    # --------------------------------------------------------
    # Basic URL validation
    # --------------------------------------------------------

    if not is_valid_url(url):

        messagebox.showwarning(
            "Invalid URL",
            "Please enter a valid URL.\n\nExample:\nhttps://example.com"
        )

        return

    # --------------------------------------------------------
    # Update URL information (direct label references)
    # --------------------------------------------------------

    update_url_information(
        ui,
        url
    )

    # --------------------------------------------------------
    # Reset result
    # --------------------------------------------------------

    ui["progress"].set(0)

    ui["progress_label"].configure(
        text="0%"
    )

    ui["status_label"].configure(
        text="Initializing phishing analysis...",
        text_color=CYAN
    )

    ui["score_label"].configure(
        text="--%",
        text_color=CYAN
    )

    ui["risk_bar"].set(0)

    ui["threat_label"].configure(
        text="ANALYZING...",
        text_color=CYAN
    )

    ui["recommendation_label"].configure(
        text="Extracting URL characteristics and running AI models...",
        text_color=MUTED
    )

    reset_model_rows(ui)

    ui["scan_button"].configure(
        state="disabled",
        text="🔍  ANALYZING..."
    )

    ui["scanning"] = True

    # --------------------------------------------------------
    # Background thread
    # --------------------------------------------------------

    thread = threading.Thread(
        target=perform_phishing_scan,
        args=(
            url,
            ui
        ),
        daemon=True
    )

    thread.start()


# ============================================================
# PERFORM PHISHING SCAN  (runs in a worker thread)
# ============================================================

def perform_phishing_scan(url, ui):

    try:

        post(lambda: set_stage(
            ui, 15, "Validating URL structure...", CYAN
        ))

        time.sleep(0.1)

        # ----------------------------------------------------
        # Feature extraction
        # ----------------------------------------------------

        post(lambda: set_stage(
            ui, 40, "Extracting URL features...", CYAN
        ))

        features = extract_features(
            url
        )

        # ----------------------------------------------------
        # AI prediction (real work, no fake delay loop)
        # ----------------------------------------------------

        post(lambda: set_stage(
            ui, 65, "Running detection models...", PURPLE
        ))

        result = run_phishing_prediction(
            url
        )

        # Prefer the engine's own features if it returned them
        if not result.get("features"):
            result["features"] = features

        post(lambda: set_stage(
            ui, 90, "Generating final phishing risk...", GREEN
        ))

        time.sleep(0.1)

        # ----------------------------------------------------
        # Result
        # ----------------------------------------------------

        post(lambda: display_phishing_result(
            ui,
            url,
            result
        ))

    except Exception as e:

        error = str(e)

        post(lambda: phishing_scan_error(
            ui,
            error
        ))


# ============================================================
# URL VALIDATION
# ============================================================

def normalize_url(url):

    url = url.strip()

    if url and "://" not in url:

        url = "http://" + url

    return url


def is_valid_url(url):

    try:

        parsed = urlparse(
            url
        )

        if parsed.scheme not in (
            "http",
            "https"
        ):

            return False

        if not parsed.hostname:

            return False

        if "." not in parsed.hostname:

            return False

        return True

    except Exception:

        return False


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def extract_features(url):

    if FEATURE_ENGINE_AVAILABLE:

        try:

            result = extract_url_features(
                url
            )

            if hasattr(
                result,
                "iloc"
            ):

                return result.iloc[0].to_dict()

            if isinstance(
                result,
                dict
            ):

                return result

            if hasattr(
                result,
                "to_dict"
            ):

                return result.to_dict()

        except Exception:
            pass

    # Fallback basic features
    parsed = urlparse(
        url
    )

    try:

        port = parsed.port

    except ValueError:

        port = None

    low = url.lower()

    return {
        "url_length": len(url),
        "domain_length": len(parsed.netloc),
        "path_length": len(parsed.path),
        "uses_https": int(
            parsed.scheme == "https"
        ),
        "uses_ip": int(
            bool(
                re.match(
                    r"^\d{1,3}(\.\d{1,3}){3}$",
                    parsed.hostname or ""
                )
            )
        ),
        "has_port": int(
            port is not None and port not in (80, 443)
        ),
        "has_punycode": int(
            "xn--" in low
        ),
        "has_login_keyword": int(
            "login" in low
        ),
        "has_verify_keyword": int(
            "verify" in low
        ),
        "has_account_keyword": int(
            "account" in low
        ),
        "has_security_keyword": int(
            "security" in low
        ),
        "has_password_keyword": int(
            "password" in low
        ),
        "has_bank_keyword": int(
            "bank" in low
        )
    }


# ============================================================
# FORMAT FEATURES
# ============================================================

def format_features(features):

    if not features:

        return "No URL features available."

    # Display important features first, then everything else
    priority = [
        "url_length",
        "domain_length",
        "path_length",
        "dot_count",
        "slash_count",
        "hyphen_count",
        "underscore_count",
        "at_count",
        "question_count",
        "equal_count",
        "ampersand_count",
        "percent_count",
        "digit_count",
        "letter_count",
        "subdomain_count",
        "uses_https",
        "uses_ip",
        "has_port",
        "has_punycode",
        "has_fragment",
        "has_query"
    ]

    keys = [
        k for k in priority
        if k in features
    ]

    keys += [
        k for k in features
        if k not in keys
        and not str(k).startswith("_")
    ]

    cells = []

    for key in keys:

        label = key.replace(
            "_",
            " "
        ).upper()

        cells.append(
            f"{label:<26}: {str(features[key]):<8}"
        )

    # Two columns
    lines = []

    for i in range(0, len(cells), 2):

        left = cells[i]

        right = (
            cells[i + 1]
            if i + 1 < len(cells)
            else ""
        )

        lines.append(
            f"{left}   {right}".rstrip()
        )

    return "\n".join(
        lines
    )


# ============================================================
# AI PREDICTION
# ============================================================

def run_phishing_prediction(url):

    # --------------------------------------------------------
    # Actual ensemble
    # --------------------------------------------------------

    if ENSEMBLE_AVAILABLE:

        try:

            result = predict_phishing_ensemble(
                url
            )

            if isinstance(
                result,
                dict
            ):

                score = result.get(
                    "risk_score",
                    result.get(
                        "score",
                        result.get(
                            "phishing_score",
                            0
                        )
                    )
                )

                # NOTE: the old "0-1 -> x100" guess was removed.
                # It turned a real 1% score into 100%.
                # The engine already returns a 0-100 score.
                score = max(
                    0.0,
                    min(
                        100.0,
                        float(score)
                    )
                )

                recommendation = result.get(
                    "recommendation",
                    ""
                )

                # Engine adds "Why: ..." text, shown in Red Flags instead
                recommendation = recommendation.split(
                    "\n\nWhy:"
                )[0]

                if not recommendation:

                    if score >= 70:

                        recommendation = (
                            "Do not open this URL. Avoid entering "
                            "credentials or sensitive information."
                        )

                    elif score >= 40:

                        recommendation = (
                            "Proceed carefully and verify the website "
                            "before providing sensitive information."
                        )

                    else:

                        recommendation = (
                            "No strong phishing indicators were detected."
                        )

                return {
                    "score": score,
                    "recommendation": recommendation,
                    "model_scores": result.get(
                        "model_scores",
                        {}
                    ),
                    "reasons": result.get(
                        "reasons",
                        []
                    ),
                    "features": result.get(
                        "features",
                        {}
                    ),
                    "demo": False
                }

        except Exception:

            traceback.print_exc()

    # --------------------------------------------------------
    # Demo fallback (engine missing or crashed)
    # --------------------------------------------------------

    lower = url.lower()

    suspicious_words = [
        "login",
        "verify",
        "account",
        "password",
        "secure",
        "bank",
        "signin",
        "confirm"
    ]

    hits = [
        word
        for word in suspicious_words
        if word in lower
    ]

    score = min(
        15 + len(hits) * 9,
        65
    )

    if score >= 40:

        recommendation = (
            "Verify the website domain before continuing."
        )

    else:

        recommendation = (
            "No strong phishing indicators were detected."
        )

    return {
        "score": score,
        "recommendation": (
            "[DEMO MODE - core engine not loaded] "
            + recommendation
        ),
        "model_scores": {
            "Heuristic Engine": score
        },
        "reasons": [
            f"Sensitive keyword in URL: {w}"
            for w in hits
        ],
        "features": {},
        "demo": True
    }


# ============================================================
# STAGE / PROGRESS
# ============================================================

def set_stage(ui, value, text, color):

    update_progress(
        ui["progress"],
        ui["progress_label"],
        value
    )

    ui["status_label"].configure(
        text=text,
        text_color=color
    )


def update_progress(
    progress,
    progress_label,
    value
):

    progress.set(
        value / 100
    )

    progress_label.configure(
        text=f"{value}%"
    )


# ============================================================
# DISPLAY RESULT
# ============================================================

def display_phishing_result(
    ui,
    url,
    result
):

    ui["scanning"] = False

    score = float(
        result["score"]
    )

    color = level_color(
        score
    )

    STATE["url"] = url

    STATE["result"] = result

    update_progress(
        ui["progress"],
        ui["progress_label"],
        100
    )

    ui["score_label"].configure(
        text=f"{score:.0f}%",
        text_color=color
    )

    ui["risk_bar"].set(
        score / 100
    )

    ui["risk_bar"].configure(
        progress_color=color
    )

    ui["threat_label"].configure(
        text=level_text(score),
        text_color=color
    )

    ui["recommendation_label"].configure(
        text=result["recommendation"],
        text_color=TEXT
    )

    if result.get("demo"):

        ui["status_label"].configure(
            text="Completed in DEMO MODE (core engine not found).",
            text_color=ORANGE
        )

    else:

        ui["status_label"].configure(
            text="URL analysis completed successfully.",
            text_color=GREEN
        )

    # Registered domain (from the feature engine)
    features = result.get(
        "features",
        {}
    )

    ui["registered_label"].configure(
        text=features.get(
            "_registered_domain"
        ) or "-"
    )

    # Features
    ui["feature_label"].configure(
        text=format_features(features),
        text_color=TEXT
    )

    # Model scores
    scores = result.get(
        "model_scores",
        {}
    )

    for name, (bar, value_label) in ui["model_rows"].items():

        if name in scores:

            s = float(
                scores[name]
            )

            bar.set(
                s / 100
            )

            bar.configure(
                progress_color=level_color(s)
            )

            value_label.configure(
                text=f"{s:.0f}%",
                text_color=level_color(s)
            )

        else:

            bar.set(0)

            value_label.configure(
                text="not loaded",
                text_color=MUTED
            )

    # Red flags
    set_flags(
        ui,
        result.get("reasons", [])
    )

    ui["scan_button"].configure(
        state="normal",
        text="🔍  ANALYZE URL"
    )


# ============================================================
# RED FLAGS
# ============================================================

def set_flags(ui, reasons):

    frame = ui["flags_frame"]

    for widget in frame.winfo_children():
        widget.destroy()

    if reasons is None:

        ctk.CTkLabel(
            frame,
            text="No URL analyzed yet.",
            font=(FONT, 12),
            text_color=MUTED
        ).pack(
            anchor="w"
        )

        return

    if not reasons:

        ctk.CTkLabel(
            frame,
            text="✓  No red flags detected.",
            font=(FONT, 13, "bold"),
            text_color=GREEN
        ).pack(
            anchor="w"
        )

        return

    for reason in reasons:

        row = ctk.CTkFrame(
            frame,
            fg_color=CARD_2,
            corner_radius=8
        )

        row.pack(
            fill="x",
            pady=3
        )

        ctk.CTkLabel(
            row,
            text="⚑",
            font=(FONT, 14),
            text_color=ORANGE
        ).pack(
            side="left",
            padx=(12, 6),
            pady=7
        )

        ctk.CTkLabel(
            row,
            text=reason,
            anchor="w",
            justify="left",
            font=(FONT, 12),
            text_color=TEXT,
            wraplength=1000
        ).pack(
            side="left",
            fill="x",
            expand=True,
            padx=(0, 12)
        )


# ============================================================
# UPDATE URL INFORMATION
# ============================================================

def update_url_information(
    ui,
    url
):

    parsed = urlparse(
        url
    )

    ui["domain_label"].configure(
        text=parsed.hostname or "-"
    )

    ui["registered_label"].configure(
        text="-"
    )

    ui["protocol_label"].configure(
        text=parsed.scheme.upper(),
        text_color=(
            GREEN
            if parsed.scheme == "https"
            else ORANGE
        )
    )

    ui["length_label"].configure(
        text=f"{len(url)} characters"
    )


# ============================================================
# ERROR
# ============================================================

def phishing_scan_error(
    ui,
    error
):

    ui["scanning"] = False

    ui["status_label"].configure(
        text=f"Scan error: {error}",
        text_color=RED
    )

    ui["threat_label"].configure(
        text="SCAN FAILED",
        text_color=RED
    )

    ui["scan_button"].configure(
        state="normal",
        text="🔍  ANALYZE URL"
    )


# ============================================================
# TEST MODE
# ============================================================

if __name__ == "__main__":

    app = ctk.CTk()

    app.title(
        "CyberShield AI - Phishing Scanner"
    )

    app.geometry(
        "1450x900"
    )

    app.configure(
        fg_color=BG
    )

    show_phishing_scanner(
        app
    )

    app.mainloop()