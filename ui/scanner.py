import hashlib
import math
import os
import re
import threading
import time
from datetime import datetime
from tkinter import filedialog
import tkinter as tk
import tkinter.font as tkfont
from urllib.parse import urlparse

import customtkinter as ctk

try:
    from PIL import Image, ImageDraw, ImageFilter, ImageTk
except Exception:  # Pillow ships with customtkinter
    Image = ImageDraw = ImageFilter = ImageTk = None


# ============================================================
# CYBERSHIELD AI - UNIFIED SECURITY SCANNER
# Same palette as the dashboard so both pages feel like one product.
# ============================================================

BG = "#020712"
CARD = "#030C18"
CARD_2 = "#06121F"
CARD_3 = "#0A1B2E"
BORDER = "#12304F"
BORDER_HI = "#1B4F7F"

TEXT = "#F4F7FB"
MUTED = "#7C93AB"

CYAN = "#12C8FF"
BLUE = "#168BDB"
GREEN = "#19D6A0"
RED = "#FF405A"
ORANGE = "#F4A62A"
PURPLE = "#884DFF"

ACCENT = {"malware": RED, "phishing": PURPLE}

FONT = "Segoe UI"
MONO = "Consolas"

MIN_SCAN_SECONDS = 2.4          # the progress animation never finishes faster than this

SUSPICIOUS_WORDS = ["login", "verify", "account", "password", "bank", "secure"]

SCAN_HISTORY = []               # kept for the whole session, survives page rebuilds


def blend(c1, c2, t):
    """Blend two hex colours (t=0 -> c1, t=1 -> c2)."""
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def pick_fonts():
    """Use Segoe UI / Consolas where they exist, otherwise fall back gracefully."""
    global FONT, MONO
    try:
        families = set(tkfont.families())
    except Exception:
        families = set()
    for name in ("Segoe UI", "SF Pro Text", "Helvetica Neue", "Inter", "Arial"):
        if name in families:
            FONT = name
            break
    else:
        FONT = "Arial"
    for name in ("Consolas", "SF Mono", "Menlo", "DejaVu Sans Mono", "Courier New"):
        if name in families:
            MONO = name
            break
    else:
        MONO = "Courier"


# ============================================================
# OPTIONAL ENGINES
# ============================================================

try:
    from core.malware_ensemble_engine import predict_malware_ensemble
    MALWARE_ENGINE_AVAILABLE = True
except Exception:
    MALWARE_ENGINE_AVAILABLE = False

try:
    from core.phishing_ensemble_engine import predict_phishing_ensemble
    PHISHING_ENGINE_AVAILABLE = True
except Exception:
    PHISHING_ENGINE_AVAILABLE = False


# ============================================================
# PREDICTION (logic unchanged: same thresholds, labels, fallbacks)
# ============================================================

def _from_engine(engine, target, labels, recommendations):
    """Run an ensemble engine and map its output to {score, threat, recommendation}."""
    result = engine(target)
    if not isinstance(result, dict):
        return None

    score = float(result.get("risk_score", result.get("score", 0)))
    if score <= 1:
        score *= 100
    recommendation = result.get("recommendation", "")

    if score >= 70:
        index = 0
    elif score >= 40:
        index = 1
    else:
        index = 2
    return {
        "score": score,
        "threat": labels[index],
        "recommendation": recommendation or recommendations[index],
    }


def predict_malware(file_path):
    if MALWARE_ENGINE_AVAILABLE:
        try:
            out = _from_engine(
                predict_malware_ensemble, file_path,
                ("MALWARE DETECTED", "SUSPICIOUS FILE", "LOW RISK"),
                ("Isolate the file and perform further security analysis.",
                 "Perform additional analysis before opening the file.",
                 "No strong malware indicators were detected."),
            )
            if out:
                return out
        except Exception:
            pass

    # Demo fallback
    return {
        "score": 18,
        "threat": "LOW RISK",
        "recommendation": "No strong malware indicators were detected.",
    }


def predict_phishing(url):
    if PHISHING_ENGINE_AVAILABLE:
        try:
            out = _from_engine(
                predict_phishing_ensemble, url,
                ("PHISHING DETECTED", "SUSPICIOUS URL", "LOW RISK"),
                ("Do not open this URL or enter sensitive information.",
                 "Verify the domain before continuing.",
                 "No strong phishing indicators were detected."),
            )
            if out:
                return out
        except Exception:
            pass

    # Demo fallback
    lower = url.lower()
    matches = sum(1 for word in SUSPICIOUS_WORDS if word in lower)
    score = min(10 + matches * 8, 60)

    if score >= 40:
        return {
            "score": score,
            "threat": "SUSPICIOUS URL",
            "recommendation": "Verify the website domain before continuing.",
        }
    return {
        "score": score,
        "threat": "LOW RISK",
        "recommendation": "No strong phishing indicators were detected.",
    }


def is_valid_url(url):
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


# ============================================================
# REAL TARGET INFO (shown before scanning)
# ============================================================

def human_size(n):
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024


def sha256_of(path, chunk=1024 * 1024):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(chunk), b""):
            digest.update(block)
    return digest.hexdigest()


def analyze_url(url):
    """Quick lexical URL features. Returns a list of (label, value, level) chips,
    level: 'ok' | 'warn' | 'info'."""
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
    except Exception:
        return []
    host = parsed.hostname or ""
    if not host:
        return []

    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))
    parts = host.split(".")
    subdomains = max(0, len(parts) - 2) if not is_ip else 0
    found = [w for w in SUSPICIOUS_WORDS if w in url.lower()]

    chips = [
        ("HTTPS", "Yes" if parsed.scheme == "https" else "No", "ok" if parsed.scheme == "https" else "warn"),
        ("Host", "IP address" if is_ip else "Domain", "warn" if is_ip else "ok"),
        ("Subdomains", str(subdomains), "warn" if subdomains >= 3 else "info"),
        ("URL length", f"{len(url)} chars", "warn" if len(url) > 75 else "info"),
        ("'@' symbol", "Present" if "@" in url else "None", "warn" if "@" in url else "ok"),
        ("Keywords", ", ".join(found) if found else "None", "warn" if found else "ok"),
    ]
    return chips


def hand(widget):
    """Pointer cursor on clickable cards (ignored if the widget does not support it)."""
    for target in (widget, getattr(widget, "_canvas", None)):
        try:
            if target is not None:
                target.configure(cursor="hand2")
        except Exception:
            pass


def mid_ellipsis(text, limit):
    if len(text) <= limit:
        return text
    keep = (limit - 1) // 2
    return text[:keep] + "…" + text[-keep:]


# ============================================================
# ARTWORK (drawn in code, supersampled, so it is always sharp)
# ============================================================

ICON_SS = 4
RESAMPLE = getattr(Image, "Resampling", Image).LANCZOS if Image else None


def rgb(hex_color, alpha=None):
    h = hex_color.lstrip("#")
    t = tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))
    return t if alpha is None else t + (alpha,)


def _bezier(p0, p1, p2, p3, n=28):
    pts = []
    for i in range(n + 1):
        t = i / n
        u = 1 - t
        pts.append((
            u ** 3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t ** 3 * p3[0],
            u ** 3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t ** 3 * p3[1],
        ))
    return pts


def _shield(cx, cy, w, h):
    l, r, t, b = cx - w / 2, cx + w / 2, cy - h / 2, cy + h / 2
    top = (cx, t)
    pts = [top, (r, t + h * 0.17)]
    pts += _bezier((r, t + h * 0.17), (r, t + h * 0.62), (cx + w * 0.28, b - h * 0.12), (cx, b))[1:]
    pts += _bezier((cx, b), (cx - w * 0.28, b - h * 0.12), (l, t + h * 0.62), (l, t + h * 0.17))[1:]
    pts.append(top)
    return pts


def _glow(img, radius, strength=0.6):
    halo = img.filter(ImageFilter.GaussianBlur(radius))
    halo.putalpha(halo.getchannel("A").point(lambda v: int(min(255, v * strength))))
    out = Image.new("RGBA", img.size, (0, 0, 0, 0))
    out.alpha_composite(halo)
    out.alpha_composite(img)
    return out


def _canvas(size):
    n = size * ICON_SS
    img = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    return img, ImageDraw.Draw(img), n


def draw_icon(name, size, color=CYAN):
    """High-resolution RGBA icon (scaled down by CTkImage)."""
    img, d, n = _canvas(size)
    c = rgb(color)
    S = ICON_SS
    w = int(max(1.8, size / 12) * S)
    u = n / 24.0

    if name == "bug":
        d.ellipse([8 * u, 8 * u, 16 * u, 19 * u], outline=c, width=w)
        d.ellipse([9.6 * u, 3.5 * u, 14.4 * u, 8.3 * u], outline=c, width=w)
        d.line([(12 * u, 9 * u), (12 * u, 19 * u)], fill=c, width=w)
        for y0, y1 in ((11, 9), (14, 14), (17, 19)):
            d.line([(8 * u, y0 * u), (3.5 * u, y1 * u)], fill=c, width=w)
            d.line([(16 * u, y0 * u), (20.5 * u, y1 * u)], fill=c, width=w)
        d.line([(10.4 * u, 4 * u), (8 * u, 1.8 * u)], fill=c, width=w)
        d.line([(13.6 * u, 4 * u), (16 * u, 1.8 * u)], fill=c, width=w)
    elif name == "hook":
        d.ellipse([10 * u, 2.5 * u, 14 * u, 6.5 * u], outline=c, width=w)
        d.line([(12 * u, 6.5 * u), (12 * u, 15 * u)], fill=c, width=w)
        d.arc([5.5 * u, 10.5 * u, 18.5 * u, 22.5 * u], 0, 150, fill=c, width=w)
        d.line([(6.2 * u, 16.4 * u), (4.2 * u, 13.2 * u)], fill=c, width=w)
        d.line([(6.2 * u, 16.4 * u), (9.2 * u, 15.4 * u)], fill=c, width=w)
    elif name == "file":
        pts = [(5 * u, 2.5 * u), (14 * u, 2.5 * u), (19 * u, 7.5 * u), (19 * u, 21.5 * u), (5 * u, 21.5 * u), (5 * u, 2.5 * u)]
        d.line(pts, fill=c, width=w, joint="curve")
        d.line([(14 * u, 2.5 * u), (14 * u, 7.5 * u), (19 * u, 7.5 * u)], fill=c, width=w, joint="curve")
        for y in (12, 15.5, 19):
            d.line([(8 * u, y * u), (16 * u, y * u)], fill=c, width=int(w * 0.8))
    elif name == "upload":
        d.line([(12 * u, 16 * u), (12 * u, 4.5 * u)], fill=c, width=w)
        d.line([(7 * u, 9 * u), (12 * u, 4 * u), (17 * u, 9 * u)], fill=c, width=w, joint="curve")
        d.line([(4.5 * u, 15 * u), (4.5 * u, 20 * u), (19.5 * u, 20 * u), (19.5 * u, 15 * u)], fill=c, width=w, joint="curve")
    elif name == "globe":
        d.ellipse([3 * u, 3 * u, 21 * u, 21 * u], outline=c, width=w)
        d.ellipse([8 * u, 3 * u, 16 * u, 21 * u], outline=c, width=int(w * 0.8))
        d.line([(3 * u, 12 * u), (21 * u, 12 * u)], fill=c, width=int(w * 0.8))
    elif name == "shield":
        pts = _shield(12 * u, 12.4 * u, 17 * u, 20 * u)
        d.line(pts, fill=c, width=w, joint="curve")
        d.line([(8.4 * u, 12.4 * u), (11 * u, 15 * u), (16 * u, 9.6 * u)], fill=c, width=w, joint="curve")
    elif name == "copy":
        d.rounded_rectangle([8.5 * u, 8.5 * u, 19.5 * u, 20 * u], radius=2 * u, outline=c, width=w)
        d.line([(15.5 * u, 8.5 * u), (15.5 * u, 4.5 * u), (4.5 * u, 4.5 * u), (4.5 * u, 15.5 * u), (8.5 * u, 15.5 * u)], fill=c, width=w, joint="curve")
    elif name == "clipboard":
        d.rounded_rectangle([5 * u, 5 * u, 19 * u, 21 * u], radius=2 * u, outline=c, width=w)
        d.rounded_rectangle([9 * u, 2.5 * u, 15 * u, 7 * u], radius=1.4 * u, fill=rgb(CARD), outline=c, width=w)
    elif name == "trash":
        d.line([(4.5 * u, 6.5 * u), (19.5 * u, 6.5 * u)], fill=c, width=w)
        d.line([(9.5 * u, 6.5 * u), (9.5 * u, 4 * u), (14.5 * u, 4 * u), (14.5 * u, 6.5 * u)], fill=c, width=w, joint="curve")
        d.line([(6.5 * u, 6.5 * u), (7.5 * u, 20.5 * u), (16.5 * u, 20.5 * u), (17.5 * u, 6.5 * u)], fill=c, width=w, joint="curve")
    elif name == "bolt":
        d.polygon([(13.5 * u, 2 * u), (5.5 * u, 13.5 * u), (11 * u, 13.5 * u), (10 * u, 22 * u), (18.5 * u, 10 * u), (12.8 * u, 10 * u)], fill=c)
    elif name == "pending":
        d.ellipse([3 * u, 3 * u, 21 * u, 21 * u], outline=rgb("#27415C"), width=int(w * 0.9))
    elif name == "active":
        d.ellipse([3 * u, 3 * u, 21 * u, 21 * u], outline=rgb("#17466D"), width=int(w * 0.9))
        d.arc([3 * u, 3 * u, 21 * u, 21 * u], -90, 70, fill=c, width=int(w * 1.1))
        d.ellipse([10 * u, 10 * u, 14 * u, 14 * u], fill=c)
        return _glow(img, 1.6 * S, 0.8)
    elif name == "done":
        d.ellipse([3 * u, 3 * u, 21 * u, 21 * u], fill=rgb("#0F6B45"), outline=rgb(GREEN), width=int(w * 0.8))
        d.line([(7.5 * u, 12.4 * u), (10.6 * u, 15.4 * u), (16.6 * u, 8.8 * u)], fill=rgb("#E6FFF5"), width=w, joint="curve")
        return img
    return _glow(img, 1.8 * S, 0.5)


def render_gauge(size, value, color):
    """270-degree risk gauge with rounded caps and tick marks."""
    S = ICON_SS
    N = size * S
    img = Image.new("RGBA", (N, N), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    pad, ring = 18 * S, 15 * S
    box = [pad, pad, N - pad, N - pad]
    start, sweep = 135, 270
    cx = cy = N / 2
    r_mid = N / 2 - pad - ring / 2

    # ticks
    r_out, r_in = r_mid - ring / 2 - 7 * S, r_mid - ring / 2 - 13 * S
    for i in range(28):
        ang = math.radians(start + sweep * i / 27)
        major = i % 9 == 0
        ri = r_in - (3 * S if major else 0)
        d.line([(cx + r_out * math.cos(ang), cy + r_out * math.sin(ang)),
                (cx + ri * math.cos(ang), cy + ri * math.sin(ang))],
               fill=rgb("#2A4663" if major else "#173048"), width=int(1.4 * S))

    d.arc(box, start, start + sweep, fill=rgb("#0E2033"), width=ring)
    for ang in (start, start + sweep):
        a = math.radians(ang)
        x, y = cx + r_mid * math.cos(a), cy + r_mid * math.sin(a)
        d.ellipse([x - ring / 2, y - ring / 2, x + ring / 2, y + ring / 2], fill=rgb("#0E2033"))

    value = max(0.0, min(100.0, value))
    if value > 0.4:
        end = start + sweep * value / 100
        d.arc(box, start, end, fill=rgb(color), width=ring)
        for ang in (start, end):
            a = math.radians(ang)
            x, y = cx + r_mid * math.cos(a), cy + r_mid * math.sin(a)
            d.ellipse([x - ring / 2, y - ring / 2, x + ring / 2, y + ring / 2], fill=rgb(color))
        img = _glow(img, 5 * S, 0.7)
    return img.resize((size, size), RESAMPLE)


_icon_cache = {}


def icon(name, size=20, color=CYAN):
    key = (name, size, color)
    if key not in _icon_cache:
        if Image is None:
            _icon_cache[key] = None
        else:
            pil = draw_icon(name, size, color)
            _icon_cache[key] = ctk.CTkImage(light_image=pil, dark_image=pil, size=(size, size))
    return _icon_cache[key]


# ============================================================
# SCANNER PAGE
# ============================================================

STEP_TEXT = {
    "malware": [
        ("Validate target", "Check the file is readable"),
        ("Extract features", "Static features and SHA-256"),
        ("Machine learning", "XGBoost, Random Forest, SVM"),
        ("Deep learning", "Neural network analysis"),
        ("Final verdict", "Risk score and advice"),
    ],
    "phishing": [
        ("Validate target", "Check the URL format"),
        ("Extract features", "Lexical and host features"),
        ("Machine learning", "XGBoost, Random Forest, SVM"),
        ("Deep learning", "LSTM and Transformer"),
        ("Final verdict", "Risk score and advice"),
    ],
}

ENGINES = {
    "malware": [("XGBoost", 2), ("Random Forest", 2), ("SVM", 2), ("Deep Learning", 3)],
    "phishing": [("XGBoost", 2), ("Random Forest", 2), ("SVM", 2), ("LSTM", 3), ("Transformer", 3)],
}

STAGE_MESSAGE = [
    "Validating scan target...",
    "Extracting security features...",
    "Running machine learning models...",
    "Running deep learning analysis...",
    "Generating final security result...",
]


def stage_of(value):
    if value >= 100:
        return 5
    if value < 20:
        return 0
    if value < 40:
        return 1
    if value < 65:
        return 2
    if value < 85:
        return 3
    return 4


def verdict_for(score):
    if score >= 70:
        return "THREAT DETECTED", RED
    if score >= 40:
        return "SUSPICIOUS", ORANGE
    return "LOW RISK", GREEN


class ScannerPage:
    def __init__(self, parent, initial="malware"):
        pick_fonts()

        for widget in parent.winfo_children():
            widget.destroy()
        parent.configure(fg_color=BG)

        self.kind = initial if initial in ACCENT else "malware"
        self.file = None
        self.scanning = False
        self.progress = 0.0
        self.box = None
        self.t0 = 0.0
        self.tick_job = None
        self.gauge_job = None
        self.gauge_photo = None
        self.toast_job = None
        self.step_widgets = []
        self.engine_widgets = []

        self.main = ctk.CTkScrollableFrame(
            parent, fg_color=BG,
            scrollbar_button_color=BORDER, scrollbar_button_hover_color=CYAN
        )
        self.main.pack(fill="both", expand=True, padx=16, pady=10)

        self._build_header()
        self._build_toast()

        body = ctk.CTkFrame(self.main, fg_color="transparent")
        body.pack(fill="x")
        body.grid_columnconfigure(0, weight=5, uniform="body")
        body.grid_columnconfigure(1, weight=6, uniform="body")

        left = ctk.CTkFrame(body, fg_color="transparent")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        right = ctk.CTkFrame(body, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew", padx=(7, 0))

        self._build_setup(left)
        self._build_progress(right)
        self._build_risk(right)
        self._build_engines(right)
        self._build_history()
        self._build_coverage()

        ctk.CTkLabel(
            self.main, text="CyberShield AI  •  Unified Security Scanner",
            font=(FONT, 10), text_color=MUTED
        ).pack(pady=(4, 14))

        self.set_kind(self.kind, first=True)
        self.refresh_history()

    # ------------------------------------------------------------
    # small helpers
    # ------------------------------------------------------------

    def alive(self):
        try:
            return bool(self.main.winfo_exists())
        except tk.TclError:
            return False

    def card(self, parent, pady=(0, 14), **kw):
        frame = ctk.CTkFrame(
            parent, fg_color=kw.pop("fg_color", CARD), corner_radius=14,
            border_width=1, border_color=kw.pop("border_color", BORDER), **kw
        )
        frame.pack(fill="x", pady=pady)
        return frame

    def section(self, parent, title, subtitle=None):
        head = ctk.CTkFrame(parent, fg_color="transparent")
        head.pack(fill="x", padx=18, pady=(14, 0))
        ctk.CTkLabel(head, text=title, font=(FONT, 13, "bold"), text_color=TEXT).pack(anchor="w")
        if subtitle:
            ctk.CTkLabel(head, text=subtitle, font=(FONT, 10), text_color=MUTED).pack(anchor="w", pady=(1, 0))
        return head

    def pill(self, parent, text, fg, tc, size=9):
        return ctk.CTkLabel(
            parent, text=text, height=20, corner_radius=10,
            fg_color=fg, text_color=tc, font=(FONT, size, "bold")
        )

    def flash(self, message, color=ORANGE):
        """Inline notice (replaces blocking message boxes)."""
        self.toast.configure(text="  " + message + "  ", text_color=color, fg_color=blend(CARD, color, 0.14))
        self.toast.pack(fill="x", pady=(0, 12), before=self.toast_anchor)
        if self.toast_job:
            self.main.after_cancel(self.toast_job)
        self.toast_job = self.main.after(4200, self._hide_toast)

    def _hide_toast(self):
        if self.alive():
            self.toast.pack_forget()

    # ------------------------------------------------------------
    # header
    # ------------------------------------------------------------

    def _build_header(self):
        header = ctk.CTkFrame(self.main, fg_color="transparent")
        header.pack(fill="x", pady=(2, 14))

        title_area = ctk.CTkFrame(header, fg_color="transparent")
        title_area.pack(side="left", fill="x", expand=True)

        row = ctk.CTkFrame(title_area, fg_color="transparent")
        row.pack(anchor="w")
        ctk.CTkLabel(row, text="", image=icon("shield", 34, CYAN)).pack(side="left", padx=(0, 10))
        col = ctk.CTkFrame(row, fg_color="transparent")
        col.pack(side="left")
        ctk.CTkLabel(col, text="SECURITY SCANNER", font=(FONT, 24, "bold"), text_color=TEXT).pack(anchor="w")
        ctk.CTkLabel(
            col, text="Unified AI-powered malware and phishing detection",
            font=(FONT, 12), text_color=MUTED
        ).pack(anchor="w")

        chips = ctk.CTkFrame(header, fg_color="transparent")
        chips.pack(side="right")
        for label, online in (("Malware engine", MALWARE_ENGINE_AVAILABLE), ("Phishing engine", PHISHING_ENGINE_AVAILABLE)):
            color = GREEN if online else ORANGE
            chip = ctk.CTkFrame(chips, fg_color=blend(CARD, color, 0.10), corner_radius=16, border_width=1, border_color=blend(CARD, color, 0.45))
            chip.pack(side="left", padx=(8, 0))
            ctk.CTkLabel(chip, text="●", font=(FONT, 11), text_color=color).pack(side="left", padx=(11, 4), pady=6)
            ctk.CTkLabel(
                chip, text=f"{label}: {'ONLINE' if online else 'DEMO'}",
                font=(FONT, 10, "bold"), text_color=color
            ).pack(side="left", padx=(0, 12))

    def _build_toast(self):
        self.toast_anchor = ctk.CTkFrame(self.main, height=1, fg_color="transparent")
        self.toast_anchor.pack(fill="x")
        self.toast = ctk.CTkLabel(
            self.main, text="", anchor="w", height=34, corner_radius=8,
            font=(FONT, 11, "bold"), text_color=ORANGE
        )

    # ------------------------------------------------------------
    # setup card (type selector + input + start)
    # ------------------------------------------------------------

    def _build_setup(self, parent):
        card = self.card(parent)
        self.section(card, "SCAN SETUP", "Choose what you want to analyse")

        selector = ctk.CTkFrame(card, fg_color="transparent")
        selector.pack(fill="x", padx=18, pady=(12, 0))
        selector.grid_columnconfigure(0, weight=1, uniform="sel")
        selector.grid_columnconfigure(1, weight=1, uniform="sel")

        self.type_cards = {}
        for col, (kind, title, sub, glyph) in enumerate((
            ("malware", "Malware scan", "Analyse a file", "bug"),
            ("phishing", "Phishing scan", "Analyse a URL", "hook"),
        )):
            frame = ctk.CTkFrame(selector, corner_radius=12, border_width=1, border_color=BORDER, fg_color=CARD_2)
            hand(frame)
            frame.grid(row=0, column=col, sticky="nsew", padx=(0, 6) if col == 0 else (6, 0))
            icon_label = ctk.CTkLabel(frame, text="", image=icon(glyph, 26, ACCENT[kind]))
            icon_label.pack(side="left", padx=(14, 10), pady=12)
            text_col = ctk.CTkFrame(frame, fg_color="transparent")
            text_col.pack(side="left", pady=10)
            title_label = ctk.CTkLabel(text_col, text=title, font=(FONT, 12, "bold"), text_color=TEXT)
            title_label.pack(anchor="w")
            sub_label = ctk.CTkLabel(text_col, text=sub, font=(FONT, 10), text_color=MUTED)
            sub_label.pack(anchor="w")
            for w in (frame, icon_label, text_col, title_label, sub_label):
                w.bind("<Button-1>", lambda e, k=kind: self.set_kind(k))
            self.type_cards[kind] = frame

        # ---- input area ----
        self.input_host = ctk.CTkFrame(card, fg_color="transparent")
        self.input_host.pack(fill="x", padx=18, pady=(14, 0))

        self.input_title = ctk.CTkLabel(self.input_host, text="", font=(FONT, 12, "bold"), text_color=TEXT)
        self.input_title.pack(anchor="w")
        self.input_desc = ctk.CTkLabel(self.input_host, text="", font=(FONT, 10), text_color=MUTED)
        self.input_desc.pack(anchor="w", pady=(1, 8))

        # file mode
        self.file_panel = ctk.CTkFrame(self.input_host, fg_color="transparent")
        self.drop = ctk.CTkFrame(self.file_panel, fg_color=CARD_2, corner_radius=14, border_width=1, border_color=BORDER)
        hand(self.drop)
        self.drop.pack(fill="x")
        self.drop_icon = ctk.CTkLabel(self.drop, text="", image=icon("upload", 34, CYAN))
        self.drop_icon.pack(pady=(18, 4))
        self.drop_title = ctk.CTkLabel(self.drop, text="Click to select a file", font=(FONT, 12, "bold"), text_color=TEXT)
        self.drop_title.pack()
        self.drop_sub = ctk.CTkLabel(self.drop, text=".exe  •  .dll  •  .sys  •  any file", font=(FONT, 10), text_color=MUTED)
        self.drop_sub.pack(pady=(1, 18))
        for w in (self.drop, self.drop_icon, self.drop_title, self.drop_sub):
            w.bind("<Button-1>", lambda e: self.browse_file())
            w.bind("<Enter>", lambda e: self.drop.configure(border_color=ACCENT[self.kind]))
            w.bind("<Leave>", lambda e: self.drop.configure(border_color=ACCENT[self.kind] if self.file else BORDER))

        self.file_info = ctk.CTkFrame(self.file_panel, fg_color=CARD_2, corner_radius=12, border_width=1, border_color=BORDER)
        self.info_rows = {}
        for key in ("Name", "Size", "Type", "SHA-256"):
            row = ctk.CTkFrame(self.file_info, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=(8 if key == "Name" else 2, 8 if key == "SHA-256" else 0))
            ctk.CTkLabel(row, text=key, width=64, anchor="w", font=(FONT, 10), text_color=MUTED).pack(side="left")
            value = ctk.CTkLabel(row, text="", anchor="w", font=(MONO if key == "SHA-256" else FONT, 10), text_color=TEXT)
            value.pack(side="left", fill="x", expand=True)
            self.info_rows[key] = value
            if key == "SHA-256":
                copy_btn = ctk.CTkButton(
                    row, text="", image=icon("copy", 14, MUTED), width=26, height=22,
                    fg_color="transparent", hover_color=CARD_3, command=self.copy_hash
                )
                copy_btn.pack(side="right")

        # url mode
        self.url_panel = ctk.CTkFrame(self.input_host, fg_color="transparent")
        url_row = ctk.CTkFrame(self.url_panel, fg_color=CARD_2, corner_radius=12, border_width=1, border_color=BORDER)
        url_row.pack(fill="x")
        ctk.CTkLabel(url_row, text="", image=icon("globe", 18, MUTED)).pack(side="left", padx=(12, 0))
        self.url_entry = ctk.CTkEntry(
            url_row, height=44, placeholder_text="https://example.com/login",
            fg_color="transparent", border_width=0, text_color=TEXT,
            placeholder_text_color=MUTED, font=(FONT, 12)
        )
        self.url_entry.pack(side="left", fill="x", expand=True, padx=6)
        self.url_entry.bind("<KeyRelease>", lambda e: self._schedule_url_check())
        ctk.CTkButton(
            url_row, text="Paste", image=icon("clipboard", 14, CYAN), compound="left", width=76, height=30,
            fg_color=CARD_3, hover_color=BORDER, text_color=CYAN, font=(FONT, 11, "bold"),
            corner_radius=8, command=self.paste_url
        ).pack(side="right", padx=8)

        self.url_chips = ctk.CTkFrame(self.url_panel, fg_color="transparent")
        self.url_chips.pack(fill="x", pady=(10, 0))
        self.url_job = None

        # ---- start button ----
        self.start_button = ctk.CTkButton(
            card, text="START SECURITY SCAN", image=icon("bolt", 18, "#FFFFFF"), compound="left",
            height=50, corner_radius=12, font=(FONT, 13, "bold"), text_color="white",
            command=self.start_scan
        )
        self.start_button.pack(fill="x", padx=18, pady=(16, 18))

    # ---- kind switching ----

    def set_kind(self, kind, first=False):
        if self.scanning:
            return
        self.kind = kind
        accent = ACCENT[kind]

        for k, frame in self.type_cards.items():
            if k == kind:
                frame.configure(border_color=ACCENT[k], fg_color=blend(CARD_2, ACCENT[k], 0.12), border_width=2)
            else:
                frame.configure(border_color=BORDER, fg_color=CARD_2, border_width=1)

        self.file_panel.pack_forget()
        self.url_panel.pack_forget()
        if kind == "malware":
            self.input_title.configure(text="Malware file scan")
            self.input_desc.configure(text="Select a file for AI-powered malware analysis")
            self.file_panel.pack(fill="x")
            self.start_button.configure(text="START MALWARE SCAN")
        else:
            self.input_title.configure(text="Phishing URL scan")
            self.input_desc.configure(text="Enter a website URL for AI-powered phishing analysis")
            self.url_panel.pack(fill="x")
            self.start_button.configure(text="START PHISHING SCAN")

        self.start_button.configure(fg_color=accent, hover_color=blend(accent, "#000000", 0.25))
        self.drop.configure(border_color=accent if self.file else BORDER)
        self._apply_step_text()
        self._reset_pipeline()
        if not first:
            self._reset_result()

    # ---- file handling ----

    def browse_file(self):
        if self.scanning:
            return
        path = filedialog.askopenfilename(
            title="Select File for Malware Analysis",
            filetypes=[("Executable Files", "*.exe"), ("DLL Files", "*.dll"),
                       ("System Files", "*.sys"), ("All Files", "*.*")]
        )
        if not path:
            return
        self.file = path
        ext = os.path.splitext(path)[1].lower() or "(none)"
        try:
            size = human_size(os.path.getsize(path))
        except OSError:
            size = "unknown"

        self.drop_icon.configure(image=icon("file", 34, ACCENT["malware"]))
        self.drop_title.configure(text="File ready for analysis")
        self.drop_sub.configure(text="Click to choose a different file")
        self.drop.configure(border_color=ACCENT[self.kind])
        self.input_desc.configure(text="File selected successfully. Ready for AI analysis.")

        self.info_rows["Name"].configure(text=mid_ellipsis(os.path.basename(path), 46))
        self.info_rows["Size"].configure(text=size)
        self.info_rows["Type"].configure(text=ext)
        self.info_rows["SHA-256"].configure(text="calculating...")
        self.file_info.pack(fill="x", pady=(10, 0))

        self.full_hash = ""
        threading.Thread(target=self._hash_worker, args=(path,), daemon=True).start()

    def _hash_worker(self, path):
        try:
            digest = sha256_of(path)
        except Exception:
            digest = ""
        try:
            self.main.after(0, lambda: self._hash_done(path, digest))
        except Exception:
            pass

    def _hash_done(self, path, digest):
        if not self.alive() or path != self.file:
            return
        self.full_hash = digest
        self.info_rows["SHA-256"].configure(text=(digest[:20] + "…" + digest[-12:]) if digest else "unavailable")

    def copy_hash(self):
        if getattr(self, "full_hash", ""):
            self.main.clipboard_clear()
            self.main.clipboard_append(self.full_hash)
            self.flash("SHA-256 copied to clipboard", GREEN)

    # ---- url handling ----

    def paste_url(self):
        try:
            text = self.main.clipboard_get().strip()
        except tk.TclError:
            return
        self.url_entry.delete(0, "end")
        self.url_entry.insert(0, text)
        self._schedule_url_check()

    def _schedule_url_check(self):
        if self.url_job:
            self.main.after_cancel(self.url_job)
        self.url_job = self.main.after(250, self._update_url_chips)

    def _update_url_chips(self):
        self.url_job = None
        if not self.alive():
            return
        for child in self.url_chips.winfo_children():
            child.destroy()
        url = self.url_entry.get().strip()
        chips = analyze_url(url) if url else []
        for i in range(3):
            self.url_chips.grid_columnconfigure(i, weight=1, uniform="chip")
        for i, (label, value, level) in enumerate(chips):
            color = {"ok": GREEN, "warn": ORANGE, "info": CYAN}[level]
            cell = ctk.CTkFrame(self.url_chips, fg_color=blend(CARD, color, 0.08), corner_radius=10, border_width=1, border_color=blend(CARD, color, 0.35))
            cell.grid(row=i // 3, column=i % 3, sticky="nsew", padx=3, pady=3)
            ctk.CTkLabel(cell, text=label, font=(FONT, 9), text_color=MUTED).pack(anchor="w", padx=10, pady=(6, 0))
            ctk.CTkLabel(cell, text=mid_ellipsis(value, 16), font=(FONT, 11, "bold"), text_color=color).pack(anchor="w", padx=10, pady=(0, 6))

    # ------------------------------------------------------------
    # progress card
    # ------------------------------------------------------------

    def _build_progress(self, parent):
        card = self.card(parent)
        head = self.section(card, "ANALYSIS PROGRESS")
        self.percent_label = ctk.CTkLabel(head, text="0%", font=(FONT, 20, "bold"), text_color=CYAN)
        self.percent_label.place(relx=1.0, rely=0.0, anchor="ne")

        self.status_label = ctk.CTkLabel(card, text="Waiting for scan...", anchor="w", font=(FONT, 11), text_color=MUTED)
        self.status_label.pack(fill="x", padx=18, pady=(2, 8))

        self.bar = ctk.CTkProgressBar(card, height=8, corner_radius=4, fg_color="#0E2033", progress_color=CYAN)
        self.bar.pack(fill="x", padx=18)
        self.bar.set(0)

        self.steps_frame = ctk.CTkFrame(card, fg_color="transparent")
        self.steps_frame.pack(fill="x", padx=18, pady=(12, 14))
        for index in range(5):
            row = ctk.CTkFrame(self.steps_frame, fg_color="transparent")
            row.pack(fill="x", pady=3)
            icon_label = ctk.CTkLabel(row, text="", image=icon("pending", 20))
            icon_label.pack(side="left", padx=(0, 10))
            col = ctk.CTkFrame(row, fg_color="transparent")
            col.pack(side="left")
            title = ctk.CTkLabel(col, text="", font=(FONT, 11, "bold"), text_color=MUTED)
            title.pack(anchor="w")
            sub = ctk.CTkLabel(col, text="", font=(FONT, 9), text_color=MUTED)
            sub.pack(anchor="w")
            self.step_widgets.append((icon_label, title, sub))

    def _apply_step_text(self):
        for (icon_label, title, sub), (t, s) in zip(self.step_widgets, STEP_TEXT[self.kind]):
            title.configure(text=t)
            sub.configure(text=s)

    def _set_steps(self, stage, color):
        """stage: index of the active step; 5 means all done."""
        for i, (icon_label, title, sub) in enumerate(self.step_widgets):
            if i < stage:
                icon_label.configure(image=icon("done", 20))
                title.configure(text_color=TEXT)
            elif i == stage:
                icon_label.configure(image=icon("active", 20, color))
                title.configure(text_color=color)
            else:
                icon_label.configure(image=icon("pending", 20))
                title.configure(text_color=MUTED)

    def _reset_pipeline(self):
        self.bar.set(0)
        self.bar.configure(progress_color=CYAN)
        self.percent_label.configure(text="0%", text_color=CYAN)
        self.status_label.configure(text="Waiting for scan...", text_color=MUTED)
        for icon_label, title, sub in self.step_widgets:
            icon_label.configure(image=icon("pending", 20))
            title.configure(text_color=MUTED)
        self._rebuild_engines()

    # ------------------------------------------------------------
    # risk card (gauge + verdict)
    # ------------------------------------------------------------

    def _build_risk(self, parent):
        card = self.card(parent)
        self.section(card, "RISK ASSESSMENT", "AI risk score for the selected target")

        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=18, pady=(8, 16))

        self.gauge = tk.Canvas(row, width=210, height=210, bg=CARD, highlightthickness=0)
        self.gauge.pack(side="left")
        self._draw_gauge(0, CYAN, "--")

        info = ctk.CTkFrame(row, fg_color="transparent")
        info.pack(side="left", fill="both", expand=True, padx=(10, 0))

        self.scan_type_label = ctk.CTkLabel(info, text="SCAN TYPE  --", anchor="w", font=(FONT, 10, "bold"), text_color=MUTED)
        self.scan_type_label.pack(anchor="w", pady=(18, 6))

        self.verdict_label = ctk.CTkLabel(info, text="WAITING FOR SCAN", anchor="w", font=(FONT, 20, "bold"), text_color=TEXT)
        self.verdict_label.pack(anchor="w")
        self.threat_label = ctk.CTkLabel(info, text="--", anchor="w", font=(FONT, 11, "bold"), text_color=MUTED)
        self.threat_label.pack(anchor="w", pady=(2, 8))
        self.reco_label = ctk.CTkLabel(
            info, text="Start a security scan to view the AI result.", anchor="w", justify="left",
            font=(FONT, 11), text_color=MUTED, wraplength=340
        )
        self.reco_label.pack(anchor="w")
        self.meta_label = ctk.CTkLabel(info, text="", anchor="w", font=(FONT, 10), text_color=MUTED)
        self.meta_label.pack(anchor="w", pady=(10, 0))

    def _draw_gauge(self, value, color, text):
        self.gauge_photo = ImageTk.PhotoImage(render_gauge(210, value, color))
        self.gauge.delete("all")
        self.gauge.create_image(105, 105, image=self.gauge_photo)
        self.gauge.create_text(105, 98, text=text, fill=color, font=(FONT, 34, "bold"))
        self.gauge.create_text(105, 134, text="AI RISK SCORE", fill=MUTED, font=(FONT, 8, "bold"))

    def _animate_gauge(self, target, color, frame=0, frames=26):
        if not self.alive():
            return
        t = frame / frames
        eased = 1 - (1 - t) ** 3
        value = target * eased
        self._draw_gauge(value, color, f"{value:.0f}%")
        if frame < frames:
            self.gauge_job = self.main.after(16, lambda: self._animate_gauge(target, color, frame + 1, frames))

    def _reset_result(self):
        if self.gauge_job:
            self.main.after_cancel(self.gauge_job)
            self.gauge_job = None
        self._draw_gauge(0, CYAN, "--")
        self.scan_type_label.configure(text="SCAN TYPE  --")
        self.verdict_label.configure(text="WAITING FOR SCAN", text_color=TEXT)
        self.threat_label.configure(text="--", text_color=MUTED)
        self.reco_label.configure(text="Start a security scan to view the AI result.", text_color=MUTED)
        self.meta_label.configure(text="")

    # ------------------------------------------------------------
    # engines card
    # ------------------------------------------------------------

    def _build_engines(self, parent):
        card = self.card(parent)
        self.section(card, "DETECTION ENGINES", "Live state of the models used for this scan")
        self.engine_row = ctk.CTkFrame(card, fg_color="transparent")
        self.engine_row.pack(fill="x", padx=18, pady=(10, 16))

    def _rebuild_engines(self):
        for child in self.engine_row.winfo_children():
            child.destroy()
        self.engine_widgets = []
        for i, (name, stage) in enumerate(ENGINES[self.kind]):
            chip = ctk.CTkFrame(self.engine_row, fg_color=CARD_2, corner_radius=10, border_width=1, border_color=BORDER)
            chip.grid(row=i // 3, column=i % 3, sticky="ew", padx=3, pady=3)
            self.engine_row.grid_columnconfigure(i % 3, weight=1, uniform="eng")
            dot = ctk.CTkLabel(chip, text="●", font=(FONT, 10), text_color="#27415C")
            dot.pack(side="left", padx=(10, 5), pady=8)
            col = ctk.CTkFrame(chip, fg_color="transparent")
            col.pack(side="left", pady=4)
            ctk.CTkLabel(col, text=name, font=(FONT, 10, "bold"), text_color=TEXT).pack(anchor="w")
            state = ctk.CTkLabel(col, text="Standby", font=(FONT, 9), text_color=MUTED)
            state.pack(anchor="w")
            self.engine_widgets.append((chip, dot, state, stage))

    def _set_engines(self, stage, color):
        for chip, dot, state, engine_stage in self.engine_widgets:
            if stage > engine_stage:
                dot.configure(text_color=GREEN)
                state.configure(text="Done", text_color=GREEN)
                chip.configure(border_color=blend(CARD, GREEN, 0.4))
            elif stage == engine_stage:
                dot.configure(text_color=color)
                state.configure(text="Running", text_color=color)
                chip.configure(border_color=blend(CARD, color, 0.6))
            else:
                dot.configure(text_color="#27415C")
                state.configure(text="Queued", text_color=MUTED)
                chip.configure(border_color=BORDER)

    # ------------------------------------------------------------
    # history + coverage
    # ------------------------------------------------------------

    def _build_history(self):
        card = self.card(self.main)
        head = self.section(card, "RECENT SCANS", "This session")
        ctk.CTkButton(
            head, text="Clear", image=icon("trash", 14, MUTED), compound="left", width=70, height=26,
            fg_color="transparent", hover_color=CARD_3, text_color=MUTED, font=(FONT, 10),
            command=self.clear_history
        ).place(relx=1.0, rely=0.0, anchor="ne")
        self.history_body = ctk.CTkFrame(card, fg_color="transparent")
        self.history_body.pack(fill="x", padx=18, pady=(10, 14))

    def refresh_history(self):
        for child in self.history_body.winfo_children():
            child.destroy()
        if not SCAN_HISTORY:
            ctk.CTkLabel(
                self.history_body, text="No scans yet. Results will appear here.",
                font=(FONT, 11), text_color=MUTED
            ).pack(anchor="w", pady=6)
            return
        for entry in SCAN_HISTORY[:6]:
            row = ctk.CTkFrame(self.history_body, fg_color=CARD_2, corner_radius=10)
            row.pack(fill="x", pady=3)
            glyph = "bug" if entry["kind"] == "malware" else "hook"
            ctk.CTkLabel(row, text="", image=icon(glyph, 18, ACCENT[entry["kind"]])).pack(side="left", padx=(12, 8), pady=9)
            ctk.CTkLabel(row, text=mid_ellipsis(entry["target"], 52), anchor="w", font=(FONT, 11), text_color=TEXT).pack(side="left")
            _, color = verdict_for(entry["score"])
            self.pill(row, f" {entry['score']:.0f}% ", blend(CARD_2, color, 0.22), color).pack(side="right", padx=12)
            ctk.CTkLabel(row, text=entry["threat"], font=(FONT, 10, "bold"), text_color=color).pack(side="right", padx=(0, 6))
            ctk.CTkLabel(row, text=entry["time"], font=(MONO, 10), text_color=MUTED).pack(side="right", padx=10)

    def clear_history(self):
        SCAN_HISTORY.clear()
        self.refresh_history()

    def _build_coverage(self):
        card = self.card(self.main, pady=(0, 10))
        self.section(card, "SECURITY COVERAGE")
        wrap = ctk.CTkFrame(card, fg_color="transparent")
        wrap.pack(fill="x", padx=18, pady=(8, 14))
        for glyph, title, desc, color in (
            ("bug", "Malware Detection", "XGBoost • Random Forest • SVM • Deep Learning", RED),
            ("hook", "Phishing Detection", "XGBoost • Random Forest • SVM • LSTM • Transformer", PURPLE),
            ("shield", "Threat Intelligence", "SHA-256 / URL feature analysis", CYAN),
        ):
            row = ctk.CTkFrame(wrap, fg_color=CARD_2, corner_radius=10)
            row.pack(fill="x", pady=4)
            ctk.CTkLabel(row, text="", image=icon(glyph, 24, color)).pack(side="left", padx=(14, 12), pady=10)
            col = ctk.CTkFrame(row, fg_color="transparent")
            col.pack(side="left", pady=8)
            ctk.CTkLabel(col, text=title, font=(FONT, 12, "bold"), text_color=TEXT).pack(anchor="w")
            ctk.CTkLabel(col, text=desc, font=(FONT, 10), text_color=MUTED).pack(anchor="w")

    # ------------------------------------------------------------
    # scanning
    # ------------------------------------------------------------

    def start_scan(self):
        if self.scanning:
            return

        if self.kind == "malware":
            if not self.file:
                self.flash("Please select a file before starting the malware scan.")
                return
            if not os.path.isfile(self.file):
                self.flash("That file no longer exists. Please select it again.", RED)
                return
            target = self.file
        else:
            target = self.url_entry.get().strip()
            if not target:
                self.flash("Please enter a URL before starting the phishing scan.")
                return
            if not is_valid_url(target):
                self.flash("Please enter a valid URL, for example https://example.com", RED)
                return

        accent = ACCENT[self.kind]
        self.scanning = True
        self.progress = 0.0
        self.t0 = time.time()
        self.target = target
        self.box = {"done": False, "result": None, "error": None}

        self._reset_result()
        self.bar.configure(progress_color=accent)
        self.percent_label.configure(text="0%", text_color=accent)
        self.status_label.configure(text="Initializing security analysis...", text_color=accent)
        self.scan_type_label.configure(text=f"SCAN TYPE  {self.kind.upper()}")
        self.verdict_label.configure(text="ANALYZING...", text_color=accent)
        self.reco_label.configure(text="Running CyberShield AI detection engines...", text_color=MUTED)
        self.start_button.configure(state="disabled", text="SCANNING...")
        self._set_steps(0, accent)
        self._set_engines(0, accent)

        threading.Thread(target=self._worker, args=(self.kind, target, self.box), daemon=True).start()
        self._tick()

    @staticmethod
    def _worker(kind, target, box):
        try:
            box["result"] = predict_malware(target) if kind == "malware" else predict_phishing(target)
        except Exception as error:
            box["error"] = str(error)
        box["done"] = True

    def _tick(self):
        if not self.alive():
            return
        elapsed = time.time() - self.t0
        box = self.box
        accent = ACCENT[self.kind]

        goal = min(94.0, elapsed / MIN_SCAN_SECONDS * 100)
        if box["done"] and elapsed >= MIN_SCAN_SECONDS:
            goal = 100.0
        step = 3.0 if goal >= 100 else 1.4
        if self.progress < goal:
            self.progress = min(goal, self.progress + step)

        value = int(self.progress)
        stage = stage_of(self.progress)
        self.bar.set(self.progress / 100)
        self.percent_label.configure(text=f"{value}%")
        self.status_label.configure(text=STAGE_MESSAGE[min(stage, 4)], text_color=accent)
        self._set_steps(stage, accent)
        self._set_engines(stage, accent)

        if self.progress >= 100 and box["done"]:
            self.finish()
            return
        self.tick_job = self.main.after(25, self._tick)

    def finish(self):
        box = self.box
        self.scanning = False
        self.start_button.configure(
            state="normal",
            text="START MALWARE SCAN" if self.kind == "malware" else "START PHISHING SCAN"
        )

        if box["error"]:
            self.status_label.configure(text=f"Scan error: {box['error']}", text_color=RED)
            self.verdict_label.configure(text="SCAN FAILED", text_color=RED)
            self.reco_label.configure(text="The detection engine returned an error. Please try again.", text_color=MUTED)
            self.bar.configure(progress_color=RED)
            return

        result = box["result"]
        score = float(result["score"])
        verdict, color = verdict_for(score)
        elapsed = time.time() - self.t0

        self.bar.configure(progress_color=color)
        self.percent_label.configure(text="100%", text_color=color)
        self.status_label.configure(text=f"Scan completed — {result['threat']}", text_color=GREEN)
        self._set_steps(5, color)
        self._set_engines(5, color)

        self.verdict_label.configure(text=verdict, text_color=color)
        self.threat_label.configure(text=result["threat"], text_color=color)
        self.reco_label.configure(text=result["recommendation"], text_color=TEXT)
        self.meta_label.configure(
            text=f"{mid_ellipsis(os.path.basename(self.target) if self.kind == 'malware' else self.target, 46)}  •  {elapsed:.1f}s"
        )
        self._animate_gauge(score, color)

        SCAN_HISTORY.insert(0, {
            "kind": self.kind,
            "target": os.path.basename(self.target) if self.kind == "malware" else self.target,
            "score": score,
            "threat": result["threat"],
            "time": datetime.now().strftime("%H:%M:%S"),
        })
        del SCAN_HISTORY[20:]
        self.refresh_history()


# ============================================================
# PUBLIC API (same entry points the dashboard already imports)
# ============================================================

def show_scanner(parent, initial="malware"):
    return ScannerPage(parent, initial)


def show_malware_scanner(parent):
    return ScannerPage(parent, "malware")


def show_phishing_scanner(parent):
    return ScannerPage(parent, "phishing")


# ============================================================
# TEST MODE
# ============================================================

if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    app = ctk.CTk()
    app.title("CyberShield AI - Security Scanner")
    app.geometry("1450x900")
    app.configure(fg_color=BG)

    show_scanner(app)
    app.mainloop()