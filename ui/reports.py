import csv
import importlib
import math
import os
from datetime import date, datetime, timedelta
from tkinter import filedialog
import tkinter as tk
import tkinter.font as tkfont

import customtkinter as ctk

try:
    from PIL import Image, ImageDraw, ImageFilter, ImageFont, ImageTk
except Exception:  # Pillow ships with customtkinter
    Image = ImageDraw = ImageFilter = ImageFont = ImageTk = None


# ============================================================
# CYBERSHIELD AI - REPORT CENTER
# Same palette as the dashboard and scanner pages.
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

RISK_COLOR = {"HIGH": RED, "MEDIUM": ORANGE, "LOW": GREEN}
TYPE_COLOR = {"Malware": RED, "Phishing": ORANGE}

FONT = "Segoe UI"
MONO = "Consolas"

DATE_FORMAT = "%d %b %Y"
FIELDS = ["id", "type", "target", "risk", "score", "date", "status"]


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
# REPORT DATA
# SAMPLE_REPORTS is demo data. Scans made in this session (from the scanner
# page) are added on top automatically. Replace load_reports() with a
# database query when you are ready.
# ============================================================

SAMPLE_REPORTS = [
    {"id": "RPT-00128", "type": "Malware", "target": "suspicious.exe", "risk": "HIGH", "score": 87, "date": "22 Sep 2026", "status": "Threat Detected"},
    {"id": "RPT-00127", "type": "Phishing", "target": "secure-login.xyz", "risk": "HIGH", "score": 92, "date": "22 Sep 2026", "status": "Phishing Detected"},
    {"id": "RPT-00126", "type": "Malware", "target": "setup.exe", "risk": "LOW", "score": 18, "date": "21 Sep 2026", "status": "Clean"},
    {"id": "RPT-00125", "type": "Phishing", "target": "example-login.com", "risk": "MEDIUM", "score": 61, "date": "21 Sep 2026", "status": "Suspicious"},
    {"id": "RPT-00124", "type": "Malware", "target": "document.exe", "risk": "HIGH", "score": 84, "date": "20 Sep 2026", "status": "Threat Detected"},
]

# Modules that may expose SCAN_HISTORY (the scanner page). First one that imports wins.
HISTORY_SOURCES = ("ui.security_scanner", "ui.scanner_page", "security_scanner", "scanner_page")


def risk_from_score(score):
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def session_reports():
    """Reports built from scans done in this session (empty if the scanner is not importable)."""
    history = []
    for name in HISTORY_SOURCES:
        try:
            module = importlib.import_module(name)
            history = list(getattr(module, "SCAN_HISTORY", []))
            break
        except Exception:
            continue

    out = []
    today = date.today().strftime(DATE_FORMAT)
    for number, entry in enumerate(reversed(history), start=1):
        score = int(round(entry["score"]))
        out.append({
            "id": f"RPT-S{number:04d}",
            "type": "Malware" if entry["kind"] == "malware" else "Phishing",
            "target": entry["target"],
            "risk": risk_from_score(score),
            "score": score,
            "date": today,
            "status": entry["threat"].title(),
            "live": True,
        })
    out.reverse()
    return out


def load_reports():
    return session_reports() + [dict(r) for r in SAMPLE_REPORTS]


def parse_date(text):
    try:
        return datetime.strptime(text, DATE_FORMAT).date()
    except Exception:
        return date.min


def recommendation_for(report):
    """Advice matches the risk level (the old text told you to isolate even clean files)."""
    if report["risk"] == "HIGH":
        if report["type"] == "Malware":
            return "Isolate the detected file and perform further analysis."
        return "Avoid entering credentials and verify the website source."
    if report["risk"] == "MEDIUM":
        if report["type"] == "Malware":
            return "Perform additional analysis before opening the file."
        return "Verify the domain before continuing."
    if report["type"] == "Malware":
        return "No strong malware indicators were detected. No action required."
    return "No strong phishing indicators were detected. No action required."


def day_series(reports, max_days=14):
    """[(date, {"HIGH": n, "MEDIUM": n, "LOW": n}), ...] over a continuous range of days."""
    days = {}
    for r in reports:
        d = parse_date(r["date"])
        if d == date.min:
            continue
        days.setdefault(d, {"HIGH": 0, "MEDIUM": 0, "LOW": 0})[r["risk"]] += 1
    if not days:
        return []
    end = max(days)
    start = max(min(days), end - timedelta(days=max_days - 1))
    series = []
    day = start
    while day <= end:
        series.append((day, days.get(day, {"HIGH": 0, "MEDIUM": 0, "LOW": 0})))
        day += timedelta(days=1)
    return series


# ============================================================
# ARTWORK (drawn in code, supersampled, so it is always sharp)
# ============================================================

SS = 3
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


def _glow(img, radius, strength=0.5):
    halo = img.filter(ImageFilter.GaussianBlur(radius))
    halo.putalpha(halo.getchannel("A").point(lambda v: int(min(255, v * strength))))
    out = Image.new("RGBA", img.size, (0, 0, 0, 0))
    out.alpha_composite(halo)
    out.alpha_composite(img)
    return out


def draw_icon(name, size, color=CYAN):
    """High-resolution RGBA icon (scaled down by CTkImage)."""
    S = ICON_SS
    n = size * S
    img = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    c = rgb(color)
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
    elif name == "shield":
        d.line(_shield(12 * u, 12.4 * u, 17 * u, 20 * u), fill=c, width=w, joint="curve")
        d.line([(8.4 * u, 12.4 * u), (11 * u, 15 * u), (16 * u, 9.6 * u)], fill=c, width=w, joint="curve")
    elif name == "reports":
        d.rounded_rectangle([4.5 * u, 3 * u, 19.5 * u, 21 * u], radius=2.2 * u, outline=c, width=w)
        d.line([(8 * u, 15 * u), (8 * u, 18 * u)], fill=c, width=w)
        d.line([(12 * u, 11 * u), (12 * u, 18 * u)], fill=c, width=w)
        d.line([(16 * u, 7.5 * u), (16 * u, 18 * u)], fill=c, width=w)
    elif name == "search":
        d.ellipse([3.5 * u, 3.5 * u, 16 * u, 16 * u], outline=c, width=w)
        d.line([(14.2 * u, 14.2 * u), (20.5 * u, 20.5 * u)], fill=c, width=w)
    elif name == "download":
        d.line([(12 * u, 3.5 * u), (12 * u, 15 * u)], fill=c, width=w)
        d.line([(7 * u, 10.5 * u), (12 * u, 15.5 * u), (17 * u, 10.5 * u)], fill=c, width=w, joint="curve")
        d.line([(4.5 * u, 15 * u), (4.5 * u, 20 * u), (19.5 * u, 20 * u), (19.5 * u, 15 * u)], fill=c, width=w, joint="curve")
    elif name == "pdf":
        pts = [(5 * u, 2.5 * u), (14 * u, 2.5 * u), (19 * u, 7.5 * u), (19 * u, 21.5 * u), (5 * u, 21.5 * u), (5 * u, 2.5 * u)]
        d.line(pts, fill=c, width=w, joint="curve")
        d.line([(14 * u, 2.5 * u), (14 * u, 7.5 * u), (19 * u, 7.5 * u)], fill=c, width=w, joint="curve")
        d.line([(8 * u, 14 * u), (16 * u, 14 * u)], fill=c, width=int(w * 0.8))
        d.line([(8 * u, 17.5 * u), (13 * u, 17.5 * u)], fill=c, width=int(w * 0.8))
    elif name == "eye":
        top = _bezier((2.5 * u, 12 * u), (6 * u, 5.5 * u), (18 * u, 5.5 * u), (21.5 * u, 12 * u))
        bot = _bezier((2.5 * u, 12 * u), (6 * u, 18.5 * u), (18 * u, 18.5 * u), (21.5 * u, 12 * u))
        d.line(top, fill=c, width=w, joint="curve")
        d.line(bot, fill=c, width=w, joint="curve")
        d.ellipse([9 * u, 9 * u, 15 * u, 15 * u], outline=c, width=w)
    elif name == "close":
        d.line([(6 * u, 6 * u), (18 * u, 18 * u)], fill=c, width=w)
        d.line([(18 * u, 6 * u), (6 * u, 18 * u)], fill=c, width=w)
    elif name == "arrow_up":
        d.polygon([(12 * u, 7 * u), (17 * u, 15 * u), (7 * u, 15 * u)], fill=c)
    elif name == "arrow_down":
        d.polygon([(12 * u, 17 * u), (17 * u, 9 * u), (7 * u, 9 * u)], fill=c)
    elif name == "info":
        d.ellipse([3 * u, 3 * u, 21 * u, 21 * u], outline=c, width=w)
        d.line([(12 * u, 11 * u), (12 * u, 17 * u)], fill=c, width=w)
        d.ellipse([11 * u, 6.6 * u, 13 * u, 8.6 * u], fill=c)
    return _glow(img, 1.8 * S, 0.45)


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


def render_donut(size, counts, colors, ring=16, pad=8, gap=2.0):
    """Donut for counts; draws only the track when everything is zero."""
    S = 4
    N = size * S
    img = Image.new("RGBA", (N, N), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    box = [pad * S, pad * S, (size - pad) * S, (size - pad) * S]
    d.arc(box, 0, 360, fill=rgb("#0E2033"), width=ring * S)
    total = sum(counts)
    if total:
        start = -90.0
        nonzero = sum(1 for v in counts if v)
        for count, color in zip(counts, colors):
            if not count:
                continue
            extent = 360.0 * count / total
            g = gap if nonzero > 1 else 0
            d.arc(box, start + g / 2, start + extent - g / 2, fill=rgb(color), width=ring * S)
            start += extent
    return img.resize((size, size), RESAMPLE)


def render_activity(w, h, series):
    """Stacked bars (LOW at the bottom, HIGH on top), drawn supersampled at w x h.

    Returns (PIL image, layout) where layout has the plot box, y ticks, x labels and bar hit boxes."""
    left, right, top, bottom = 34, 10, 12, 28
    plot = (left, top, w - right, h - bottom)
    pw, ph = plot[2] - plot[0], plot[3] - plot[1]

    peak = max([sum(counts.values()) for _, counts in series] + [1])
    step = 1 if peak <= 4 else int(math.ceil(peak / 4))
    top_value = step * int(math.ceil(peak / step))

    img = Image.new("RGB", (w * SS, h * SS), rgb(CARD))
    d = ImageDraw.Draw(img)

    ticks = []
    for value in range(0, top_value + 1, step):
        y = plot[3] - ph * value / top_value
        ticks.append((y, value))
        dash = 0
        while dash < pw:
            d.line([((plot[0] + dash) * SS, y * SS), ((plot[0] + min(dash + 4, pw)) * SS, y * SS)],
                   fill=rgb("#10263A" if value else "#1B3855"), width=int(1 * SS))
            dash += 8

    slot = pw / max(len(series), 1)
    bar_w = max(6, min(38, slot * 0.56))
    bars, labels = [], []
    every = 1 if slot >= 44 else 2
    for i, (day, counts) in enumerate(series):
        cx = plot[0] + slot * (i + 0.5)
        x0, x1 = cx - bar_w / 2, cx + bar_w / 2
        y = plot[3]
        segments = [(k, counts[k]) for k in ("LOW", "MEDIUM", "HIGH") if counts[k]]
        for index, (key, count) in enumerate(segments):
            seg_h = ph * count / top_value
            y_top = y - seg_h
            box = [x0 * SS, (y_top + 1) * SS, x1 * SS, (y - 1) * SS]
            is_top = index == len(segments) - 1
            try:
                d.rounded_rectangle(box, radius=4 * SS, fill=rgb(RISK_COLOR[key]),
                                    corners=(is_top, is_top, False, False))
            except TypeError:
                d.rectangle(box, fill=rgb(RISK_COLOR[key]))
            y = y_top
        bars.append((x0, x1, plot[1], plot[3], day, counts))
        if i % every == 0:
            labels.append((cx, day.strftime("%d %b")))

    layout = {"plot": plot, "ticks": ticks, "labels": labels, "bars": bars}
    return img.resize((w, h), RESAMPLE), layout


# ============================================================
# PDF (pure function so it can be tested without any window)
# ============================================================

def build_pdf(report, path):
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    risk = report["risk"]
    risk_hex = {"HIGH": "#D92D43", "MEDIUM": "#D98B14", "LOW": "#12A67A"}[risk]
    brand = colors.HexColor("#06111C")
    accent = colors.HexColor("#12C8FF")
    risk_color = colors.HexColor(risk_hex)

    styles = getSampleStyleSheet()
    label = ParagraphStyle("label", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=9, textColor=colors.HexColor("#5B7288"), alignment=TA_LEFT)
    value = ParagraphStyle("value", parent=styles["BodyText"], fontName="Helvetica", fontSize=10.5, textColor=colors.HexColor("#101820"))
    score_big = ParagraphStyle("score_big", parent=value, fontName="Helvetica-Bold", fontSize=28, leading=34)
    score_mid = ParagraphStyle("score_mid", parent=value, fontName="Helvetica-Bold", fontSize=13, leading=34)
    body = ParagraphStyle("body", parent=styles["BodyText"], fontName="Helvetica", fontSize=10.5, leading=15, textColor=colors.HexColor("#101820"))
    small = ParagraphStyle("small", parent=styles["BodyText"], fontName="Helvetica", fontSize=8.5, textColor=colors.HexColor("#6B7F92"))
    white_big = ParagraphStyle("wb", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=20, textColor=colors.white, alignment=TA_LEFT, leading=24)
    white_small = ParagraphStyle("ws", parent=styles["BodyText"], fontName="Helvetica", fontSize=10, textColor=colors.HexColor("#9BD8EE"))
    section = ParagraphStyle("section", parent=styles["Heading3"], fontName="Helvetica-Bold", fontSize=11, textColor=colors.HexColor("#101820"), spaceBefore=14, spaceAfter=6)

    width = A4[0] - 40 * mm
    document = SimpleDocTemplate(
        path, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm, topMargin=18 * mm, bottomMargin=18 * mm,
        title=f"CyberShield AI - {report['id']}", author="CyberShield AI",
    )
    story = []

    banner = Table(
        [[Paragraph("CYBERSHIELD AI", white_big)], [Paragraph("Security Detection Report", white_small)]],
        colWidths=[width],
    )
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), brand),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (0, 0), 14),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 14),
        ("LINEBELOW", (0, -1), (-1, -1), 3, accent),
    ]))
    story += [banner, Spacer(1, 16)]

    score_box = Table(
        [[Paragraph("AI RISK SCORE", label), Paragraph("RISK LEVEL", label), Paragraph("STATUS", label)],
         [Paragraph(f'<font color="{risk_hex}"><b>{report["score"]}%</b></font>', score_big),
          Paragraph(f'<font color="{risk_hex}"><b>{risk}</b></font>', score_mid),
          Paragraph(f'<b>{report["status"]}</b>', score_mid)]],
        colWidths=[width * 0.3, width * 0.3, width * 0.4],
    )
    score_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F2F6F9")),
        ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#D5DEE6")),
        ("LINEBEFORE", (0, 0), (0, -1), 4, risk_color),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story += [score_box, Paragraph("REPORT DETAILS", section)]

    rows = [
        ("Report ID", report["id"]),
        ("Detection Type", report["type"]),
        ("Target", report["target"]),
        ("Date", report["date"]),
    ]
    details = Table([[Paragraph(k, label), Paragraph(v, value)] for k, v in rows], colWidths=[width * 0.28, width * 0.72])
    details.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#F7FAFC")]),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#E0E8EF")),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story += [details, Paragraph("RECOMMENDATION", section)]

    rec = Table([[Paragraph(recommendation_for(report), body)]], colWidths=[width])
    rec.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F2F6F9")),
        ("LINEBEFORE", (0, 0), (0, -1), 3, accent),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story += [rec, Spacer(1, 26)]
    story.append(Paragraph(
        "Generated by CyberShield AI on " + datetime.now().strftime("%d %b %Y, %H:%M")
        + ". Automated analysis; confirm critical findings with a security analyst.", small))
    document.build(story)


def write_csv(reports, path):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        for report in reports:
            writer.writerow(report)


# ============================================================
# REPORT PAGE
# ============================================================

COLUMNS = [
    # key, title, minimum width, weight, sortable
    ("id", "REPORT ID", 100, 0, True),
    ("type", "TYPE", 90, 0, False),
    ("target", "TARGET", 160, 1, False),
    ("risk", "RISK", 92, 0, False),
    ("score", "SCORE", 70, 0, True),
    ("date", "DATE", 104, 0, True),
    ("action", "ACTION", 150, 0, False),
]


class ReportsPage:
    def __init__(self, parent):
        pick_fonts()

        for widget in parent.winfo_children():
            widget.destroy()
        parent.configure(fg_color=BG)

        self.parent = parent
        self.reports = load_reports()
        self.query = ""
        self.type_filter = "All"
        self.risk_filter = "All"
        self.sort_key = "date"
        self.sort_reverse = True
        self.toast_job = None
        self.render_job = None
        self.activity_layout = None
        self.activity_photo = None
        self.donut_photo = None
        self.chip_buttons = {}
        self.sort_labels = {}

        self.scroll = ctk.CTkScrollableFrame(
            parent, fg_color=BG,
            scrollbar_button_color=BORDER, scrollbar_button_hover_color=CYAN
        )
        self.scroll.pack(fill="both", expand=True, padx=18, pady=12)

        self._build_header()
        self.toast_anchor = ctk.CTkFrame(self.scroll, height=1, fg_color="transparent")
        self.toast_anchor.pack(fill="x")
        self.toast = ctk.CTkLabel(
            self.scroll, text="", anchor="w", height=34, corner_radius=8,
            font=(FONT, 11, "bold")
        )
        self._build_notice()
        self._build_stats()
        self._build_charts()
        self._build_table()

        ctk.CTkLabel(
            self.scroll, text="CyberShield AI  •  AI-Powered Malware & Phishing Detection",
            font=(FONT, 10), text_color=MUTED
        ).pack(pady=(4, 16))

        self.refresh_all()

    # ------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------

    def alive(self):
        try:
            return bool(self.scroll.winfo_exists())
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

    def flash(self, message, color=GREEN):
        self.toast.configure(text="  " + message + "  ", text_color=color, fg_color=blend(CARD, color, 0.14))
        self.toast.pack(fill="x", pady=(0, 12), before=self.toast_anchor)
        if self.toast_job:
            self.scroll.after_cancel(self.toast_job)
        self.toast_job = self.scroll.after(4200, lambda: self.alive() and self.toast.pack_forget())

    def filtered(self):
        q = self.query.lower().strip()
        rows = []
        for r in self.reports:
            if self.type_filter != "All" and r["type"] != self.type_filter:
                continue
            if self.risk_filter != "All" and r["risk"] != self.risk_filter.upper():
                continue
            if q and q not in " ".join(str(r[k]) for k in FIELDS).lower():
                continue
            rows.append(r)

        def key(r):
            if self.sort_key == "score":
                return (r["score"], parse_date(r["date"]))
            if self.sort_key == "id":
                return r["id"]
            return (parse_date(r["date"]), r["id"])

        rows.sort(key=key, reverse=self.sort_reverse)
        return rows

    # ------------------------------------------------------------
    # header
    # ------------------------------------------------------------

    def _build_header(self):
        header = ctk.CTkFrame(self.scroll, fg_color="transparent")
        header.pack(fill="x", pady=(2, 16))

        title_area = ctk.CTkFrame(header, fg_color="transparent")
        title_area.pack(side="left", fill="x", expand=True)
        row = ctk.CTkFrame(title_area, fg_color="transparent")
        row.pack(anchor="w")
        ctk.CTkLabel(row, text="", image=icon("reports", 34, CYAN)).pack(side="left", padx=(0, 10))
        col = ctk.CTkFrame(row, fg_color="transparent")
        col.pack(side="left")
        ctk.CTkLabel(col, text="REPORT CENTER", font=(FONT, 24, "bold"), text_color=TEXT).pack(anchor="w")
        ctk.CTkLabel(col, text="Security analysis and detection reports", font=(FONT, 12), text_color=MUTED).pack(anchor="w")

        tools = ctk.CTkFrame(header, fg_color="transparent")
        tools.pack(side="right")

        search_box = ctk.CTkFrame(tools, fg_color=CARD, corner_radius=10, border_width=1, border_color=BORDER)
        search_box.pack(side="left", padx=(0, 8))
        ctk.CTkLabel(search_box, text="", image=icon("search", 16, MUTED)).pack(side="left", padx=(12, 0))
        self.search_entry = ctk.CTkEntry(
            search_box, width=230, height=38, placeholder_text="Search ID, target, status...",
            fg_color="transparent", border_width=0, text_color=TEXT,
            placeholder_text_color=MUTED, font=(FONT, 12)
        )
        self.search_entry.pack(side="left", padx=(4, 6))
        self.search_entry.bind("<KeyRelease>", lambda e: self._on_search())

        ctk.CTkButton(
            tools, text="Export CSV", image=icon("download", 16, "#001018"), compound="left",
            width=124, height=40, corner_radius=10, fg_color=CYAN, hover_color=BLUE,
            text_color="#001018", font=(FONT, 12, "bold"), command=self.export_csv
        ).pack(side="left")

    def _on_search(self):
        self.query = self.search_entry.get()
        if self.render_job:
            self.scroll.after_cancel(self.render_job)
        self.render_job = self.scroll.after(150, self.render_table)

    # ------------------------------------------------------------
    # notice (sample data)
    # ------------------------------------------------------------

    def _build_notice(self):
        self.notice = ctk.CTkFrame(
            self.scroll, fg_color=blend(CARD, CYAN, 0.07), corner_radius=10,
            border_width=1, border_color=blend(CARD, CYAN, 0.30)
        )
        ctk.CTkLabel(self.notice, text="", image=icon("info", 16, CYAN)).pack(side="left", padx=(12, 8), pady=9)
        self.notice_text = ctk.CTkLabel(self.notice, text="", anchor="w", font=(FONT, 11), text_color=TEXT)
        self.notice_text.pack(side="left", fill="x", expand=True, pady=9, padx=(0, 12))

    def _update_notice(self):
        samples = sum(1 for r in self.reports if not r.get("live"))
        live = len(self.reports) - samples
        if samples:
            text = f"{samples} sample reports are shown for demonstration."
            text += f" {live} from your scans this session." if live else " Run a scan and it will appear here."
            self.notice_text.configure(text=text)
            self.notice.pack(fill="x", pady=(0, 14), before=self.stats_frame)
        else:
            self.notice.pack_forget()

    # ------------------------------------------------------------
    # stats
    # ------------------------------------------------------------

    def _build_stats(self):
        self.stats_frame = ctk.CTkFrame(self.scroll, fg_color="transparent")
        self.stats_frame.pack(fill="x", pady=(0, 14))
        for i in range(4):
            self.stats_frame.grid_columnconfigure(i, weight=1, uniform="stat")
        self.stat_values = []
        spec = (
            ("TOTAL REPORTS", "reports", CYAN),
            ("MALWARE DETECTIONS", "bug", RED),
            ("PHISHING DETECTIONS", "hook", ORANGE),
            ("THREATS BLOCKED", "shield", GREEN),
        )
        for col, (title, glyph, color) in enumerate(spec):
            card = ctk.CTkFrame(self.stats_frame, fg_color=CARD, corner_radius=14, border_width=1, border_color=BORDER)
            card.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else 6, 0 if col == 3 else 6))
            top = ctk.CTkFrame(card, fg_color="transparent")
            top.pack(fill="x", padx=18, pady=(16, 0))
            badge = ctk.CTkFrame(top, width=40, height=40, corner_radius=12, fg_color=blend(CARD, color, 0.14))
            badge.pack(side="left")
            badge.pack_propagate(False)
            ctk.CTkLabel(badge, text="", image=icon(glyph, 22, color)).place(relx=0.5, rely=0.5, anchor="center")
            value = ctk.CTkLabel(top, text="0", font=(FONT, 30, "bold"), text_color=TEXT)
            value.pack(side="right")
            ctk.CTkLabel(card, text=title, font=(FONT, 10, "bold"), text_color=MUTED).pack(anchor="w", padx=18, pady=(10, 0))
            caption = ctk.CTkLabel(card, text="", font=(FONT, 10), text_color=color)
            caption.pack(anchor="w", padx=18, pady=(1, 16))
            self.stat_values.append((value, caption))

    def _update_stats(self):
        total = len(self.reports)
        malware = sum(1 for r in self.reports if r["type"] == "Malware")
        phishing = sum(1 for r in self.reports if r["type"] == "Phishing")
        high = sum(1 for r in self.reports if r["risk"] == "HIGH")

        def share(n):
            return f"{round(100 * n / total)}% of all reports" if total else "No reports yet"

        data = (
            (total, f"{sum(1 for r in self.reports if r.get('live'))} from this session"),
            (malware, share(malware)),
            (phishing, share(phishing)),
            (high, share(high) + " are high risk" if total else "No reports yet"),
        )
        for (value, caption), (n, cap) in zip(self.stat_values, data):
            value.configure(text=str(n))
            caption.configure(text=cap)

    # ------------------------------------------------------------
    # charts
    # ------------------------------------------------------------

    def _build_charts(self):
        row = ctk.CTkFrame(self.scroll, fg_color="transparent")
        row.pack(fill="x", pady=(0, 14))
        row.grid_columnconfigure(0, weight=3, uniform="charts")
        row.grid_columnconfigure(1, weight=2, uniform="charts")

        activity = ctk.CTkFrame(row, fg_color=CARD, corner_radius=14, border_width=1, border_color=BORDER)
        activity.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        head = self.section(activity, "THREAT ACTIVITY", "Scans per day by risk level")

        legend = ctk.CTkFrame(head, fg_color="transparent")
        legend.place(relx=1.0, rely=0.0, anchor="ne")
        for label, color in (("High", RED), ("Medium", ORANGE), ("Low", GREEN)):
            ctk.CTkLabel(legend, text="●", font=(FONT, 10), text_color=color).pack(side="left", padx=(10, 3))
            ctk.CTkLabel(legend, text=label, font=(FONT, 10), text_color=MUTED).pack(side="left")

        self.activity_canvas = tk.Canvas(activity, height=210, bg=CARD, highlightthickness=0)
        self.activity_canvas.pack(fill="x", padx=14, pady=(8, 14))
        self.activity_canvas.bind("<Configure>", lambda e: self._schedule_activity())
        self.activity_canvas.bind("<Motion>", self._activity_hover)
        self.activity_canvas.bind("<Leave>", lambda e: self.activity_canvas.delete("tip"))
        self.activity_job = None

        distribution = ctk.CTkFrame(row, fg_color=CARD, corner_radius=14, border_width=1, border_color=BORDER)
        distribution.grid(row=0, column=1, sticky="nsew", padx=(7, 0))
        self.section(distribution, "THREAT DISTRIBUTION", "Reports by risk level")

        body = ctk.CTkFrame(distribution, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=18, pady=(10, 16))
        self.donut = tk.Canvas(body, width=140, height=140, bg=CARD, highlightthickness=0)
        self.donut.pack(side="left", padx=(0, 16))
        self.dist_rows = ctk.CTkFrame(body, fg_color="transparent")
        self.dist_rows.pack(side="left", fill="both", expand=True)

    def _schedule_activity(self):
        if self.activity_job:
            self.scroll.after_cancel(self.activity_job)
        self.activity_job = self.scroll.after(60, self._draw_activity)

    def _draw_activity(self):
        self.activity_job = None
        if not self.alive():
            return
        c = self.activity_canvas
        w, h = c.winfo_width(), c.winfo_height()
        if w < 80 or h < 80:
            return
        c.delete("all")
        series = day_series(self.reports)
        if not series:
            c.create_text(w / 2, h / 2, text="No reports to chart yet", fill=MUTED, font=(FONT, 11))
            self.activity_layout = None
            return
        img, layout = render_activity(w, h, series)
        self.activity_photo = ImageTk.PhotoImage(img)
        c.create_image(0, 0, image=self.activity_photo, anchor="nw")
        left = layout["plot"][0]
        for y, value in layout["ticks"]:
            c.create_text(left - 8, y, text=str(value), anchor="e", fill=MUTED, font=(FONT, 9))
        for x, text in layout["labels"]:
            c.create_text(x, layout["plot"][3] + 14, text=text, fill=MUTED, font=(FONT, 9))
        self.activity_layout = layout

    def _activity_hover(self, event):
        c = self.activity_canvas
        c.delete("tip")
        layout = self.activity_layout
        if not layout:
            return
        for x0, x1, y0, y1, day, counts in layout["bars"]:
            pad = (x1 - x0) * 0.35
            if x0 - pad <= event.x <= x1 + pad:
                total = sum(counts.values())
                text = f"{day.strftime('%d %b')}  •  {total} scan{'s' if total != 1 else ''}  •  {counts['HIGH']} high"
                tx = min(max(event.x, 90), c.winfo_width() - 90)
                ty = max(event.y - 22, 14)
                t = c.create_text(tx, ty, text=text, fill=TEXT, font=(FONT, 9, "bold"), tags="tip")
                bx0, by0, bx1, by1 = c.bbox(t)
                r = c.create_rectangle(bx0 - 8, by0 - 4, bx1 + 8, by1 + 4, fill=CARD_3, outline=BORDER_HI, tags="tip")
                c.tag_raise(t, r)
                return

    def _update_distribution(self):
        counts = {k: sum(1 for r in self.reports if r["risk"] == k) for k in ("HIGH", "MEDIUM", "LOW")}
        total = len(self.reports)

        self.donut_photo = ImageTk.PhotoImage(
            render_donut(140, [counts["HIGH"], counts["MEDIUM"], counts["LOW"]], [RED, ORANGE, GREEN])
        )
        self.donut.delete("all")
        self.donut.create_image(70, 70, image=self.donut_photo)
        self.donut.create_text(70, 64, text=str(total), fill=TEXT, font=(FONT, 24, "bold"))
        self.donut.create_text(70, 88, text="REPORTS", fill=MUTED, font=(FONT, 8, "bold"))

        for child in self.dist_rows.winfo_children():
            child.destroy()
        for label, key, color in (("High risk", "HIGH", RED), ("Medium risk", "MEDIUM", ORANGE), ("Low risk", "LOW", GREEN)):
            n = counts[key]
            pct = round(100 * n / total) if total else 0
            row = ctk.CTkFrame(self.dist_rows, fg_color="transparent")
            row.pack(fill="x", pady=6)
            top = ctk.CTkFrame(row, fg_color="transparent")
            top.pack(fill="x")
            ctk.CTkLabel(top, text="●", font=(FONT, 10), text_color=color).pack(side="left", padx=(0, 6))
            ctk.CTkLabel(top, text=label, font=(FONT, 11, "bold"), text_color=TEXT).pack(side="left")
            ctk.CTkLabel(top, text=f"{n}  ({pct}%)", font=(FONT, 10), text_color=MUTED).pack(side="right")
            track = ctk.CTkFrame(row, fg_color="#0E2033", height=6, corner_radius=3)
            track.pack(fill="x", pady=(5, 0))
            if n:
                ctk.CTkFrame(track, fg_color=color, height=6, corner_radius=3).place(relx=0, rely=0, relwidth=max(pct / 100, 0.02), relheight=1)

    # ------------------------------------------------------------
    # table
    # ------------------------------------------------------------

    def _build_table(self):
        card = self.card(self.scroll, pady=(0, 10))
        head = self.section(card, "RECENT SECURITY REPORTS", "Latest malware and phishing detection reports")
        self.count_label = ctk.CTkLabel(head, text="", font=(FONT, 11), text_color=MUTED)
        self.count_label.place(relx=1.0, rely=0.0, anchor="ne")

        filters = ctk.CTkFrame(card, fg_color="transparent")
        filters.pack(fill="x", padx=18, pady=(12, 0))
        for group, options, attr in (
            ("Type", ("All", "Malware", "Phishing"), "type_filter"),
            ("Risk", ("All", "High", "Medium", "Low"), "risk_filter"),
        ):
            box = ctk.CTkFrame(filters, fg_color="transparent")
            box.pack(side="left", padx=(0, 22))
            ctk.CTkLabel(box, text=group.upper(), font=(FONT, 9, "bold"), text_color=MUTED).pack(side="left", padx=(0, 8))
            for option in options:
                btn = ctk.CTkButton(
                    box, text=option, width=0, height=26, corner_radius=13, font=(FONT, 11),
                    command=lambda a=attr, o=option: self.set_filter(a, o)
                )
                btn.pack(side="left", padx=2)
                self.chip_buttons[(attr, option)] = btn

        self.table = ctk.CTkFrame(card, fg_color="transparent")
        self.table.pack(fill="x", padx=14, pady=(12, 14))
        for index, (key, title, minimum, weight, sortable) in enumerate(COLUMNS):
            self.table.grid_columnconfigure(index, weight=weight, minsize=minimum)

        head_row = ctk.CTkFrame(self.table, fg_color=CARD_2, corner_radius=8, height=36)
        head_row.grid(row=0, column=0, columnspan=len(COLUMNS), sticky="ew", pady=(0, 4))
        for index, (key, title, minimum, weight, sortable) in enumerate(COLUMNS):
            head_row.grid_columnconfigure(index, weight=weight, minsize=minimum)
            label = ctk.CTkLabel(
                head_row, text=title, anchor="w", font=(FONT, 10, "bold"), text_color=MUTED,
                image=icon("blank", 12), compound="right"
            )
            label.grid(row=0, column=index, sticky="w", padx=(12, 4), pady=9)
            if sortable:
                label.bind("<Button-1>", lambda e, k=key: self.set_sort(k))
                self.sort_labels[key] = label
        self.rows_host = ctk.CTkFrame(self.table, fg_color="transparent")
        self.rows_host.grid(row=1, column=0, columnspan=len(COLUMNS), sticky="ew")
        for index, (key, title, minimum, weight, sortable) in enumerate(COLUMNS):
            self.rows_host.grid_columnconfigure(index, weight=weight, minsize=minimum)

    def set_filter(self, attr, option):
        setattr(self, attr, option)
        self.render_table()

    def set_sort(self, key):
        if self.sort_key == key:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_key = key
            self.sort_reverse = True
        self.render_table()

    def _style_controls(self):
        for (attr, option), btn in self.chip_buttons.items():
            active = getattr(self, attr) == option
            color = CYAN
            if attr == "risk_filter" and option != "All":
                color = RISK_COLOR[option.upper()]
            if attr == "type_filter" and option != "All":
                color = TYPE_COLOR[option]
            if active:
                btn.configure(fg_color=blend(CARD, color, 0.22), hover_color=blend(CARD, color, 0.30),
                              text_color=color, border_width=1, border_color=blend(CARD, color, 0.6))
            else:
                btn.configure(fg_color="transparent", hover_color=CARD_3, text_color=MUTED, border_width=1, border_color=BORDER)
        for key, label in self.sort_labels.items():
            # never pass image=None: CTkLabel would keep showing the previous arrow
            arrow = icon("arrow_down" if self.sort_reverse else "arrow_up", 12, CYAN) if key == self.sort_key else icon("blank", 12)
            label.configure(image=arrow, text_color=CYAN if key == self.sort_key else MUTED)

    def render_table(self):
        self.render_job = None
        if not self.alive():
            return
        self._style_controls()
        for child in self.rows_host.winfo_children():
            child.destroy()

        rows = self.filtered()
        self.count_label.configure(text=f"Showing {len(rows)} of {len(self.reports)}")

        if not rows:
            empty = ctk.CTkLabel(
                self.rows_host, text="No reports match your search or filters.",
                font=(FONT, 12), text_color=MUTED
            )
            empty.grid(row=0, column=0, columnspan=len(COLUMNS), pady=28)
            return

        for r_index, report in enumerate(rows):
            row = ctk.CTkFrame(self.rows_host, fg_color="transparent", corner_radius=8)
            row.grid(row=r_index, column=0, columnspan=len(COLUMNS), sticky="ew", pady=1)
            for index, (key, title, minimum, weight, sortable) in enumerate(COLUMNS):
                row.grid_columnconfigure(index, weight=weight, minsize=minimum)
            self._fill_row(row, report)
            self._hover(row)

    def _fill_row(self, row, report):
        pad = dict(padx=(12, 4), pady=9)
        risk_color = RISK_COLOR[report["risk"]]
        type_color = TYPE_COLOR.get(report["type"], CYAN)

        ctk.CTkLabel(row, text=report["id"], anchor="w", font=(FONT, 11, "bold"), text_color=CYAN).grid(row=0, column=0, sticky="w", **pad)

        type_box = ctk.CTkFrame(row, fg_color="transparent")
        type_box.grid(row=0, column=1, sticky="w", **pad)
        ctk.CTkLabel(type_box, text="", image=icon("bug" if report["type"] == "Malware" else "hook", 16, type_color)).pack(side="left", padx=(0, 6))
        ctk.CTkLabel(type_box, text=report["type"], font=(FONT, 11, "bold"), text_color=type_color).pack(side="left")

        target = ctk.CTkFrame(row, fg_color="transparent")
        target.grid(row=0, column=2, sticky="w", **pad)
        ctk.CTkLabel(target, text=report["target"], anchor="w", font=(FONT, 11), text_color=TEXT).pack(side="left")
        if report.get("live"):
            ctk.CTkLabel(
                target, text=" LIVE ", height=16, corner_radius=8, font=(FONT, 8, "bold"),
                fg_color=blend(CARD, GREEN, 0.2), text_color=GREEN
            ).pack(side="left", padx=(8, 0))

        ctk.CTkLabel(
            row, text=report["risk"], width=74, height=24, corner_radius=12,
            fg_color=blend(CARD, risk_color, 0.20), text_color=risk_color, font=(FONT, 10, "bold")
        ).grid(row=0, column=3, sticky="w", **pad)

        ctk.CTkLabel(row, text=f"{report['score']}%", anchor="w", font=(FONT, 12, "bold"), text_color=risk_color).grid(row=0, column=4, sticky="w", **pad)
        ctk.CTkLabel(row, text=report["date"], anchor="w", font=(FONT, 11), text_color=MUTED).grid(row=0, column=5, sticky="w", **pad)

        actions = ctk.CTkFrame(row, fg_color="transparent")
        actions.grid(row=0, column=6, sticky="w", padx=(8, 4), pady=5)
        ctk.CTkButton(
            actions, text="View", image=icon("eye", 14, TEXT), compound="left", width=74, height=30,
            corner_radius=8, fg_color=CARD_3, hover_color=BORDER, border_width=1, border_color=BORDER,
            text_color=TEXT, font=(FONT, 11, "bold"), command=lambda r=report: self.show_details(r)
        ).pack(side="left", padx=(0, 6))
        ctk.CTkButton(
            actions, text="PDF", image=icon("pdf", 14, "#001018"), compound="left", width=66, height=30,
            corner_radius=8, fg_color=CYAN, hover_color=BLUE, text_color="#001018",
            font=(FONT, 11, "bold"), command=lambda r=report: self.generate_pdf(r)
        ).pack(side="left")

    @staticmethod
    def _hover(row):
        def enter(_):
            row.configure(fg_color=CARD_2)

        def leave(_):
            row.configure(fg_color="transparent")

        def bind_all(widget):
            widget.bind("<Enter>", enter, add="+")
            widget.bind("<Leave>", leave, add="+")
            for child in widget.winfo_children():
                bind_all(child)

        bind_all(row)

    # ------------------------------------------------------------
    # refresh
    # ------------------------------------------------------------

    def refresh_all(self):
        self._update_notice()
        self._update_stats()
        self._update_distribution()
        self.render_table()
        self._schedule_activity()

    # ------------------------------------------------------------
    # details window
    # ------------------------------------------------------------

    def show_details(self, report):
        window = ctk.CTkToplevel(self.parent)
        window.title(f"CyberShield AI - {report['id']}")
        window.geometry("820x640")
        window.minsize(760, 600)
        window.configure(fg_color=BG)
        try:
            window.transient(self.parent.winfo_toplevel())
        except Exception:
            pass
        # grab_set before the window is visible can fail on Windows, so wait a moment
        window.after(150, lambda: self._grab(window))

        color = RISK_COLOR[report["risk"]]

        head = ctk.CTkFrame(window, fg_color="transparent")
        head.pack(fill="x", padx=28, pady=(24, 0))
        ctk.CTkLabel(head, text="", image=icon("reports", 30, CYAN)).pack(side="left", padx=(0, 10))
        col = ctk.CTkFrame(head, fg_color="transparent")
        col.pack(side="left")
        ctk.CTkLabel(col, text="SECURITY REPORT", font=(FONT, 22, "bold"), text_color=TEXT).pack(anchor="w")
        ctk.CTkLabel(col, text=f"{report['id']}  •  Generated by CyberShield AI", font=(FONT, 11), text_color=MUTED).pack(anchor="w")
        ctk.CTkLabel(
            head, text=f"  {report['status'].upper()}  ", height=26, corner_radius=13,
            fg_color=blend(CARD, color, 0.2), text_color=color, font=(FONT, 10, "bold")
        ).pack(side="right")

        top = ctk.CTkFrame(window, fg_color=CARD, corner_radius=14, border_width=1, border_color=BORDER)
        top.pack(fill="x", padx=28, pady=(18, 12))

        gauge = tk.Canvas(top, width=190, height=190, bg=CARD, highlightthickness=0)
        gauge.pack(side="left", padx=(14, 6), pady=14)
        gauge.photo = ImageTk.PhotoImage(render_gauge(190, report["score"], color))
        gauge.create_image(95, 95, image=gauge.photo)
        gauge.create_text(95, 90, text=f"{report['score']}%", fill=color, font=(FONT, 30, "bold"))
        gauge.create_text(95, 122, text="AI RISK SCORE", fill=MUTED, font=(FONT, 8, "bold"))

        info = ctk.CTkFrame(top, fg_color="transparent")
        info.pack(side="left", fill="both", expand=True, padx=(8, 18), pady=14)
        for key, value in (
            ("Report ID", report["id"]),
            ("Detection Type", report["type"]),
            ("Target", report["target"]),
            ("Risk Level", report["risk"] + " RISK"),
            ("Date", report["date"]),
        ):
            row = ctk.CTkFrame(info, fg_color="transparent")
            row.pack(fill="x", pady=4)
            ctk.CTkLabel(row, text=key, width=120, anchor="w", font=(FONT, 11), text_color=MUTED).pack(side="left")
            ctk.CTkLabel(
                row, text=value, anchor="w", font=(FONT, 12, "bold"),
                text_color=color if key == "Risk Level" else TEXT
            ).pack(side="left")

        reco = ctk.CTkFrame(window, fg_color=blend(CARD, color, 0.07), corner_radius=14, border_width=1, border_color=blend(CARD, color, 0.4))
        reco.pack(fill="x", padx=28, pady=(0, 12))
        ctk.CTkLabel(reco, text="RECOMMENDATION", font=(FONT, 10, "bold"), text_color=color).pack(anchor="w", padx=18, pady=(14, 2))
        ctk.CTkLabel(
            reco, text=recommendation_for(report), font=(FONT, 13), text_color=TEXT,
            wraplength=720, justify="left"
        ).pack(anchor="w", padx=18, pady=(0, 14))

        buttons = ctk.CTkFrame(window, fg_color="transparent")
        buttons.pack(pady=(6, 20))
        ctk.CTkButton(
            buttons, text="Generate PDF", image=icon("pdf", 16, "#001018"), compound="left",
            width=160, height=42, corner_radius=10, fg_color=CYAN, hover_color=BLUE,
            text_color="#001018", font=(FONT, 12, "bold"), command=lambda: self.generate_pdf(report, window)
        ).pack(side="left", padx=5)
        ctk.CTkButton(
            buttons, text="Close", width=120, height=42, corner_radius=10, fg_color=CARD_3,
            hover_color=BORDER, border_width=1, border_color=BORDER, text_color=TEXT,
            font=(FONT, 12, "bold"), command=window.destroy
        ).pack(side="left", padx=5)

    @staticmethod
    def _grab(window):
        try:
            if window.winfo_exists():
                window.grab_set()
                window.focus_force()
        except Exception:
            pass

    # ------------------------------------------------------------
    # export
    # ------------------------------------------------------------

    def export_csv(self):
        rows = self.filtered()
        if not rows:
            self.flash("Nothing to export with the current filters.", ORANGE)
            return
        path = filedialog.asksaveasfilename(
            title="Export Security Reports", defaultextension=".csv",
            initialfile=f"cybershield_reports_{date.today():%Y%m%d}.csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        if not path:
            return
        try:
            write_csv(rows, path)
            self.flash(f"Exported {len(rows)} reports to {os.path.basename(path)}")
        except Exception as error:
            self.flash(f"Export failed: {error}", RED)

    def generate_pdf(self, report, window=None):
        path = filedialog.asksaveasfilename(
            title="Generate Security Report", defaultextension=".pdf",
            initialfile=f"{report['id']}.pdf", filetypes=[("PDF Files", "*.pdf")]
        )
        if window is not None:
            try:
                window.lift()
            except Exception:
                pass
        if not path:
            return
        try:
            build_pdf(report, path)
            self.flash(f"PDF saved: {os.path.basename(path)}")
        except ImportError:
            self.flash("PDF needs the reportlab package. Run: pip install reportlab", ORANGE)
        except Exception as error:
            self.flash(f"PDF failed: {error}", RED)


# ============================================================
# PUBLIC API
# ============================================================

def show_reports(parent):
    return ReportsPage(parent)


# ============================================================
# TEST MODE
# ============================================================

if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    app = ctk.CTk()
    app.title("CyberShield AI - Report Center")
    app.geometry("1450x900")
    app.configure(fg_color=BG)

    show_reports(app)
    app.mainloop()