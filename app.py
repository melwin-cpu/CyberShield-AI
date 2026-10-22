"""
CyberShield AI - Security Operations Center UI

NOTICE: several map, attack-vector, compliance, asset and feed panels are illustrative demo UI, not live telemetry.

Files that must sit in the same folder:
    app.py   (this file)
    gfx.py   (crisp artwork renderer)
    ui/      (your malware_scanner.py / phishing_scanner.py)

Why this version does not break when you maximize / minimize / resize:
  * almost everything is a light-weight tk widget (the old version had 400+
    customtkinter widgets that all had to redraw on every resize event)
  * artwork is rendered in a background thread and only AFTER the window
    stops resizing (debounced), so the UI thread never freezes
  * animations pause while the window is being resized
"""

import os
import sys
import time
import math
import queue
import random
import threading
from database.scan_history_db import get_all_scans

from core.malware_ensemble_engine import get_engine_status

from datetime import datetime, timezone

import tkinter as tk
import customtkinter as ctk
from PIL import Image, ImageTk
from ui.history import show_history

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gfx  # noqa: E402


# ============================================================
# OPTIONAL SCANNER IMPORTS (your own modules)
# ============================================================

try:
    from ui.malware_scanner import show_malware_scanner
except Exception as e:
    show_malware_scanner = None
    print("Malware Scanner import error:", e)

try:
    from ui.phishing_scanner import show_phishing_scanner
except Exception as e:
    show_phishing_scanner = None
    print("Phishing Scanner import error:", e)


# ============================================================
# THEME
# ============================================================

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

FONT = "Segoe UI" if sys.platform.startswith("win") else "Helvetica"

BG = "#020712"
HEADER_BG = "#010510"
PANEL = "#030C18"
BORDER = "#12304F"
BORDER_2 = "#0F4A7E"
NAV_BG = "#020C18"
NAV_ACTIVE = "#06274A"
NAV_HOVER = "#0A2239"

TEXT = "#F4F7FB"
MUTED = "#8DA3BA"
SUB = "#5F84AB"

CYAN = "#12C8FF"
BLUE = "#168BDB"
GREEN = "#19D6A0"
RED = "#FF405A"
ORANGE = "#F4A62A"
PURPLE = "#884DFF"

PROGRESS = "#0C9DF0"
TRACK = "#0E1E38"

DONUT_COLORS = ["#E0303F", "#E0652A", "#E3A52A", "#2BAA5B"]
# slice sizes follow the design; use [428, 1934, 4387, 17638] for real proportions
DONUT_WEIGHTS = [0.17, 0.19, 0.16, 0.48]

SEVERITY = [("Critical", 428), ("High", 1934), ("Medium", 4387), ("Low", 17638)]

BADGE = {
    "CRITICAL": ("#B3102A", "#FFFFFF"),
    "HIGH": ("#6A2414", "#FFB38A"),
    "MEDIUM": ("#8F6A12", "#FFE3A0"),
    "LOW": ("#166C49", "#C5FFE0"),
}


# ============================================================
# WINDOW
# ============================================================

app = ctk.CTk()
app.title("CyberShield AI")
app.geometry("1500x840")
app.minsize(1180, 700)
app.configure(fg_color=BG)

UI = max(1.0, app.winfo_fpixels("1i") / 96.0)   # screen DPI factor for raw tk widgets


def px(n):
    return max(1, int(round(n * UI)))


scan_state = {"active": False}
resize_state = {"t": 0.0}


def on_app_configure(event):
    if event.widget is app:
        resize_state["t"] = time.monotonic()


app.bind("<Configure>", on_app_configure, add="+")


def settled(delay=0.35):
    return (time.monotonic() - resize_state["t"]) > delay


def alive(widget):
    try:
        return bool(widget.winfo_exists())
    except tk.TclError:
        return False


# ============================================================
# BACKGROUND RENDERING (keeps the UI thread free)
# ============================================================

_work = queue.Queue()
_done = queue.Queue()


def _worker():
    while True:
        pane, token, fn, size = _work.get()
        if token != pane.token:          # a newer request exists -> skip
            continue
        try:
            img = fn(*size)
        except Exception as err:         # never kill the worker
            print("render error:", err)
            img = None
        _done.put((pane, token, img))


threading.Thread(target=_worker, daemon=True).start()


def _poll_done():
    try:
        while True:
            pane, token, img = _done.get_nowait()
            if alive(pane):
                pane.apply(token, img)
    except queue.Empty:
        pass
    except tk.TclError:
        pass
    app.after(30, _poll_done)


class ImagePane(tk.Canvas):
    """Canvas that shows a crisp, pixel-exact image rendered for its own size."""

    def __init__(self, parent, render, bg=PANEL, size=(2, 2)):
        super().__init__(parent, width=size[0], height=size[1], bg=bg,
                         highlightthickness=0, bd=0)
        self.render = render
        self.token = 0
        self.photo = None
        self.rendered = (0, 0)
        self._job = None
        self.bind("<Configure>", self._on_configure)

    def _on_configure(self, event):
        w, h = event.width, event.height
        if w < 8 or h < 8 or (w, h) == self.rendered:
            return
        if self._job:
            try:
                self.after_cancel(self._job)
            except Exception:
                pass
        delay = 20 if self.photo is None else 300
        self._job = self.after(delay, self._start)

    def _start(self):
        self._job = None
        if not alive(self):
            return
        w, h = self.winfo_width(), self.winfo_height()
        if w < 8 or h < 8:
            return
        self.token += 1
        _work.put((self, self.token, self.render, (w, h)))

    def apply(self, token, img):
        if token != self.token or img is None:
            return
        self.photo = ImageTk.PhotoImage(img)
        self.rendered = img.size
        if self.find_withtag("img"):
            self.itemconfig("img", image=self.photo)
        else:
            self.create_image(0, 0, image=self.photo, anchor="nw", tags="img")
        self.tag_lower("img")
        self.after_render(img.size)

    def after_render(self, size):
        pass

    def destroy(self):
        if self._job:
            try:
                self.after_cancel(self._job)
            except Exception:
                pass
        self.token += 1
        super().destroy()


# ============================================================
# TINY WIDGET HELPERS
# ============================================================

def F(parent, bg=PANEL, **kw):
    return tk.Frame(parent, bg=bg, bd=0, highlightthickness=0, **kw)


def L(parent, text="", size=10, bold=False, fg=TEXT, bg=PANEL, anchor="w", **kw):
    return tk.Label(parent, text=text, fg=fg, bg=bg, anchor=anchor, bd=0,
                    highlightthickness=0, padx=0, pady=0,
                    font=(FONT, size, "bold" if bold else "normal"), **kw)


def button(parent, text, command, bg=BLUE, fg="white", size=10, padx=18, pady=9, border=None):
    b = tk.Label(parent, text=text, bg=bg, fg=fg, font=(FONT, size, "bold"),
                 padx=px(padx), pady=px(pady), cursor="hand2",
                 highlightthickness=1 if border else 0,
                 highlightbackground=border or bg)
    b.bind("<Button-1>", lambda e: command())
    return b


def make_clickable(widget, command):
    widget.bind("<Button-1>", lambda e: command(), add="+")
    try:
        widget.configure(cursor="hand2")
    except tk.TclError:
        pass
    for child in widget.winfo_children():
        make_clickable(child, command)


def card(parent, title="", subtitle="", check=False, fit=False):
    """Rounded card shell + light tk body. Returns (shell, body).
    fit=True -> the card grows to its content (used on simple list pages)."""
    shell = ctk.CTkFrame(parent, width=10, height=10, fg_color=PANEL,
                         corner_radius=10, border_width=1, border_color=BORDER)
    if not fit:
        shell.pack_propagate(False)
    body = F(shell)
    body.pack(fill="both", expand=True, padx=px(3), pady=px(3))

    if title:
        head = F(body)
        head.pack(fill="x", padx=px(12), pady=(px(8), 0))
        col = F(head)
        col.pack(side="left")
        L(col, title.upper(), 11, True).pack(anchor="w")
        if subtitle:
            L(col, subtitle, 8, fg=SUB).pack(anchor="w", pady=(px(2), 0))
        if check:
            ImagePane(head, lambda w, h: gfx.render_check(min(w, h), PANEL), PANEL,
                      size=(px(18), px(18))).pack(side="right", anchor="n")
    return shell, body


class BarCanvas(tk.Canvas):
    def __init__(self, parent, frac, color, track=TRACK, height=6):
        super().__init__(parent, height=px(height), bg=track, highlightthickness=0, bd=0)
        self.frac, self.color = frac, color
        self.bind("<Configure>", self._draw)

    def _draw(self, event=None):
        self.delete("all")
        w, h = self.winfo_width(), self.winfo_height()
        self.create_rectangle(0, 0, int(w * self.frac), h, fill=self.color, width=0)


# ============================================================
# HEADER
# ============================================================

root = F(app, BG)
root.pack(fill="both", expand=True)
root.grid_columnconfigure(0, weight=1)
root.grid_rowconfigure(1, weight=1)

header = F(root, HEADER_BG, height=px(66))
header.grid(row=0, column=0, sticky="ew")
header.grid_propagate(False)
F(root, "#0A1626", height=1).grid(row=0, column=0, sticky="sew")

ImagePane(header, lambda w, h: gfx.render_logo(min(w, h), HEADER_BG), HEADER_BG,
          size=(px(44), px(44))).place(x=px(20), rely=0.5, anchor="w")
L(header, "CyberShield AI", 17, True, bg=HEADER_BG).place(x=px(76), y=px(10))
L(header, "Real-Time Threat Intelligence", 8, fg=SUB, bg=HEADER_BG).place(x=px(77), y=px(40))

nav_frame = tk.Frame(header, bg=NAV_BG, highlightthickness=1, highlightbackground="#0D2A48", bd=0)
nav_frame.place(relx=0.218, rely=0.5, anchor="w")
nav_tabs = {}


def set_active_nav(name):
    for key, tab in nav_tabs.items():
        active = key == name
        tab.configure(bg=NAV_ACTIVE if active else NAV_BG,
                      highlightbackground=BORDER_2 if active else NAV_BG)


def add_nav(name, command):
    tab = tk.Label(nav_frame, text=name, bg=NAV_BG, fg="#D5E1EE", font=(FONT, 10),
                   padx=px(20), pady=px(7), cursor="hand2",
                   highlightthickness=1, highlightbackground=NAV_BG)
    tab.pack(side="left", padx=px(2), pady=px(3))
    tab.bind("<Button-1>", lambda e: command())
    tab.bind("<Enter>", lambda e: tab.configure(bg=NAV_HOVER) if tab.cget("bg") != NAV_ACTIVE else None)
    tab.bind("<Leave>", lambda e: tab.configure(bg=NAV_ACTIVE if tab.cget("highlightbackground") == BORDER_2 else NAV_BG))
    nav_tabs[name] = tab


def start_scan():
    if scan_state["active"]:
        return
    scan_state["active"] = True
    deep_scan.configure(text="SCANNING...")
    app.after(3500, finish_scan)


def finish_scan():
    scan_state["active"] = False
    deep_scan.configure(text="✓ SCAN COMPLETE")
    app.after(2500, lambda: deep_scan.configure(text="⚡ DEEP SCAN"))


deep_scan = tk.Label(header, text="⚡ DEEP SCAN", bg="#1D1040", fg="#E5DAFF",
                     font=(FONT, 9, "bold"), padx=px(14), pady=px(6), cursor="hand2",
                     highlightthickness=1, highlightbackground=PURPLE)
deep_scan.place(relx=0.775, rely=0.5, anchor="w")
deep_scan.bind("<Button-1>", lambda e: start_scan())

ImagePane(header, lambda w, h: gfx.render_bell(min(w, h), HEADER_BG), HEADER_BG,
          size=(px(34), px(34))).place(relx=0.872, rely=0.5, anchor="w")
gear = ImagePane(header, lambda w, h: gfx.render_gear(min(w, h), HEADER_BG), HEADER_BG,
                 size=(px(30), px(30)))
gear.place(relx=0.906, rely=0.5, anchor="w")
gear.configure(cursor="hand2")
gear.bind("<Button-1>", lambda e: open_settings())

F(header, "#18283A", width=1, height=px(36)).place(relx=0.93, rely=0.5, anchor="w")
time_label = L(header, "", 10, True, bg=HEADER_BG, anchor="e")
time_label.place(relx=0.99, y=px(17), anchor="ne")
date_label = L(header, "", 9, fg=SUB, bg=HEADER_BG, anchor="e")
date_label.place(relx=0.99, y=px(38), anchor="ne")


def update_clock():
    now = datetime.now(timezone.utc)
    time_label.configure(text=now.strftime("%H:%M:%S UTC"))
    date_label.configure(text=now.strftime("%b %d, %Y"))
    app.after(1000, update_clock)


page_view = ctk.CTkFrame(root, fg_color=BG, corner_radius=0)
page_view.grid(row=1, column=0, sticky="nsew")

state = {"map": None}


def clear_page_view():
    state["map"] = None
    for widget in page_view.winfo_children():
        widget.destroy()


# ============================================================
# DATA
# ============================================================

rng = random.Random(11)
SPARK = [20 + i * 0.35 + rng.uniform(-7, 9) for i in range(70)]

feed_events = [
    ("CRITICAL", "Ransomware Detected", "Endpoint: FIN-LAPTOP-32", "14:35:22"),
    ("HIGH", "Unauthorized Access Attempt", "User: admin@corporate.com", "14:35:18"),
    ("HIGH", "Malicious IP Connection Blocked", "Source IP: 185.234.216.98", "14:35:15"),
    ("MEDIUM", "Suspicious File Behavior", "File: invoice_update.exe", "14:35:10"),
    ("LOW", "Phishing Email Quarantined", "User: j.doe@corporate.com", "14:35:05"),
]
history_log = list(feed_events)

FEED_POOL = [
    ("CRITICAL", "Ransomware Detected", "Endpoint: {host}"),
    ("HIGH", "Unauthorized Access Attempt", "User: {user}"),
    ("HIGH", "Malicious IP Connection Blocked", "Source IP: {ip}"),
    ("MEDIUM", "Suspicious File Behavior", "File: {file}"),
    ("LOW", "Phishing Email Quarantined", "User: {user}"),
]
HOSTS = ["FIN-LAPTOP-32", "HR-DESKTOP-11", "DEV-WS-07", "SRV-DB-02"]
USERS = ["admin@corporate.com", "j.doe@corporate.com", "m.khan@corporate.com", "a.ravi@corporate.com"]
FILES = ["invoice_update.exe", "payroll_q3.xlsm", "setup_patch.msi", "report_final.scr"]

AI_MODELS = [
    ("XGBoost", 98), ("Random Forest", 96), ("SVM", 94), ("Deep Learning", 93),
    ("LSTM", 91), ("Transformer", 89), ("Ensemble Model", 97),
    ("Behavioral Analysis", 90), ("Anomaly Detection", 88),
]


def new_feed_event():
    sev, title, sub = random.choice(FEED_POOL)
    sub = sub.format(
        host=random.choice(HOSTS), user=random.choice(USERS),
        ip=".".join(str(random.randint(11, 223)) for _ in range(4)),
        file=random.choice(FILES))
    return (sev, title, sub, datetime.now(timezone.utc).strftime("%H:%M:%S"))


# ============================================================
# DASHBOARD - LEFT COLUMN
# ============================================================


def build_overview(parent):
    history = get_all_scans()

    total_scans = len(history)
    high_count = sum(
        1 for scan in history
        if str(scan.get("risk", "")).strip().lower() == "high"
    )
    medium_count = sum(
        1 for scan in history
        if str(scan.get("risk", "")).strip().lower() == "medium"
    )
    low_count = sum(
        1 for scan in history
        if str(scan.get("risk", "")).strip().lower() == "low"
    )

    shell, body = card(parent, "Threat Overview", "Based on saved scan history")

    stats = F(body)
    stats.pack(
        side="bottom",
        fill="x",
        padx=px(10),
        pady=(0, px(10))
    )

    for i, wt in enumerate((3, 2, 2, 3)):
        stats.grid_columnconfigure(i, weight=wt)

    items = [
        ("TOTAL SCANS", f"{total_scans:,}", "Saved records", BLUE),
        ("HIGH RISK", f"{high_count:,}", "Saved records", RED),
        ("MEDIUM RISK", f"{medium_count:,}", "Saved records", ORANGE),
        ("LOW RISK", f"{low_count:,}", "Saved records", GREEN),
    ]

    for col, (label, value, detail, color) in enumerate(items):
        box = F(stats)
        box.grid(row=0, column=col)

        L(
            box, label, 8,
            fg=MUTED,
            anchor="center"
        ).pack()

        L(
            box, value, 17,
            True,
            anchor="center"
        ).pack(pady=(px(2), 0))

        L(
            box, detail, 8,
            fg=color,
            anchor="center"
        ).pack(pady=(px(2), 0))

    ImagePane(
        body,
        lambda w, h: gfx.render_area(
            w, h, SPARK,
            line="#E0303F",
            top="#8A1626",
            bottom=PANEL,
            bg=PANEL
        ),
        PANEL
    ).pack(
        fill="both",
        expand=True,
        padx=px(12),
        pady=(px(6), px(8))
    )

    return shell



def build_active_threats(parent):
    history = get_all_scans()

    # Count saved scans by risk level
    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for scan in history:
        risk = str(scan.get("risk", "")).strip().lower()

        if risk == "critical":
            severity_counts["Critical"] += 1
        elif risk == "high":
            severity_counts["High"] += 1
        elif risk == "medium":
            severity_counts["Medium"] += 1
        elif risk == "low":
            severity_counts["Low"] += 1

    total_scans = len(history)

    severity = [
        (name, severity_counts[name])
        for name in severity_counts
    ]

    # Keep the existing chart colors and UI
    colors = DONUT_COLORS

    weights = [value for _, value in severity]

    # Avoid a zero-sized donut when history is empty
    if sum(weights) == 0:
        weights = [1, 1, 1, 1]

    shell, body = card(
        parent,
        "Active Threats",
        "Based on saved scan history",
        check=True
    )

    inner = F(body)
    inner.pack(
        fill="both",
        expand=True,
        padx=px(12),
        pady=(px(2), px(8))
    )

    donut = ImagePane(
        inner,
        lambda w, h: gfx.render_donut2(
            min(w, h), weights, colors, PANEL
        ),
        PANEL,
        size=(px(126), px(126))
    )
    donut.pack(side="left", padx=(px(2), px(16)))

    L(
        donut, f"{total_scans:,}", 14, True, anchor="center"
    ).place(relx=0.5, rely=0.44, anchor="center")

    L(
        donut, "TOTAL", 7, fg=MUTED, anchor="center"
    ).place(relx=0.5, rely=0.62, anchor="center")

    legend = F(inner)
    legend.pack(side="left", fill="both", expand=True)
    legend.grid_columnconfigure(1, weight=1)

    for i, ((name, value), color) in enumerate(
        zip(severity, colors)
    ):
        legend.grid_rowconfigure(i, weight=1)

        L(legend, "●", 9, fg=color).grid(
            row=i, column=0, sticky="w"
        )

        L(legend, name, 10).grid(
            row=i, column=1, sticky="w", padx=px(8)
        )

        L(legend, f"{value:,}", 10, anchor="e").grid(
            row=i, column=2, sticky="e"
        )

    return shell


feed_rows = []


def update_feed():
    for i, row in enumerate(feed_rows):
        if i >= len(feed_events):
            break
        sev, title, sub, stamp = feed_events[i]
        bg, fg = BADGE[sev]
        row["badge"].configure(text=sev, bg=bg, fg=fg)
        row["title"].configure(text=title)
        row["sub"].configure(text=sub)
        row["time"].configure(text=stamp)


def tick_feed(anchor):
    if not alive(anchor):
        return
    ev = new_feed_event()
    feed_events.insert(0, ev)
    del feed_events[8:]
    history_log.insert(0, ev)
    del history_log[200:]
    update_feed()
    app.after(4500, lambda: tick_feed(anchor))



def build_feed(parent):
    history = get_all_scans()

    shell, body = card(
        parent,
        "Threat Activity Feed",
        "Latest saved malware and phishing scans",
        check=True
    )

    box = F(body)
    box.pack(
        fill="both",
        expand=True,
        padx=px(12),
        pady=(px(2), px(6))
    )
    box.grid_columnconfigure(0, weight=1)

    feed_rows.clear()

    # Display up to five most recent saved scans
    records = history[:5]

    if not records:
        L(
            box,
            "No scan activity yet",
            11,
            fg=MUTED,
            anchor="center"
        ).grid(row=0, column=0, sticky="nsew", pady=20)

        return shell

    for i, scan in enumerate(records):
        box.grid_rowconfigure(i, weight=1, uniform="feed")

        row = F(box)
        row.grid(row=i, column=0, sticky="nsew")

        if i < len(records) - 1:
            F(row, "#0C1B2C", height=1).pack(
                side="bottom", fill="x"
            )

        inner = F(row)
        inner.pack(expand=True, fill="x")

        risk = str(scan.get("risk", "Unknown")).strip().upper()
        scan_type = str(scan.get("type", "Scan")).strip()
        target = str(scan.get("target", "Unknown target")).strip()
        result = str(scan.get("result", "Completed")).strip()
        timestamp = str(scan.get("time", "")).strip()

        risk_colors = {
            "CRITICAL": "#FF1744",
            "HIGH": RED,
            "MEDIUM": ORANGE,
            "LOW": GREEN
        }
        badge_color = risk_colors.get(risk, MUTED)

        badge = tk.Label(
            inner,
            text=risk[:9],
            width=9,
            font=(FONT, 7, "bold"),
            bg=badge_color,
            fg="#FFFFFF",
            bd=0,
            pady=px(2)
        )
        badge.pack(side="left", padx=(0, px(12)))

        txt = F(inner)
        txt.pack(side="left", fill="x", expand=True)

        title_text = f"{scan_type} Scan — {result}"
        title = L(txt, title_text, 9, True)
        title.pack(anchor="w")

        sub = L(txt, target, 8, fg=MUTED)
        sub.pack(anchor="w")

        stamp = L(
            inner,
            timestamp,
            8,
            fg=MUTED,
            anchor="e"
        )
        stamp.pack(side="right")

    return shell


def build_left(dash):
    left = F(dash, BG)
    left.grid(row=0, column=0, sticky="nsew", padx=(0, px(6)))
    left.grid_columnconfigure(0, weight=1)
    for i, wt in enumerate((200, 184, 264)):
        left.grid_rowconfigure(i, weight=wt, uniform="left")
    build_overview(left).grid(row=0, column=0, sticky="nsew", pady=(0, px(8)))
    build_active_threats(left).grid(row=1, column=0, sticky="nsew", pady=(0, px(8)))
    build_feed(left).grid(row=2, column=0, sticky="nsew")


# ============================================================
# DASHBOARD - CENTER (map + shield, system cards)
# ============================================================

class MapPane(ImagePane):
    """World map. The hot-spot rings and the status badge are lightweight overlays."""

    def __init__(self, parent):
        super().__init__(parent, lambda w, h: gfx.render_map(w, h), "#020812")
        self.psize = px(46)
        self.frames = [ImageTk.PhotoImage(f) for f in gfx.pulse_frames(self.psize, 16)]
        self.spots = []
        self.phase = 0
        self.filter = "All Threats"
        self.size_wh = (0, 0)

    def after_render(self, size):
        w, h = size
        self.size_wh = (w, h)
        self.delete("pulse")
        self.delete("status")
        self.spots = []
        for i, (x, y, sz, kind) in enumerate(gfx.hotspot_pixels(w, h)):
            item = self.create_image(x, y, image=self.frames[0], tags="pulse")
            self.spots.append((item, kind, i))
        bw, bh = px(214), px(46)
        cx, cy = w / 2, h - px(34)
        self.create_rectangle(cx - bw / 2, cy - bh / 2, cx + bw / 2, cy + bh / 2,
                              fill="#06180F", outline="#14A064", width=2, tags=("status", "st_box"))
        self.create_text(cx, cy - px(8), text="THREAT INTELLIGENCE", fill=GREEN,
                         font=(FONT, 13, "bold"), tags=("status", "st_title"))
        self.create_text(cx, cy + px(11), text="NOT A LIVE SECURITY STATUS", fill=GREEN,
                         font=(FONT, 7), tags=("status", "st_sub"))

    def tick(self):
        if not self.spots:
            return
        self.phase += 1
        n = len(self.frames)
        for item, kind, i in self.spots:
            visible = self.filter == "All Threats" or kind == self.filter
            if visible:
                self.itemconfig(item, state="normal", image=self.frames[(self.phase + i * 3) % n])
            else:
                self.itemconfig(item, state="hidden")
        pulse = (math.sin(self.phase / 4.0) + 1) / 2
        if scan_state["active"]:
            self.itemconfig("st_box", fill="#1A1406", outline=gfx_mix("#6A4A10", ORANGE, pulse))
            self.itemconfig("st_title", text="DEMO SCAN ANIMATION", fill=ORANGE)
            self.itemconfig("st_sub", text="NO LIVE ASSET SCAN CONNECTED", fill=ORANGE)
        else:
            self.itemconfig("st_box", fill="#06180F", outline=gfx_mix("#0C5A3C", GREEN, pulse))
            self.itemconfig("st_title", text="THREAT INTELLIGENCE", fill=GREEN)
            self.itemconfig("st_sub", text="NOT A LIVE SECURITY STATUS", fill=GREEN)


def gfx_mix(c1, c2, t):
    r, g, b = gfx.mix(c1, c2, t)
    return "#%02x%02x%02x" % (r, g, b)


def build_map(parent):
    shell, body = card(parent, "Global Threat Map", "Illustrative visualization — not live threat telemetry")
    pane = MapPane(body)
    pane.pack(fill="both", expand=True, padx=px(4), pady=(px(6), px(4)))
    state["map"] = pane

    menu = ctk.CTkOptionMenu(
        shell, values=["All Threats", "Malware", "Phishing", "Ransomware"],
        width=116, height=26, fg_color="#071426", button_color="#0B2A4A",
        text_color=MUTED, font=(FONT, 11),
        command=lambda v: setattr(pane, "filter", v))
    menu.place(relx=1.0, x=-16, y=12, anchor="ne")
    return shell



def system_card(parent, col, title, kind, protected, at_risk, seed, command):
    shell, body = card(
        parent,
        title,
        "Saved Scan Statistics",
        check=True
    )

    shell.grid(
        row=0,
        column=col,
        sticky="nsew",
        padx=(
            0 if col == 0 else px(4),
            0 if col == 2 else px(4)
        )
    )

    # Read actual saved scan history
    history = get_all_scans()

    if title == "Endpoints":
        relevant = [
            scan for scan in history
            if str(scan.get("type", "")).lower() == "malware"
        ]
    elif title == "Cloud Systems":
        relevant = [
            scan for scan in history
            if str(scan.get("type", "")).lower() == "phishing"
        ]
    else:
        relevant = history

    total = len(relevant)

    risky = sum(
        1 for scan in relevant
        if str(scan.get("risk", "")).strip().lower()
        in ("critical", "high")
    )

    values = [0.0] * 28

    ImagePane(
        body,
        lambda w, h: gfx.render_area(
            w, h, values,
            line="#2A9DFF",
            top="#0F4C8A",
            bottom=PANEL,
            bg=PANEL
        ),
        PANEL,
        size=(2, px(34))
    ).pack(
        side="bottom",
        fill="x",
        padx=px(8),
        pady=(0, px(8))
    )

    mid = F(body)
    mid.pack(
        fill="both",
        expand=True,
        padx=px(14),
        pady=(px(2), 0)
    )

    ImagePane(
        mid,
        lambda w, h: gfx.render_icon(kind, min(w, h), PANEL),
        PANEL,
        size=(px(58), px(58))
    ).pack(side="left", padx=(0, px(16)))

    info = F(mid)
    info.pack(side="left")

    L(
        info, "Saved scans", 9,
        True, fg=GREEN
    ).pack(anchor="w")

    L(
        info, f"{total:,}", 21, True
    ).pack(anchor="w")

    L(
        info, "High / Critical risk", 9,
        fg=MUTED
    ).pack(anchor="w")

    L(
        info, str(risky), 14,
        True, fg="#E0202F"
    ).pack(anchor="w")

    make_clickable(mid, command)
    return shell



def build_center(dash):
    center = F(dash, BG)
    center.grid(row=0, column=1, sticky="nsew", padx=px(6))
    center.grid_columnconfigure(0, weight=1)
    center.grid_rowconfigure(0, weight=484, uniform="mid")
    center.grid_rowconfigure(1, weight=179, uniform="mid")

    build_map(center).grid(row=0, column=0, sticky="nsew", pady=(0, px(8)))

    bottom = F(center, BG)
    bottom.grid(row=1, column=0, sticky="nsew")
    bottom.grid_rowconfigure(0, weight=1)
    for i in range(3):
        bottom.grid_columnconfigure(i, weight=1, uniform="sys")

    system_card(bottom, 0, "Endpoints", "laptop", 7892, 23, 1, lambda: open_asset_page("ENDPOINTS"))
    system_card(bottom, 1, "Cloud Systems", "cloud", 1256, 8, 2, lambda: open_asset_page("CLOUD"))
    system_card(bottom, 2, "Network", "network", 4325, 17, 3, lambda: open_asset_page("NETWORK"))


# ============================================================
# DASHBOARD - RIGHT COLUMN
# ============================================================

def render_brain_fit(w, h):
    bw = min(w, int(h * 1.12))
    bh = int(bw / 1.12)
    brain = gfx.render_brain(bw, bh, bg=PANEL)
    out = Image.new("RGB", (w, h), gfx.hex_rgb(PANEL))
    out.paste(brain, ((w - bw) // 2, (h - bh) // 2))
    return out



def build_engine(parent):
    shell, body = card(
        parent,
        "Threat Detection Engine",
        "Engine capability status"
    )

    mid = F(body)
    mid.pack(
        fill="both",
        expand=True,
        padx=px(10),
        pady=(px(8), px(6))
    )

    mid.grid_rowconfigure(0, weight=1)
    mid.grid_columnconfigure(0, weight=11, uniform="eng")
    mid.grid_columnconfigure(1, weight=10, uniform="eng")

    # Brain image
    ImagePane(
        mid,
        render_brain_fit,
        PANEL
    ).grid(
        row=0,
        column=0,
        sticky="nsew"
    )

    # Check model file availability
    try:
        engine_status = get_engine_status()

        available_count = engine_status["available_models"]
        total_count = engine_status["total_models"]

        engine_label = (
            f"Model files: {available_count}/{total_count} available"
        )

        ml_status = (
            "Model files found"
            if available_count > 0
            else "No model files found"
        )

    except Exception as exc:
        engine_label = "Engine status unavailable"
        ml_status = "Status check failed"
        print("Engine status error:", exc)

    # Capability list
    items = F(mid)
    items.grid(
        row=0,
        column=1,
        sticky="nsew"
    )

    capabilities = [
        ("File Hash / Metadata", "Available in scanner"),
        ("Behavior Analysis", "Not configured"),
        ("Anomaly Detection", "Not configured"),
        ("ML Classification", ml_status),
    ]

    for i, (name, status) in enumerate(capabilities):
        items.grid_rowconfigure(i, weight=1)

        row = F(items)
        row.grid(
            row=i,
            column=0,
            sticky="w"
        )

        ImagePane(
            row,
            lambda w, h: gfx.render_node(min(w, h), PANEL),
            PANEL,
            size=(px(22), px(22))
        ).pack(
            side="left",
            padx=(0, px(10))
        )

        col = F(row)
        col.pack(side="left")

        L(col, name, 9).pack(anchor="w")
        L(col, status, 8, fg=SUB).pack(anchor="w")

    # Model file status below the brain image
    L(
        mid,
        engine_label,
        8,
        fg=SUB
    ).grid(
        row=1,
        column=0,
        sticky="w",
        pady=(px(4), 0)
    )

    make_clickable(body, open_intelligence)

    return shell


def build_vectors(parent):
    shell, body = card(parent, "Top Attack Vectors", "Sample percentages — not calculated from scans")
    box = F(body)
    box.pack(fill="both", expand=True, padx=px(14), pady=(px(2), px(8)))
    box.grid_columnconfigure(1, weight=1)
    vectors = [("Malware", 38.7, "#D4061C"), ("Phishing", 24.1, "#C52E1D"),
               ("Exploits", 17.3, "#C05A1C"), ("Unauthorized Access", 12.6, "#CC8630"),
               ("Other", 7.3, "#10A166")]
    for i, (name, pct, color) in enumerate(vectors):
        box.grid_rowconfigure(i, weight=1)
        L(box, name, 9).grid(row=i, column=0, sticky="w")
        BarCanvas(box, pct / 38.7, color, height=4).grid(row=i, column=1, sticky="ew", padx=px(12))
        L(box, f"{pct}%", 9, anchor="e").grid(row=i, column=2, sticky="e")
    return shell


def build_compliance_card(parent):
    shell, body = card(parent, "Compliance Status", "Illustrative only — no compliance audit connected")

    btn = tk.Label(body, text="View Compliance Report", fg="#CFE0F1", bg="#021D38",
                   font=(FONT, 10), padx=px(24), pady=px(6), cursor="hand2",
                   highlightthickness=1, highlightbackground=BORDER_2)
    btn.pack(side="bottom", pady=(px(2), px(12)))
    btn.bind("<Button-1>", lambda e: open_compliance())

    row = F(body)
    row.pack(fill="both", expand=True, padx=px(8), pady=(px(4), 0))
    row.grid_rowconfigure(0, weight=1)
    standards = [("ISO 27001", "shield", 0.82, "#22D07A", "#2A8CFF"),
                 ("SOC 2", "lock", 0.74, "#22D07A", "#2A8CFF"),
                 ("GDPR", "stars", 0.66, "#2AA6FF", "#22D07A"),
                 ("HIPAA", "cross", 0.72, "#2AA6FF", "#22D0B0")]
    for col, (name, glyph, pct, c1, c2) in enumerate(standards):
        row.grid_columnconfigure(col, weight=1, uniform="cmp")
        cell = F(row)
        cell.grid(row=0, column=col)
        ImagePane(cell, lambda w, h, g=glyph, p=pct, a=c1, b=c2: gfx.render_ring_icon(
            min(w, h), p, g, a, b, PANEL), PANEL, size=(px(62), px(62))).pack()
        L(cell, name, 8, anchor="center").pack(pady=(px(3), 0))
        L(cell, "NOT VERIFIED", 7, fg=ORANGE, anchor="center").pack()
    return shell


def build_right(dash):
    right = F(dash, BG)
    right.grid(row=0, column=2, sticky="nsew", padx=(px(6), 0))
    right.grid_columnconfigure(0, weight=1)
    for i, wt in enumerate((259, 203, 188)):
        right.grid_rowconfigure(i, weight=wt, uniform="right")
    build_engine(right).grid(row=0, column=0, sticky="nsew", pady=(0, px(8)))
    build_vectors(right).grid(row=1, column=0, sticky="nsew", pady=(0, px(8)))
    build_compliance_card(right).grid(row=2, column=0, sticky="nsew")


def open_dashboard():
    clear_page_view()
    set_active_nav("DASHBOARD")
    dash = F(page_view, BG)
    dash.pack(fill="both", expand=True, padx=px(12), pady=(px(8), px(10)))
    dash.grid_rowconfigure(0, weight=1)
    dash.grid_columnconfigure(0, weight=300, uniform="cols")
    dash.grid_columnconfigure(1, weight=647, uniform="cols")
    dash.grid_columnconfigure(2, weight=341, uniform="cols")
    build_left(dash)
    build_center(dash)
    build_right(dash)


# ============================================================
# SECONDARY PAGES
# ============================================================

def page_header(title, subtitle):
    wrap = F(page_view, BG)
    wrap.pack(fill="x", padx=px(24), pady=(px(20), px(10)))
    L(wrap, title, 22, True, bg=BG).pack(anchor="w")
    L(wrap, subtitle, 10, fg=MUTED, bg=BG).pack(anchor="w", pady=(px(3), 0))


def tiles(items):
    row = F(page_view, BG)
    row.pack(fill="x", padx=px(20))
    for i, (label, value, color) in enumerate(items):
        row.grid_columnconfigure(i, weight=1, uniform="tiles")
        shell, body = card(row)
        shell.configure(height=96)
        shell.grid(row=0, column=i, sticky="ew", padx=px(5))
        L(body, label, 9, True, fg=MUTED).pack(pady=(px(18), px(4)))
        L(body, value, 24, True, fg=color).pack()
    return row


def open_scanner_hub():
    clear_page_view()
    set_active_nav("SCANNER")
    page_header("SCANNER", "CyberShield AI malware and phishing detection")
    tiles([("MALWARE THREATS", "0", RED), ("PHISHING THREATS", "0", ORANGE),
           ("AI MODELS", "9", CYAN), ("SYSTEM STATUS", "READY", GREEN)])

    row = F(page_view, BG)
    row.pack(fill="both", expand=True, padx=px(20), pady=px(14))
    row.grid_rowconfigure(0, weight=1)
    for i in (0, 1):
        row.grid_columnconfigure(i, weight=1, uniform="hub")

    for col, (title, desc, engines, color, cmd, label) in enumerate([
        ("Malware Detection", "AI-powered PE malware detection",
         "XGBoost  •  Random Forest  •  SVM  •  Deep Learning", BLUE, open_malware_scanner,
         "OPEN MALWARE SCANNER"),
        ("Phishing Detection", "AI-powered URL phishing detection",
         "XGBoost  •  Random Forest  •  SVM  •  LSTM  •  Transformer", PURPLE, open_phishing_scanner,
         "OPEN PHISHING SCANNER")]):
        shell, body = card(row, title, desc)
        shell.grid(row=0, column=col, sticky="nsew", padx=px(5))
        L(body, engines, 9, fg=CYAN if col == 0 else "#B79BFF").pack(anchor="w", padx=px(14), pady=px(14))
        button(body, label, cmd, bg=color).pack(anchor="w", padx=px(14), pady=px(8))


ASSET_PAGES = {
    "ENDPOINTS": ("ENDPOINTS", "Protected workstations and servers", 7892, 23,
                  [("WORKSTATION", "FIN-LAPTOP-32", "88%", "CRITICAL"),
                   ("WORKSTATION", "HR-DESKTOP-11", "94%", "LOW"),
                   ("SERVER", "core-server-07", "91%", "MEDIUM")]),
    "CLOUD": ("CLOUD SYSTEMS", "Cloud workloads and storage", 1256, 8,
              [("CLOUD", "cloud-node-14", "94%", "LOW"),
               ("CLOUD", "storage-bucket-03", "90%", "MEDIUM"),
               ("CLOUD", "api-gateway-eu", "86%", "CRITICAL")]),
    "NETWORK": ("NETWORK", "Network devices and gateways", 4325, 17,
                [("EDGE", "edge-gateway-v2", "88%", "CRITICAL"),
                 ("CORE", "core-switch-01", "95%", "LOW"),
                 ("FIREWALL", "fw-perimeter-02", "92%", "MEDIUM")]),
}


def open_asset_page(key):
    clear_page_view()
    set_active_nav("DASHBOARD")
    title, subtitle, protected, at_risk, rows = ASSET_PAGES[key]
    page_header(title, subtitle)
    tiles([("PROTECTED", f"{protected:,}", GREEN), ("AT RISK", str(at_risk), RED),
           ("COVERAGE", f"{protected / (protected + at_risk) * 100:.1f}%", CYAN)])

    shell, body = card(page_view, "Connected Assets")
    shell.pack(fill="both", expand=True, padx=px(25), pady=px(14))
    for env, node, score, threat in rows:
        r = F(body, "#07111A")
        r.pack(fill="x", padx=px(14), pady=px(4))
        L(r, env, 9, True, bg="#07111A", width=14).pack(side="left", padx=px(12), pady=px(10))
        L(r, node, 9, fg=MUTED, bg="#07111A", width=24).pack(side="left")
        L(r, score, 9, True, fg=GREEN, bg="#07111A", width=10).pack(side="left")
        color = RED if threat == "CRITICAL" else ORANGE if threat == "MEDIUM" else GREEN
        L(r, "● " + threat, 9, True, fg=color, bg="#07111A", width=14).pack(side="left")


def open_intelligence():
    clear_page_view()
    set_active_nav("DASHBOARD")
    page_header("AI INTELLIGENCE", "Detection engines powering CyberShield AI")
    shell, body = card(page_view, "AI Detection Engines", fit=True)
    shell.pack(fill="x", padx=px(25), pady=px(10))
    for model, score in AI_MODELS:
        r = F(body)
        r.pack(fill="x", padx=px(16), pady=px(6))
        r.grid_columnconfigure(1, weight=1)
        L(r, model, 10, width=18).grid(row=0, column=0, sticky="w")
        BarCanvas(r, score / 100, CYAN, height=6).grid(row=0, column=1, sticky="ew", padx=px(12))
        L(r, f"{score}%", 10, True, fg=MUTED, anchor="e").grid(row=0, column=2)
    F(body, height=px(8)).pack()


def open_compliance():
    clear_page_view()
    set_active_nav("REPORTS")
    page_header("COMPLIANCE", "Security compliance overview")
    wrap = F(page_view, BG)
    wrap.pack(fill="x", padx=px(25))
    for std in ("ISO 27001", "SOC 2", "GDPR", "HIPAA"):
        shell, body = card(wrap)
        shell.configure(height=56)
        shell.pack(fill="x", pady=px(5))
        r = F(body)
        r.pack(fill="both", expand=True, padx=px(16))
        L(r, "◇  " + std, 13, True).pack(side="left", pady=px(10))
        L(r, "✓ COMPLIANT", 10, True, fg=GREEN, anchor="e").pack(side="right")
    button(wrap, "←  Back to Dashboard", open_dashboard, bg="#021D38", border=BORDER_2).pack(anchor="w", pady=px(14))


def open_reports():
    clear_page_view()
    set_active_nav("REPORTS")
    page_header("SECURITY REPORTS", "CyberShield AI malware and phishing detection reports")
    shell, body = card(page_view, "Latest Security Report", fit=True)
    shell.pack(fill="x", padx=px(25), pady=px(10))
    for name, value, color in (("Malware Detection", "READY", GREEN), ("Phishing Detection", "READY", GREEN),
                               ("AI Detection Engines", "9", CYAN), ("Model Training", "PENDING DATASET", ORANGE)):
        r = F(body, "#07111A")
        r.pack(fill="x", padx=px(14), pady=px(4))
        L(r, name, 9, fg=MUTED, bg="#07111A").pack(side="left", padx=px(12), pady=px(10))
        L(r, value, 9, True, fg=color, bg="#07111A", anchor="e").pack(side="right", padx=px(12))
    status = L(body, "", 10, True, fg=GREEN)

    def generate():
        status.configure(text="✓ Security report generation started (" + datetime.now().strftime("%H:%M:%S") + ")")

    button(body, "GENERATE REPORT", generate).pack(anchor="w", padx=px(14), pady=(px(16), px(6)))
    status.pack(anchor="w", padx=px(14), pady=(0, px(14)))


def open_history():
    clear_page_view()
    set_active_nav("HISTORY")
    show_history(page_view)
    shell, body = card(page_view, "Detection History", f"{len(history_log)} events this session")
    shell.pack(fill="both", expand=True, padx=px(25), pady=px(10))
    for sev, title, sub, stamp in history_log[:14]:
        bg, fg = BADGE[sev]
        r = F(body, "#07111A")
        r.pack(fill="x", padx=px(14), pady=px(3))
        tk.Label(r, text=sev, width=9, bg=bg, fg=fg, font=(FONT, 7, "bold"), bd=0).pack(side="left", padx=px(10), pady=px(8))
        L(r, title, 9, True, bg="#07111A", width=32).pack(side="left")
        L(r, sub, 9, fg=MUTED, bg="#07111A").pack(side="left")
        L(r, stamp, 9, fg=MUTED, bg="#07111A", anchor="e").pack(side="right", padx=px(12))


def open_settings():
    clear_page_view()
    set_active_nav("")
    page_header("SETTINGS", "Protection and notification preferences")
    shell, body = card(page_view, "Preferences", fit=True)
    shell.pack(fill="x", padx=px(25), pady=px(10))
    for label in ("Real-time protection", "Auto-quarantine detected threats",
                  "Email alerts for critical threats", "Cloud threat intelligence sync"):
        r = F(body, "#07111A")
        r.pack(fill="x", padx=px(14), pady=px(4))
        L(r, label, 10, bg="#07111A").pack(side="left", padx=px(12), pady=px(12))
        sw = ctk.CTkSwitch(r, text="", progress_color=CYAN)
        sw.select()
        sw.pack(side="right", padx=px(12))
    F(body, height=px(8)).pack()


def _show_scanner(fn, name, nav):
    clear_page_view()
    set_active_nav(nav)
    if fn is not None:
        try:
            fn(page_view)
            return
        except Exception as error:
            L(page_view, f"{name.upper()} SCANNER ERROR", 20, True, fg=RED, bg=BG, anchor="center").pack(pady=(px(100), px(10)))
            L(page_view, str(error), 10, fg=MUTED, bg=BG, anchor="center", wraplength=px(850)).pack()
            print(f"{name} scanner error:", error)
            return
    L(page_view, f"{name} Scanner", 26, True, bg=BG, anchor="center").pack(pady=px(100))


def open_malware_scanner():
    _show_scanner(show_malware_scanner, "Malware", "MALWARE")


def open_phishing_scanner():
    _show_scanner(show_phishing_scanner, "Phishing", "PHISHING")


# ============================================================
# NAVIGATION  (edit this list to add / rename tabs)
# ============================================================

NAV_ITEMS = [
    ("DASHBOARD", open_dashboard),
    ("SCANNER", open_scanner_hub),
    ("MALWARE", open_malware_scanner),
    ("PHISHING", open_phishing_scanner),
    ("HISTORY", open_history),
    ("REPORTS", open_reports),
]

for _name, _cmd in NAV_ITEMS:
    add_nav(_name, _cmd)


# ============================================================
# BACKGROUND LOOPS
# ============================================================

def animate():
    pane = state.get("map")
    if pane is not None and alive(pane) and settled():
        try:
            pane.tick()
        except tk.TclError:
            pass
    app.after(90, animate)


# ============================================================
# START
# ============================================================

update_clock()
_poll_done()
open_dashboard()
animate()
app.mainloop()
