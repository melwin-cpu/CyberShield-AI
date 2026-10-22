import customtkinter as ctk
import importlib
import math
from datetime import datetime, timedelta
from tkinter import filedialog, messagebox

# ============================================================
# CYBERSHIELD AI - COMMAND CENTER DASHBOARD
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


# ============================================================
# REAL DATA SOURCES
# ============================================================

try:
    from database.scan_history_db import get_all_scans, clear_all_scans
    HISTORY_AVAILABLE = True
except Exception:
    get_all_scans = None
    clear_all_scans = None
    HISTORY_AVAILABLE = False

try:
    from core.phishing_ensemble_engine import get_ensemble_status as phishing_status
except Exception:
    phishing_status = None

try:
    from core.malware_ensemble_engine import get_ensemble_status as malware_status
except Exception:
    malware_status = None

BUILTIN_ENGINES = ("Heuristic Engine", "Static Analysis")


def empty_stats():
    return {"total": 0, "malware": 0, "phishing": 0, "suspicious": 0,
            "clean": 0, "clean_rate": None, "has_demo": False}


def empty_daily():
    today = datetime.now().date()
    return [{"label": (today - timedelta(days=i)).strftime("%a").upper(),
             "total": 0, "threats": 0} for i in range(6, -1, -1)]


def get_engine_groups():
    groups = []
    for title, fn, builtin in (("PHISHING ENGINE", phishing_status, None),
                               ("MALWARE ENGINE", malware_status, "Static Analysis")):
        if fn is None:
            groups.append((title, None))
            continue
        try:
            status = fn()
            status = {k: bool(v) for k, v in status.items()} if isinstance(status, dict) else {}
        except Exception:
            status = {}
        if builtin:
            status = {builtin: True, **status}
        groups.append((title, status))
    return groups


def _normalise_record(row):
    """Convert database.scan_history_db rows to dashboard's display format."""
    scan_type = str(row.get("type", row.get("scan_type", ""))).strip().lower()
    result = str(row.get("result", "Unknown"))
    risk = str(row.get("risk", "UNKNOWN")).upper()
    target = str(row.get("target", "Unknown target"))
    try:
        score = float(row.get("score", 0) or 0)
    except (TypeError, ValueError):
        score = 0.0

    stamp = str(row.get("scanned_at", "") or "")
    if not stamp:
        date_part, time_part = str(row.get("date", "")), str(row.get("time", ""))
        stamp = f"{date_part} {time_part}".strip()
    parsed = None
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%d-%m-%Y %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            parsed = datetime.fromisoformat(stamp) if fmt is None else datetime.strptime(stamp, fmt)
            break
        except Exception:
            continue
    if parsed is None:
        parsed = datetime.now()
    ts = parsed.isoformat()

    if "phish" in scan_type:
        kind = "phishing"
    else:
        kind = "malware"

    low_result = result.lower()
    if risk == "HIGH" or "malware detected" in low_result or "phishing detected" in low_result:
        category = "malware" if kind == "malware" else "phishing"
    elif risk == "MEDIUM" or "suspicious" in low_result:
        category = "suspicious"
    elif risk in ("LOW", "CLEAN") or "low risk" in low_result or "clean" in low_result or "safe" in low_result:
        category = "clean"
    else:
        category = "unknown"

    return {"id": row.get("id", ""), "kind": kind, "category": category,
            "target": target, "result": result, "risk": risk, "score": score,
            "ts": ts, "date": parsed.date()}


def load_dashboard_data():
    data = {"stats": empty_stats(), "daily": empty_daily(), "recent": [],
            "groups": get_engine_groups(), "error": None}
    if not HISTORY_AVAILABLE:
        data["error"] = "Database history module unavailable"
        return data
    try:
        rows = get_all_scans() or []
        records = [_normalise_record(r) for r in rows]
        cutoff = datetime.now() - timedelta(days=30)
        recent_window = [r for r in records if datetime.fromisoformat(r["ts"]) >= cutoff]
        stats = empty_stats()
        stats["total"] = len(recent_window)
        stats["malware"] = sum(r["category"] == "malware" for r in recent_window)
        stats["phishing"] = sum(r["category"] == "phishing" for r in recent_window)
        stats["suspicious"] = sum(r["category"] == "suspicious" for r in recent_window)
        stats["clean"] = sum(r["category"] == "clean" for r in recent_window)
        if stats["total"]:
            stats["clean_rate"] = stats["clean"] * 100.0 / stats["total"]
        data["stats"] = stats
        data["recent"] = sorted(records, key=lambda r: r["ts"], reverse=True)[:5]
        days = empty_daily()
        by_date = {datetime.now().date() - timedelta(days=i): item for i, item in enumerate(reversed(days))}
        for rec in records:
            bucket = by_date.get(rec["date"])
            if bucket is not None:
                bucket["total"] += 1
                if rec["category"] in ("malware", "phishing", "suspicious"):
                    bucket["threats"] += 1
        data["daily"] = days
    except Exception as exc:
        data["error"] = str(exc)
    return data


def ago(ts):
    try:
        seconds = (datetime.now() - datetime.fromisoformat(ts)).total_seconds()
    except Exception:
        return ""
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{int(seconds // 60)} min ago"
    if seconds < 86400:
        return f"{int(seconds // 3600)} hr ago"
    return f"{int(seconds // 86400)} d ago"


# ============================================================
# MAIN DASHBOARD
# ============================================================

def show_dashboard(
    parent,
    on_scan_file=None,
    on_scan_url=None,
    on_reports=None
):
    """
    on_scan_file / on_scan_url / on_reports are optional callbacks used by
    the Quick Action buttons (e.g. your sidebar navigation).
    """

    data = load_dashboard_data()

    stats = data["stats"]

    # Clear existing page
    for widget in parent.winfo_children():
        widget.destroy()

    parent.configure(fg_color=BG)

    def refresh():

        show_dashboard(
            parent,
            on_scan_file,
            on_scan_url,
            on_reports
        )

    # ========================================================
    # SCROLLABLE DASHBOARD
    # ========================================================

    dashboard = ctk.CTkScrollableFrame(
        parent,
        fg_color=BG,
        scrollbar_button_color=BORDER,
        scrollbar_button_hover_color=CYAN
    )

    dashboard.pack(
        fill="both",
        expand=True,
        padx=18,
        pady=12
    )

    # ========================================================
    # HEADER
    # ========================================================

    header = ctk.CTkFrame(
        dashboard,
        fg_color="transparent"
    )

    header.pack(
        fill="x",
        pady=(5, 18)
    )

    # Left
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
        text="CYBERSHIELD AI",
        font=(FONT, 30, "bold"),
        text_color=TEXT
    ).pack(
        anchor="w"
    )

    ctk.CTkLabel(
        title_frame,
        text="AI-Powered Cybersecurity Command Center",
        font=(FONT, 15),
        text_color=MUTED
    ).pack(
        anchor="w",
        pady=(2, 0)
    )

    # System status (real: counts loaded ML models)
    loaded_models = 0

    engines_found = 0

    for _, status in data["groups"]:

        if status is not None:

            engines_found += 1

            loaded_models += sum(
                1
                for name, ok in status.items()
                if ok and name not in BUILTIN_ENGINES
            )

    if engines_found == 0:

        status_text = "NO ENGINES FOUND"

        status_color = RED

    elif loaded_models == 0:

        status_text = "RULE ENGINES ACTIVE - NO ML MODELS LOADED"

        status_color = ORANGE

    else:

        status_text = f"ONLINE - {loaded_models} AI MODEL(S) LOADED"

        status_color = GREEN

    status_frame = ctk.CTkFrame(
        header,
        fg_color=CARD,
        corner_radius=12,
        border_width=1,
        border_color=BORDER
    )

    status_frame.pack(
        side="right",
        padx=5
    )

    ctk.CTkLabel(
        status_frame,
        text="●",
        font=(FONT, 18),
        text_color=status_color
    ).pack(
        side="left",
        padx=(14, 5),
        pady=10
    )

    ctk.CTkLabel(
        status_frame,
        text=status_text,
        font=(FONT, 12, "bold"),
        text_color=status_color
    ).pack(
        side="left",
        padx=(0, 14)
    )

    ctk.CTkLabel(
        header,
        text=f"Updated {datetime.now():%H:%M:%S}",
        font=(FONT, 11),
        text_color=MUTED
    ).pack(
        side="right",
        padx=10
    )

    # ========================================================
    # SECURITY OVERVIEW
    # ========================================================

    overview = ctk.CTkFrame(
        dashboard,
        fg_color="transparent"
    )

    overview.pack(
        fill="x",
        pady=(0, 18)
    )

    rate = stats["clean_rate"]

    create_stat_card(
        overview,
        "SECURITY SCORE",
        "--" if rate is None else f"{rate:.0f}%",
        "Clean scan rate (30 days)",
        CYAN,
        "🛡"
    )

    create_stat_card(
        overview,
        "MALWARE DETECTED",
        str(stats["malware"]),
        "Files flagged malicious",
        RED,
        "🦠"
    )

    create_stat_card(
        overview,
        "PHISHING DETECTED",
        str(stats["phishing"]),
        "Malicious URLs",
        ORANGE,
        "⚠"
    )

    create_stat_card(
        overview,
        "SCANS COMPLETED",
        str(stats["total"]),
        f"{stats['suspicious']} suspicious  •  last 30 days",
        GREEN,
        "✓"
    )

    # ========================================================
    # MIDDLE ROW
    # ========================================================

    middle_row = ctk.CTkFrame(
        dashboard,
        fg_color="transparent"
    )

    middle_row.pack(
        fill="x",
        pady=(0, 18)
    )

    # ========================================================
    # THREAT ACTIVITY CARD
    # ========================================================

    activity_card = ctk.CTkFrame(
        middle_row,
        fg_color=CARD,
        corner_radius=15,
        border_width=1,
        border_color=BORDER
    )

    activity_card.pack(
        side="left",
        fill="both",
        expand=True,
        padx=(0, 8)
    )

    ctk.CTkLabel(
        activity_card,
        text="THREAT ACTIVITY",
        font=(FONT, 18, "bold"),
        text_color=TEXT
    ).pack(
        anchor="w",
        padx=20,
        pady=(18, 2)
    )

    ctk.CTkLabel(
        activity_card,
        text="Scans and threats detected over the last 7 days",
        font=(FONT, 12),
        text_color=MUTED
    ).pack(
        anchor="w",
        padx=20
    )

    graph = ctk.CTkCanvas(
        activity_card,
        height=220,
        bg=CARD,
        highlightthickness=0
    )

    graph.pack(
        fill="x",
        padx=20,
        pady=15
    )

    # Redraws whenever the window is resized
    graph.bind(
        "<Configure>",
        lambda event: draw_threat_graph(
            graph,
            data["daily"]
        )
    )

    # ========================================================
    # AI ENGINE STATUS
    # ========================================================

    engine_card = ctk.CTkFrame(
        middle_row,
        fg_color=CARD,
        corner_radius=15,
        border_width=1,
        border_color=BORDER,
        width=350
    )

    engine_card.pack(
        side="right",
        fill="both",
        padx=(8, 0)
    )

    ctk.CTkLabel(
        engine_card,
        text="AI ENGINE STATUS",
        font=(FONT, 18, "bold"),
        text_color=TEXT
    ).pack(
        anchor="w",
        padx=20,
        pady=(18, 2)
    )

    ctk.CTkLabel(
        engine_card,
        text="Detection models (live status)",
        font=(FONT, 12),
        text_color=MUTED
    ).pack(
        anchor="w",
        padx=20,
        pady=(0, 6)
    )

    for title, status in data["groups"]:

        ctk.CTkLabel(
            engine_card,
            text=title,
            font=(FONT, 10, "bold"),
            text_color=CYAN
        ).pack(
            anchor="w",
            padx=20,
            pady=(8, 0)
        )

        if status is None:

            ctk.CTkLabel(
                engine_card,
                text="● Engine module not found",
                font=(FONT, 11, "bold"),
                text_color=ORANGE
            ).pack(
                anchor="w",
                padx=20,
                pady=4
            )

            continue

        for name, ok in status.items():

            row = ctk.CTkFrame(
                engine_card,
                fg_color="transparent"
            )

            row.pack(
                fill="x",
                padx=20,
                pady=3
            )

            ctk.CTkLabel(
                row,
                text=name,
                font=(FONT, 12, "bold"),
                text_color=TEXT
            ).pack(
                side="left"
            )

            ctk.CTkLabel(
                row,
                text="● READY" if ok else "● NOT LOADED",
                font=(FONT, 11, "bold"),
                text_color=GREEN if ok else MUTED
            ).pack(
                side="right"
            )

    ctk.CTkLabel(
        engine_card,
        text="",
        height=10
    ).pack()

    # ========================================================
    # LOWER ROW
    # ========================================================

    lower_row = ctk.CTkFrame(
        dashboard,
        fg_color="transparent"
    )

    lower_row.pack(
        fill="x",
        pady=(0, 18)
    )

    # ========================================================
    # THREAT DISTRIBUTION
    # ========================================================

    distribution_card = ctk.CTkFrame(
        lower_row,
        fg_color=CARD,
        corner_radius=15,
        border_width=1,
        border_color=BORDER
    )

    distribution_card.pack(
        side="left",
        fill="both",
        expand=True,
        padx=(0, 8)
    )

    ctk.CTkLabel(
        distribution_card,
        text="THREAT DISTRIBUTION",
        font=(FONT, 18, "bold"),
        text_color=TEXT
    ).pack(
        anchor="w",
        padx=20,
        pady=(18, 2)
    )

    ctk.CTkLabel(
        distribution_card,
        text="Scan results classification (last 30 days)",
        font=(FONT, 12),
        text_color=MUTED
    ).pack(
        anchor="w",
        padx=20,
        pady=(0, 15)
    )

    total = stats["total"]

    for name, key, color in (
        ("Malware", "malware", RED),
        ("Phishing", "phishing", ORANGE),
        ("Suspicious", "suspicious", PURPLE),
        ("Clean", "clean", GREEN)
    ):

        create_distribution(
            distribution_card,
            name,
            stats[key],
            total,
            color
        )

    if total == 0:

        ctk.CTkLabel(
            distribution_card,
            text="No scans yet. Run a file or URL scan.",
            font=(FONT, 11),
            text_color=MUTED
        ).pack(
            anchor="w",
            padx=20,
            pady=(6, 0)
        )

    ctk.CTkLabel(
        distribution_card,
        text="",
        height=10
    ).pack()

    # ========================================================
    # RECENT ACTIVITY
    # ========================================================

    recent_card = ctk.CTkFrame(
        lower_row,
        fg_color=CARD,
        corner_radius=15,
        border_width=1,
        border_color=BORDER
    )

    recent_card.pack(
        side="right",
        fill="both",
        expand=True,
        padx=(8, 0)
    )

    ctk.CTkLabel(
        recent_card,
        text="RECENT SECURITY ACTIVITY",
        font=(FONT, 18, "bold"),
        text_color=TEXT
    ).pack(
        anchor="w",
        padx=20,
        pady=(18, 2)
    )

    ctk.CTkLabel(
        recent_card,
        text="Latest detection events",
        font=(FONT, 12),
        text_color=MUTED
    ).pack(
        anchor="w",
        padx=20,
        pady=(0, 10)
    )

    if not data["recent"]:

        ctk.CTkLabel(
            recent_card,
            text="No scan activity yet.",
            font=(FONT, 12),
            text_color=MUTED
        ).pack(
            anchor="w",
            padx=20,
            pady=(4, 18)
        )

    for rec in data["recent"]:

        icon, title, color = describe_event(rec)

        target = rec["target"]

        if len(target) > 38:

            target = target[:35] + "..."

        create_activity_item(
            recent_card,
            icon,
            title,
            f"{target}  •  {rec['score']:.0f}%",
            ago(rec["ts"]),
            color
        )

    ctk.CTkLabel(
        recent_card,
        text="",
        height=8
    ).pack()

    # ========================================================
    # QUICK ACTIONS
    # ========================================================

    quick_card = ctk.CTkFrame(
        dashboard,
        fg_color=CARD,
        corner_radius=15,
        border_width=1,
        border_color=BORDER
    )

    quick_card.pack(
        fill="x",
        pady=(0, 18)
    )

    ctk.CTkLabel(
        quick_card,
        text="QUICK ACTIONS",
        font=(FONT, 18, "bold"),
        text_color=TEXT
    ).pack(
        side="left",
        padx=20,
        pady=18
    )

    actions = ctk.CTkFrame(
        quick_card,
        fg_color="transparent"
    )

    actions.pack(
        side="right",
        padx=15
    )

    create_action_button(
        actions,
        "🦠  SCAN FILE",
        RED,
        lambda: open_page(
            parent,
            on_scan_file,
            ("malware_scanner", "pages.malware_scanner", "ui.malware_scanner"),
            "show_malware_scanner"
        )
    )

    create_action_button(
        actions,
        "🔗  SCAN URL",
        ORANGE,
        lambda: open_page(
            parent,
            on_scan_url,
            ("phishing_scanner", "pages.phishing_scanner", "ui.phishing_scanner"),
            "show_phishing_scanner"
        )
    )

    create_action_button(
        actions,
        "📊  EXPORT HISTORY",
        CYAN,
        lambda: export_history(on_reports)
    )

    create_action_button(
        actions,
        "↻  REFRESH",
        CARD_2,
        refresh,
        text_color=TEXT,
        border=True
    )

    if HISTORY_AVAILABLE:
        create_action_button(
            actions,
            "CLEAR HISTORY",
            CARD_2,
            lambda: clear_history(refresh),
            text_color=TEXT,
            border=True
        )

    # ========================================================
    # FOOTER
    # ========================================================

    ctk.CTkLabel(
        dashboard,
        text="CyberShield AI  •  Real-Time Malware & Phishing Detection",
        font=(FONT, 11),
        text_color=MUTED
    ).pack(
        pady=(0, 20)
    )

    # Poll the SQLite scan history every 5 seconds for near-real-time updates.
    # Cancel the previous scheduled refresh to avoid duplicate timer chains.
    try:
        old_job = getattr(parent, "_cybershield_dashboard_job", None)
        if old_job:
            parent.after_cancel(old_job)
    except Exception:
        pass
    try:
        parent._cybershield_dashboard_job = parent.after(5000, refresh)
    except Exception:
        pass


# ============================================================
# EVENT DESCRIPTION
# ============================================================

def describe_event(rec):

    category = rec["category"]

    is_file = rec["kind"] == "malware"

    if category == "malware":

        return "🦠", "Malware detected", RED

    if category == "phishing":

        return "⚠", "Phishing detected", ORANGE

    if category == "suspicious":

        return (
            "⚠",
            "Suspicious file" if is_file else "Suspicious URL",
            PURPLE
        )

    return (
        "✓",
        "File scanned" if is_file else "URL verified",
        GREEN
    )


# ============================================================
# QUICK ACTION HANDLERS
# ============================================================

def open_page(parent, callback, module_names, func_name):

    if callback:

        callback()

        return

    for name in module_names:

        try:

            module = importlib.import_module(name)

            getattr(module, func_name)(parent)

            return

        except Exception:

            continue

    messagebox.showinfo(
        "Navigation",
        "Connect this button to your app navigation:\n\n"
        "show_dashboard(parent, on_scan_file=..., on_scan_url=...)"
    )


def export_history(callback):
    if callback:
        callback()
        return
    if not HISTORY_AVAILABLE:
        messagebox.showerror("Database unavailable", "Could not load database/scan_history_db.py")
        return
    path = filedialog.asksaveasfilename(
        defaultextension=".csv", filetypes=[("CSV file", "*.csv")],
        initialfile="cybershield_scan_history.csv")
    if not path:
        return
    import csv
    rows = get_all_scans() or []
    fields = ["id", "type", "target", "result", "risk", "score", "date", "time"]
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fields})
    messagebox.showinfo("Exported", f"{len(rows)} real scan record(s) saved to:\n{path}")


def clear_history(refresh):
    if not HISTORY_AVAILABLE:
        messagebox.showerror("Database unavailable", "Could not load database/scan_history_db.py")
        return
    if messagebox.askyesno("Clear history", "Delete all saved scan history?"):
        clear_all_scans()
        refresh()


# ============================================================
# STAT CARD
# ============================================================

def create_stat_card(
    parent,
    title,
    value,
    subtitle,
    color,
    icon
):

    card = ctk.CTkFrame(
        parent,
        fg_color=CARD,
        corner_radius=15,
        border_width=1,
        border_color=BORDER,
        height=135
    )

    card.pack(
        side="left",
        fill="both",
        expand=True,
        padx=5
    )

    top = ctk.CTkFrame(
        card,
        fg_color="transparent"
    )

    top.pack(
        fill="x",
        padx=17,
        pady=(15, 0)
    )

    ctk.CTkLabel(
        top,
        text=icon,
        font=(FONT, 22),
        text_color=color
    ).pack(
        side="left"
    )

    ctk.CTkLabel(
        top,
        text=title,
        font=(FONT, 11, "bold"),
        text_color=MUTED
    ).pack(
        side="left",
        padx=10
    )

    ctk.CTkLabel(
        card,
        text=value,
        font=(FONT, 28, "bold"),
        text_color=TEXT
    ).pack(
        anchor="w",
        padx=18,
        pady=(5, 0)
    )

    ctk.CTkLabel(
        card,
        text=subtitle,
        font=(FONT, 11),
        text_color=MUTED
    ).pack(
        anchor="w",
        padx=18,
        pady=(0, 12)
    )


# ============================================================
# THREAT GRAPH  (real data, auto-scaled, resizes with window)
# ============================================================

def draw_threat_graph(canvas, daily):

    canvas.delete("all")

    width = max(canvas.winfo_width(), 320)

    left = 45
    right = width - 25
    top = 20
    bottom = 185

    totals = [d["total"] for d in daily]
    threats = [d["threats"] for d in daily]

    peak = max(totals + threats + [0])

    top_value = max(
        4,
        int(math.ceil(peak / 4.0) * 4)
    )

    # Grid + Y labels
    for i in range(5):

        y = top + (bottom - top) * i / 4

        canvas.create_line(
            left,
            y,
            right,
            y,
            fill="#102638"
        )

        canvas.create_text(
            left - 12,
            y,
            text=str(int(top_value * (4 - i) / 4)),
            fill=MUTED,
            font=("Arial", 9),
            anchor="e"
        )

    count = len(daily)

    step = (right - left) / (count - 1) if count > 1 else 0

    def point(i, value):

        x = left + i * step

        y = bottom - (value / top_value) * (bottom - top)

        return (x, y)

    # X labels
    for i, d in enumerate(daily):

        canvas.create_text(
            left + i * step,
            205,
            text=d["label"],
            fill=MUTED,
            font=("Arial", 9)
        )

    if peak == 0:

        canvas.create_text(
            (left + right) / 2,
            (top + bottom) / 2,
            text="No scan activity in the last 7 days",
            fill=MUTED,
            font=(FONT, 13)
        )

        return

    total_points = [point(i, v) for i, v in enumerate(totals)]

    threat_points = [point(i, v) for i, v in enumerate(threats)]

    # Total scans (thin line)
    for i in range(count - 1):

        canvas.create_line(
            *total_points[i],
            *total_points[i + 1],
            fill="#3F6E8F",
            width=2,
            dash=(4, 3)
        )

    # Threat area
    polygon = [(threat_points[0][0], bottom)]

    polygon.extend(threat_points)

    polygon.append((threat_points[-1][0], bottom))

    canvas.create_polygon(
        polygon,
        fill="#082338",
        outline=""
    )

    # Threat line
    for i in range(count - 1):

        canvas.create_line(
            *threat_points[i],
            *threat_points[i + 1],
            fill=CYAN,
            width=3
        )

    # Threat points
    for x, y in threat_points:

        canvas.create_oval(
            x - 5,
            y - 5,
            x + 5,
            y + 5,
            fill=CYAN,
            outline=""
        )

    # Legend
    canvas.create_line(
        right - 190, 8, right - 170, 8,
        fill=CYAN, width=3
    )

    canvas.create_text(
        right - 165, 8,
        text="Threats",
        fill=MUTED,
        font=("Arial", 9),
        anchor="w"
    )

    canvas.create_line(
        right - 100, 8, right - 80, 8,
        fill="#3F6E8F", width=2, dash=(4, 3)
    )

    canvas.create_text(
        right - 75, 8,
        text="All scans",
        fill=MUTED,
        font=("Arial", 9),
        anchor="w"
    )


# ============================================================
# THREAT DISTRIBUTION
# ============================================================

def create_distribution(
    parent,
    name,
    count,
    total,
    color
):

    percentage = (count / total * 100) if total else 0

    row = ctk.CTkFrame(
        parent,
        fg_color="transparent"
    )

    row.pack(
        fill="x",
        padx=20,
        pady=6
    )

    top = ctk.CTkFrame(
        row,
        fg_color="transparent"
    )

    top.pack(
        fill="x"
    )

    ctk.CTkLabel(
        top,
        text=name,
        font=(FONT, 12, "bold"),
        text_color=TEXT
    ).pack(
        side="left"
    )

    ctk.CTkLabel(
        top,
        text=f"{count}  •  {percentage:.0f}%",
        font=(FONT, 11, "bold"),
        text_color=MUTED
    ).pack(
        side="right"
    )

    bar_bg = ctk.CTkFrame(
        row,
        fg_color="#10202E",
        height=9,
        corner_radius=5
    )

    bar_bg.pack(
        fill="x",
        pady=(5, 0)
    )

    if percentage > 0:

        bar = ctk.CTkFrame(
            bar_bg,
            fg_color=color,
            height=9,
            corner_radius=5
        )

        bar.place(
            relx=0,
            rely=0,
            relwidth=percentage / 100,
            relheight=1
        )


# ============================================================
# RECENT ACTIVITY ITEM
# ============================================================

def create_activity_item(
    parent,
    icon,
    title,
    target,
    time,
    color
):

    row = ctk.CTkFrame(
        parent,
        fg_color=CARD_2,
        corner_radius=10
    )

    row.pack(
        fill="x",
        padx=15,
        pady=4
    )

    ctk.CTkLabel(
        row,
        text=icon,
        font=(FONT, 18),
        text_color=color,
        width=35
    ).pack(
        side="left",
        padx=(8, 0)
    )

    info = ctk.CTkFrame(
        row,
        fg_color="transparent"
    )

    info.pack(
        side="left",
        fill="x",
        expand=True,
        pady=6
    )

    ctk.CTkLabel(
        info,
        text=title,
        font=(FONT, 12, "bold"),
        text_color=TEXT,
        anchor="w"
    ).pack(
        anchor="w"
    )

    ctk.CTkLabel(
        info,
        text=target,
        font=(FONT, 10),
        text_color=MUTED,
        anchor="w"
    ).pack(
        anchor="w"
    )

    ctk.CTkLabel(
        row,
        text=time,
        font=(FONT, 10),
        text_color=MUTED
    ).pack(
        side="right",
        padx=12
    )


# ============================================================
# QUICK ACTION BUTTON
# ============================================================

def create_action_button(
    parent,
    text,
    color,
    command,
    text_color="#001018",
    border=False
):

    button = ctk.CTkButton(
        parent,
        text=text,
        width=145,
        height=40,
        fg_color=color,
        hover_color=BORDER if border else BLUE,
        text_color=text_color,
        font=(FONT, 12, "bold"),
        corner_radius=9,
        border_width=1 if border else 0,
        border_color=BORDER,
        command=command
    )

    button.pack(
        side="left",
        padx=5,
        pady=12
    )


# ============================================================
# TEST MODE
# ============================================================

if __name__ == "__main__":

    app = ctk.CTk()

    app.title("CyberShield AI - Dashboard")

    app.geometry("1400x900")

    app.configure(
        fg_color=BG
    )

    show_dashboard(app)

    app.mainloop()