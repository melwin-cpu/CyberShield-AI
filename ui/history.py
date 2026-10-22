import customtkinter as ctk
from tkinter import messagebox
from datetime import datetime

from database.scan_history_db import get_all_scans, clear_all_scans

# ============================================================
# CYBERSHIELD AI - SCAN HISTORY
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
# REAL DATABASE HISTORY
# ============================================================

SCAN_HISTORY = []


def load_scan_history():
    """Load actual scan records from SQLite database."""
    global SCAN_HISTORY

    try:
        SCAN_HISTORY = get_all_scans()
    except Exception as error:
        SCAN_HISTORY = []
        print(f"Failed to load scan history: {error}")

# ============================================================
# MAIN HISTORY PAGE
# ============================================================

def show_history(parent):
    
    # Load latest records from the database
    load_scan_history()

    # Clear page
    for widget in parent.winfo_children():
        widget.destroy()

    parent.configure(fg_color=BG)

    # ========================================================
    # SCROLLABLE CONTAINER
    # ========================================================

    history_frame = ctk.CTkScrollableFrame(
        parent,
        fg_color=BG,
        scrollbar_button_color=BORDER,
        scrollbar_button_hover_color=CYAN
    )

    history_frame.pack(
        fill="both",
        expand=True,
        padx=18,
        pady=12
    )

    # ========================================================
    # HEADER
    # ========================================================

    header = ctk.CTkFrame(
        history_frame,
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
        text="SCAN HISTORY",
        font=(FONT, 30, "bold"),
        text_color=TEXT
    ).pack(anchor="w")

    ctk.CTkLabel(
        title_frame,
        text="Complete malware and phishing scan activity",
        font=(FONT, 15),
        text_color=MUTED
    ).pack(
        anchor="w",
        pady=(2, 0)
    )

    # ========================================================
    # HEADER ACTIONS
    # ========================================================

    action_frame = ctk.CTkFrame(
        header,
        fg_color="transparent"
    )

    action_frame.pack(
        side="right"
    )

    ctk.CTkButton(
        action_frame,
        text="↻ Refresh",
        width=110,
        height=38,
        fg_color=CARD,
        hover_color=CARD_2,
        border_width=1,
        border_color=BORDER,
        text_color=TEXT,
        font=(FONT, 12, "bold"),
        command=lambda: refresh_history(parent)
    ).pack(
        side="left",
        padx=4
    )

    ctk.CTkButton(
        action_frame,
        text="🗑 Clear",
        width=100,
        height=38,
        fg_color=RED,
        hover_color="#C92F46",
        text_color="#FFFFFF",
        font=(FONT, 12, "bold"),
        command=lambda: clear_history(parent)
    ).pack(
        side="left",
        padx=4
    )

    # ========================================================
    # SUMMARY CARDS
    # ========================================================

    summary = ctk.CTkFrame(
        history_frame,
        fg_color="transparent"
    )

    summary.pack(
        fill="x",
        pady=(0, 18)
    )

    total = len(SCAN_HISTORY)

    malware = sum(
        1 for x in SCAN_HISTORY
        if x["type"] == "Malware"
    )

    phishing = sum(
        1 for x in SCAN_HISTORY
        if x["type"] == "Phishing"
    )

    threats = sum(
        1 for x in SCAN_HISTORY
        if x["risk"] == "HIGH"
    )

    create_summary_card(
        summary,
        "TOTAL SCANS",
        str(total),
        "All security scans",
        CYAN,
        "◉"
    )

    create_summary_card(
        summary,
        "MALWARE SCANS",
        str(malware),
        "File analysis",
        RED,
        "🦠"
    )

    create_summary_card(
        summary,
        "PHISHING SCANS",
        str(phishing),
        "URL analysis",
        ORANGE,
        "⚠"
    )

    create_summary_card(
        summary,
        "HIGH RISK",
        str(threats),
        "Threat events",
        RED,
        "!"
    )

    # ========================================================
    # FILTER SECTION
    # ========================================================

    filter_card = ctk.CTkFrame(
        history_frame,
        fg_color=CARD,
        corner_radius=14,
        border_width=1,
        border_color=BORDER
    )

    filter_card.pack(
        fill="x",
        pady=(0, 18)
    )

    ctk.CTkLabel(
        filter_card,
        text="FILTER SCANS",
        font=(FONT, 15, "bold"),
        text_color=TEXT
    ).pack(
        side="left",
        padx=(20, 10),
        pady=15
    )

    filter_var = ctk.StringVar(
        value="All"
    )

    filter_menu = ctk.CTkOptionMenu(
        filter_card,
        variable=filter_var,
        values=[
            "All",
            "Malware",
            "Phishing",
            "HIGH",
            "MEDIUM",
            "LOW",
            "UNKNOWN"
        ],
        width=130,
        height=35,
        fg_color=CARD_2,
        button_color=CYAN,
        button_hover_color=BLUE,
        text_color=TEXT,
        font=(FONT, 11, "bold")
    )

    filter_menu.pack(
        side="left",
        padx=5
    )

    search_entry = ctk.CTkEntry(
        filter_card,
        placeholder_text="Search target or scan ID...",
        width=280,
        height=35,
        fg_color=CARD_2,
        border_color=BORDER,
        text_color=TEXT,
        placeholder_text_color=MUTED,
        font=(FONT, 11)
    )

    search_entry.pack(
        side="left",
        padx=8
    )

    ctk.CTkButton(
        filter_card,
        text="Search",
        width=90,
        height=35,
        fg_color=CYAN,
        hover_color=BLUE,
        text_color="#001018",
        font=(FONT, 11, "bold"),
        command=lambda: filter_history(
            history_list,
            filter_var.get(),
            search_entry.get()
        )
    ).pack(
        side="left",
        padx=5
    )

    # ========================================================
    # HISTORY LIST
    # ========================================================

    history_list = ctk.CTkFrame(
        history_frame,
        fg_color="transparent"
    )

    history_list.pack(
        fill="x"
    )

    create_history_table(
        history_list,
        SCAN_HISTORY
    )

    # ========================================================
    # FOOTER
    # ========================================================

    ctk.CTkLabel(
        history_frame,
        text="CyberShield AI  •  Scan history and security activity",
        font=(FONT, 11),
        text_color=MUTED
    ).pack(
        pady=20
    )


# ============================================================
# SUMMARY CARD
# ============================================================

def create_summary_card(
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
        corner_radius=14,
        border_width=1,
        border_color=BORDER,
        height=120
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
        padx=16,
        pady=(13, 0)
    )

    ctk.CTkLabel(
        top,
        text=icon,
        font=(FONT, 20),
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
        padx=8
    )

    ctk.CTkLabel(
        card,
        text=value,
        font=(FONT, 27, "bold"),
        text_color=TEXT
    ).pack(
        anchor="w",
        padx=16
    )

    ctk.CTkLabel(
        card,
        text=subtitle,
        font=(FONT, 10),
        text_color=MUTED
    ).pack(
        anchor="w",
        padx=16
    )


# ============================================================
# HISTORY TABLE
# ============================================================

def create_history_table(
    parent,
    data
):

    # Clear old table
    for widget in parent.winfo_children():
        widget.destroy()

    # ========================================================
    # HEADER
    # ========================================================

    header = ctk.CTkFrame(
        parent,
        fg_color=CARD_2,
        corner_radius=9
    )

    header.pack(
        fill="x",
        pady=(0, 6)
    )

    columns = [
        ("SCAN ID", 120),
        ("TYPE", 100),
        ("TARGET", 220),
        ("RESULT", 170),
        ("RISK", 90),
        ("SCORE", 80),
        ("DATE", 120),
        ("TIME", 100),
        ("ACTION", 100)
    ]

    for name, width in columns:

        ctk.CTkLabel(
            header,
            text=name,
            width=width,
            font=(FONT, 11, "bold"),
            text_color=MUTED,
            anchor="w"
        ).pack(
            side="left",
            padx=5,
            pady=11
        )

    # ========================================================
    # ROWS
    # ========================================================

    for scan in data:

        row = ctk.CTkFrame(
            parent,
            fg_color=CARD,
            corner_radius=8,
            border_width=1,
            border_color="#0D2638"
        )

        row.pack(
            fill="x",
            pady=3
        )

        # ID
        ctk.CTkLabel(
            row,
            text=scan["id"],
            width=120,
            font=(FONT, 11, "bold"),
            text_color=CYAN,
            anchor="w"
        ).pack(
            side="left",
            padx=5,
            pady=9
        )

        # Type
        type_color = (
            RED
            if scan["type"] == "Malware"
            else ORANGE
        )

        ctk.CTkLabel(
            row,
            text=scan["type"],
            width=100,
            font=(FONT, 11, "bold"),
            text_color=type_color,
            anchor="w"
        ).pack(
            side="left",
            padx=5
        )

        # Target
        ctk.CTkLabel(
            row,
            text=scan["target"],
            width=220,
            font=(FONT, 11),
            text_color=TEXT,
            anchor="w"
        ).pack(
            side="left",
            padx=5
        )

        # Result
        ctk.CTkLabel(
            row,
            text=scan["result"],
            width=170,
            font=(FONT, 11),
            text_color=TEXT,
            anchor="w"
        ).pack(
            side="left",
            padx=5
        )

        # Risk
        risk_color = get_risk_color(
            scan["risk"]
        )

        ctk.CTkLabel(
            row,
            text=scan["risk"],
            width=90,
            height=25,
            corner_radius=7,
            fg_color=risk_color,
            text_color="#FFFFFF",
            font=(FONT, 10, "bold")
        ).pack(
            side="left",
            padx=5
        )

        # Score
        ctk.CTkLabel(
            row,
            text=f"{scan['score']}%",
            width=80,
            font=(FONT, 11, "bold"),
            text_color=risk_color
        ).pack(
            side="left",
            padx=5
        )

        # Date
        ctk.CTkLabel(
            row,
            text=scan["date"],
            width=120,
            font=(FONT, 10),
            text_color=MUTED,
            anchor="w"
        ).pack(
            side="left",
            padx=5
        )

        # Time
        ctk.CTkLabel(
            row,
            text=scan["time"],
            width=100,
            font=(FONT, 10),
            text_color=MUTED,
            anchor="w"
        ).pack(
            side="left",
            padx=5
        )

        # View
        ctk.CTkButton(
            row,
            text="View",
            width=75,
            height=28,
            fg_color=CARD_2,
            hover_color=BORDER,
            border_width=1,
            border_color=BORDER,
            text_color=TEXT,
            font=(FONT, 10, "bold"),
            command=lambda s=scan: show_scan_details(s)
        ).pack(
            side="left",
            padx=5
        )


# ============================================================
# RISK COLOR
# ============================================================

def get_risk_color(risk):
    
    if risk == "HIGH":
        return RED

    if risk == "MEDIUM":
        return ORANGE

    if risk == "UNKNOWN":
        return "#64748B"

    if risk == "LOW":
        return GREEN

    return "#64748B"


# ============================================================
# FILTER HISTORY
# ============================================================

def filter_history(
    parent,
    selected_filter,
    search_text
):

    search_text = search_text.lower().strip()

    filtered = []

    for scan in SCAN_HISTORY:

        filter_match = (
            selected_filter == "All"
            or scan["type"] == selected_filter
            or scan["risk"] == selected_filter
        )

        search_match = (
            not search_text
            or search_text in scan["id"].lower()
            or search_text in scan["target"].lower()
            or search_text in scan["result"].lower()
        )

        if filter_match and search_match:
            filtered.append(scan)

    create_history_table(
        parent,
        filtered
    )


# ============================================================
# SHOW SCAN DETAILS
# ============================================================

def show_scan_details(scan):

    window = ctk.CTkToplevel()

    window.title(
        f"CyberShield AI - {scan['id']}"
    )

    window.geometry(
        "700x620"
    )

    window.configure(
        fg_color=BG
    )

    window.grab_set()

    # Header
    ctk.CTkLabel(
        window,
        text="SCAN DETAILS",
        font=(FONT, 28, "bold"),
        text_color=TEXT
    ).pack(
        anchor="w",
        padx=30,
        pady=(25, 2)
    )

    ctk.CTkLabel(
        window,
        text=scan["id"],
        font=(FONT, 13),
        text_color=CYAN
    ).pack(
        anchor="w",
        padx=30
    )

    # Risk
    risk_card = ctk.CTkFrame(
        window,
        fg_color=CARD,
        corner_radius=15,
        border_width=1,
        border_color=BORDER
    )

    risk_card.pack(
        fill="x",
        padx=30,
        pady=20
    )

    ctk.CTkLabel(
        risk_card,
        text="AI RISK SCORE",
        font=(FONT, 12, "bold"),
        text_color=MUTED
    ).pack(
        pady=(18, 0)
    )

    ctk.CTkLabel(
        risk_card,
        text=f"{scan['score']}%",
        font=(FONT, 42, "bold"),
        text_color=get_risk_color(scan["risk"])
    ).pack()

    ctk.CTkLabel(
        risk_card,
        text=scan["risk"] + " RISK",
        font=(FONT, 14, "bold"),
        text_color=TEXT
    ).pack(
        pady=(0, 18)
    )

    # Information
    info = ctk.CTkFrame(
        window,
        fg_color=CARD,
        corner_radius=15,
        border_width=1,
        border_color=BORDER
    )

    info.pack(
        fill="x",
        padx=30
    )

    details = [
        ("Scan ID", scan["id"]),
        ("Detection Type", scan["type"]),
        ("Target", scan["target"]),
        ("Result", scan["result"]),
        ("Risk Level", scan["risk"]),
        ("AI Score", f"{scan['score']}%"),
        ("Date", scan["date"]),
        ("Time", scan["time"])
    ]

    for key, value in details:

        row = ctk.CTkFrame(
            info,
            fg_color="transparent"
        )

        row.pack(
            fill="x",
            padx=18,
            pady=5
        )

        ctk.CTkLabel(
            row,
            text=key,
            width=150,
            anchor="w",
            font=(FONT, 11, "bold"),
            text_color=MUTED
        ).pack(
            side="left"
        )

        ctk.CTkLabel(
            row,
            text=value,
            anchor="w",
            font=(FONT, 11),
            text_color=TEXT
        ).pack(
            side="left"
        )

    # Close
    ctk.CTkButton(
        window,
        text="Close",
        width=130,
        height=40,
        fg_color=CYAN,
        hover_color=BLUE,
        text_color="#001018",
        font=(FONT, 12, "bold"),
        command=window.destroy
    ).pack(
        pady=25
    )


# ============================================================
# REFRESH
# ============================================================

def refresh_history(parent):

    show_history(parent)


# ============================================================
# CLEAR HISTORY
# ============================================================

def clear_history(parent):
    
    answer = messagebox.askyesno(
        "Clear Scan History",
        "Are you sure you want to permanently delete all scan history?"
    )

    if not answer:
        return

    try:
        clear_all_scans()
        load_scan_history()
        show_history(parent)
        print("HISTORY DATA:", SCAN_HISTORY)

        messagebox.showinfo(
            "Scan History",
            "Scan history cleared successfully."
        )

    except Exception as error:
        messagebox.showerror(
            "Database Error",
            f"Could not clear scan history:\n{error}"
        )

# ============================================================
# TEST MODE
# ============================================================

if __name__ == "__main__":

    app = ctk.CTk()

    app.title(
        "CyberShield AI - Scan History"
    )

    app.geometry(
        "1450x900"
    )

    app.configure(
        fg_color=BG
    )

    show_history(app)

    app.mainloop()