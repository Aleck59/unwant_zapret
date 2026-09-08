"""Оформление окна.

Tkinter выбран не от бедности. У программы, которая ставится с правами
системы, каждая внешняя зависимость — это ещё один способ ей навредить, а
tkinter входит в состав Python и не тянет за собой ничего. Взамен приходится
описывать вид руками: тема `clam` — единственная встроенная, которая слушается
настроек цвета целиком.
"""

from __future__ import annotations

import contextlib
import sys
import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk


class Palette:
    """Цвета. Собраны в одном месте, чтобы их можно было пересобрать разом."""

    bg = "#f4f5f7"
    surface = "#ffffff"
    surface_alt = "#eef0f4"
    border = "#d7dae0"

    sidebar = "#1f2733"
    sidebar_text = "#c7cedb"
    sidebar_active = "#2c3849"
    sidebar_active_text = "#ffffff"

    text = "#1c2430"
    muted = "#6b7684"

    accent = "#2f6fed"
    accent_dark = "#2258c8"

    ok = "#1f9254"
    ok_bg = "#e6f5ec"
    warn = "#b7791f"
    warn_bg = "#fdf3e2"
    danger = "#c33f3f"
    danger_bg = "#fdecec"


def pick_font() -> str:
    for name in ("Segoe UI", "Inter", "Noto Sans", "DejaVu Sans", "Helvetica"):
        try:
            if name in tkfont.families():
                return name
        except tk.TclError:
            break
    return "TkDefaultFont"


class Fonts:
    def __init__(self, root: tk.Misc) -> None:
        family = pick_font()
        self.body = tkfont.Font(root=root, family=family, size=10)
        self.small = tkfont.Font(root=root, family=family, size=9)
        self.strong = tkfont.Font(root=root, family=family, size=10, weight="bold")
        self.title = tkfont.Font(root=root, family=family, size=15, weight="bold")
        self.huge = tkfont.Font(root=root, family=family, size=22, weight="bold")
        self.mono = tkfont.Font(
            root=root,
            family="Consolas" if sys.platform == "win32" else "monospace",
            size=9,
        )


def apply(root: tk.Tk) -> Fonts:
    """Настроить стили и вернуть набор шрифтов."""
    fonts = Fonts(root)
    style = ttk.Style(root)
    with contextlib.suppress(tk.TclError):
        style.theme_use("clam")

    p = Palette
    root.configure(background=p.bg)

    style.configure(".", background=p.bg, foreground=p.text, font=fonts.body)
    style.configure("TFrame", background=p.bg)
    style.configure("Card.TFrame", background=p.surface, relief="flat")
    style.configure("Sidebar.TFrame", background=p.sidebar)

    style.configure("TLabel", background=p.bg, foreground=p.text)
    style.configure("Card.TLabel", background=p.surface, foreground=p.text)
    style.configure("CardMuted.TLabel", background=p.surface, foreground=p.muted, font=fonts.small)
    style.configure("Muted.TLabel", background=p.bg, foreground=p.muted, font=fonts.small)
    style.configure("Title.TLabel", background=p.bg, foreground=p.text, font=fonts.title)
    style.configure("CardTitle.TLabel", background=p.surface, foreground=p.text, font=fonts.strong)
    style.configure("Huge.TLabel", background=p.surface, foreground=p.text, font=fonts.huge)

    style.configure(
        "TButton",
        background=p.surface_alt,
        foreground=p.text,
        borderwidth=0,
        focuscolor=p.accent,
        padding=(14, 8),
    )
    style.map(
        "TButton",
        background=[("active", p.border), ("disabled", p.surface_alt)],
        foreground=[("disabled", p.muted)],
    )
    style.configure("Accent.TButton", background=p.accent, foreground="#ffffff", padding=(18, 10))
    style.map(
        "Accent.TButton",
        background=[("active", p.accent_dark), ("disabled", p.border)],
        foreground=[("disabled", p.muted)],
    )
    style.configure("Danger.TButton", background=p.danger_bg, foreground=p.danger, padding=(18, 10))
    style.map("Danger.TButton", background=[("active", "#f7d7d7")])

    style.configure(
        "Nav.TButton",
        background=p.sidebar,
        foreground=p.sidebar_text,
        borderwidth=0,
        anchor="w",
        padding=(18, 12),
    )
    style.map(
        "Nav.TButton",
        background=[("active", p.sidebar_active), ("selected", p.sidebar_active)],
        foreground=[("active", p.sidebar_active_text), ("selected", p.sidebar_active_text)],
    )
    style.configure(
        "NavActive.TButton",
        background=p.sidebar_active,
        foreground=p.sidebar_active_text,
        borderwidth=0,
        anchor="w",
        padding=(18, 12),
    )
    style.map("NavActive.TButton", background=[("active", p.sidebar_active)])

    style.configure(
        "Treeview",
        background=p.surface,
        fieldbackground=p.surface,
        foreground=p.text,
        borderwidth=0,
        rowheight=26,
    )
    style.configure(
        "Treeview.Heading",
        background=p.surface_alt,
        foreground=p.muted,
        font=fonts.small,
        borderwidth=0,
        padding=(8, 6),
    )
    style.map("Treeview.Heading", background=[("active", p.border)])
    style.map("Treeview", background=[("selected", "#dbe7ff")], foreground=[("selected", p.text)])

    style.configure("TEntry", fieldbackground=p.surface, borderwidth=1, padding=6)
    style.configure("TCombobox", fieldbackground=p.surface, borderwidth=1, padding=4)
    style.configure("TCheckbutton", background=p.surface, foreground=p.text)
    style.configure("Plain.TCheckbutton", background=p.bg, foreground=p.text)
    style.configure("TNotebook", background=p.bg, borderwidth=0)
    style.configure("TNotebook.Tab", padding=(16, 8), background=p.surface_alt)
    style.map("TNotebook.Tab", background=[("selected", p.surface)])
    style.configure("TSeparator", background=p.border)
    style.configure(
        "Thin.Horizontal.TProgressbar",
        background=p.accent,
        troughcolor=p.surface_alt,
        borderwidth=0,
    )
    return fonts
