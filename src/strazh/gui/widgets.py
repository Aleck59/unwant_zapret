"""Мелкие части окна, которых нет в tkinter.

Каждая написана потому, что стандартная выглядит инородно рядом с
остальными: карточка с полем и заголовком, переключатель, значок уровня,
строка поиска с подсказкой внутри.
"""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable
from tkinter import ttk
from typing import ClassVar

from strazh.gui.theme import Fonts, Palette


class Card(ttk.Frame):
    """Белый прямоугольник с полями — основной строительный блок окна."""

    def __init__(self, master: tk.Misc, *, padding: int = 16, **kwargs: object) -> None:
        super().__init__(master, style="Card.TFrame", padding=padding, **kwargs)  # type: ignore[arg-type]


class Switch(tk.Canvas):
    """Переключатель.

    В tkinter галочка есть, а переключателя нет. Для главного действия
    программы — «защита включена/выключена» — галочка слишком незаметна:
    состояние должно читаться с другого конца комнаты.
    """

    WIDTH = 52
    HEIGHT = 28

    def __init__(
        self,
        master: tk.Misc,
        *,
        value: bool = False,
        command: Callable[[bool], None] | None = None,
        background: str = Palette.surface,
    ) -> None:
        super().__init__(
            master,
            width=self.WIDTH,
            height=self.HEIGHT,
            highlightthickness=0,
            bd=0,
            bg=background,
            cursor="hand2",
        )
        self._value = value
        self._command = command
        self._enabled = True
        self.bind("<Button-1>", self._clicked)
        self.redraw()

    def _clicked(self, _event: tk.Event) -> None:
        if not self._enabled:
            return
        self.value = not self._value
        if self._command is not None:
            self._command(self._value)

    @property
    def value(self) -> bool:
        return self._value

    @value.setter
    def value(self, new: bool) -> None:
        self._value = bool(new)
        self.redraw()

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        self.configure(cursor="hand2" if enabled else "")
        self.redraw()

    def redraw(self) -> None:
        self.delete("all")
        if not self._enabled:
            track = Palette.border
        elif self._value:
            track = Palette.ok
        else:
            track = "#b8bfca"
        radius = self.HEIGHT // 2
        self._rounded(0, 0, self.WIDTH, self.HEIGHT, radius, track)
        knob = self.WIDTH - radius if self._value else radius
        self.create_oval(
            knob - radius + 3, 3, knob + radius - 3, self.HEIGHT - 3, fill="#ffffff", outline=""
        )

    def _rounded(self, x1: int, y1: int, x2: int, y2: int, r: int, colour: str) -> None:
        self.create_oval(x1, y1, x1 + 2 * r, y2, fill=colour, outline="")
        self.create_oval(x2 - 2 * r, y1, x2, y2, fill=colour, outline="")
        self.create_rectangle(x1 + r, y1, x2 - r, y2, fill=colour, outline="")


class Badge(tk.Label):
    """Цветная пометка: уровень опасности, состояние механизма."""

    TONES: ClassVar[dict[str, tuple[str, str]]] = {
        "ok": (Palette.ok, Palette.ok_bg),
        "warn": (Palette.warn, Palette.warn_bg),
        "danger": (Palette.danger, Palette.danger_bg),
        "muted": (Palette.muted, Palette.surface_alt),
    }

    def __init__(self, master: tk.Misc, text: str, tone: str = "muted", *, font: object = None):
        fg, bg = self.TONES.get(tone, self.TONES["muted"])
        super().__init__(
            master,
            text=f" {text} ",
            fg=fg,
            bg=bg,
            bd=0,
            padx=6,
            pady=2,
            font=font,  # type: ignore[arg-type]
        )

    def set(self, text: str, tone: str = "muted") -> None:
        fg, bg = self.TONES.get(tone, self.TONES["muted"])
        self.configure(text=f" {text} ", fg=fg, bg=bg)


class SearchBox(ttk.Frame):
    """Поле поиска с подсказкой внутри и мгновенным откликом."""

    def __init__(
        self, master: tk.Misc, *, placeholder: str = "Поиск…", on_change: Callable[[str], None]
    ) -> None:
        super().__init__(master, style="Card.TFrame")
        self._on_change = on_change
        self._placeholder = placeholder
        self.var = tk.StringVar()
        self.entry = ttk.Entry(self, textvariable=self.var, width=32)
        self.entry.pack(fill="x")
        self._showing_placeholder = True
        self.entry.insert(0, placeholder)
        self.entry.configure(foreground=Palette.muted)
        self.entry.bind("<FocusIn>", self._focus_in)
        self.entry.bind("<FocusOut>", self._focus_out)
        self.var.trace_add("write", self._changed)

    def _focus_in(self, _event: tk.Event) -> None:
        if self._showing_placeholder:
            self.entry.delete(0, "end")
            self.entry.configure(foreground=Palette.text)
            self._showing_placeholder = False

    def _focus_out(self, _event: tk.Event) -> None:
        if not self.var.get().strip():
            self._showing_placeholder = True
            self.entry.insert(0, self._placeholder)
            self.entry.configure(foreground=Palette.muted)

    def _changed(self, *_args: object) -> None:
        if self._showing_placeholder:
            return
        self._on_change(self.var.get().strip())

    def text(self) -> str:
        return "" if self._showing_placeholder else self.var.get().strip()


def section(master: tk.Misc, title: str, fonts: Fonts, subtitle: str = "") -> ttk.Frame:
    """Заголовок раздела с подписью. Возвращает рамку под содержимое."""
    wrapper = ttk.Frame(master)
    ttk.Label(wrapper, text=title, style="Title.TLabel").pack(anchor="w")
    if subtitle:
        ttk.Label(wrapper, text=subtitle, style="Muted.TLabel", wraplength=760).pack(
            anchor="w", pady=(2, 0)
        )
    return wrapper


def scrollable_tree(
    master: tk.Misc, columns: tuple[str, ...], headings: tuple[str, ...], widths: tuple[int, ...]
) -> tuple[ttk.Frame, ttk.Treeview]:
    """Таблица с полосой прокрутки — она нужна в трёх разделах из пяти."""
    holder = ttk.Frame(master, style="Card.TFrame")
    tree = ttk.Treeview(holder, columns=columns, show="headings", selectmode="browse")
    for name, title, width in zip(columns, headings, widths, strict=True):
        tree.heading(name, text=title)
        tree.column(name, width=width, anchor="w", stretch=name == columns[-1])
    bar = ttk.Scrollbar(holder, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=bar.set)
    tree.pack(side="left", fill="both", expand=True)
    bar.pack(side="right", fill="y")
    return holder, tree
