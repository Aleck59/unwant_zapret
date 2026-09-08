"""Журнал событий."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING

from strazh.core.journal import EventKind
from strazh.gui.theme import Fonts, Palette
from strazh.gui.widgets import Card, scrollable_tree

if TYPE_CHECKING:
    from strazh.gui.app import StrazhWindow

KIND_TITLES = {
    EventKind.BLOCKED_PROCESS: "запуск остановлен",
    EventKind.BLOCKED_INSTALLER: "установщик опознан",
    EventKind.QUARANTINED: "в карантине",
    EventKind.PROTECTION_ON: "защита включена",
    EventKind.PROTECTION_OFF: "защита выключена",
    EventKind.RULE_APPLIED: "правило применено",
    EventKind.RULE_REVERTED: "правило снято",
    EventKind.CATALOG_CHANGED: "каталог изменён",
    EventKind.SCAN_FINDING: "находка проверки",
    EventKind.ERROR: "ошибка",
}

LOUD = {EventKind.BLOCKED_PROCESS, EventKind.QUARANTINED, EventKind.ERROR}


class JournalPage(ttk.Frame):
    def __init__(self, master: tk.Misc, app: StrazhWindow, fonts: Fonts) -> None:
        super().__init__(master)
        self.app = app

        head = Card(self, padding=16)
        head.pack(fill="x")
        ttk.Label(head, text="Журнал", style="CardTitle.TLabel").pack(side="left")
        ttk.Button(head, text="Обновить", command=self.refresh).pack(side="right")
        ttk.Button(head, text="Очистить", command=self._clear).pack(side="right", padx=(0, 8))

        holder, self.tree = scrollable_tree(
            self,
            columns=("time", "kind", "message"),
            headings=("Когда", "Что", "Подробности"),
            widths=(150, 170, 640),
        )
        holder.pack(fill="both", expand=True, pady=(12, 0))
        self.tree.tag_configure("loud", foreground=Palette.danger)

    def refresh(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for index, event in enumerate(self.app.core.recent(400)):
            self.tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    event.local_time,
                    KIND_TITLES.get(event.kind, event.kind.value),
                    event.message,
                ),
                tags=("loud",) if event.kind in LOUD else (),
            )

    def _clear(self) -> None:
        self.app.core.journal.clear()
        self.refresh()
