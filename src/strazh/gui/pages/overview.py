"""Обзор: состояние защиты и главный выключатель."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import TYPE_CHECKING

from strazh.gui.theme import Fonts, Palette
from strazh.gui.widgets import Badge, Card, Switch

if TYPE_CHECKING:
    from strazh.gui.app import StrazhWindow

MECHANISM_TITLES = {
    "ifeo": ("Перехват запуска по имени файла", "Не даёт запуститься известным файлам"),
    "srp": ("Правила по пути и маске", "Ловит установщики по маске имени и месту"),
    "group_policy": (
        "Локальная групповая политика",
        "Windows сама возвращает запрет, если его стёрли из реестра",
    ),
    "process_watch": ("Наблюдение за процессами", "Ловит переименованные файлы по подписи"),
    "download_watch": ("Наблюдение за загрузками", "Убирает установщики в карантин"),
    "firewall": ("Правила брандмауэра", "Отрезает сеть уже установленному"),
    "hosts": ("Закрытие адресов", "Мешает скачать установщик"),
    "defender_pua": ("Защита Windows от PUA", "Встроенный фильтр нежелательных программ"),
    "neutralize_services": ("Службы и задания", "Останавливает службы найденных целей"),
    "disallow_run": ("Запрет запуска из оболочки", "Дополнительный слой для проводника"),
}


class OverviewPage(ttk.Frame):
    def __init__(self, master: tk.Misc, app: StrazhWindow, fonts: Fonts) -> None:
        super().__init__(master)
        self.app = app
        self.fonts = fonts

        self._build_status()
        self._build_counters()
        self._build_mechanisms()

    # ── части страницы ────────────────────────────────────────────────────────

    def _build_status(self) -> None:
        card = Card(self, padding=24)
        card.pack(fill="x")

        left = ttk.Frame(card, style="Card.TFrame")
        left.pack(side="left", fill="both", expand=True)

        self.status_label = ttk.Label(left, text="—", style="Huge.TLabel")
        self.status_label.pack(anchor="w")
        self.status_hint = ttk.Label(left, text="", style="CardMuted.TLabel", wraplength=520)
        self.status_hint.pack(anchor="w", pady=(6, 0))

        right = ttk.Frame(card, style="Card.TFrame")
        right.pack(side="right")
        self.switch = Switch(right, command=self._toggled)
        self.switch.pack(anchor="e")
        self.switch_hint = ttk.Label(right, text="", style="CardMuted.TLabel")
        self.switch_hint.pack(anchor="e", pady=(8, 0))

    def _build_counters(self) -> None:
        row = ttk.Frame(self)
        row.pack(fill="x", pady=(14, 0))
        self.counters: dict[str, ttk.Label] = {}
        for key, title in (
            ("targets", "Целей включено"),
            ("changes", "Изменений в системе"),
            ("blocked", "Остановлено запусков"),
            ("caught", "Задержано установщиков"),
        ):
            card = Card(row, padding=16)
            card.pack(side="left", fill="both", expand=True, padx=(0, 10))
            value = ttk.Label(card, text="—", style="Huge.TLabel")
            value.pack(anchor="w")
            ttk.Label(card, text=title, style="CardMuted.TLabel").pack(anchor="w")
            self.counters[key] = value

    def _build_mechanisms(self) -> None:
        card = Card(self, padding=20)
        card.pack(fill="both", expand=True, pady=(14, 0))
        ttk.Label(card, text="Слои защиты", style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(
            card,
            text=(
                "Ни один слой не закрывает всё: перехват по имени обходится переименованием, "
                "наблюдатель за процессами срабатывает уже после запуска. Вместе они закрывают "
                "слабости друг друга. Настроить набор можно в разделе «Настройки»."
            ),
            style="CardMuted.TLabel",
            wraplength=720,
        ).pack(anchor="w", pady=(4, 14))

        self.mech_rows: dict[str, tuple[Badge, ttk.Label]] = {}
        grid = ttk.Frame(card, style="Card.TFrame")
        grid.pack(fill="both", expand=True)
        grid.columnconfigure(1, weight=1)
        for index, (key, (title, hint)) in enumerate(MECHANISM_TITLES.items()):
            badge = Badge(grid, "выкл", "muted", font=self.fonts.small)
            badge.grid(row=index, column=0, sticky="w", pady=3, padx=(0, 12))
            label = ttk.Label(grid, text=f"{title} — {hint}", style="Card.TLabel")
            label.grid(row=index, column=1, sticky="w", pady=3)
            self.mech_rows[key] = (badge, label)

    # ── обновление ────────────────────────────────────────────────────────────

    def refresh(self) -> None:
        core = self.app.core
        on = core.protection_on
        self.status_label.configure(
            text="Защита включена" if on else "Защита выключена",
            foreground=Palette.ok if on else Palette.danger,
        )
        if on:
            hint = (
                f"Правила применены {core.state.applied_at or 'ранее'}. "
                "Выключение снимет все изменения, которые программа внесла в систему."
            )
        else:
            hint = (
                "Ничего не запрещено. Включите защиту, чтобы применить каталог: "
                "будут заведены правила запуска, правила по маске и, если включено, "
                "правила брандмауэра."
            )
        self.status_hint.configure(text=hint)
        self.switch.value = on
        self.switch.set_enabled(self.app.can_change_system)
        self.switch_hint.configure(
            text="" if self.app.can_change_system else "нужны права администратора"
        )

        stats = self.app.supervisor.stats if self.app.supervisor else {"blocked": 0, "caught": 0}
        self.counters["targets"].configure(text=str(len(core.catalog.enabled())))
        self.counters["changes"].configure(text=str(len(core.state.changes)))
        self.counters["blocked"].configure(text=str(stats["blocked"]))
        self.counters["caught"].configure(text=str(stats["caught"]))

        mechanisms = core.settings.mechanisms
        source = self.app.supervisor.source_title if self.app.supervisor else ""
        for key, (badge, label) in self.mech_rows.items():
            if key == "process_watch" and source:
                title, _ = MECHANISM_TITLES[key]
                label.configure(text=f"{title} — {source}")
            enabled = bool(getattr(mechanisms, key, False))
            if not enabled:
                badge.set("выкл", "muted")
            elif on or key in ("process_watch", "download_watch"):
                badge.set("вкл", "ok")
            else:
                badge.set("готов", "warn")
            label.configure(foreground=Palette.text if enabled else Palette.muted)

    # ── действия ──────────────────────────────────────────────────────────────

    def _toggled(self, value: bool) -> None:
        # Возвращаем переключатель в прежнее положение: он должен показывать
        # состояние системы, а не намерение. Настоящее положение вернётся из
        # refresh(), когда работа закончится.
        self.switch.value = not value
        if value:
            self.app.turn_protection_on()
        else:
            if messagebox.askyesno(
                "Выключить защиту",
                "Все изменения, внесённые программой, будут сняты: правила запуска, "
                "правила по маске, правила брандмауэра и записи в hosts.\n\nПродолжить?",
                parent=self,
            ):
                self.app.turn_protection_off()
