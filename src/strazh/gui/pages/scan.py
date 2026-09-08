"""Проверка машины: что из каталога уже стоит и уже работает.

Раздел отвечает на вопрос, которого нет у остальных: защиту включили сегодня,
а «360» стоит с прошлого года — запрет запуска ему уже не помеха, служба
поднимет его сама. Здесь такое находят и обезвреживают.
"""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import TYPE_CHECKING

from strazh.app import ScanResult
from strazh.core.models import Severity
from strazh.gui.theme import Fonts, Palette
from strazh.gui.widgets import Card, scrollable_tree

if TYPE_CHECKING:
    from strazh.gui.app import StrazhWindow


class ScanPage(ttk.Frame):
    def __init__(self, master: tk.Misc, app: StrazhWindow, fonts: Fonts) -> None:
        super().__init__(master)
        self.app = app
        self.fonts = fonts
        self._result: ScanResult | None = None
        self._running = False

        head = Card(self, padding=20)
        head.pack(fill="x")
        ttk.Label(head, text="Проверка машины", style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(
            head,
            text=(
                "Сверяет список установленных программ и работающие процессы с каталогом. "
                "Ничего не удаляет: найденное можно остановить и лишить сети, а удалять — "
                "штатным средством самой программы."
            ),
            style="CardMuted.TLabel",
            wraplength=760,
        ).pack(anchor="w", pady=(4, 12))

        row = ttk.Frame(head, style="Card.TFrame")
        row.pack(fill="x")
        self.start_button = ttk.Button(
            row, text="Проверить", style="Accent.TButton", command=self.start
        )
        self.start_button.pack(side="left")
        self.neutralize_button = ttk.Button(
            row, text="Обезвредить найденное", command=self.neutralize, state="disabled"
        )
        self.neutralize_button.pack(side="left", padx=(8, 0))
        self.summary = ttk.Label(row, text="Проверка не запускалась", style="CardMuted.TLabel")
        self.summary.pack(side="left", padx=(16, 0))

        self.progress = ttk.Progressbar(
            head, mode="indeterminate", style="Thin.Horizontal.TProgressbar"
        )

        holder, self.tree = scrollable_tree(
            self,
            columns=("where", "title", "target", "reason"),
            headings=("Где", "Что найдено", "Цель из каталога", "Почему"),
            widths=(90, 320, 220, 380),
        )
        holder.pack(fill="both", expand=True, pady=(12, 0))
        self.tree.tag_configure("high", foreground=Palette.danger)

    def refresh(self) -> None:
        """Раздел не обновляется сам: проверка занимает секунды и запускается
        человеком осознанно."""

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self.start_button.configure(state="disabled")
        self.neutralize_button.configure(state="disabled")
        self.tree.delete(*self.tree.get_children())
        self.summary.configure(text="Идёт проверка…")
        self.progress.pack(fill="x", pady=(12, 0))
        self.progress.start(12)

        def work() -> None:
            result = self.app.core.scan()
            self.after(0, lambda: self._done(result))

        threading.Thread(target=work, name="strazh-scan", daemon=True).start()

    def _done(self, result: ScanResult) -> None:
        self._running = False
        self._result = result
        self.progress.stop()
        self.progress.pack_forget()
        self.start_button.configure(state="normal")
        for index, finding in enumerate(result.findings):
            self.tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    finding.where,
                    finding.title,
                    finding.verdict.target_name or "—",
                    finding.verdict.reason,
                ),
                tags=("high",) if finding.verdict.severity is Severity.HIGH else (),
            )
        if result.clean:
            self.summary.configure(
                text=(
                    f"Чисто. Просмотрено процессов: {result.processes_seen}, "
                    f"программ: {result.programs_seen}."
                )
            )
        else:
            self.summary.configure(text=f"Найдено: {len(result.findings)}")
            self.neutralize_button.configure(state="normal")

    def neutralize(self) -> None:
        if self._result is None or self._result.clean:
            return
        if not self.app.can_change_system:
            messagebox.showwarning(
                "Права",
                "Чтобы остановить службы и закрыть сеть, нужны права администратора.",
                parent=self,
            )
            return
        if not messagebox.askyesno(
            "Обезвредить",
            "Найденные программы будут остановлены, их службы отключены, а выход в сеть "
            "закрыт правилом брандмауэра. Файлы останутся на месте.\n\nПродолжить?",
            parent=self,
        ):
            return

        stopped = 0
        for finding in self._result.findings:
            if (
                finding.facts is not None
                and finding.facts.pid
                and self.app.core.enforcer.terminate(finding.facts.pid)
            ):
                stopped += 1
        report = self.app.core.apply_protection()
        self.app.refresh_all()
        messagebox.showinfo(
            "Готово",
            f"Остановлено процессов: {stopped}.\n\n{report.text()}",
            parent=self,
        )
