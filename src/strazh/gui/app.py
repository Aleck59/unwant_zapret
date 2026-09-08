"""Главное окно.

Слева — разделы, справа — содержимое. Все длинные действия (включение защиты,
проверка машины) уходят в отдельный поток: окно, которое замирает на десять
секунд, выглядит сломанным, а включение защиты именно столько и занимает —
там сотни ключей реестра.
"""

from __future__ import annotations

import sys
import threading
import tkinter as tk
from collections.abc import Callable
from functools import partial
from tkinter import messagebox, ttk
from typing import Any, Protocol

from strazh.app import Strazh
from strazh.core.journal import Event, EventKind
from strazh.gui.pages.catalog import CatalogPage
from strazh.gui.pages.journal import JournalPage
from strazh.gui.pages.overview import OverviewPage
from strazh.gui.pages.scan import ScanPage
from strazh.gui.pages.settings import SettingsPage
from strazh.gui.theme import Palette, apply
from strazh.version import APP_NAME, __version__
from strazh.watch.downloads import Caught
from strazh.watch.processes import Blocked
from strazh.watch.supervisor import Supervisor

REFRESH_MS = 5000
"""Как часто окно освежает показания. Раньше было две секунды, но окно
открыто часами, а меняться в нём между событиями нечему: обновление идёт
только когда числа действительно изменились."""


class Page(Protocol):
    """Всё, что окно требует от раздела: уметь показать себя и обновиться."""

    def pack(self, **kwargs: Any) -> None: ...
    def pack_forget(self) -> None: ...
    def refresh(self) -> None: ...


class StrazhWindow(tk.Tk):
    def __init__(self, *, dry_run: bool = False) -> None:
        super().__init__()
        self.core = Strazh(dry_run=dry_run)
        self.supervisor: Supervisor | None = None  # создаётся после страниц

        self.title(f"{APP_NAME} {__version__}")
        self.geometry("1120x760")
        self.minsize(940, 620)
        self.fonts = apply(self)

        self._busy = False
        self._last_snapshot: tuple[object, ...] = ()
        self._build()
        self._start_watchers()
        self.refresh_all()
        self.after(REFRESH_MS, self._tick)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── сборка ────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        sidebar = ttk.Frame(self, style="Sidebar.TFrame", width=210)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        header = tk.Frame(sidebar, bg=Palette.sidebar, padx=18, pady=22)
        header.pack(fill="x")
        tk.Label(
            header, text=APP_NAME, bg=Palette.sidebar, fg="#ffffff", font=self.fonts.title
        ).pack(anchor="w")
        tk.Label(
            header,
            text="запрет нежелательного ПО",
            bg=Palette.sidebar,
            fg=Palette.sidebar_text,
            font=self.fonts.small,
            wraplength=170,
            justify="left",
            anchor="w",
        ).pack(anchor="w", fill="x")

        body = ttk.Frame(self, padding=20)
        body.pack(side="right", fill="both", expand=True)

        self.pages: dict[str, Page] = {
            "overview": OverviewPage(body, self, self.fonts),
            "catalog": CatalogPage(body, self, self.fonts),
            "scan": ScanPage(body, self, self.fonts),
            "journal": JournalPage(body, self, self.fonts),
            "settings": SettingsPage(body, self, self.fonts),
        }
        self.nav_buttons: dict[str, ttk.Button] = {}
        for key, title in (
            ("overview", "Обзор"),
            ("catalog", "Каталог"),
            ("scan", "Проверка"),
            ("journal", "Журнал"),
            ("settings", "Настройки"),
        ):
            button = ttk.Button(
                sidebar, text=title, style="Nav.TButton", command=partial(self.show, key)
            )
            button.pack(fill="x")
            self.nav_buttons[key] = button

        self.status_bar = tk.Label(
            sidebar,
            text="",
            bg=Palette.sidebar,
            fg=Palette.sidebar_text,
            font=self.fonts.small,
            wraplength=180,
            justify="left",
            padx=18,
            pady=16,
        )
        self.status_bar.pack(side="bottom", fill="x")

        self.current = "overview"
        self.show("overview")

    def show(self, key: str) -> None:
        for name, page in self.pages.items():
            page.pack_forget()
            self.nav_buttons[name].configure(style="Nav.TButton")
        self.pages[key].pack(fill="both", expand=True)
        self.nav_buttons[key].configure(style="NavActive.TButton")
        self.current = key
        self.pages[key].refresh()

    # ── состояние ─────────────────────────────────────────────────────────────

    @property
    def can_change_system(self) -> bool:
        """Хватает ли прав менять систему. В учебном режиме — всегда да."""
        return self.core.enforcer.platform != "windows" or self.core.enforcer.is_admin()

    def refresh_all(self) -> None:
        for page in self.pages.values():
            page.refresh()
        self._update_status_bar()

    def _update_status_bar(self) -> None:
        parts = []
        if self.core.enforcer.platform != "windows":
            parts.append("Учебный режим: система не меняется.")
        elif not self.core.enforcer.is_admin():
            parts.append("Без прав администратора. Часть слоёв недоступна.")
        if self.supervisor is not None and self.supervisor.running:
            stats = self.supervisor.stats
            parts.append(
                f"Страж работает ({self.supervisor.source_title}).\n"
                f"Остановлено: {stats['blocked']}, задержано: {stats['caught']}."
            )
        else:
            parts.append("Наблюдатели выключены.")
        self.status_bar.configure(text="\n\n".join(parts))

    def _tick(self) -> None:
        if not self._busy:
            snapshot = self._snapshot()
            if snapshot != self._last_snapshot:
                self._last_snapshot = snapshot
                self._update_status_bar()
                if self.current == "overview":
                    self.pages["overview"].refresh()
        self.after(REFRESH_MS, self._tick)

    def _snapshot(self) -> tuple[object, ...]:
        """Всё, что показывает обзор, одной строкой. Совпало с прошлым разом —
        перерисовывать нечего."""
        stats = self.supervisor.stats if self.supervisor is not None else {}
        return (
            self.core.protection_on,
            len(self.core.state.changes),
            stats.get("blocked", 0),
            stats.get("caught", 0),
            self.supervisor.running if self.supervisor is not None else False,
        )

    # ── длинные действия ──────────────────────────────────────────────────────

    def _run_async(
        self, title: str, work: Callable[[], Any], done: Callable[[Any], object]
    ) -> None:
        """Выполнить долгое действие, не подвешивая окно."""
        if self._busy:
            return
        self._busy = True
        self.configure(cursor="watch")
        self.status_bar.configure(text=title)

        def runner() -> None:
            try:
                result = work()
                error = None
            except Exception as exc:
                result, error = None, exc
            self.after(0, lambda: finish(result, error))

        def finish(result, error) -> None:
            self._busy = False
            self.configure(cursor="")
            if error is not None:
                self.core.log(Event(kind=EventKind.ERROR, message=str(error)))
                messagebox.showerror("Не получилось", str(error), parent=self)
            else:
                done(result)
            self.refresh_all()

        threading.Thread(target=runner, name="strazh-work", daemon=True).start()

    def turn_protection_on(self) -> None:
        if not self.can_change_system:
            self._offer_elevation()
            return
        self._run_async(
            "Применяю правила…",
            self.core.apply_protection,
            lambda report: messagebox.showinfo(
                "Защита включена",
                f"Внесено изменений: {report.total}\n\n{report.text()}",
                parent=self,
            ),
        )

    def turn_protection_off(self) -> None:
        if not self.can_change_system:
            self._offer_elevation()
            return
        self._run_async(
            "Снимаю правила…",
            self.core.revert_protection,
            lambda report: messagebox.showinfo(
                "Защита выключена",
                f"Снято изменений: {report.total}\n\n{report.text()}",
                parent=self,
            ),
        )

    def _offer_elevation(self) -> None:
        if sys.platform != "win32":
            return
        if messagebox.askyesno(
            "Нужны права администратора",
            "Правила запуска заводятся в общей ветке реестра, и без повышения прав "
            "их не изменить.\n\nПерезапустить программу с правами администратора?",
            parent=self,
        ):
            from strazh.enforce.windows.procs import relaunch_as_admin

            if relaunch_as_admin([]):
                self.destroy()
            else:
                messagebox.showwarning("Отказ", "Повышение прав не получено.", parent=self)

    # ── наблюдатели ───────────────────────────────────────────────────────────

    def _start_watchers(self) -> None:
        self.supervisor = Supervisor(self.core, on_block=self._on_block, on_catch=self._on_catch)
        self.supervisor.start()

    def restart_watchers(self) -> None:
        if self.supervisor is not None:
            self.supervisor.restart()

    def _on_block(self, blocked: Blocked) -> None:
        # Вызывается из потока наблюдателя: любое обращение к окну — только
        # через after, иначе tkinter упадёт в чужом потоке.
        self.after(0, lambda: self._notify(f"Остановлен запуск: {blocked.facts.image_name}"))

    def _on_catch(self, caught: Caught) -> None:
        self.after(0, lambda: self._notify(f"Задержан установщик: {caught.path.name}"))

    def _notify(self, message: str) -> None:
        self.status_bar.configure(text=message)
        if self.current == "journal":
            self.pages["journal"].refresh()

    def after_catalog_change(self) -> None:
        """Каталог изменили: пересобрать списки и сбросить память наблюдателя."""
        if self.supervisor is not None:
            self.supervisor.processes.forget_cache()
        self.refresh_all()

    def _on_close(self) -> None:
        if self.supervisor is not None:
            self.supervisor.stop()
        self.destroy()


def main() -> int:
    from strazh import console

    console.setup()
    dry_run = "--dry-run" in sys.argv
    try:
        window = StrazhWindow(dry_run=dry_run)
    except tk.TclError as exc:
        sys.stderr.write(
            "Не удалось открыть окно: "
            f"{exc}\nПроверьте, что установлен tkinter (в Windows он входит в состав Python).\n"
        )
        return 1
    window.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
