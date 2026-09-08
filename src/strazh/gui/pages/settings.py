"""Настройки: слои защиты, папки наблюдения, исключения, карантин."""

from __future__ import annotations

import tkinter as tk
from functools import partial
from tkinter import filedialog, messagebox, ttk
from typing import TYPE_CHECKING

from strazh import paths
from strazh.core.quarantine import entries as quarantine_entries
from strazh.core.quarantine import restore as quarantine_restore
from strazh.gui.theme import Fonts, Palette
from strazh.gui.widgets import Card, scrollable_tree

if TYPE_CHECKING:
    from strazh.gui.app import StrazhWindow

MECHANISM_ROWS: tuple[tuple[str, str, str], ...] = (
    (
        "ifeo",
        "Перехват запуска по имени файла",
        "Основной слой. Запрещает запуск известных файлов до того, как они начнут работать.",
    ),
    (
        "srp",
        "Правила по пути и маске",
        "Ловит установщики по маске имени (360*setup*.exe) и по месту установки.",
    ),
    (
        "group_policy",
        "Локальная групповая политика",
        "Те же запреты, записанные в файлы политики Windows. Стереть ключ из реестра мало: "
        "система вернёт его обратно сама. Видно в gpedit.msc.",
    ),
    (
        "process_watch",
        "Наблюдение за процессами",
        "Единственный слой, который ловит переименованный файл: сверяет подпись и исходное имя. "
        "Работает подпиской на события Windows, а не опросом: в простое не тратит ничего.",
    ),
    (
        "download_watch",
        "Наблюдение за загрузками",
        "Проверяет новые файлы в папках загрузок и убирает совпавшие в карантин.",
    ),
    (
        "neutralize_services",
        "Службы и задания",
        "Останавливает и отключает службы найденных программ. Без этого они поднимут себя сами.",
    ),
    (
        "firewall",
        "Правила брандмауэра",
        "Закрывает сеть тому, что уже установлено: не обновится и не отправит собранное.",
    ),
    (
        "defender_pua",
        "Защита Windows от нежелательных программ",
        "Включает встроенный фильтр PUA. Работает независимо от этой программы.",
    ),
    (
        "hosts",
        "Закрытие адресов через hosts",
        "Мешает скачать установщик. Выключено по умолчанию: запись действует на всю машину.",
    ),
    (
        "disallow_run",
        "Запрет запуска из оболочки",
        "Слабый дополнительный слой: действует только на проводник и обходится переименованием.",
    ),
)


class SettingsPage(ttk.Frame):
    def __init__(self, master: tk.Misc, app: StrazhWindow, fonts: Fonts) -> None:
        super().__init__(master)
        self.app = app
        self.fonts = fonts
        self.vars: dict[str, tk.BooleanVar] = {}

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True)
        notebook.add(self._mechanisms_tab(notebook), text="  Слои защиты  ")
        notebook.add(self._watch_tab(notebook), text="  Наблюдение  ")
        notebook.add(self._quarantine_tab(notebook), text="  Карантин  ")
        notebook.add(self._about_tab(notebook), text="  О программе  ")

    # ── вкладки ───────────────────────────────────────────────────────────────

    def _mechanisms_tab(self, master: tk.Misc) -> ttk.Frame:
        page = Card(master, padding=20)
        ttk.Label(
            page,
            text=(
                "Изменения вступают в силу при следующем включении защиты. "
                "Если защита уже включена, нажмите «Применить заново»."
            ),
            style="CardMuted.TLabel",
            wraplength=760,
        ).pack(anchor="w", pady=(0, 14))

        for key, title, hint in MECHANISM_ROWS:
            var = tk.BooleanVar(value=bool(getattr(self.app.core.settings.mechanisms, key)))
            self.vars[key] = var
            row = ttk.Frame(page, style="Card.TFrame")
            row.pack(fill="x", pady=4)
            ttk.Checkbutton(row, text=title, variable=var, command=partial(self._toggle, key)).pack(
                anchor="w"
            )
            ttk.Label(row, text=hint, style="CardMuted.TLabel", wraplength=740).pack(
                anchor="w", padx=(22, 0)
            )

        buttons = ttk.Frame(page, style="Card.TFrame")
        buttons.pack(anchor="w", pady=(16, 0))
        ttk.Button(
            buttons,
            text="Применить заново",
            style="Accent.TButton",
            command=self.app.turn_protection_on,
        ).pack(side="left")
        return page

    def _watch_tab(self, master: tk.Misc) -> ttk.Frame:
        page = Card(master, padding=20)
        ttk.Label(page, text="Папки, за которыми следит страж", style="CardTitle.TLabel").pack(
            anchor="w"
        )
        ttk.Label(
            page,
            text=(
                "Пусто — берутся стандартные: загрузки и рабочий стол всех учётных записей "
                "и временные папки."
            ),
            style="CardMuted.TLabel",
            wraplength=740,
        ).pack(anchor="w", pady=(4, 10))

        self.dirs_list = tk.Listbox(page, height=6, bd=1, relief="solid", font=self.fonts.mono)
        self.dirs_list.pack(fill="x")
        for path in self.app.core.settings.watch_dirs:
            self.dirs_list.insert("end", path)

        row = ttk.Frame(page, style="Card.TFrame")
        row.pack(anchor="w", pady=(8, 18))
        ttk.Button(row, text="Добавить папку", command=self._add_dir).pack(side="left")
        ttk.Button(row, text="Убрать", command=self._remove_dir).pack(side="left", padx=(8, 0))

        self.quarantine_var = tk.BooleanVar(value=self.app.core.settings.quarantine)
        ttk.Checkbutton(
            page,
            text="Убирать найденные установщики в карантин",
            variable=self.quarantine_var,
            command=self._save_flags,
        ).pack(anchor="w")
        ttk.Label(
            page,
            text=(
                "Без этого установщик остаётся на месте — "
                "программа только запишет находку в журнал."
            ),
            style="CardMuted.TLabel",
            wraplength=740,
        ).pack(anchor="w", padx=(22, 0))

        self.notify_var = tk.BooleanVar(value=self.app.core.settings.notify)
        ttk.Checkbutton(
            page,
            text="Показывать сообщение при срабатывании",
            variable=self.notify_var,
            command=self._save_flags,
        ).pack(anchor="w", pady=(10, 0))
        return page

    def _quarantine_tab(self, master: tk.Misc) -> ttk.Frame:
        page = Card(master, padding=20)
        ttk.Label(page, text="Карантин", style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(
            page,
            text=(
                "Задержанные установщики. Файлы не удалены: если правило ошиблось, "
                "файл можно вернуть на прежнее место."
            ),
            style="CardMuted.TLabel",
            wraplength=740,
        ).pack(anchor="w", pady=(4, 10))

        holder, self.quarantine_tree = scrollable_tree(
            page,
            columns=("at", "name", "target", "reason"),
            headings=("Когда", "Файл", "Цель", "Почему"),
            widths=(150, 280, 200, 320),
        )
        holder.pack(fill="both", expand=True)

        row = ttk.Frame(page, style="Card.TFrame")
        row.pack(anchor="w", pady=(10, 0))
        ttk.Button(row, text="Обновить", command=self._load_quarantine).pack(side="left")
        ttk.Button(row, text="Вернуть файл", command=self._restore).pack(side="left", padx=(8, 0))
        self._load_quarantine()
        return page

    def _about_tab(self, master: tk.Misc) -> ttk.Frame:
        from strazh.version import APP_NAME, __version__

        page = Card(master, padding=20)
        ttk.Label(page, text=f"{APP_NAME} {__version__}", style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(
            page,
            text=(
                "Запрет запуска и установки нежелательного и шпионского ПО на уровне системы.\n\n"
                "Программа не заменяет антивирус: она не ищет неизвестное, а запрещает известное. "
                "Встроенную защиту Windows она не выключает, а наоборот включает её фильтр "
                "нежелательных программ.\n\n"
                "Все изменения обратимы. Список того, что изменено, хранится в state.json рядом "
                "с каталогом; «Выключить защиту» снимает изменения по этому списку."
            ),
            style="CardMuted.TLabel",
            wraplength=740,
            justify="left",
        ).pack(anchor="w", pady=(8, 14))

        for title, value in (
            ("Данные и каталог", str(paths.machine_dir())),
            ("Свои цели", str(paths.user_catalog_dir())),
            ("Журнал", str(paths.journal_file())),
            ("Карантин", str(paths.quarantine_dir())),
            ("Распорядитель", self.app.core.enforcer.platform),
        ):
            row = ttk.Frame(page, style="Card.TFrame")
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=f"{title}:", style="Card.TLabel", width=20).pack(side="left")
            tk.Label(
                row, text=value, bg=Palette.surface, fg=Palette.muted, font=self.fonts.mono
            ).pack(side="left")
        return page

    # ── действия ──────────────────────────────────────────────────────────────

    def _toggle(self, key: str) -> None:
        setattr(self.app.core.settings.mechanisms, key, self.vars[key].get())
        self.app.core.save()
        self.app.restart_watchers()
        self.app.refresh_all()

    def _save_flags(self) -> None:
        self.app.core.settings.quarantine = self.quarantine_var.get()
        self.app.core.settings.notify = self.notify_var.get()
        self.app.core.save()

    def _add_dir(self) -> None:
        chosen = filedialog.askdirectory(parent=self, title="Папка для наблюдения")
        if not chosen:
            return
        self.dirs_list.insert("end", chosen)
        self.app.core.settings.watch_dirs = list(self.dirs_list.get(0, "end"))
        self.app.core.save()
        self.app.restart_watchers()

    def _remove_dir(self) -> None:
        selection = self.dirs_list.curselection()
        if not selection:
            return
        self.dirs_list.delete(selection[0])
        self.app.core.settings.watch_dirs = list(self.dirs_list.get(0, "end"))
        self.app.core.save()
        self.app.restart_watchers()

    def _load_quarantine(self) -> None:
        self.quarantine_tree.delete(*self.quarantine_tree.get_children())
        self._quarantine = quarantine_entries(paths.quarantine_dir())
        for index, entry in enumerate(self._quarantine):
            self.quarantine_tree.insert(
                "",
                "end",
                iid=str(index),
                values=(entry.at, entry.stored.name, entry.target_name, entry.reason),
            )

    def _restore(self) -> None:
        selection = self.quarantine_tree.selection()
        if not selection:
            return
        entry = self._quarantine[int(selection[0])]
        if not messagebox.askyesno(
            "Вернуть файл",
            f"Вернуть «{entry.stored.name}» обратно в {entry.original}?\n\n"
            "Добавьте программу в исключения, иначе страж задержит файл снова.",
            parent=self,
        ):
            return
        restored = quarantine_restore(entry.stored)
        if restored is None:
            messagebox.showerror("Не вышло", "Файл вернуть не удалось.", parent=self)
        else:
            messagebox.showinfo("Готово", f"Файл возвращён: {restored}", parent=self)
        self._load_quarantine()

    def refresh(self) -> None:
        for key, var in self.vars.items():
            var.set(bool(getattr(self.app.core.settings.mechanisms, key)))
