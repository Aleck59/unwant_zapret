"""Каталог: список целей, поиск, добавление и правка.

Главное требование к разделу — «лёгкое добавление новых программ». Поэтому
добавить цель можно двумя способами: коротким (название и список файлов) и
подробным (все признаки сразу). Оба пишут в один и тот же файл, который
переживает обновление программы.
"""

from __future__ import annotations

import tkinter as tk
import webbrowser
from functools import partial
from tkinter import messagebox, ttk
from typing import TYPE_CHECKING

from strazh.core.catalog import CATEGORIES
from strazh.core.models import Action, MatchSpec, Severity, Target
from strazh.gui.theme import Fonts, Palette
from strazh.gui.widgets import Card, SearchBox, scrollable_tree

if TYPE_CHECKING:
    from strazh.gui.app import StrazhWindow

ALL_CATEGORIES = "Все разделы"

SEVERITY_TEXT = {Severity.HIGH: "высокий", Severity.MEDIUM: "средний", Severity.LOW: "низкий"}


class CatalogPage(ttk.Frame):
    def __init__(self, master: tk.Misc, app: StrazhWindow, fonts: Fonts) -> None:
        super().__init__(master)
        self.app = app
        self.fonts = fonts
        self._query = ""
        self._category = ALL_CATEGORIES
        self._show_disabled = tk.BooleanVar(value=True)

        self._build_toolbar()
        self._build_table()
        self._build_details()

    def _build_toolbar(self) -> None:
        bar = Card(self, padding=12)
        bar.pack(fill="x")

        # Две строки, а не одна: в одну строку поиск, фильтр, галочка и три
        # кнопки не помещаются на узком окне, и кнопка добавления — та самая,
        # ради которой раздел и существует, — уезжает за край.
        top = ttk.Frame(bar, style="Card.TFrame")
        top.pack(fill="x")
        SearchBox(
            top, placeholder="Поиск по названию, издателю, файлу…", on_change=self._search
        ).pack(side="left", padx=(0, 12))

        self.category_box = ttk.Combobox(
            top,
            state="readonly",
            width=26,
            values=[ALL_CATEGORIES, *CATEGORIES.values()],
        )
        self.category_box.set(ALL_CATEGORIES)
        self.category_box.bind("<<ComboboxSelected>>", self._category_changed)
        self.category_box.pack(side="left", padx=(0, 12))

        ttk.Checkbutton(
            top,
            text="Показывать выключенные",
            variable=self._show_disabled,
            command=self.refresh,
        ).pack(side="left")

        bottom = ttk.Frame(bar, style="Card.TFrame")
        bottom.pack(fill="x", pady=(10, 0))
        ttk.Button(
            bottom, text="Добавить программу", style="Accent.TButton", command=self.add_target
        ).pack(side="left")
        ttk.Button(bottom, text="Изменить", command=self.edit_target).pack(side="left", padx=(8, 0))
        ttk.Button(bottom, text="Удалить", command=self.delete_target).pack(
            side="left", padx=(8, 0)
        )
        ttk.Label(
            bottom,
            text="Двойной щелчок включает и выключает цель",
            style="CardMuted.TLabel",
        ).pack(side="left", padx=(16, 0))

    def _build_table(self) -> None:
        holder, self.tree = scrollable_tree(
            self,
            columns=("state", "name", "vendor", "category", "severity", "source"),
            headings=("", "Название", "Издатель", "Раздел", "Уровень", "Откуда"),
            widths=(34, 280, 150, 170, 78, 78),
        )
        holder.pack(fill="both", expand=True, pady=(12, 0))
        self.tree.column("state", anchor="center", stretch=False)
        self.tree.tag_configure("off", foreground=Palette.muted)
        self.tree.tag_configure("high", foreground=Palette.text)
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._show_details())
        self.tree.bind("<Double-1>", self._toggle_selected)
        self.tree.bind("<space>", self._toggle_selected)

    def _build_details(self) -> None:
        card = Card(self, padding=16)
        card.pack(fill="x", pady=(12, 0))
        self.detail_title = ttk.Label(card, text="Выберите цель", style="CardTitle.TLabel")
        self.detail_title.pack(anchor="w")
        self.detail_why = ttk.Label(card, text="", style="CardMuted.TLabel", wraplength=860)
        self.detail_why.pack(anchor="w", pady=(4, 8))
        self.detail_match = ttk.Label(
            card, text="", style="Card.TLabel", wraplength=860, justify="left"
        )
        self.detail_match.pack(anchor="w")
        self.links = ttk.Frame(card, style="Card.TFrame")
        self.links.pack(anchor="w", pady=(8, 0))

        actions = ttk.Frame(card, style="Card.TFrame")
        actions.pack(anchor="w", pady=(12, 0))
        self.toggle_button = ttk.Button(actions, text="Выключить", command=self._toggle_selected)
        self.toggle_button.pack(side="left")

    # ── данные ────────────────────────────────────────────────────────────────

    def _visible(self) -> list[Target]:
        targets = self.app.core.catalog.as_list()
        if not self._show_disabled.get():
            targets = [t for t in targets if t.enabled]
        if self._category != ALL_CATEGORIES:
            wanted = [k for k, v in CATEGORIES.items() if v == self._category]
            targets = [t for t in targets if t.category in wanted]
        if self._query:
            needle = self._query.casefold()
            targets = [t for t in targets if _matches(t, needle)]
        return targets

    def refresh(self) -> None:
        selected = self._selected_id()
        self.tree.delete(*self.tree.get_children())
        for target in self._visible():
            self.tree.insert(
                "",
                "end",
                iid=target.id,
                values=(
                    "✓" if target.enabled else "×",
                    target.name,
                    target.vendor or "—",
                    CATEGORIES.get(target.category, target.category),
                    SEVERITY_TEXT.get(target.severity, "—"),
                    "своя" if target.source == "user" else "поставка",
                ),
                tags=("high" if target.enabled else "off",),
            )
        if selected and self.tree.exists(selected):
            self.tree.selection_set(selected)
        self._show_details()

    def _selected_id(self) -> str | None:
        selection = self.tree.selection()
        return selection[0] if selection else None

    def _selected(self) -> Target | None:
        target_id = self._selected_id()
        return self.app.core.catalog.targets.get(target_id) if target_id else None

    def _show_details(self) -> None:
        target = self._selected()
        for child in self.links.winfo_children():
            child.destroy()
        if target is None:
            self.detail_title.configure(text="Выберите цель")
            self.detail_why.configure(text="")
            self.detail_match.configure(text="")
            self.toggle_button.configure(state="disabled")
            return
        self.detail_title.configure(text=f"{target.name}  ·  {target.id}")
        self.detail_why.configure(text=target.why or "Пояснение не указано.")
        rows = []
        for name, values in target.match.to_json().items():
            rows.append(f"{_FIELD_TITLES.get(name, name)}: {', '.join(values)}")
        rows.append(
            "Действия: " + ", ".join(_ACTION_TITLES.get(a, a.value) for a in target.actions)
        )
        self.detail_match.configure(text="\n".join(rows))
        for url in target.references:
            link = tk.Label(
                self.links, text=url, fg=Palette.accent, bg=Palette.surface, cursor="hand2"
            )
            link.pack(anchor="w")
            link.bind("<Button-1>", partial(self._open_link, url))
        self.toggle_button.configure(
            state="normal", text="Выключить" if target.enabled else "Включить"
        )

    # ── действия ──────────────────────────────────────────────────────────────

    @staticmethod
    def _open_link(url: str, _event: tk.Event) -> None:
        webbrowser.open(url)

    def _search(self, text: str) -> None:
        self._query = text
        self.refresh()

    def _category_changed(self, _event: tk.Event) -> None:
        self._category = self.category_box.get()
        self.refresh()

    def _toggle_selected(self, _event: tk.Event | None = None) -> None:
        target = self._selected()
        if target is None:
            return
        self.app.core.set_target_enabled(target.id, not target.enabled)
        self.app.after_catalog_change()

    def add_target(self) -> None:
        dialog = TargetDialog(self, self.fonts)
        self.wait_window(dialog)
        if dialog.result is not None:
            self.app.core.save_user_target(dialog.result)
            self.app.after_catalog_change()

    def edit_target(self) -> None:
        target = self._selected()
        if target is None:
            messagebox.showinfo("Изменение", "Сначала выберите цель в списке.", parent=self)
            return
        if target.source != "user":
            messagebox.showinfo(
                "Запись из поставки",
                "Записи из поставки не редактируются: обновление программы вернуло бы правку "
                "обратно. Её можно выключить, а рядом создать свою — «Добавить программу».",
                parent=self,
            )
            return
        dialog = TargetDialog(self, self.fonts, target=target)
        self.wait_window(dialog)
        if dialog.result is not None:
            self.app.core.save_user_target(dialog.result)
            self.app.after_catalog_change()

    def delete_target(self) -> None:
        target = self._selected()
        if target is None:
            return
        if target.source != "user":
            messagebox.showinfo(
                "Запись из поставки",
                "Такую запись нельзя удалить — её можно выключить двойным щелчком.",
                parent=self,
            )
            return
        if messagebox.askyesno("Удаление", f"Удалить «{target.name}»?", parent=self):
            self.app.core.delete_user_target(target.id)
            self.app.after_catalog_change()


_FIELD_TITLES = {
    "executables": "Файлы программы",
    "installers": "Установщики",
    "original_filenames": "Исходные имена",
    "product_names": "Названия продукта",
    "publishers": "Издатели",
    "paths": "Пути",
    "sha256": "Контрольные суммы",
    "services": "Службы",
    "scheduled_tasks": "Задания",
    "domains": "Адреса",
}

_ACTION_TITLES = {
    Action.BLOCK_EXEC: "запретить запуск",
    Action.BLOCK_INSTALL: "запретить установку",
    Action.BLOCK_NETWORK: "закрыть сеть",
    Action.BLOCK_DOMAINS: "закрыть адреса",
    Action.NEUTRALIZE_SERVICES: "отключить службы",
    Action.QUARANTINE: "в карантин",
}


def _matches(target: Target, needle: str) -> bool:
    if needle in target.name.casefold() or needle in target.id.casefold():
        return True
    if needle in target.vendor.casefold():
        return True
    spec = target.match
    return any(
        needle in value.casefold()
        for group in (spec.executables, spec.installers, spec.publishers, spec.domains)
        for value in group
    )


class TargetDialog(tk.Toplevel):
    """Окно добавления и правки своей цели.

    Поля многострочные и подписаны примерами: добавление программы не должно
    требовать чтения документации. Обязателен только один признак — иначе
    цель никогда не сработает, и об этом честнее сказать сразу.
    """

    FIELDS: tuple[tuple[str, str, str], ...] = (
        ("executables", "Файлы программы", "по одному в строке, например 360tray.exe"),
        ("installers", "Установщики", "можно с маской: 360*setup*.exe"),
        ("publishers", "Издатели", "часть имени из подписи: Qihoo 360"),
        ("paths", "Пути", "маска места установки: *\\360\\*"),
        ("services", "Службы", "имена служб, можно с маской"),
        ("domains", "Адреса", "домены загрузки и отправки данных"),
    )

    def __init__(self, master: tk.Misc, fonts: Fonts, target: Target | None = None) -> None:
        super().__init__(master)
        self.result: Target | None = None
        self._source = target
        self.title("Изменить программу" if target else "Добавить программу")
        self.configure(bg=Palette.bg, padx=20, pady=20)
        self.resizable(False, False)
        self.transient(master.winfo_toplevel())
        self.grab_set()

        ttk.Label(
            self,
            text="Название",
            style="Muted.TLabel",
        ).grid(row=0, column=0, sticky="w")
        self.name_var = tk.StringVar(value=target.name if target else "")
        ttk.Entry(self, textvariable=self.name_var, width=54).grid(
            row=1, column=0, columnspan=2, sticky="ew", pady=(2, 10)
        )

        ttk.Label(self, text="Раздел", style="Muted.TLabel").grid(row=2, column=0, sticky="w")
        self.category = ttk.Combobox(self, state="readonly", values=list(CATEGORIES.values()))
        self.category.set(CATEGORIES.get(target.category if target else "other", "Прочее"))
        self.category.grid(row=3, column=0, sticky="ew", pady=(2, 10))

        ttk.Label(self, text="Уровень", style="Muted.TLabel").grid(
            row=2, column=1, sticky="w", padx=(10, 0)
        )
        self.severity = ttk.Combobox(self, state="readonly", values=list(SEVERITY_TEXT.values()))
        self.severity.set(SEVERITY_TEXT[target.severity if target else Severity.HIGH])
        self.severity.grid(row=3, column=1, sticky="ew", pady=(2, 10), padx=(10, 0))

        self.boxes: dict[str, tk.Text] = {}
        row = 4
        for key, title, hint in self.FIELDS:
            ttk.Label(self, text=f"{title}  ·  {hint}", style="Muted.TLabel").grid(
                row=row, column=0, columnspan=2, sticky="w", pady=(6, 2)
            )
            box = tk.Text(self, height=3, width=64, bd=1, relief="solid", font=fonts.mono)
            box.grid(row=row + 1, column=0, columnspan=2, sticky="ew")
            if target is not None:
                box.insert("1.0", "\n".join(getattr(target.match, key)))
            self.boxes[key] = box
            row += 2

        buttons = ttk.Frame(self)
        buttons.grid(row=row, column=0, columnspan=2, sticky="e", pady=(16, 0))
        ttk.Button(buttons, text="Отмена", command=self.destroy).pack(side="right", padx=(8, 0))
        ttk.Button(buttons, text="Сохранить", style="Accent.TButton", command=self._save).pack(
            side="right"
        )
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)

    def _save(self) -> None:
        name = self.name_var.get().strip()
        if not name:
            messagebox.showwarning("Название", "Укажите название программы.", parent=self)
            return
        values = {
            key: tuple(
                line.strip()
                for line in self.boxes[key].get("1.0", "end").splitlines()
                if line.strip()
            )
            for key, _, _ in self.FIELDS
        }
        if not any(values.values()):
            messagebox.showwarning(
                "Признаки",
                "Заполните хотя бы одно поле: без признаков цель никогда не сработает.",
                parent=self,
            )
            return

        from strazh.core.models import pattern_touches_protected

        dangerous = [
            p
            for p in (*values["executables"], *values["installers"])
            if pattern_touches_protected(p)
        ]
        if dangerous:
            messagebox.showerror(
                "Системный файл",
                "Эти маски задевают файлы, без которых Windows не запустится:\n\n"
                + "\n".join(dangerous)
                + "\n\nИсправьте их, чтобы сохранить.",
                parent=self,
            )
            return

        category = next((k for k, v in CATEGORIES.items() if v == self.category.get()), "other")
        severity = next(
            (k for k, v in SEVERITY_TEXT.items() if v == self.severity.get()), Severity.HIGH
        )
        target_id = (
            self._source.id
            if self._source is not None
            else "user-" + "".join(ch if ch.isalnum() else "-" for ch in name.casefold()).strip("-")
        )
        self.result = Target(
            id=target_id or "user-target",
            name=name,
            vendor="",
            category=category,
            severity=severity,
            enabled=True,
            why=self._source.why if self._source else "Добавлено вручную",
            match=MatchSpec(**values),
            actions=(
                Action.BLOCK_EXEC,
                Action.BLOCK_INSTALL,
                Action.BLOCK_NETWORK,
                Action.NEUTRALIZE_SERVICES,
                *((Action.BLOCK_DOMAINS,) if values["domains"] else ()),
            ),
            source="user",
        )
        self.destroy()
