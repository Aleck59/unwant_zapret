#!/usr/bin/env python3
"""Проверка, что окно вообще собирается и работает.

Обычные проверки не трогают интерфейс: у tkinter нет способа «вызвать
кнопку» без настоящего экрана. Но неверный порядок сборки виджетов или
опечатка в имени стиля роняют окно на первом же запуске, и узнавать об этом
от человека — поздно. Здесь окно поднимается на подставном экране (Xvfb),
переключаются все разделы и проверяется главное обещание: правило,
способное заблокировать вход в систему, через окно не заводится.
"""

from __future__ import annotations

import os
import sys
import tempfile
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def main() -> int:
    workdir = tempfile.mkdtemp(prefix="strazh-gui-")
    os.environ["STRAZH_HOME"] = str(Path(workdir) / "machine")
    os.environ["STRAZH_USER_HOME"] = str(Path(workdir) / "user")

    from strazh.gui.app import StrazhWindow
    from strazh.gui.pages.catalog import TargetDialog

    failures: list[str] = []
    window = StrazhWindow(dry_run=True)
    window.update_idletasks()
    window.update()

    for page in ("overview", "catalog", "scan", "journal", "settings"):
        try:
            window.show(page)
            window.update_idletasks()
            window.update()
            print(f"раздел «{page}» — открылся")
        except Exception:  # noqa: BLE001 - в проверке нужен весь разбор
            failures.append(page)
            traceback.print_exc()

    try:
        dialog = TargetDialog(window.pages["catalog"], window.fonts)  # type: ignore[arg-type]
        dialog.update_idletasks()
        dialog.name_var.set("Проверочная запись")
        dialog.boxes["executables"].insert("1.0", "checkme.exe")
        dialog._save()
        assert dialog.result is not None
        assert dialog.result.match.executables == ("checkme.exe",)
        print("добавление цели — работает")
    except Exception:  # noqa: BLE001
        failures.append("добавление цели")
        traceback.print_exc()

    try:
        from tkinter import messagebox

        shown: list[object] = []
        messagebox.showerror = lambda *a, **k: shown.append(a)  # type: ignore[assignment]
        guard = TargetDialog(window.pages["catalog"], window.fonts)  # type: ignore[arg-type]
        guard.update_idletasks()
        guard.name_var.set("Опасная запись")
        guard.boxes["executables"].insert("1.0", "lsass.exe")
        guard._save()
        assert guard.result is None, "окно позволило завести правило на системный файл"
        assert shown, "окно не предупредило о системном файле"
        print("защита от блокировки системных файлов — работает")
    except Exception:  # noqa: BLE001
        failures.append("защита от блокировки системных файлов")
        traceback.print_exc()

    window.destroy()
    if failures:
        print("\nНе прошло: " + ", ".join(failures))
        return 1
    print("\nОкно в порядке.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
