"""Список установленных программ.

Читается из тех же трёх веток реестра, что показывает «Программы и
компоненты». Нужен, чтобы понять, что уже успело встать на машину до того,
как защиту включили: запретить такому запуск задним числом мало — надо
отобрать службу и сеть.
"""

from __future__ import annotations

import sys

from strazh.enforce.base import InstalledProgram
from strazh.enforce.windows import registry as reg

UNINSTALL_PATHS = (
    (reg.HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (reg.HKLM, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    (reg.HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
)


def installed_programs() -> list[InstalledProgram]:
    if sys.platform != "win32":
        return []
    found: dict[str, InstalledProgram] = {}
    for root, base in UNINSTALL_PATHS:
        for name in reg.subkeys(root, base):
            path = f"{base}\\{name}"
            values = reg.values(root, path)
            title = str(values.get("DisplayName", "")).strip()
            if not title:
                continue
            # Обновления Windows перечислены там же и нам не интересны.
            if values.get("SystemComponent") == 1 or values.get("ParentKeyName"):
                continue
            program = InstalledProgram(
                name=title,
                publisher=str(values.get("Publisher", "")).strip(),
                version=str(values.get("DisplayVersion", "")).strip(),
                install_location=str(values.get("InstallLocation", "")).strip(),
                uninstall_string=str(values.get("UninstallString", "")).strip(),
                registry_key=f"{root}\\{path}",
            )
            found.setdefault(title.casefold() + "|" + program.version, program)
    return sorted(found.values(), key=lambda p: p.name.casefold())
