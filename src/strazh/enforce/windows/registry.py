"""Тонкая обёртка над winreg.

Смысл обёртки один: сделать работу с реестром обратимой. Каждая запись
возвращает прежнее значение, каждое удаление умеет отличить «не было» от
«не удалось». Без этого откат защиты превращается в гадание.
"""

from __future__ import annotations

import sys
from typing import Any

if sys.platform == "win32":  # pragma: no cover - ветка только для Windows
    import winreg
else:  # pragma: no cover - заглушка, чтобы модуль импортировался в проверках
    winreg = None  # type: ignore[assignment]

HKLM = "HKLM"
HKCU = "HKCU"

# 64-разрядное представление реестра. Без этого 32-разрядный Python видел бы
# ветку WOW6432Node, а перехват запуска надо ставить в общую.
_ACCESS_64 = 0x0100  # KEY_WOW64_64KEY


def _root(name: str) -> Any:
    if winreg is None:  # pragma: no cover
        raise RuntimeError("реестр доступен только в Windows")
    return {HKLM: winreg.HKEY_LOCAL_MACHINE, HKCU: winreg.HKEY_CURRENT_USER}[name]


def open_key(root: str, path: str, *, write: bool = False, create: bool = False) -> Any:
    """Открыть ключ. `create=True` заводит его, если нет."""
    access = (winreg.KEY_READ | winreg.KEY_WRITE if write else winreg.KEY_READ) | _ACCESS_64
    if create:
        return winreg.CreateKeyEx(_root(root), path, 0, access)
    return winreg.OpenKeyEx(_root(root), path, 0, access)


def read_value(root: str, path: str, name: str) -> Any | None:
    """Значение или `None`, если нет ни ключа, ни значения."""
    try:
        with open_key(root, path) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return value
    except (OSError, FileNotFoundError):
        return None


def key_exists(root: str, path: str) -> bool:
    try:
        with open_key(root, path):
            return True
    except OSError:
        return False


def write_value(root: str, path: str, name: str, value: Any, kind: int | None = None) -> Any | None:
    """Записать значение, вернув прежнее (или `None`, если его не было)."""
    if kind is None:
        kind = winreg.REG_DWORD if isinstance(value, int) else winreg.REG_SZ
    previous = read_value(root, path, name)
    with open_key(root, path, write=True, create=True) as key:
        winreg.SetValueEx(key, name, 0, kind, value)
    return previous


def delete_value(root: str, path: str, name: str) -> bool:
    try:
        with open_key(root, path, write=True) as key:
            winreg.DeleteValue(key, name)
            return True
    except OSError:
        return False


def delete_key_if_empty(root: str, path: str) -> bool:
    """Убрать ключ, если после отката в нём ничего не осталось.

    Ключ, который был до нас и содержит чужие значения, не трогаем: чужие
    настройки отладки — не наша забота.
    """
    try:
        with open_key(root, path) as key:
            subkey_count, value_count, _ = winreg.QueryInfoKey(key)
        if subkey_count or value_count:
            return False
        winreg.DeleteKeyEx(_root(root), path, _ACCESS_64, 0)
        return True
    except OSError:
        return False


def subkeys(root: str, path: str) -> list[str]:
    out: list[str] = []
    try:
        with open_key(root, path) as key:
            index = 0
            while True:
                try:
                    out.append(winreg.EnumKey(key, index))
                except OSError:
                    break
                index += 1
    except OSError:
        return []
    return out


def values(root: str, path: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    try:
        with open_key(root, path) as key:
            index = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, index)
                except OSError:
                    break
                out[name] = value
                index += 1
    except OSError:
        return {}
    return out


def delete_tree(root: str, path: str) -> bool:
    """Удалить ключ вместе с содержимым."""
    for child in subkeys(root, path):
        delete_tree(root, f"{path}\\{child}")
    try:
        winreg.DeleteKeyEx(_root(root), path, _ACCESS_64, 0)
        return True
    except OSError:
        return False
