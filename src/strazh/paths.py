"""Где программа держит свои файлы.

Данные защиты (каталог, состояние, журнал) общие для всей машины и лежат в
`%ProgramData%`: службу-наблюдателя запускает система, и класть её состояние
в профиль конкретного человека было бы неверно. Настройки окна — личные,
поэтому уезжают в `%LOCALAPPDATA%`.

На не-Windows берутся каталоги по XDG: программа должна запускаться под
разработчиком и в проверках, иначе её нельзя ни собрать, ни проверить.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from strazh.version import APP_ID

IS_WINDOWS = sys.platform == "win32"


def _env_dir(name: str, fallback: Path) -> Path:
    raw = os.environ.get(name, "").strip()
    return Path(raw) if raw else fallback


def machine_dir() -> Path:
    """Общие для машины данные: каталог целей, состояние, журнал, карантин."""
    override = os.environ.get("STRAZH_HOME", "").strip()
    if override:
        return Path(override)
    if IS_WINDOWS:
        return _env_dir("ProgramData", Path("C:/ProgramData")) / "Strazh"
    return _env_dir("XDG_DATA_HOME", Path.home() / ".local" / "share") / APP_ID


def user_dir() -> Path:
    """Личные настройки окна: размер, выбранная вкладка, последний фильтр."""
    override = os.environ.get("STRAZH_USER_HOME", "").strip()
    if override:
        return Path(override)
    if IS_WINDOWS:
        return _env_dir("LOCALAPPDATA", Path.home() / "AppData" / "Local") / "Strazh"
    return _env_dir("XDG_CONFIG_HOME", Path.home() / ".config") / APP_ID


def builtin_catalog_dir() -> Path:
    """Каталог из поставки. Меняется только вместе с новой версией программы."""
    return Path(__file__).resolve().parent / "data" / "catalog"


def user_catalog_dir() -> Path:
    """Каталог, который правит человек. Обновление программы его не трогает."""
    return machine_dir() / "catalog.d"


def settings_file() -> Path:
    return machine_dir() / "settings.json"


def state_file() -> Path:
    """Что именно программа изменила в системе. Без этого файла нет отката."""
    return machine_dir() / "state.json"


def journal_file() -> Path:
    return machine_dir() / "journal.jsonl"


def quarantine_dir() -> Path:
    return machine_dir() / "quarantine"


def ensure_dirs() -> None:
    """Создать всё, чего не хватает. Безопасно вызывать сколько угодно раз."""
    for path in (machine_dir(), user_catalog_dir(), quarantine_dir(), user_dir()):
        path.mkdir(parents=True, exist_ok=True)
