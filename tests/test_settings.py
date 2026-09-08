"""Проверки настроек: значения по умолчанию и разбор частичного файла."""

from __future__ import annotations

import json
from pathlib import Path

from strazh.core.settings import Mechanisms, Settings, load_settings, save_settings


def test_defaults_are_conservative() -> None:
    """Слои, которые задевают всю машину, по умолчанию выключены."""
    m = Mechanisms()
    assert m.ifeo and m.srp and m.process_watch and m.download_watch
    assert not m.hosts, "hosts правит общий файл — включается осознанно"
    assert not m.disallow_run, "слабый слой не должен создавать ложное чувство защиты"


def test_partial_file_keeps_defaults(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"mechanisms": {"hosts": True}}), encoding="utf-8")
    settings = load_settings(path)
    assert settings.mechanisms.hosts is True
    assert settings.mechanisms.ifeo is True


def test_unknown_keys_are_ignored(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"выдуманное": 1, "mechanisms": {"нет": True}}), encoding="utf-8")
    assert load_settings(path).mechanisms.ifeo is True


def test_broken_file_gives_defaults(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text("{сломано", encoding="utf-8")
    assert load_settings(path).mechanisms.ifeo is True


def test_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    settings = Settings()
    settings.mechanisms.hosts = True
    settings.set_enabled("qihoo-360", False)
    settings.allow_names = ["mytool.exe"]
    save_settings(path, settings)

    restored = load_settings(path)
    assert restored.mechanisms.hosts is True
    assert restored.overrides == {"qihoo-360": {"enabled": False}}
    assert restored.allowlist().names == {"mytool.exe"}
