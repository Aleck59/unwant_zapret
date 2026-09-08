"""Общая обвязка проверок.

Все проверки работают в своей папке: ни одна не читает и не пишет настоящие
`%ProgramData%\\Strazh`. Иначе прогон на машине разработчика менял бы его
собственную защиту.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("STRAZH_HOME", str(tmp_path / "machine"))
    monkeypatch.setenv("STRAZH_USER_HOME", str(tmp_path / "user"))
    return tmp_path


@pytest.fixture
def core(home: Path):
    from strazh.app import Strazh

    return Strazh(dry_run=True)
