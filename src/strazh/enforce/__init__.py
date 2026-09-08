"""Выбор распорядителя под текущую систему."""

from __future__ import annotations

import sys

from strazh.enforce.base import Enforcer, InstalledProgram, Mechanism, Report, StepResult

__all__ = ["Enforcer", "InstalledProgram", "Mechanism", "Report", "StepResult", "get_enforcer"]


def get_enforcer(*, force_dry_run: bool = False) -> Enforcer:
    """Настоящий распорядитель на Windows, разборщик плана — везде остальном.

    Подмена не тихая: у распорядителя есть поле `platform`, и окно показывает
    «учебный режим» прямо в заголовке, чтобы никто не решил, будто защита
    включена, когда она только нарисована.
    """
    if not force_dry_run and sys.platform == "win32":
        from strazh.enforce.windows.enforcer import WindowsEnforcer

        return WindowsEnforcer()
    from strazh.enforce.dryrun import DryRunEnforcer

    return DryRunEnforcer()
