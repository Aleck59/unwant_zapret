"""Перехват запуска по имени файла.

Windows разрешает назначить программе «отладчик»: вместо неё запускается
указанный файл, а её строка запуска передаётся ему как аргументы. Механизм
задуман для разработчиков, но работает раньше самой программы и на всех
изданиях Windows, включая домашние, где нет ни AppLocker, ни редактора
групповых политик. Поэтому он и взят основным.

Ограничение честное: ключ называется именем файла, поэтому переименованный
файл через него не поймать. Этим занимается наблюдатель за процессами.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from strazh.core.models import Target, is_protected
from strazh.core.state import Change, State
from strazh.enforce import plan as planner
from strazh.enforce.base import Mechanism, StepResult
from strazh.enforce.windows import registry as reg

IFEO_PATH = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"

MECHANISM = "ifeo"


def deny_command() -> str | None:
    """Чем подменять запуск.

    Значение «отладчика» обязано указывать на файл, который существует.
    Указывающее в пустоту оставит человека наедине с ошибкой запуска без
    единого слова о том, кто и почему остановил программу, — а перехват
    ключа при этом будет выглядеть работающим.

    Поэтому кандидаты перебираются по убыванию пригодности, и каждый
    проверяется на существование. Если не подошёл ни один, механизм честно
    объявляет себя недоступным вместо того, чтобы записать негодное значение.
    """
    if getattr(sys, "frozen", False):
        stub = Path(sys.executable).parent / "strazh-deny.exe"
        if stub.exists():
            return f'"{stub}"'

    # Запуск из исходников: обработчик — обычный сценарий, и его умеет
    # запустить тот же самый Python.
    source_stub = Path(__file__).resolve().parents[4] / "packaging" / "deny_stub.py"
    if source_stub.exists() and Path(sys.executable).exists():
        return f'"{sys.executable}" "{source_stub}"'

    # Последняя возможность: системная заглушка, которая просто немедленно
    # завершается. Она есть не во всех сборках Windows, поэтому проверяется.
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    systray = Path(system_root) / "System32" / "systray.exe"
    if systray.exists():
        return f'"{systray}"'
    return None


class IfeoMechanism(Mechanism):
    key = MECHANISM
    title = "Перехват запуска по имени файла"

    def __init__(self, command: str | None = None) -> None:
        self._command = command or deny_command()

    def available(self) -> tuple[bool, str]:
        if sys.platform != "win32":
            return False, "механизм есть только в Windows"
        if not self._command:
            return False, "не найден обработчик заблокированного запуска"
        return True, ""

    def apply(self, targets: list[Target], state: State) -> StepResult:
        ops = planner.plan_ifeo(targets)
        command = self._command
        if not command:
            return StepResult(
                mechanism=self.key,
                title=self.title,
                ok=False,
                count=0,
                message="не найден обработчик заблокированного запуска",
            )
        done = 0
        failed: list[str] = []
        for op in ops:
            if is_protected(op.key):
                continue
            path = f"{IFEO_PATH}\\{op.key}"
            try:
                existed = reg.key_exists(reg.HKLM, path)
                previous = reg.write_value(reg.HKLM, path, "Debugger", command)
                state.add(
                    Change(
                        mechanism=self.key,
                        key=op.key,
                        target_id=op.target_id,
                        # Чужое значение «отладчика» запоминаем целиком, а
                        # «ключа не было» и «ключ был пустым» различаем: при
                        # откате первый удаляется, второй остаётся на месте.
                        previous=previous if previous is not None else ("" if existed else None),
                    )
                )
                done += 1
            except OSError as exc:
                failed.append(f"{op.key}: {exc}")
        return StepResult(
            mechanism=self.key,
            title=self.title,
            ok=not failed,
            count=done,
            message="; ".join(failed[:3]) if failed else "",
            details=[op.description for op in ops[:200]],
        )

    def revert(self, state: State) -> StepResult:
        changes = state.by_mechanism(self.key)
        done = 0
        failed: list[str] = []
        for change in changes:
            path = f"{IFEO_PATH}\\{change.key}"
            try:
                if change.previous:
                    reg.write_value(reg.HKLM, path, "Debugger", change.previous)
                else:
                    reg.delete_value(reg.HKLM, path, "Debugger")
                    if change.previous is None:
                        reg.delete_key_if_empty(reg.HKLM, path)
                state.remove(self.key, change.key)
                done += 1
            except OSError as exc:
                failed.append(f"{change.key}: {exc}")
        return StepResult(
            mechanism=self.key,
            title=self.title,
            ok=not failed,
            count=done,
            message="; ".join(failed[:3]) if failed else "",
        )

    @staticmethod
    def current() -> dict[str, str]:
        """Что сейчас стоит в перехвате — для проверки «защита правда включена»."""
        out: dict[str, str] = {}
        for name in reg.subkeys(reg.HKLM, IFEO_PATH):
            value = reg.read_value(reg.HKLM, f"{IFEO_PATH}\\{name}", "Debugger")
            if value:
                out[name] = str(value)
        return out
