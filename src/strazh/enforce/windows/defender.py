"""Встроенная защита Windows от нежелательных программ.

У Защитника есть отдельный переключатель PUA: он ловит рекламные довески,
поддельные «ускорители» и обёртки установщиков — ровно тот класс, ради
которого написана эта программа. Он выключен по умолчанию, и включить его
одной галочкой полезнее, чем любое собственное правило.

Механизм ничего не изобретает, а лишь переводит переключатель и запоминает,
в каком положении он был.
"""

from __future__ import annotations

import subprocess
import sys

from strazh.core.models import Target
from strazh.core.state import Change, State
from strazh.enforce.base import Mechanism, StepResult

MECHANISM = "defender"
_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0

ENABLED = "1"
DISABLED = "0"


def _powershell(command: str) -> tuple[int, str]:
    try:
        done = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=90,
            creationflags=_NO_WINDOW,
        )
        return done.returncode, ((done.stdout or "") + (done.stderr or "")).strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, str(exc)


class DefenderPuaMechanism(Mechanism):
    key = MECHANISM
    title = "Защита Windows от нежелательных программ"

    def available(self) -> tuple[bool, str]:
        if sys.platform != "win32":
            return False, "механизм есть только в Windows"
        return True, ""

    def apply(self, targets: list[Target], state: State) -> StepResult:
        code, output = _powershell("(Get-MpPreference).PUAProtection")
        previous = output.strip().splitlines()[0].strip() if code == 0 and output.strip() else ""
        if previous == ENABLED:
            return StepResult(self.key, self.title, ok=True, count=0, message="уже включена")

        code, output = _powershell("Set-MpPreference -PUAProtection Enabled")
        if code != 0:
            return StepResult(
                self.key,
                self.title,
                ok=False,
                count=0,
                message=output[:160] or "не удалось изменить настройку Защитника",
            )
        state.add(Change(mechanism=self.key, key="PUAProtection", previous=previous or None))
        return StepResult(
            self.key,
            self.title,
            ok=True,
            count=1,
            details=["PUAProtection = Enabled"],
        )

    def revert(self, state: State) -> StepResult:
        done = 0
        for change in state.by_mechanism(self.key):
            # Прежнее значение вернём как есть: если раньше стояло «только
            # сообщать», молча включать блокировку после отката нечестно.
            value = {ENABLED: "Enabled", "2": "AuditMode"}.get(change.previous or "", "Disabled")
            _powershell(f"Set-MpPreference -PUAProtection {value}")
            state.remove(self.key, change.key)
            done += 1
        return StepResult(self.key, self.title, ok=True, count=done)
