"""Службы и задания планировщика уже установленных целей.

Защитные пакеты держатся на машине не файлом, а службой, которая её же и
восстанавливает. Поэтому цель, которую нашли установленной, сначала лишают
службы и задания, и только потом имеет смысл всё остальное.

Прежний тип запуска запоминается: откат возвращает службу ровно в то
состояние, в каком её застали.
"""

from __future__ import annotations

import contextlib
import subprocess
import sys

from strazh.core.models import Action, Target
from strazh.core.state import Change, State
from strazh.enforce import plan as planner
from strazh.enforce.base import Mechanism, StepResult
from strazh.enforce.windows import registry as reg
from strazh.enforce.windows.autostart import TASK_NAME

SERVICES_PATH = r"SYSTEM\CurrentControlSet\Services"
MECHANISM_SERVICE = "service"
MECHANISM_TASK = "task"

START_DISABLED = 4

_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


def _run(args: list[str]) -> tuple[int, str]:
    try:
        done = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            creationflags=_NO_WINDOW,
        )
        return done.returncode, (done.stdout or "") + (done.stderr or "")
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, str(exc)


def installed_services() -> set[str]:
    return {name.casefold() for name in reg.subkeys(reg.HKLM, SERVICES_PATH)}


def _expand(patterns: list[str], known: set[str]) -> list[str]:
    """Маски вида `360*` разворачиваются по списку установленных служб."""
    from strazh.core.models import compile_pattern

    out: list[str] = []
    for pattern in patterns:
        if any(ch in pattern for ch in "*?["):
            regex = compile_pattern(pattern)
            out.extend(name for name in known if regex.match(name))
        elif pattern.casefold() in known:
            out.append(pattern)
    return sorted(set(out))


class ServicesMechanism(Mechanism):
    key = MECHANISM_SERVICE
    title = "Службы целей"

    def available(self) -> tuple[bool, str]:
        if sys.platform != "win32":
            return False, "механизм есть только в Windows"
        return True, ""

    def apply(self, targets: list[Target], state: State) -> StepResult:
        ops = planner.plan_services(targets)
        if not ops:
            return StepResult(self.key, self.title, ok=True, count=0)
        known = installed_services()
        done = 0
        failed: list[str] = []
        details: list[str] = []
        for op in ops:
            for name in _expand([op.key], known):
                previous = reg.read_value(reg.HKLM, f"{SERVICES_PATH}\\{name}", "Start")
                _run(["sc", "stop", name])
                code, output = _run(["sc", "config", name, "start=", "disabled"])
                if code != 0:
                    failed.append(f"{name}: {output.strip()[:100]}")
                    continue
                state.add(
                    Change(
                        mechanism=self.key,
                        key=name,
                        target_id=op.target_id,
                        previous=str(previous) if previous is not None else None,
                    )
                )
                details.append(f"служба {name} остановлена и отключена")
                done += 1
        return StepResult(
            mechanism=self.key,
            title=self.title,
            ok=not failed,
            count=done,
            message="; ".join(failed[:3]) if failed else "",
            details=details[:200],
        )

    def revert(self, state: State) -> StepResult:
        done = 0
        for change in state.by_mechanism(self.key):
            if change.previous is not None:
                with contextlib.suppress(OSError, ValueError):
                    reg.write_value(
                        reg.HKLM, f"{SERVICES_PATH}\\{change.key}", "Start", int(change.previous)
                    )
            state.remove(self.key, change.key)
            done += 1
        return StepResult(self.key, self.title, ok=True, count=done)


class TasksMechanism(Mechanism):
    key = MECHANISM_TASK
    title = "Задания планировщика"

    def available(self) -> tuple[bool, str]:
        if sys.platform != "win32":
            return False, "механизм есть только в Windows"
        return True, ""

    def _known_tasks(self) -> list[str]:
        code, output = _run(["schtasks", "/Query", "/FO", "LIST"])
        if code != 0:
            return []
        names: list[str] = []
        for line in output.splitlines():
            # Вывод локализован, поэтому опираемся не на подпись поля, а на
            # то, что имя задания всегда начинается с обратной косой черты.
            _, _, value = line.partition(":")
            value = value.strip()
            if value.startswith("\\"):
                names.append(value)
        return names

    def apply(self, targets: list[Target], state: State) -> StepResult:
        ops = planner.plan_tasks(targets)
        if not ops:
            return StepResult(self.key, self.title, ok=True, count=0)
        from strazh.core.models import compile_pattern

        known = self._known_tasks()
        done = 0
        failed: list[str] = []
        details: list[str] = []
        for op in ops:
            regex = compile_pattern(op.key if op.key.startswith("\\") else f"*{op.key}*")
            for name in known:
                if not regex.match(name):
                    continue
                # Своё задание не отключаем ни при каких масках: правило в
                # каталоге не должно уметь выключить наблюдение.
                if name.strip("\\").casefold() == TASK_NAME.casefold():
                    continue
                code, output = _run(["schtasks", "/Change", "/TN", name, "/Disable"])
                if code != 0:
                    failed.append(f"{name}: {output.strip()[:100]}")
                    continue
                state.add(
                    Change(mechanism=self.key, key=name, target_id=op.target_id, previous="enabled")
                )
                details.append(f"задание {name} отключено")
                done += 1
        return StepResult(
            mechanism=self.key,
            title=self.title,
            ok=not failed,
            count=done,
            message="; ".join(failed[:3]) if failed else "",
            details=details[:200],
        )

    def revert(self, state: State) -> StepResult:
        done = 0
        for change in state.by_mechanism(self.key):
            _run(["schtasks", "/Change", "/TN", change.key, "/Enable"])
            state.remove(self.key, change.key)
            done += 1
        return StepResult(self.key, self.title, ok=True, count=done)


def targets_needing_services(targets: list[Target]) -> list[Target]:
    return [t for t in targets if t.has(Action.NEUTRALIZE_SERVICES)]
