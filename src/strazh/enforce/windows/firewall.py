"""Правила брандмауэра.

Нужны для того, что уже стоит на машине: запретить запуск задним числом
нельзя, а отрезать программе сеть — можно, и этого обычно достаточно, чтобы
она перестала обновляться, тянуть довесок и отправлять собранное.

`netsh` принимает только настоящий путь, без масок. Поэтому список путей
берётся не из каталога, а из осмотра машины: что нашлось среди установленных
программ и что прямо сейчас работает.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable

from strazh.core.models import Action, Target
from strazh.core.state import Change, State
from strazh.enforce.base import Mechanism, StepResult

MECHANISM = "firewall"
RULE_PREFIX = "Страж: "

_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


def _run(args: list[str]) -> tuple[int, str]:
    try:
        done = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            creationflags=_NO_WINDOW,
        )
        return done.returncode, (done.stdout or "") + (done.stderr or "")
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, str(exc)


def rule_name(target_id: str, path: str) -> str:
    """Имя правила должно быть коротким, но различимым: `netsh` ищет по нему."""
    tail = path.rsplit("\\", 1)[-1]
    return f"{RULE_PREFIX}{target_id} — {tail}"


class FirewallMechanism(Mechanism):
    key = MECHANISM
    title = "Правила брандмауэра"

    def __init__(self, resolver: Callable[[list[Target]], list[tuple[str, str]]]) -> None:
        self._resolver = resolver

    def available(self) -> tuple[bool, str]:
        if sys.platform != "win32":
            return False, "механизм есть только в Windows"
        return True, ""

    def apply(self, targets: list[Target], state: State) -> StepResult:
        wanted = [t for t in targets if t.has(Action.BLOCK_NETWORK)]
        if not wanted:
            return StepResult(self.key, self.title, ok=True, count=0)
        found = self._resolver(wanted)
        known = {c.key.casefold() for c in state.by_mechanism(self.key)}
        done = 0
        failed: list[str] = []
        details: list[str] = []
        for target_id, path in found:
            if path.casefold() in known:
                continue
            name = rule_name(target_id, path)
            # Оба направления: исходящее закрывает обновления и отправку
            # данных, входящее — попытки достучаться снаружи.
            ok = True
            for direction in ("out", "in"):
                code, output = _run(
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        f"name={name}",
                        f"dir={direction}",
                        f"program={path}",
                        "action=block",
                        "enable=yes",
                        "profile=any",
                    ]
                )
                if code != 0:
                    ok = False
                    failed.append(f"{path}: {output.strip()[:120]}")
                    break
            if ok:
                state.add(Change(mechanism=self.key, key=path, target_id=target_id, previous=name))
                details.append(f"сеть закрыта для {path}")
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
        failed: list[str] = []
        for change in state.by_mechanism(self.key):
            name = change.previous or rule_name(change.target_id, change.key)
            code, output = _run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]
            )
            # `netsh` возвращает ошибку и когда правила уже нет. Для отката
            # это успех: цель — отсутствие правила, а не факт удаления.
            if code != 0 and "No rules match" not in output and "Не найдено" not in output:
                failed.append(f"{name}: {output.strip()[:120]}")
                continue
            state.remove(self.key, change.key)
            done += 1
        return StepResult(
            mechanism=self.key,
            title=self.title,
            ok=not failed,
            count=done,
            message="; ".join(failed[:3]) if failed else "",
        )
