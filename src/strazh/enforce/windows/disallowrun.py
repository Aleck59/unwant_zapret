"""Запрет запуска из оболочки.

Самый слабый слой: он действует только на то, что запускают через проводник
и меню «Пуск», и обходится переименованием файла. Держится в наборе потому,
что стоит дёшево, ставится в ветку пользователя (то есть работает и без прав
администратора) и закрывает самый частый способ запуска — двойным щелчком.

По умолчанию выключен: без остальных слоёв он создаёт ложное ощущение защиты.
"""

from __future__ import annotations

import contextlib
import sys

from strazh.core.models import Target
from strazh.core.state import Change, State
from strazh.enforce import plan as planner
from strazh.enforce.base import Mechanism, StepResult
from strazh.enforce.windows import registry as reg

POLICY = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
LIST_KEY = POLICY + r"\DisallowRun"
MECHANISM = "disallow_run"

LIMIT = 200
"""Оболочка перестаёт учитывать список после нескольких сотен записей, и
переполнять его вредно: перестанет работать весь список целиком."""


class DisallowRunMechanism(Mechanism):
    key = MECHANISM
    title = "Запрет запуска из оболочки"

    def available(self) -> tuple[bool, str]:
        if sys.platform != "win32":
            return False, "механизм есть только в Windows"
        return True, ""

    def apply(self, targets: list[Target], state: State) -> StepResult:
        names = [op.key for op in planner.plan_ifeo(targets)][:LIMIT]
        if not names:
            return StepResult(self.key, self.title, ok=True, count=0)
        try:
            previous_flag = reg.read_value(reg.HKCU, POLICY, "DisallowRun")
            state.add(
                Change(
                    mechanism=self.key,
                    key="__flag__",
                    previous=str(previous_flag) if previous_flag is not None else None,
                )
            )
            reg.write_value(reg.HKCU, POLICY, "DisallowRun", 1)
            # Список нумерованный, и чужие номера занимать нельзя: начинаем
            # с первого свободного.
            existing = reg.values(reg.HKCU, LIST_KEY)
            taken = {int(k) for k in existing if k.isdigit()}
            index = 1
            for name in names:
                if name in existing.values():
                    continue
                while index in taken:
                    index += 1
                reg.write_value(reg.HKCU, LIST_KEY, str(index), name)
                state.add(Change(mechanism=self.key, key=str(index), previous=None))
                taken.add(index)
        except OSError as exc:
            return StepResult(self.key, self.title, ok=False, count=0, message=str(exc))
        return StepResult(self.key, self.title, ok=True, count=len(names))

    def revert(self, state: State) -> StepResult:
        done = 0
        for change in state.by_mechanism(self.key):
            if change.key == "__flag__":
                if change.previous is None:
                    reg.delete_value(reg.HKCU, POLICY, "DisallowRun")
                else:
                    with contextlib.suppress(OSError, ValueError):
                        reg.write_value(reg.HKCU, POLICY, "DisallowRun", int(change.previous))
            else:
                reg.delete_value(reg.HKCU, LIST_KEY, change.key)
                done += 1
            state.remove(self.key, change.key)
        reg.delete_key_if_empty(reg.HKCU, LIST_KEY)
        return StepResult(self.key, self.title, ok=True, count=done)
