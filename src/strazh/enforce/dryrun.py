"""Распорядитель, который ничего не меняет.

Нужен в двух случаях. Первый — разработка и проверки: окно и весь сценарий
«включить защиту» должны собираться и запускаться там, где нет ни реестра,
ни служб. Второй — предпросмотр на самой Windows: команда `strazh apply
--dry-run` показывает точный список того, что произойдёт, до того как хоть
что-то произойдёт.
"""

from __future__ import annotations

import os
from collections.abc import Callable

from strazh.core.models import FileFacts, Target
from strazh.core.settings import Settings
from strazh.core.state import Change, State
from strazh.enforce import plan as planner
from strazh.enforce.base import Enforcer, InstalledProgram, Mechanism, StepResult

_TITLES = {
    "ifeo": "Перехват запуска по имени файла",
    "srp": "Правила по пути и маске",
    "hash": "Запрет по контрольной сумме",
    "firewall": "Правила брандмауэра",
    "hosts": "Закрытие адресов",
    "service": "Службы целей",
    "task": "Задания планировщика",
}


class PlanOnlyMechanism(Mechanism):
    """Считает план и записывает его в состояние, ничего не выполняя."""

    def __init__(
        self, key: str, builder: Callable[[list[Target]], list[planner.Operation]]
    ) -> None:
        self.key = key
        self.title = _TITLES.get(key, key)
        self._builder = builder

    def apply(self, targets: list[Target], state: State) -> StepResult:
        ops = self._builder(targets)
        for op in ops:
            state.add(Change(mechanism=self.key, key=op.key, target_id=op.target_id))
        return StepResult(
            mechanism=self.key,
            title=self.title,
            ok=True,
            count=len(ops),
            message="разбор без изменений в системе",
            details=[op.description for op in ops[:200]],
        )

    def revert(self, state: State) -> StepResult:
        count = len(state.by_mechanism(self.key))
        state.changes = [c for c in state.changes if c.mechanism != self.key]
        return StepResult(mechanism=self.key, title=self.title, ok=True, count=count)


class DryRunEnforcer(Enforcer):
    platform = "dry-run"

    def __init__(self, processes: list[FileFacts] | None = None) -> None:
        self._processes = processes or []

    def is_admin(self) -> bool:
        # Права здесь ни на что не влияют, но врать «нет» тоже не стоит:
        # окно по этому признаку решает, показывать ли просьбу перезапуска.
        return True

    def mechanisms(self, settings: Settings) -> list[Mechanism]:
        m = settings.mechanisms
        wanted: list[tuple[str, bool, Callable[[list[Target]], list[planner.Operation]]]] = [
            ("ifeo", m.ifeo, planner.plan_ifeo),
            ("srp", m.srp, planner.plan_srp),
            ("hash", m.srp, planner.plan_hashes),
            ("firewall", m.firewall, planner.plan_firewall),
            ("hosts", m.hosts, planner.plan_hosts),
            ("service", m.neutralize_services, planner.plan_services),
            ("task", m.neutralize_services, planner.plan_tasks),
        ]
        return [PlanOnlyMechanism(key, builder) for key, on, builder in wanted if on]

    def process_list(self) -> list[tuple[int, str, str | None]]:
        return [(f.pid or 0, f.image_name, f.image_path) for f in self._processes]

    def running_processes(self) -> list[FileFacts]:
        return list(self._processes)

    def installed_programs(self) -> list[InstalledProgram]:
        return []

    def terminate(self, pid: int) -> bool:
        return False

    def facts_for_path(
        self, path: str, *, with_hash: bool = False, with_signature: bool = True
    ) -> FileFacts:
        from strazh.core.hashing import sha256_file

        known = {f.image_path: f for f in self._processes if f.image_path}
        if path in known:
            return known[path]
        return FileFacts(
            image_name=os.path.basename(path),
            image_path=path,
            sha256=sha256_file(path) if with_hash else None,
        )
