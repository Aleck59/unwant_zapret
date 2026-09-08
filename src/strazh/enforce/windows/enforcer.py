"""Распорядитель для Windows: собирает механизмы и смотрит на систему."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from strazh.core.hashing import sha256_file
from strazh.core.matcher import Matcher
from strazh.core.models import FileFacts, Target
from strazh.core.settings import Settings
from strazh.enforce.base import Enforcer, InstalledProgram, Mechanism
from strazh.enforce.windows import peinfo, procs
from strazh.enforce.windows.defender import DefenderPuaMechanism
from strazh.enforce.windows.disallowrun import DisallowRunMechanism
from strazh.enforce.windows.firewall import FirewallMechanism
from strazh.enforce.windows.gpo import GroupPolicyMechanism
from strazh.enforce.windows.hostsfile import HostsMechanism
from strazh.enforce.windows.ifeo import IfeoMechanism
from strazh.enforce.windows.installed import installed_programs
from strazh.enforce.windows.services import ServicesMechanism, TasksMechanism
from strazh.enforce.windows.srp import SrpMechanism


class WindowsEnforcer(Enforcer):
    platform = "windows"

    def is_admin(self) -> bool:
        return procs.is_admin()

    def mechanisms(self, settings: Settings) -> list[Mechanism]:
        """Порядок важен: сперва отбираем службы у того, что уже стоит, потом
        закрываем запуск, и лишь затем сеть и адреса — иначе служба успеет
        подняться и вернуть себе файлы."""
        m = settings.mechanisms
        out: list[Mechanism] = []
        if m.neutralize_services:
            out.append(ServicesMechanism())
            out.append(TasksMechanism())
        if m.ifeo:
            out.append(IfeoMechanism())
        if m.srp:
            out.append(SrpMechanism())
        if m.group_policy:
            out.append(GroupPolicyMechanism())
        if m.disallow_run:
            out.append(DisallowRunMechanism())
        if m.firewall:
            out.append(FirewallMechanism(self._resolve_paths))
        if m.hosts:
            out.append(HostsMechanism())
        if m.defender_pua:
            out.append(DefenderPuaMechanism())
        return out

    # ── осмотр системы ────────────────────────────────────────────────────────

    def process_list(self) -> list[tuple[int, str, str | None]]:
        return [(e.pid, e.name, e.path) for e in procs.list_processes()]

    def path_of(self, pid: int) -> str | None:
        return procs.image_path(pid)

    def running_processes(self) -> list[FileFacts]:
        out: list[FileFacts] = []
        for pid, name, path in self.process_list():
            if path is None:
                out.append(FileFacts(image_name=name, pid=pid))
                continue
            facts = self.facts_for_path(path, with_signature=False)
            out.append(
                FileFacts(
                    image_name=name,
                    image_path=path,
                    original_filename=facts.original_filename,
                    product_name=facts.product_name,
                    company_name=facts.company_name,
                    pid=pid,
                )
            )
        return out

    def installed_programs(self) -> list[InstalledProgram]:
        return installed_programs()

    def terminate(self, pid: int) -> bool:
        return procs.terminate(pid)

    def facts_for_path(
        self, path: str, *, with_hash: bool = False, with_signature: bool = True
    ) -> FileFacts:
        info = peinfo.version_info(path)
        return FileFacts(
            image_name=os.path.basename(path),
            image_path=path,
            original_filename=info.original_filename,
            product_name=info.product_name,
            company_name=info.company_name,
            publisher=peinfo.signature_subject(path) if with_signature else None,
            sha256=sha256_file(path) if with_hash else None,
        )

    # ── подбор настоящих путей для правил брандмауэра ────────────────────────

    def _resolve_paths(self, targets: list[Target]) -> list[tuple[str, str]]:
        """Найти на диске то, для чего есть смысл заводить правило.

        Берём два источника: работающие процессы (там путь известен точно) и
        папки установки из списка установленных программ. Маски из каталога
        разворачиваются только внутри найденных папок — обход всего диска ради
        правила брандмауэра не стоит потраченного времени.
        """
        matcher = Matcher(targets)
        found: dict[str, str] = {}

        for facts in self.running_processes():
            if not facts.image_path:
                continue
            verdict = matcher.evaluate(facts)
            if not verdict.allowed and verdict.target_id:
                found.setdefault(facts.image_path, verdict.target_id)

        for program in self.installed_programs():
            verdict = matcher.evaluate(program.facts())
            if verdict.allowed or not verdict.target_id:
                continue
            location = program.install_location
            if not location or not Path(location).is_dir():
                continue
            for exe in _executables_in(Path(location)):
                found.setdefault(str(exe), verdict.target_id)

        return [(target_id, path) for path, target_id in found.items()]


MAX_EXECUTABLES_PER_FOLDER = 40
"""Пакеты вроде 360 кладут в свою папку десятки файлов. Правило на каждый
не нужно: важны те, что лежат ближе к корню папки установки."""


def _executables_in(folder: Path) -> list[Path]:
    """Первые несколько десятков файлов из папки установки.

    Без сортировки намеренно: `sorted()` заставил бы обойти папку целиком, а
    у защитного пакета в ней бывают тысячи файлов — ради сорока правил
    брандмауэра это неоправданно.
    """
    out: list[Path] = []
    try:
        for entry in folder.rglob("*.exe"):
            out.append(entry)
            if len(out) >= MAX_EXECUTABLES_PER_FOLDER:
                break
    except OSError:
        return out
    return out


def relaunch_as_admin() -> bool:
    return procs.relaunch_as_admin(sys.argv[1:])
