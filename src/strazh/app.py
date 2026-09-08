"""Прикладное ядро: одно место, где сходятся каталог, настройки и система.

И окно, и командная строка, и фоновый страж работают через этот класс. Ни у
кого из них нет своей копии правил загрузки каталога или своего порядка
применения механизмов — иначе они разъехались бы на второй же неделе.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from strazh import paths
from strazh.core import catalog as catalog_mod
from strazh.core.catalog import Catalog
from strazh.core.journal import Event, EventKind, Journal
from strazh.core.matcher import Matcher
from strazh.core.models import Action, FileFacts, MatchSpec, Severity, Target, Verdict
from strazh.core.settings import Settings, load_settings, save_settings
from strazh.core.state import State, load_state, save_state
from strazh.enforce import Enforcer, Report, get_enforcer
from strazh.enforce.base import InstalledProgram

USER_CATALOG_FILE = "custom.json"
"""Куда складываются цели, добавленные через окно. Отдельный файл, чтобы
человек мог унести его на другую машину или показать кому-то целиком."""


@dataclass(slots=True)
class Finding:
    """Что нашла проверка машины."""

    where: str
    """`процесс`, `программа` или путь к файлу."""

    title: str
    verdict: Verdict
    facts: FileFacts | None = None
    program: InstalledProgram | None = None


@dataclass(slots=True)
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    processes_seen: int = 0
    programs_seen: int = 0

    @property
    def clean(self) -> bool:
        return not self.findings


class Strazh:
    """Ядро программы."""

    def __init__(self, *, dry_run: bool = False, home: Path | None = None) -> None:
        if home is not None:
            import os

            os.environ["STRAZH_HOME"] = str(home)
        paths.ensure_dirs()
        self.enforcer: Enforcer = get_enforcer(force_dry_run=dry_run)
        self.journal = Journal(paths.journal_file())
        self.settings: Settings = load_settings(paths.settings_file())
        self.state: State = load_state(paths.state_file())
        self.catalog: Catalog = catalog_mod.Catalog(targets={}, issues=[])
        self._matcher: Matcher | None = None
        self.reload()

    # ── каталог и настройки ───────────────────────────────────────────────────

    def reload(self) -> None:
        """Перечитать каталог и пересобрать сопоставитель."""
        self.catalog = catalog_mod.load(
            paths.builtin_catalog_dir(),
            paths.user_catalog_dir(),
            self.settings.overrides,
        )
        self._matcher = None

    @property
    def matcher(self) -> Matcher:
        if self._matcher is None:
            self._matcher = Matcher(self.catalog.enabled(), self.settings.allowlist())
        return self._matcher

    def save(self) -> None:
        save_settings(paths.settings_file(), self.settings)
        save_state(paths.state_file(), self.state)

    def set_target_enabled(self, target_id: str, enabled: bool) -> None:
        self.settings.set_enabled(target_id, enabled)
        save_settings(paths.settings_file(), self.settings)
        self.reload()
        self.journal.write(
            Event(
                kind=EventKind.CATALOG_CHANGED,
                message=("включена" if enabled else "выключена") + f" цель {target_id}",
                target_id=target_id,
            )
        )

    def user_targets(self) -> list[Target]:
        return [t for t in self.catalog.as_list() if t.source == "user"]

    def save_user_target(self, target: Target) -> None:
        """Добавить или изменить свою цель.

        Все свои цели живут в одном файле: так их проще унести и вернуть.
        Файл переписывается целиком — он маленький, а частичная правка JSON
        порождает больше ошибок, чем экономит времени.
        """
        existing = {t.id: t for t in self.user_targets()}
        existing[target.id] = target
        path = paths.user_catalog_dir() / USER_CATALOG_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            catalog_mod.dump_targets(
                sorted(existing.values(), key=lambda t: t.name.casefold()),
                comment="Свои цели. Файл переписывается программой целиком.",
            ),
            encoding="utf-8",
        )
        self.reload()
        self.journal.write(
            Event(
                kind=EventKind.CATALOG_CHANGED,
                message=f"сохранена своя цель «{target.name}»",
                target_id=target.id,
                target_name=target.name,
            )
        )

    def delete_user_target(self, target_id: str) -> bool:
        existing = {t.id: t for t in self.user_targets()}
        if target_id not in existing:
            return False
        del existing[target_id]
        path = paths.user_catalog_dir() / USER_CATALOG_FILE
        path.write_text(
            catalog_mod.dump_targets(sorted(existing.values(), key=lambda t: t.name.casefold())),
            encoding="utf-8",
        )
        self.reload()
        return True

    @staticmethod
    def quick_target(name: str, executables: list[str], *, category: str = "other") -> Target:
        """Собрать цель по паре «название — список файлов».

        Быстрое добавление из окна: человек вводит имя программы и имена её
        файлов, всё остальное берётся по умолчанию.
        """
        target_id = "user-" + "".join(
            ch if ch.isalnum() else "-" for ch in name.strip().casefold()
        ).strip("-")
        return Target(
            id=target_id or f"user-{datetime.now(UTC):%Y%m%d%H%M%S}",
            name=name.strip() or target_id,
            category=category,
            severity=Severity.HIGH,
            why="Добавлено вручную",
            match=MatchSpec(executables=tuple(e.strip() for e in executables if e.strip())),
            actions=(Action.BLOCK_EXEC, Action.BLOCK_INSTALL),
            source="user",
        )

    # ── защита ────────────────────────────────────────────────────────────────

    @property
    def protection_on(self) -> bool:
        return self.state.protection_on

    def apply_protection(self) -> Report:
        report = self.enforcer.apply(self.catalog, self.settings, self.state, self.journal)
        self.state.protection_on = True
        self.state.applied_at = datetime.now(UTC).isoformat(timespec="seconds")
        save_state(paths.state_file(), self.state)
        self.journal.write(
            Event(
                kind=EventKind.PROTECTION_ON,
                message=f"защита включена, изменений: {report.total}",
                detail={"steps": [s.line for s in report.steps]},
            )
        )
        return report

    def revert_protection(self) -> Report:
        report = self.enforcer.revert(self.settings, self.state, self.journal)
        self.state.protection_on = False
        save_state(paths.state_file(), self.state)
        self.journal.write(
            Event(
                kind=EventKind.PROTECTION_OFF,
                message=f"защита выключена, снято изменений: {report.total}",
                detail={"steps": [s.line for s in report.steps]},
            )
        )
        return report

    # ── осмотр машины ─────────────────────────────────────────────────────────

    def scan(self) -> ScanResult:
        """Найти цели среди работающих процессов и установленных программ."""
        result = ScanResult()
        matcher = self.matcher

        processes = self.enforcer.running_processes()
        result.processes_seen = len(processes)
        for facts in processes:
            verdict = matcher.evaluate(facts)
            if not verdict.allowed:
                result.findings.append(
                    Finding(
                        where="процесс",
                        title=facts.image_path or facts.image_name,
                        verdict=verdict,
                        facts=facts,
                    )
                )

        programs = self.enforcer.installed_programs()
        result.programs_seen = len(programs)
        for program in programs:
            verdict = matcher.evaluate(program.facts())
            if not verdict.allowed:
                result.findings.append(
                    Finding(
                        where="программа",
                        title=program.name,
                        verdict=verdict,
                        program=program,
                    )
                )

        for finding in result.findings:
            self.journal.write(
                Event(
                    kind=EventKind.SCAN_FINDING,
                    message=f"{finding.where}: {finding.title} — {finding.verdict.reason}",
                    target_id=finding.verdict.target_id or "",
                    target_name=finding.verdict.target_name or "",
                )
            )
        return result

    def check_file(self, path: str | Path) -> tuple[FileFacts, Verdict]:
        """Проверить один файл — им пользуется наблюдатель за загрузками."""
        facts = self.enforcer.facts_for_path(str(path), with_hash=True)
        return facts, self.matcher.evaluate(facts)

    # ── журнал ────────────────────────────────────────────────────────────────

    def log(self, event: Event) -> None:
        self.journal.write(event)

    def recent(self, limit: int = 300) -> list[Event]:
        return self.journal.read(limit)
