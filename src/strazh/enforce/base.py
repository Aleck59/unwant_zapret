"""Общий вид механизма защиты и того, кто ими распоряжается.

Разделение на «механизм» и «распорядителя» позволяет окну говорить об одних
и тех же вещах на любой системе: на Windows механизмы правят реестр, в
остальных случаях — только рассказывают, что сделали бы. Благодаря этому
интерфейс собирается и проверяется там же, где всё остальное.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from strazh.core.catalog import Catalog
from strazh.core.journal import Journal
from strazh.core.models import FileFacts, Target
from strazh.core.settings import Settings
from strazh.core.state import State


@dataclass(slots=True)
class StepResult:
    """Итог работы одного механизма."""

    mechanism: str
    title: str
    ok: bool
    count: int = 0
    message: str = ""
    details: list[str] = field(default_factory=list)

    @property
    def line(self) -> str:
        mark = "✓" if self.ok else "✗"
        tail = f" — {self.message}" if self.message else ""
        return f"{mark} {self.title}: {self.count}{tail}"


@dataclass(slots=True)
class Report:
    """Итог применения или отката целиком."""

    steps: list[StepResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(step.ok for step in self.steps)

    @property
    def total(self) -> int:
        return sum(step.count for step in self.steps)

    def failures(self) -> list[StepResult]:
        return [s for s in self.steps if not s.ok]

    def text(self) -> str:
        return "\n".join(step.line for step in self.steps)


@dataclass(slots=True)
class InstalledProgram:
    """Запись из списка установленных программ."""

    name: str
    publisher: str = ""
    version: str = ""
    install_location: str = ""
    uninstall_string: str = ""
    registry_key: str = ""

    def facts(self) -> FileFacts:
        """Свести запись к тем же признакам, по которым ищут файлы."""
        return FileFacts(
            image_name=self.name,
            image_path=self.install_location or None,
            product_name=self.name,
            company_name=self.publisher or None,
            publisher=self.publisher or None,
        )


class Mechanism(ABC):
    """Один способ что-то запретить.

    От механизма требуется две вещи: применить себя к списку целей и уметь
    отменить ровно то, что применил, — по записям в `State`, а не по догадкам.
    """

    key: str = ""
    title: str = ""

    @abstractmethod
    def apply(self, targets: list[Target], state: State) -> StepResult: ...

    @abstractmethod
    def revert(self, state: State) -> StepResult: ...

    def available(self) -> tuple[bool, str]:
        """Можно ли механизм использовать здесь и сейчас."""
        return True, ""


class Enforcer(ABC):
    """Распорядитель механизмов: включает защиту, снимает её, смотрит систему."""

    platform: str = "generic"

    @abstractmethod
    def is_admin(self) -> bool:
        """Хватает ли прав. Без прав администратора реестр машины не правится."""

    @abstractmethod
    def mechanisms(self, settings: Settings) -> list[Mechanism]:
        """Механизмы, включённые в настройках, в порядке применения."""

    @abstractmethod
    def process_list(self) -> list[tuple[int, str, str | None]]:
        """Дешёвый снимок: номер, имя файла, путь.

        Отдельно от `running_processes` потому, что наблюдатель просматривает
        список раз в секунду, а разбор ресурса версии и подписи стоит на
        порядки дороже перечисления. Дорогое считается только для того, чего
        мы ещё не видели.
        """

    @abstractmethod
    def running_processes(self) -> list[FileFacts]:
        """Что сейчас работает, со всеми признаками — для проверки машины."""

    @abstractmethod
    def installed_programs(self) -> list[InstalledProgram]:
        """Что уже установлено — для проверки того, что попало до защиты."""

    @abstractmethod
    def terminate(self, pid: int) -> bool:
        """Снять процесс. Возвращает, получилось ли."""

    @abstractmethod
    def facts_for_path(
        self, path: str, *, with_hash: bool = False, with_signature: bool = True
    ) -> FileFacts:
        """Собрать признаки файла.

        Разбор подписи и подсчёт суммы отключаемы: на горячем пути они не
        нужны, пока не промахнулись все дешёвые признаки.
        """

    # ── общий сценарий, одинаковый на всех системах ──────────────────────────

    def apply(
        self, catalog: Catalog, settings: Settings, state: State, journal: Journal | None = None
    ) -> Report:
        targets = catalog.enabled()
        report = Report()
        for mechanism in self.mechanisms(settings):
            ok, why = mechanism.available()
            if not ok:
                report.steps.append(
                    StepResult(mechanism.key, mechanism.title, ok=True, count=0, message=why)
                )
                continue
            report.steps.append(mechanism.apply(targets, state))
        return report

    def revert(self, settings: Settings, state: State, journal: Journal | None = None) -> Report:
        """Откат идёт по всем известным механизмам, а не только по включённым:
        человек мог выключить механизм в настройках уже после применения, и
        его следы всё равно надо убрать."""
        report = Report()
        for mechanism in self.mechanisms(_all_on(settings)):
            report.steps.append(mechanism.revert(state))
        return report


def _all_on(settings: Settings) -> Settings:
    from copy import deepcopy

    copy = deepcopy(settings)
    for name in type(copy.mechanisms).__annotations__:
        setattr(copy.mechanisms, name, True)
    return copy
