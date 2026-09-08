"""Типы, на которых держится весь остальной код.

Здесь нет ни реестра, ни файлов, ни Windows: только описание того, *что*
считается целью, *по каким* признакам её узнают и *что* с ней делают. Это
позволяет проверять логику на любой машине, а не только на той, где программа
в итоге работает.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """Насколько цель нежелательна. Влияет только на подсказки в окне."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Action(StrEnum):
    """Что делать с целью.

    Набор намеренно небольшой: каждое действие отображается на конкретный
    механизм Windows, и пользователь в настройках может выключить механизм
    целиком, не трогая каталог.
    """

    BLOCK_EXEC = "block_exec"
    """Не давать запускаться уже лежащему на диске файлу."""

    BLOCK_INSTALL = "block_install"
    """Перехватывать установщик до того, как его запустят."""

    BLOCK_NETWORK = "block_network"
    """Запретить программе выход в сеть правилом брандмауэра."""

    BLOCK_DOMAINS = "block_domains"
    """Закрыть адреса, откуда программа скачивается и куда шлёт данные."""

    NEUTRALIZE_SERVICES = "neutralize_services"
    """Остановить и отключить службы и задания планировщика цели."""

    QUARANTINE = "quarantine"
    """Убрать найденный установщик в карантин."""


class MatchKind(StrEnum):
    """Признак, по которому цель опознана. Пишется в журнал: по нему видно,
    сработало ли простое имя файла или пришлось разбирать подпись."""

    EXECUTABLE = "executable"
    INSTALLER = "installer"
    ORIGINAL_FILENAME = "original_filename"
    PRODUCT_NAME = "product_name"
    PUBLISHER = "publisher"
    PATH = "path"
    SHA256 = "sha256"
    SERVICE = "service"
    SCHEDULED_TASK = "scheduled_task"


@dataclass(frozen=True, slots=True)
class MatchSpec:
    """Признаки одной цели.

    Все строковые списки нечувствительны к регистру и понимают маски вида
    `360*setup*.exe`. Пустой список означает «этот признак не используется»,
    а не «подходит всё».
    """

    executables: tuple[str, ...] = ()
    installers: tuple[str, ...] = ()
    original_filenames: tuple[str, ...] = ()
    product_names: tuple[str, ...] = ()
    publishers: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()
    sha256: tuple[str, ...] = ()
    services: tuple[str, ...] = ()
    scheduled_tasks: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()

    def is_empty(self) -> bool:
        return not any(
            (
                self.executables,
                self.installers,
                self.original_filenames,
                self.product_names,
                self.publishers,
                self.paths,
                self.sha256,
                self.services,
                self.scheduled_tasks,
                self.domains,
            )
        )

    def to_json(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for name in (
            "executables",
            "installers",
            "original_filenames",
            "product_names",
            "publishers",
            "paths",
            "sha256",
            "services",
            "scheduled_tasks",
            "domains",
        ):
            value = getattr(self, name)
            if value:
                out[name] = list(value)
        return out

    @staticmethod
    def from_json(raw: dict[str, Any]) -> MatchSpec:
        def seq(key: str) -> tuple[str, ...]:
            value = raw.get(key) or ()
            if isinstance(value, str):
                value = [value]
            return tuple(str(item).strip() for item in value if str(item).strip())

        return MatchSpec(
            executables=seq("executables"),
            installers=seq("installers"),
            original_filenames=seq("original_filenames"),
            product_names=seq("product_names"),
            publishers=seq("publishers"),
            paths=seq("paths"),
            sha256=tuple(h.lower() for h in seq("sha256")),
            services=seq("services"),
            scheduled_tasks=seq("scheduled_tasks"),
            domains=tuple(d.lower().lstrip(".") for d in seq("domains")),
        )


@dataclass(frozen=True, slots=True)
class Target:
    """Одна программа (или семейство программ) из каталога."""

    id: str
    name: str
    vendor: str = ""
    category: str = "other"
    severity: Severity = Severity.MEDIUM
    enabled: bool = True
    why: str = ""
    references: tuple[str, ...] = ()
    match: MatchSpec = field(default_factory=MatchSpec)
    actions: tuple[Action, ...] = (Action.BLOCK_EXEC, Action.BLOCK_INSTALL)
    source: str = "builtin"
    """Откуда пришла запись: `builtin` — из поставки, `user` — добавлена вручную.
    Встроенные записи не удаляются, а выключаются: обновление вернуло бы их назад."""

    def has(self, action: Action) -> bool:
        return action in self.actions

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity.value,
            "enabled": self.enabled,
            "match": self.match.to_json(),
            "actions": [a.value for a in self.actions],
        }
        if self.vendor:
            out["vendor"] = self.vendor
        if self.why:
            out["why"] = self.why
        if self.references:
            out["references"] = list(self.references)
        return out


@dataclass(frozen=True, slots=True)
class FileFacts:
    """Всё, что удалось узнать о файле, который собирается запуститься.

    Отдельный тип нужен, чтобы сопоставление не зависело от способа добычи
    сведений: в бою их даёт разбор PE-заголовка, в тестах — литерал.
    """

    image_name: str
    """Имя файла с расширением, как его видит система: `360tray.exe`."""

    image_path: str | None = None
    original_filename: str | None = None
    """`OriginalFilename` из ресурса версии. Переименование файла его не меняет."""

    product_name: str | None = None
    company_name: str | None = None
    publisher: str | None = None
    """Кому выдан сертификат подписи. Самый устойчивый признак."""

    sha256: str | None = None
    command_line: str | None = None
    pid: int | None = None


@dataclass(frozen=True, slots=True)
class Verdict:
    """Ответ сопоставителя. `allowed=True` — трогать нечего."""

    allowed: bool
    target_id: str | None = None
    target_name: str | None = None
    kind: MatchKind | None = None
    pattern: str | None = None
    severity: Severity | None = None
    reason: str = ""

    @staticmethod
    def allow(reason: str = "") -> Verdict:
        return Verdict(allowed=True, reason=reason)


# ──────────────────────────────────────────────────────────────────────────────
# Список неприкосновенных имён.
#
# Опечатка в правиле не должна оставлять человека без рабочего стола, поэтому
# ни каталог из поставки, ни правило, добавленное вручную, не могут упомянуть
# эти файлы. Проверка живёт здесь, рядом с типами, а не в интерфейсе: тогда её
# нельзя обойти, добавив цель в обход окна — например, положив файл в
# catalog.d руками.
# ──────────────────────────────────────────────────────────────────────────────
PROTECTED_EXECUTABLES: frozenset[str] = frozenset(
    {
        # Ядро сеанса и входа в систему
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "lsass.exe",
        "lsaiso.exe",
        "svchost.exe",
        "userinit.exe",
        "sihost.exe",
        "fontdrvhost.exe",
        "dwm.exe",
        "ctfmon.exe",
        "logonui.exe",
        "conhost.exe",
        "runtimebroker.exe",
        "dllhost.exe",
        "wudfhost.exe",
        "spoolsv.exe",
        # Оболочка и средства управления
        "explorer.exe",
        "taskmgr.exe",
        "regedit.exe",
        "mmc.exe",
        "control.exe",
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "conemu.exe",
        "wt.exe",
        "rundll32.exe",
        "msiexec.exe",
        "systemsettings.exe",
        "sethc.exe",
        "utilman.exe",
        "narrator.exe",
        "magnify.exe",
        "osk.exe",
        # Обновление и восстановление
        "wuauclt.exe",
        "usoclient.exe",
        "trustedinstaller.exe",
        "tiworker.exe",
        "sfc.exe",
        "dism.exe",
        "recoverydrive.exe",
        "systemreset.exe",
        # Встроенная защита. Блокировать её этой программой — значит
        # выключить единственный настоящий антивирус на машине.
        "msmpeng.exe",
        "mpcmdrun.exe",
        "nissrv.exe",
        "securityhealthservice.exe",
        "securityhealthsystray.exe",
        "smartscreen.exe",
        "mpdefendercoreservice.exe",
        # Сеть и вход
        "netsh.exe",
        "net.exe",
        "net1.exe",
        "sc.exe",
        "schtasks.exe",
        # Сама программа
        "strazh.exe",
        "strazh-deny.exe",
        "strazh-gui.exe",
    }
)


def is_protected(name: str) -> bool:
    """Стоит ли имя файла под защитой от блокировки."""
    return name.strip().lower() in PROTECTED_EXECUTABLES


def pattern_touches_protected(pattern: str) -> bool:
    """Правда ли, что маска задевает хотя бы одно неприкосновенное имя.

    Маску `*.exe` пропустить нельзя не потому, что она подозрительна, а потому
    что она заведомо накрывает `lsass.exe`. Проверяем прямым перебором:
    список короткий, а ошибка дорогая.
    """
    p = pattern.strip().lower()
    if not p:
        return False
    if p in PROTECTED_EXECUTABLES:
        return True
    if any(ch in p for ch in "*?["):
        return any(fnmatch.fnmatchcase(name, p) for name in PROTECTED_EXECUTABLES)
    return False


def compile_pattern(pattern: str) -> re.Pattern[str]:
    """Маска в стиле оболочки → регулярное выражение без учёта регистра.

    `fnmatch.translate` уже умеет ровно это, но зависит от разделителя путей
    в текущей системе; каталог же пишется один раз и читается и на Windows,
    и в проверках на Linux. Поэтому переводим сами и заодно приравниваем
    `/` к `\\`, чтобы маска пути работала с любым написанием.
    """
    out = ["(?s:"]
    for ch in pattern:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        elif ch in "\\/":
            out.append("[\\\\/]")
        else:
            out.append(re.escape(ch))
    out.append(r")\Z")
    return re.compile("".join(out), re.IGNORECASE)
