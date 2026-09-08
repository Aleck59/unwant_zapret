"""Что именно надо сделать, чтобы каталог превратился в запрет.

Здесь считается план: список операций вида «завести ключ реестра для
360tray.exe», «закрыть адрес duba.net», «остановить службу ZhuDongFangYu».
Счёт не зависит от системы, поэтому его можно проверить обычным тестом, а
исполнение — отдельная и намеренно скучная часть.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from strazh.core.models import Action, Target, is_protected

_WILDCARD = re.compile(r"[*?\[]")

# Имена, которые бессмысленно заводить в перехват запуска по имени файла:
# общий установщик встречается у сотен программ, и запрет по такому имени
# зацепил бы всё подряд. Такие маски уходят в правила по пути, где рядом
# стоит проверка издателя.
_TOO_GENERIC = frozenset(
    {
        "setup.exe",
        "install.exe",
        "installer.exe",
        "update.exe",
        "updater.exe",
        "launcher.exe",
        "uninstall.exe",
        "unins000.exe",
        "main.exe",
        "app.exe",
        "start.exe",
        "run.exe",
        "service.exe",
        "server.exe",
        "client.exe",
        "helper.exe",
        "agent.exe",
        "tray.exe",
        "monitor.exe",
    }
)


@dataclass(frozen=True, slots=True)
class Operation:
    """Одна операция плана."""

    mechanism: str
    key: str
    target_id: str
    description: str

    def __str__(self) -> str:
        return self.description


def has_wildcard(pattern: str) -> bool:
    return bool(_WILDCARD.search(pattern))


def _usable_name(name: str) -> bool:
    lowered = name.strip().casefold()
    if not lowered or has_wildcard(lowered):
        return False
    if is_protected(lowered):
        return False
    if lowered in _TOO_GENERIC:
        return False
    return lowered.endswith((".exe", ".com", ".scr", ".pif"))


def plan_ifeo(targets: list[Target]) -> list[Operation]:
    """Перехват запуска по имени файла.

    Механизм разбирает только точные имена: ключ реестра называется именем
    файла, места для маски там нет. Всё с масками достаётся правилам по пути.
    """
    seen: set[str] = set()
    ops: list[Operation] = []
    for target in targets:
        if not target.has(Action.BLOCK_EXEC) and not target.has(Action.BLOCK_INSTALL):
            continue
        names = list(target.match.executables)
        if target.has(Action.BLOCK_INSTALL):
            names += list(target.match.installers)
        for name in names:
            key = name.strip()
            if not _usable_name(key) or key.casefold() in seen:
                continue
            seen.add(key.casefold())
            ops.append(
                Operation(
                    mechanism="ifeo",
                    key=key,
                    target_id=target.id,
                    description=f"перехват запуска {key} ({target.name})",
                )
            )
    return ops


def plan_srp(targets: list[Target]) -> list[Operation]:
    """Правила по пути: сюда уходят маски и известные места установки."""
    seen: set[str] = set()
    ops: list[Operation] = []
    for target in targets:
        if not target.has(Action.BLOCK_EXEC) and not target.has(Action.BLOCK_INSTALL):
            continue
        patterns: list[str] = []
        for name in (*target.match.executables, *target.match.installers):
            if has_wildcard(name):
                patterns.append(name)
            elif name.strip().casefold() in _TOO_GENERIC:
                # Слишком общее имя годится только вместе с путём.
                continue
        patterns.extend(target.match.paths)
        for pattern in patterns:
            key = pattern.strip()
            if not key or is_protected(key) or key.casefold() in seen:
                continue
            seen.add(key.casefold())
            ops.append(
                Operation(
                    mechanism="srp",
                    key=key,
                    target_id=target.id,
                    description=f"запрет пути {key} ({target.name})",
                )
            )
    return ops


def plan_hashes(targets: list[Target]) -> list[Operation]:
    """Запрет по контрольной сумме — единственный признак, который нельзя
    обойти переименованием или переносом файла."""
    ops: list[Operation] = []
    seen: set[str] = set()
    for target in targets:
        for digest in target.match.sha256:
            key = digest.strip().lower()
            if len(key) != 64 or key in seen:
                continue
            seen.add(key)
            ops.append(
                Operation(
                    mechanism="hash",
                    key=key,
                    target_id=target.id,
                    description=f"запрет по сумме {key[:16]}… ({target.name})",
                )
            )
    return ops


def plan_hosts(targets: list[Target]) -> list[Operation]:
    """Закрытие адресов: откуда программа скачивается и куда шлёт данные."""
    ops: list[Operation] = []
    seen: set[str] = set()
    for target in targets:
        if not target.has(Action.BLOCK_DOMAINS):
            continue
        for domain in target.match.domains:
            key = domain.strip().lower().lstrip(".")
            if not key or key in seen or "/" in key or " " in key:
                continue
            seen.add(key)
            ops.append(
                Operation(
                    mechanism="hosts",
                    key=key,
                    target_id=target.id,
                    description=f"закрыт адрес {key} ({target.name})",
                )
            )
    return ops


def plan_firewall(targets: list[Target]) -> list[Operation]:
    """Правила брандмауэра. Пути известны заранее — для того, что уже стоит,
    правило добавит проверка установленного."""
    ops: list[Operation] = []
    seen: set[str] = set()
    for target in targets:
        if not target.has(Action.BLOCK_NETWORK):
            continue
        for path in target.match.paths:
            key = path.strip()
            if not key or key.casefold() in seen:
                continue
            seen.add(key.casefold())
            ops.append(
                Operation(
                    mechanism="firewall",
                    key=key,
                    target_id=target.id,
                    description=f"запрет сети для {key} ({target.name})",
                )
            )
    return ops


def plan_services(targets: list[Target]) -> list[Operation]:
    ops: list[Operation] = []
    seen: set[str] = set()
    for target in targets:
        if not target.has(Action.NEUTRALIZE_SERVICES):
            continue
        for name in target.match.services:
            key = name.strip()
            if not key or key.casefold() in seen:
                continue
            seen.add(key.casefold())
            ops.append(
                Operation(
                    mechanism="service",
                    key=key,
                    target_id=target.id,
                    description=f"остановлена служба {key} ({target.name})",
                )
            )
    return ops


def plan_tasks(targets: list[Target]) -> list[Operation]:
    ops: list[Operation] = []
    seen: set[str] = set()
    for target in targets:
        if not target.has(Action.NEUTRALIZE_SERVICES):
            continue
        for name in target.match.scheduled_tasks:
            key = name.strip()
            if not key or key.casefold() in seen:
                continue
            seen.add(key.casefold())
            ops.append(
                Operation(
                    mechanism="task",
                    key=key,
                    target_id=target.id,
                    description=f"отключено задание {key} ({target.name})",
                )
            )
    return ops


def plan_all(targets: list[Target]) -> dict[str, list[Operation]]:
    """Полный план по механизмам — то, что показывает предпросмотр в окне."""
    return {
        "ifeo": plan_ifeo(targets),
        "srp": plan_srp(targets),
        "hash": plan_hashes(targets),
        "firewall": plan_firewall(targets),
        "hosts": plan_hosts(targets),
        "service": plan_services(targets),
        "task": plan_tasks(targets),
    }
