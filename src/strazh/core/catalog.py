"""Чтение, проверка и слияние каталогов целей.

Каталог — это набор файлов JSON. Один комплект приезжает вместе с программой
и обновляется вместе с ней, второй лежит в `%ProgramData%\\Strazh\\catalog.d`
и принадлежит человеку. Записи из второго перекрывают первый по полю `id`:
так «выключить 360 Total Security» и «поправить маску» не превращаются в
правку файла, который затрёт следующее обновление.

Проверка намеренно строгая и с внятными сообщениями: каталог правят руками,
и «ошибка в строке 12» лучше, чем молча пропущенная цель.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from strazh.core.models import (
    Action,
    MatchSpec,
    Severity,
    Target,
    pattern_touches_protected,
)

SCHEMA_VERSION = 1

CATEGORIES: dict[str, str] = {
    "cn-security-suite": "Китайские защитные пакеты",
    "av-bundleware": "Антивирусы, приходящие в комплекте",
    "rogue-security": "Мнимая защита и запугивание",
    "system-optimizer": "«Ускорители» и чистильщики",
    "driver-updater": "Обновляльщики драйверов",
    "ru-bundleware": "Спутники русскоязычных установщиков",
    "stalkerware": "Слежка за человеком и перехват клавиш",
    "adware-installer": "Установщики-обёртки и рекламные модули",
    "remote-access-abused": "Средства удалённого доступа из мошеннических схем",
    "miner": "Скрытая добыча криптовалюты",
    "crack-tool": "Обход лицензий",
    "other": "Прочее",
}


class CatalogError(ValueError):
    """Каталог не прочитан. Текст рассчитан на человека, а не на журнал."""


@dataclass(frozen=True, slots=True)
class CatalogIssue:
    """Замечание, не мешающее загрузке: запись пропущена, остальное живо."""

    file: str
    target_id: str
    message: str

    def __str__(self) -> str:
        where = f"{self.file}"
        if self.target_id:
            where += f" → {self.target_id}"
        return f"{where}: {self.message}"


@dataclass(slots=True)
class Catalog:
    """Слитый каталог: цели по `id` плюс замечания, набранные при чтении."""

    targets: dict[str, Target]
    issues: list[CatalogIssue]

    def as_list(self) -> list[Target]:
        return sorted(self.targets.values(), key=lambda t: (t.category, t.name.casefold()))

    def enabled(self) -> list[Target]:
        return [t for t in self.as_list() if t.enabled]

    def by_category(self) -> dict[str, list[Target]]:
        out: dict[str, list[Target]] = {}
        for target in self.as_list():
            out.setdefault(target.category, []).append(target)
        return out

    def domains(self) -> list[str]:
        seen: set[str] = set()
        for target in self.enabled():
            if target.has(Action.BLOCK_DOMAINS):
                seen.update(target.match.domains)
        return sorted(seen)


# ── разбор одной записи ───────────────────────────────────────────────────────


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    raise CatalogError(f"ожидался список строк, получено {type(value).__name__}")


def parse_target(raw: Any, *, source: str = "builtin", file: str = "") -> Target:
    """Словарь из JSON → `Target`. Бросает `CatalogError` с понятным текстом."""
    if not isinstance(raw, dict):
        raise CatalogError("запись цели должна быть объектом")

    target_id = str(raw.get("id", "")).strip()
    if not target_id:
        raise CatalogError("у записи нет поля id")
    if not all(ch.isalnum() or ch in "-_." for ch in target_id):
        raise CatalogError(f"id «{target_id}»: допустимы буквы, цифры, дефис, подчёркивание, точка")

    name = str(raw.get("name", "")).strip() or target_id

    severity_raw = str(raw.get("severity", "medium")).strip().lower()
    try:
        severity = Severity(severity_raw)
    except ValueError as exc:
        allowed = ", ".join(s.value for s in Severity)
        raise CatalogError(f"уровень «{severity_raw}» неизвестен, допустимы: {allowed}") from exc

    category = str(raw.get("category", "other")).strip() or "other"
    if category not in CATEGORIES:
        raise CatalogError(f"раздел «{category}» неизвестен, допустимы: {', '.join(CATEGORIES)}")

    actions_raw = _as_str_list(raw.get("actions")) or [
        Action.BLOCK_EXEC.value,
        Action.BLOCK_INSTALL.value,
    ]
    actions: list[Action] = []
    for item in actions_raw:
        try:
            actions.append(Action(item.strip()))
        except ValueError as exc:
            allowed = ", ".join(a.value for a in Action)
            raise CatalogError(f"действие «{item}» неизвестно, допустимы: {allowed}") from exc

    match_raw = raw.get("match")
    if not isinstance(match_raw, dict):
        raise CatalogError("нет раздела match с признаками")
    spec = MatchSpec.from_json(match_raw)
    if spec.is_empty():
        raise CatalogError("в match не задано ни одного признака — цель никогда не сработает")

    # Признак, задевающий системный файл, — не повод пропустить всю запись,
    # но и оставлять его нельзя. Такие маски вычищаются, а не игнорируются
    # на месте применения: иначе они разошлись бы по всем механизмам сразу.
    dangerous = [
        p
        for p in (*spec.executables, *spec.installers, *spec.original_filenames)
        if pattern_touches_protected(p)
    ]
    if dangerous:
        raise CatalogError(
            "маски "
            + ", ".join(f"«{p}»" for p in sorted(set(dangerous)))
            + " задевают защищённые файлы Windows и не будут применены"
        )

    return Target(
        id=target_id,
        name=name,
        vendor=str(raw.get("vendor", "")).strip(),
        category=category,
        severity=severity,
        enabled=bool(raw.get("enabled", True)),
        why=str(raw.get("why", "")).strip(),
        references=tuple(_as_str_list(raw.get("references"))),
        match=spec,
        actions=tuple(dict.fromkeys(actions)),
        source=source,
    )


def parse_document(raw: Any, *, source: str, file: str) -> tuple[list[Target], list[CatalogIssue]]:
    """Разобрать содержимое одного файла каталога."""
    if not isinstance(raw, dict):
        raise CatalogError("файл каталога должен содержать объект верхнего уровня")

    version = raw.get("version", SCHEMA_VERSION)
    if not isinstance(version, int) or version > SCHEMA_VERSION:
        raise CatalogError(
            f"версия формата {version} новее поддерживаемой ({SCHEMA_VERSION}) — обновите программу"
        )

    entries = raw.get("targets")
    if not isinstance(entries, list):
        raise CatalogError("в файле нет списка targets")

    targets: list[Target] = []
    issues: list[CatalogIssue] = []
    for index, entry in enumerate(entries):
        entry_id = str(entry.get("id", f"#{index}")) if isinstance(entry, dict) else f"#{index}"
        try:
            targets.append(parse_target(entry, source=source, file=file))
        except CatalogError as exc:
            issues.append(CatalogIssue(file=file, target_id=entry_id, message=str(exc)))
    return targets, issues


# ── чтение с диска ────────────────────────────────────────────────────────────


def load_dir(directory: Path, *, source: str) -> tuple[list[Target], list[CatalogIssue]]:
    """Прочитать все `*.json` каталога. Отсутствующая папка — не ошибка."""
    targets: list[Target] = []
    issues: list[CatalogIssue] = []
    if not directory.is_dir():
        return targets, issues
    for path in sorted(directory.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            issues.append(CatalogIssue(file=path.name, target_id="", message=f"не прочитан: {exc}"))
            continue
        try:
            found, found_issues = parse_document(raw, source=source, file=path.name)
        except CatalogError as exc:
            issues.append(CatalogIssue(file=path.name, target_id="", message=str(exc)))
            continue
        targets.extend(found)
        issues.extend(found_issues)
    return targets, issues


def merge(
    builtin: list[Target],
    user: list[Target],
    overrides: dict[str, dict[str, Any]] | None = None,
) -> Catalog:
    """Собрать итоговый каталог.

    Порядок: поставка → пользовательские файлы → переопределения из настроек.
    Последнее слово всегда за человеком, но встроенную запись он не удаляет,
    а выключает: удаление вернулось бы обратно со следующим обновлением.
    """
    targets: dict[str, Target] = {}
    issues: list[CatalogIssue] = []

    for target in builtin:
        if target.id in targets:
            issues.append(
                CatalogIssue(file="поставка", target_id=target.id, message="повторяющийся id")
            )
        targets[target.id] = target

    for target in user:
        base = targets.get(target.id)
        targets[target.id] = target if base is None else replace(target, source="user")

    for target_id, patch in (overrides or {}).items():
        base = targets.get(target_id)
        if base is None:
            continue
        changes: dict[str, Any] = {}
        if "enabled" in patch:
            changes["enabled"] = bool(patch["enabled"])
        if "actions" in patch:
            try:
                changes["actions"] = tuple(Action(a) for a in _as_str_list(patch["actions"]))
            except ValueError:
                issues.append(
                    CatalogIssue(
                        file="settings.json",
                        target_id=target_id,
                        message="в переопределении указано неизвестное действие",
                    )
                )
        if changes:
            targets[target_id] = replace(base, **changes)

    return Catalog(targets=targets, issues=issues)


def load(
    builtin_dir: Path,
    user_dir: Path | None = None,
    overrides: dict[str, dict[str, Any]] | None = None,
) -> Catalog:
    """Полная загрузка: поставка + пользовательские файлы + переопределения."""
    builtin, issues = load_dir(builtin_dir, source="builtin")
    user: list[Target] = []
    if user_dir is not None:
        user, user_issues = load_dir(user_dir, source="user")
        issues.extend(user_issues)
    catalog = merge(builtin, user, overrides)
    catalog.issues = issues + catalog.issues
    return catalog


def dump_targets(targets: list[Target], *, comment: str = "") -> str:
    """Список целей → текст файла каталога, готовый к записи."""
    doc: dict[str, Any] = {"version": SCHEMA_VERSION}
    if comment:
        doc["comment"] = comment
    doc["targets"] = [t.to_json() for t in targets]
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"
