"""Сопоставление файла с каталогом целей.

Модуль ничего не знает ни о Windows, ни о том, кто его вызвал: на входе
`FileFacts`, на выходе `Verdict`. Из-за этого самую важную часть программы —
решение «пускать или нет» — можно прогнать в проверках на любой машине.

Порядок признаков выбран так, чтобы переименование файла не спасало:
сначала быстрые точные совпадения по имени, затем подпись издателя и
`OriginalFilename`, которые при переименовании остаются на месте.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from strazh.core.models import (
    Action,
    FileFacts,
    MatchKind,
    Severity,
    Target,
    Verdict,
    compile_pattern,
    is_protected,
)

_WILDCARDS = re.compile(r"[*?\[]")

_SEVERITY_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}


def _has_wildcard(pattern: str) -> bool:
    return bool(_WILDCARDS.search(pattern))


@dataclass(frozen=True, slots=True)
class _NameRule:
    regex: re.Pattern[str]
    pattern: str
    target: Target
    kind: MatchKind


@dataclass(frozen=True, slots=True)
class _TextRule:
    """Признак, который ищут внутри строки: издатель, название продукта.

    Без подстановочных знаков ищем вхождение — сертификат подписан на
    «Qihoo 360 Software (Beijing) Company Limited», а в каталоге разумно
    держать короткое «Qihoo 360».
    """

    needle: str
    """Искомое, приведённое к нижнему регистру."""

    display: str
    """Как признак записан в каталоге — попадает в журнал без изменений."""

    regex: re.Pattern[str] | None
    target: Target
    kind: MatchKind

    def matches(self, value: str) -> bool:
        if self.regex is not None:
            return self.regex.match(value) is not None
        return self.needle in value


class Allowlist:
    """Исключения. Всё, что сюда попало, не блокируется никогда.

    Нужен как аварийный выход: если правило зацепило чужой файл, человек
    должен уметь вернуть себе программу, не разбирая каталог по частям.
    """

    __slots__ = ("_path_re", "names", "paths", "sha256")

    def __init__(
        self,
        names: set[str] | None = None,
        paths: list[str] | None = None,
        sha256: set[str] | None = None,
    ) -> None:
        self.names = {n.strip().casefold() for n in (names or set()) if n.strip()}
        self.paths = [p for p in (paths or []) if p.strip()]
        self.sha256 = {h.strip().lower() for h in (sha256 or set()) if h.strip()}
        self._path_re = [compile_pattern(p) for p in self.paths]

    def covers(self, facts: FileFacts) -> str | None:
        if facts.image_name and facts.image_name.casefold() in self.names:
            return f"имя {facts.image_name}"
        if facts.sha256 and facts.sha256.lower() in self.sha256:
            return "контрольная сумма"
        if facts.image_path:
            for rx in self._path_re:
                if rx.match(facts.image_path):
                    return f"путь {facts.image_path}"
        return None

    def to_json(self) -> dict[str, list[str]]:
        return {
            "names": sorted(self.names),
            "paths": list(self.paths),
            "sha256": sorted(self.sha256),
        }


class Matcher:
    """Скомпилированный каталог.

    Компиляция делается один раз при загрузке: наблюдатель за процессами
    вызывает `evaluate` на каждый запуск в системе, и разбирать там маски
    заново было бы расточительно.
    """

    def __init__(self, targets: list[Target], allowlist: Allowlist | None = None) -> None:
        self.allowlist = allowlist or Allowlist()
        self._exact: dict[str, list[_NameRule]] = {}
        self._globs: list[_NameRule] = []
        self._texts: list[_TextRule] = []
        self._paths: list[_NameRule] = []
        self._hashes: dict[str, Target] = {}
        self._targets: list[Target] = []
        for target in sorted(targets, key=lambda t: (_SEVERITY_ORDER.get(t.severity, 9), t.id)):
            self._add(target)

    # ── сборка индекса ────────────────────────────────────────────────────────

    def _add(self, target: Target) -> None:
        if not target.enabled:
            return
        self._targets.append(target)
        spec = target.match

        for kind, patterns in (
            (MatchKind.EXECUTABLE, spec.executables),
            (MatchKind.INSTALLER, spec.installers),
            (MatchKind.ORIGINAL_FILENAME, spec.original_filenames),
        ):
            for pattern in patterns:
                # Неприкосновенное имя не попадает в индекс вовсе. Правило с
                # ним не «не срабатывает» — его просто нет, и никакая ошибка
                # в каталоге не сможет остановить вход в систему.
                if is_protected(pattern):
                    continue
                rule = _NameRule(compile_pattern(pattern), pattern, target, kind)
                if _has_wildcard(pattern):
                    self._globs.append(rule)
                else:
                    self._exact.setdefault(pattern.casefold(), []).append(rule)

        for kind, patterns in (
            (MatchKind.PUBLISHER, spec.publishers),
            (MatchKind.PRODUCT_NAME, spec.product_names),
        ):
            for pattern in patterns:
                regex = compile_pattern(pattern) if _has_wildcard(pattern) else None
                self._texts.append(_TextRule(pattern.casefold(), pattern, regex, target, kind))

        for pattern in spec.paths:
            self._paths.append(_NameRule(compile_pattern(pattern), pattern, target, MatchKind.PATH))

        for digest in spec.sha256:
            self._hashes.setdefault(digest.lower(), target)

    # ── запросы ───────────────────────────────────────────────────────────────

    @property
    def targets(self) -> list[Target]:
        """Только включённые цели, в порядке убывания опасности."""
        return list(self._targets)

    def evaluate(self, facts: FileFacts) -> Verdict:
        """Пускать файл или нет.

        Возвращает первое совпадение: цели отсортированы по опасности, так
        что при пересечении масок в журнал попадёт более серьёзная запись.
        """
        name = (facts.image_name or "").strip()
        if not name:
            return Verdict.allow("нет имени файла")

        # Неприкосновенные имена не проверяются вообще — это дешевле любой
        # проверки и надёжнее любого правила.
        if is_protected(name):
            return Verdict.allow("файл системы под защитой")

        covered = self.allowlist.covers(facts)
        if covered is not None:
            return Verdict.allow(f"в исключениях: {covered}")

        folded = name.casefold()

        if facts.sha256:
            target = self._hashes.get(facts.sha256.lower())
            if target is not None:
                return _deny_of(target, MatchKind.SHA256, facts.sha256.lower())

        for rule in self._exact.get(folded, ()):
            return self._deny(rule)

        original = (facts.original_filename or "").strip().casefold()
        if original and original != folded:
            for rule in self._exact.get(original, ()):
                return self._deny(rule)

        for rule in self._globs:
            if rule.regex.match(name) or (original and rule.regex.match(original)):
                return self._deny(rule)

        publisher = (facts.publisher or "").casefold()
        company = (facts.company_name or "").casefold()
        product = (facts.product_name or "").casefold()
        for text_rule in self._texts:
            haystacks = (
                (publisher, company) if text_rule.kind is MatchKind.PUBLISHER else (product,)
            )
            for haystack in haystacks:
                if haystack and text_rule.matches(haystack):
                    return _deny_of(text_rule.target, text_rule.kind, text_rule.display, haystack)

        if facts.image_path:
            for rule in self._paths:
                if rule.regex.match(facts.image_path):
                    return self._deny(rule)

        return Verdict.allow()

    def target_by_id(self, target_id: str) -> Target | None:
        for target in self._targets:
            if target.id == target_id:
                return target
        return None

    def targets_with(self, action: Action) -> list[Target]:
        return [t for t in self._targets if t.has(action)]

    # ── оформление ответа ─────────────────────────────────────────────────────

    @staticmethod
    def _deny(rule: _NameRule) -> Verdict:
        return _deny_of(rule.target, rule.kind, rule.pattern)


def _deny_of(target: Target, kind: MatchKind, pattern: str, haystack: str = "") -> Verdict:
    return Verdict(
        allowed=False,
        target_id=target.id,
        target_name=target.name,
        kind=kind,
        pattern=pattern,
        severity=target.severity,
        reason=_reason(kind, pattern, haystack),
    )


def _reason(kind: MatchKind, pattern: str, haystack: str = "") -> str:
    match kind:
        case MatchKind.EXECUTABLE:
            return f"имя файла совпало с «{pattern}»"
        case MatchKind.INSTALLER:
            return f"имя установщика совпало с «{pattern}»"
        case MatchKind.ORIGINAL_FILENAME:
            return f"исходное имя в ресурсе версии — «{pattern}» (файл переименован)"
        case MatchKind.PUBLISHER:
            tail = f": {haystack}" if haystack else ""
            return f"подпись издателя содержит «{pattern}»{tail}"
        case MatchKind.PRODUCT_NAME:
            return f"название продукта содержит «{pattern}»"
        case MatchKind.PATH:
            return f"путь подошёл под «{pattern}»"
        case MatchKind.SHA256:
            return "контрольная сумма файла есть в каталоге"
        case _:
            return f"совпадение по «{pattern}»"
