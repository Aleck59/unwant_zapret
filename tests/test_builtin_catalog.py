"""Проверки самого каталога, а не кода, который его читает.

Каталог — это данные, но ошибка в данных стоит столько же, сколько ошибка в
коде: лишняя маска отберёт у человека нужную программу, а опечатка в имени
службы оставит цель работать. Поэтому поставляемый каталог проверяется в
сборке наравне с кодом.
"""

from __future__ import annotations

import json

import pytest

from strazh import paths
from strazh.core.catalog import CATEGORIES, load_dir
from strazh.core.models import pattern_touches_protected
from strazh.enforce import plan


@pytest.fixture(scope="module")
def builtin():
    targets, issues = load_dir(paths.builtin_catalog_dir(), source="builtin")
    return targets, issues


def test_catalog_loads_without_complaints(builtin) -> None:
    targets, issues = builtin
    assert not issues, "\n".join(str(i) for i in issues)
    assert len(targets) >= 30


def test_every_file_is_valid_json() -> None:
    for path in paths.builtin_catalog_dir().glob("*.json"):
        json.loads(path.read_text(encoding="utf-8"))


def test_ids_are_unique(builtin) -> None:
    targets, _ = builtin
    ids = [t.id for t in targets]
    assert len(ids) == len(set(ids))


def test_every_target_explains_itself(builtin) -> None:
    """Запись без объяснения — это «мы решили за вас». Человек должен видеть,
    почему программа в списке, и иметь возможность не согласиться."""
    targets, _ = builtin
    missing = [t.id for t in targets if len(t.why) < 40]
    assert not missing, f"без внятного пояснения: {missing}"


def test_categories_are_known(builtin) -> None:
    targets, _ = builtin
    assert {t.category for t in targets} <= set(CATEGORIES)


def test_no_target_touches_system_files(builtin) -> None:
    targets, _ = builtin
    bad: list[str] = []
    for target in targets:
        for pattern in (
            *target.match.executables,
            *target.match.installers,
            *target.match.original_filenames,
        ):
            if pattern_touches_protected(pattern):
                bad.append(f"{target.id}: {pattern}")
    assert not bad, bad


def test_executable_names_look_like_files(builtin) -> None:
    targets, _ = builtin
    wrong = [
        f"{t.id}: {name}"
        for t in targets
        for name in t.match.executables
        if not name.casefold().endswith((".exe", ".com", ".scr", ".pif"))
    ]
    assert not wrong, wrong


def test_domains_have_no_scheme_or_path(builtin) -> None:
    targets, _ = builtin
    wrong = [
        f"{t.id}: {d}" for t in targets for d in t.match.domains if "/" in d or ":" in d or " " in d
    ]
    assert not wrong, wrong


def test_disabled_targets_say_why_they_are_disabled(builtin) -> None:
    """Выключенная запись обязана объяснить, почему её не включили: иначе она
    выглядит забытой, а не обдуманной."""
    targets, _ = builtin
    silent = [t.id for t in targets if not t.enabled and "выключен" not in t.why.casefold()]
    assert not silent, silent


def test_plan_is_built_and_is_not_trivial(builtin) -> None:
    targets, _ = builtin
    enabled = [t for t in targets if t.enabled]
    built = plan.plan_all(enabled)
    assert len(built["ifeo"]) > 100
    assert len(built["srp"]) > 50
    assert len(built["service"]) > 20


def test_plan_has_no_duplicate_keys(builtin) -> None:
    targets, _ = builtin
    for mechanism, ops in plan.plan_all([t for t in targets if t.enabled]).items():
        keys = [op.key.casefold() for op in ops]
        assert len(keys) == len(set(keys)), f"повторы в плане {mechanism}"


def test_generic_installer_names_never_reach_name_blocking(builtin) -> None:
    """`setup.exe` есть у половины программ на свете. Такая маска обязана
    уходить в правила по пути, где рядом стоит проверка издателя."""
    targets, _ = builtin
    names = {op.key.casefold() for op in plan.plan_ifeo([t for t in targets if t.enabled])}
    assert names.isdisjoint(plan._TOO_GENERIC)
