"""Проверки сопоставителя — самой ответственной части программы.

Здесь проверяется не «работает ли код», а два обещания: запрещённое не
проходит даже переименованным, а системное не блокируется никогда.
"""

from __future__ import annotations

import pytest

from strazh.core.matcher import Allowlist, Matcher
from strazh.core.models import (
    Action,
    FileFacts,
    MatchKind,
    MatchSpec,
    Severity,
    Target,
    is_protected,
    pattern_touches_protected,
)


def target(**kwargs) -> Target:
    spec = kwargs.pop("match", MatchSpec(executables=("bad.exe",)))
    return Target(
        id=kwargs.pop("id", "test"),
        name=kwargs.pop("name", "Тестовая цель"),
        match=spec,
        **kwargs,
    )


class TestNameMatching:
    def test_exact_name_blocked(self) -> None:
        m = Matcher([target(match=MatchSpec(executables=("360tray.exe",)))])
        verdict = m.evaluate(FileFacts(image_name="360tray.exe"))
        assert not verdict.allowed
        assert verdict.kind is MatchKind.EXECUTABLE

    def test_name_is_case_insensitive(self) -> None:
        m = Matcher([target(match=MatchSpec(executables=("360Tray.exe",)))])
        assert not m.evaluate(FileFacts(image_name="360TRAY.EXE")).allowed

    def test_unknown_name_allowed(self) -> None:
        m = Matcher([target(match=MatchSpec(executables=("360tray.exe",)))])
        assert m.evaluate(FileFacts(image_name="notepad.exe")).allowed

    @pytest.mark.parametrize(
        "name",
        ["360TS_Setup_Mini.exe", "360ts_setup.exe", "install_360TS_Setup_full.exe"],
    )
    def test_installer_masks(self, name: str) -> None:
        m = Matcher([target(match=MatchSpec(installers=("*360ts_setup*.exe",)))])
        assert not m.evaluate(FileFacts(image_name=name)).allowed


class TestRenameResistance:
    """Переименование — самый дешёвый обход, поэтому ему отдельный раздел."""

    def test_original_filename_catches_rename(self) -> None:
        m = Matcher([target(match=MatchSpec(original_filenames=("360Safe.exe",)))])
        verdict = m.evaluate(
            FileFacts(image_name="svc_helper.exe", original_filename="360Safe.exe")
        )
        assert not verdict.allowed
        assert verdict.kind is MatchKind.ORIGINAL_FILENAME

    def test_publisher_catches_rename(self) -> None:
        m = Matcher([target(match=MatchSpec(publishers=("Qihoo 360",)))])
        verdict = m.evaluate(
            FileFacts(
                image_name="totally_innocent.exe",
                publisher="Qihoo 360 Software (Beijing) Company Limited",
            )
        )
        assert not verdict.allowed
        assert verdict.kind is MatchKind.PUBLISHER

    def test_publisher_falls_back_to_company_name(self) -> None:
        """Разбор подписи может не получиться — тогда остаётся поле CompanyName
        из ресурса версии. Признак должен работать и по нему."""
        m = Matcher([target(match=MatchSpec(publishers=("Qihoo 360",)))])
        facts = FileFacts(image_name="x.exe", company_name="Qihoo 360 Software")
        assert not m.evaluate(facts).allowed

    def test_hash_catches_everything(self) -> None:
        digest = "a" * 64
        m = Matcher([target(match=MatchSpec(sha256=(digest,)))])
        verdict = m.evaluate(FileFacts(image_name="whatever.exe", sha256=digest.upper()))
        assert not verdict.allowed
        assert verdict.kind is MatchKind.SHA256

    def test_path_mask_matches_both_separators(self) -> None:
        m = Matcher([target(match=MatchSpec(paths=("*\\360\\*",)))])
        assert not m.evaluate(
            FileFacts(image_name="x.exe", image_path="C:/Program Files/360/x.exe")
        ).allowed


class TestSafety:
    """Обещание, которое дороже всех остальных: программа не должна
    превратить рабочую машину в кирпич."""

    @pytest.mark.parametrize(
        "name", ["lsass.exe", "explorer.exe", "svchost.exe", "MsMpEng.exe", "winlogon.exe"]
    )
    def test_system_files_never_blocked(self, name: str) -> None:
        # Даже если такое правило каким-то образом окажется в каталоге.
        m = Matcher([target(match=MatchSpec(executables=(name,)))])
        assert m.evaluate(FileFacts(image_name=name)).allowed

    def test_wide_mask_does_not_take_down_the_system(self) -> None:
        m = Matcher([target(match=MatchSpec(executables=("*.exe",)))])
        assert m.evaluate(FileFacts(image_name="lsass.exe")).allowed
        assert not m.evaluate(FileFacts(image_name="anything-else.exe")).allowed

    def test_protected_patterns_are_detected(self) -> None:
        assert pattern_touches_protected("*.exe")
        assert pattern_touches_protected("lsass.exe")
        assert pattern_touches_protected("s*.exe")
        assert not pattern_touches_protected("360tray.exe")
        assert not pattern_touches_protected("360*setup*.exe")

    def test_is_protected_ignores_case_and_spaces(self) -> None:
        assert is_protected("  LSASS.EXE ")


class TestAllowlist:
    def test_allowlist_beats_catalog(self) -> None:
        m = Matcher(
            [target(match=MatchSpec(executables=("bad.exe",)))],
            Allowlist(names={"bad.exe"}),
        )
        verdict = m.evaluate(FileFacts(image_name="bad.exe"))
        assert verdict.allowed
        assert "исключени" in verdict.reason

    def test_allowlist_by_path(self) -> None:
        m = Matcher(
            [target(match=MatchSpec(executables=("bad.exe",)))],
            Allowlist(paths=["C:\\Tools\\*"]),
        )
        assert m.evaluate(FileFacts(image_name="bad.exe", image_path="C:\\Tools\\bad.exe")).allowed
        assert not m.evaluate(
            FileFacts(image_name="bad.exe", image_path="C:\\Other\\bad.exe")
        ).allowed


class TestOrdering:
    def test_disabled_targets_are_not_indexed(self) -> None:
        m = Matcher([target(enabled=False)])
        assert m.evaluate(FileFacts(image_name="bad.exe")).allowed
        assert m.targets == []

    def test_more_severe_target_wins(self) -> None:
        low = target(id="low", name="Слабая", severity=Severity.LOW)
        high = target(id="high", name="Опасная", severity=Severity.HIGH)
        m = Matcher([low, high])
        assert m.evaluate(FileFacts(image_name="bad.exe")).target_id == "high"

    def test_targets_with_action(self) -> None:
        a = target(id="a", actions=(Action.BLOCK_EXEC,))
        b = target(id="b", actions=(Action.BLOCK_EXEC, Action.BLOCK_NETWORK))
        m = Matcher([a, b])
        assert [t.id for t in m.targets_with(Action.BLOCK_NETWORK)] == ["b"]


def test_empty_name_is_allowed() -> None:
    assert Matcher([target()]).evaluate(FileFacts(image_name="")).allowed
