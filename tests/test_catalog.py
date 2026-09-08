"""Проверки чтения каталога.

Каталог правят руками, поэтому от разбора требуется не «не упасть», а
объяснить, что именно не так, и не потерять из-за одной плохой записи весь
остальной файл.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strazh.core.catalog import (
    SCHEMA_VERSION,
    Catalog,
    CatalogError,
    dump_targets,
    load,
    load_dir,
    merge,
    parse_document,
    parse_target,
)
from strazh.core.models import Action, MatchSpec, Severity, Target


def write(path: Path, targets: list[dict], version: int = SCHEMA_VERSION) -> Path:
    path.write_text(
        json.dumps({"version": version, "targets": targets}, ensure_ascii=False), encoding="utf-8"
    )
    return path


GOOD = {
    "id": "sample",
    "name": "Пример",
    "category": "other",
    "severity": "high",
    "match": {"executables": ["sample.exe"]},
    "actions": ["block_exec"],
}


class TestParseTarget:
    def test_minimal_record(self) -> None:
        target = parse_target({"id": "a", "name": "A", "match": {"executables": ["a.exe"]}})
        assert target.id == "a"
        assert target.severity is Severity.MEDIUM
        assert target.actions == (Action.BLOCK_EXEC, Action.BLOCK_INSTALL)

    def test_missing_id(self) -> None:
        with pytest.raises(CatalogError, match="нет поля id"):
            parse_target({"name": "A", "match": {"executables": ["a.exe"]}})

    def test_missing_match(self) -> None:
        with pytest.raises(CatalogError, match="признак"):
            parse_target({"id": "a", "name": "A"})

    def test_empty_match_is_rejected(self) -> None:
        with pytest.raises(CatalogError, match="никогда не сработает"):
            parse_target({"id": "a", "name": "A", "match": {"executables": []}})

    def test_unknown_severity(self) -> None:
        with pytest.raises(CatalogError, match="неизвестен"):
            parse_target({**GOOD, "severity": "критический"})

    def test_unknown_category(self) -> None:
        with pytest.raises(CatalogError, match="неизвестен"):
            parse_target({**GOOD, "category": "выдуманный"})

    def test_unknown_action(self) -> None:
        with pytest.raises(CatalogError, match="неизвестно"):
            parse_target({**GOOD, "actions": ["delete_everything"]})

    def test_bad_id_characters(self) -> None:
        with pytest.raises(CatalogError, match="допустимы"):
            parse_target({**GOOD, "id": "a b/c"})

    def test_protected_pattern_rejected(self) -> None:
        """Запись, способная заблокировать вход в систему, не принимается —
        ни из поставки, ни из пользовательского файла."""
        with pytest.raises(CatalogError, match="защищённые файлы"):
            parse_target({**GOOD, "match": {"executables": ["lsass.exe"]}})

    def test_scalar_instead_of_list_is_accepted(self) -> None:
        target = parse_target({**GOOD, "match": {"executables": "one.exe"}})
        assert target.match.executables == ("one.exe",)


class TestParseDocument:
    def test_bad_record_does_not_lose_the_rest(self) -> None:
        targets, issues = parse_document(
            {"version": 1, "targets": [GOOD, {"id": "broken"}]}, source="builtin", file="f.json"
        )
        assert [t.id for t in targets] == ["sample"]
        assert len(issues) == 1
        assert "broken" in str(issues[0])

    def test_future_version_is_refused(self) -> None:
        with pytest.raises(CatalogError, match="новее"):
            parse_document({"version": 99, "targets": []}, source="builtin", file="f.json")

    def test_missing_targets_list(self) -> None:
        with pytest.raises(CatalogError, match="targets"):
            parse_document({"version": 1}, source="builtin", file="f.json")


class TestLoadAndMerge:
    def test_missing_directory_is_not_an_error(self, tmp_path: Path) -> None:
        targets, issues = load_dir(tmp_path / "нет-такой", source="user")
        assert targets == [] and issues == []

    def test_broken_json_is_reported(self, tmp_path: Path) -> None:
        (tmp_path / "bad.json").write_text("{не json", encoding="utf-8")
        targets, issues = load_dir(tmp_path, source="builtin")
        assert targets == []
        assert "не прочитан" in str(issues[0])

    def test_user_record_overrides_builtin(self, tmp_path: Path) -> None:
        builtin = tmp_path / "builtin"
        user = tmp_path / "user"
        builtin.mkdir()
        user.mkdir()
        write(builtin / "a.json", [GOOD])
        write(user / "a.json", [{**GOOD, "name": "Моё название"}])
        catalog = load(builtin, user)
        assert catalog.targets["sample"].name == "Моё название"
        assert catalog.targets["sample"].source == "user"

    def test_overrides_switch_targets_off(self, tmp_path: Path) -> None:
        builtin = tmp_path / "builtin"
        builtin.mkdir()
        write(builtin / "a.json", [GOOD])
        catalog = load(builtin, None, {"sample": {"enabled": False}})
        assert catalog.targets["sample"].enabled is False
        assert catalog.enabled() == []

    def test_override_of_unknown_target_is_ignored(self) -> None:
        catalog = merge([], [], {"нет-такой": {"enabled": False}})
        assert catalog.targets == {}

    def test_duplicate_builtin_ids_are_reported(self) -> None:
        one = Target(id="x", name="X", match=MatchSpec(executables=("x.exe",)))
        catalog = merge([one, one], [])
        assert any("повторяющийся" in str(i) for i in catalog.issues)


class TestDump:
    def test_round_trip(self) -> None:
        target = Target(
            id="x",
            name="X",
            category="miner",
            severity=Severity.HIGH,
            match=MatchSpec(executables=("x.exe",), domains=("example.com",)),
            actions=(Action.BLOCK_EXEC, Action.BLOCK_DOMAINS),
        )
        raw = json.loads(dump_targets([target]))
        restored = parse_target(raw["targets"][0])
        assert restored.id == target.id
        assert restored.match.executables == target.match.executables
        assert restored.actions == target.actions


class TestCatalogHelpers:
    def test_domains_only_from_targets_that_ask_for_it(self) -> None:
        with_domains = Target(
            id="a",
            name="A",
            match=MatchSpec(domains=("a.example",)),
            actions=(Action.BLOCK_DOMAINS,),
        )
        without = Target(
            id="b",
            name="B",
            match=MatchSpec(domains=("b.example",)),
            actions=(Action.BLOCK_EXEC,),
        )
        catalog = Catalog(targets={"a": with_domains, "b": without}, issues=[])
        assert catalog.domains() == ["a.example"]
