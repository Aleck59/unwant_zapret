"""Проверки обратимости: состояние и карантин.

Обе части существуют ради одного — чтобы всё сделанное можно было отменить.
"""

from __future__ import annotations

import json
from pathlib import Path

from strazh.core.quarantine import entries, quarantine, restore
from strazh.core.state import Change, State, load_state, save_state


class TestState:
    def test_add_replaces_same_key(self) -> None:
        state = State()
        state.add(Change(mechanism="ifeo", key="a.exe", previous=None))
        state.add(Change(mechanism="ifeo", key="A.EXE", previous="prev"))
        assert len(state.changes) == 1
        assert state.changes[0].previous == "prev"

    def test_same_key_different_mechanism_kept(self) -> None:
        state = State()
        state.add(Change(mechanism="ifeo", key="a.exe"))
        state.add(Change(mechanism="srp", key="a.exe"))
        assert len(state.changes) == 2

    def test_remove(self) -> None:
        state = State()
        state.add(Change(mechanism="ifeo", key="a.exe"))
        state.remove("ifeo", "A.EXE")
        assert state.changes == []

    def test_round_trip(self, tmp_path: Path) -> None:
        state = State(protection_on=True, applied_at="2026-01-01T00:00:00+00:00")
        state.add(Change(mechanism="hosts", key="x.example", target_id="t", previous="было"))
        path = tmp_path / "state.json"
        save_state(path, state)
        restored = load_state(path)
        assert restored.protection_on
        assert restored.changes[0].previous == "было"

    def test_broken_file_gives_empty_state(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"
        path.write_text("не json", encoding="utf-8")
        assert load_state(path).changes == []

    def test_missing_file_gives_empty_state(self, tmp_path: Path) -> None:
        assert load_state(tmp_path / "нет.json").protection_on is False

    def test_records_without_mechanism_are_skipped(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"
        path.write_text(
            json.dumps({"changes": [{"key": "a"}, {"mechanism": "ifeo", "key": "b"}]}),
            encoding="utf-8",
        )
        assert [c.key for c in load_state(path).changes] == ["b"]


class TestQuarantine:
    def test_file_is_moved_not_deleted(self, tmp_path: Path) -> None:
        source = tmp_path / "360TS_Setup.exe"
        source.write_bytes(b"MZ payload")
        folder = tmp_path / "quarantine"

        entry = quarantine(source, folder, target_id="q", target_name="360", reason="маска")
        assert entry is not None
        assert not source.exists()
        assert entry.stored.exists()
        assert entry.stored.read_bytes() == b"MZ payload"

    def test_stored_file_cannot_be_launched_by_extension(self, tmp_path: Path) -> None:
        source = tmp_path / "bad.exe"
        source.write_bytes(b"x")
        entry = quarantine(source, tmp_path / "q", target_id="t", target_name="T", reason="")
        assert entry is not None
        assert entry.stored.suffix == ".blocked"

    def test_note_explains_what_happened(self, tmp_path: Path) -> None:
        source = tmp_path / "bad.exe"
        source.write_bytes(b"x")
        entry = quarantine(source, tmp_path / "q", target_id="t", target_name="Цель", reason="имя")
        assert entry is not None
        note = json.loads(entry.note.read_text(encoding="utf-8"))
        assert note["original"] == str(source)
        assert note["target_name"] == "Цель"

    def test_restore_puts_the_file_back(self, tmp_path: Path) -> None:
        source = tmp_path / "bad.exe"
        source.write_bytes(b"payload")
        entry = quarantine(source, tmp_path / "q", target_id="t", target_name="T", reason="")
        assert entry is not None
        assert restore(entry.stored) is not None
        assert source.exists()
        assert source.read_bytes() == b"payload"

    def test_entries_lists_what_is_stored(self, tmp_path: Path) -> None:
        folder = tmp_path / "q"
        for name in ("a.exe", "b.exe"):
            path = tmp_path / name
            path.write_bytes(b"x")
            quarantine(path, folder, target_id="t", target_name="T", reason="")
        assert len(entries(folder)) == 2

    def test_missing_source_is_reported_not_raised(self, tmp_path: Path) -> None:
        assert (
            quarantine(
                tmp_path / "нет.exe", tmp_path / "q", target_id="", target_name="", reason=""
            )
            is None
        )

    def test_name_collision_does_not_overwrite(self, tmp_path: Path) -> None:
        folder = tmp_path / "q"
        stored = []
        for _ in range(2):
            source = tmp_path / "same.exe"
            source.write_bytes(b"x")
            entry = quarantine(source, folder, target_id="t", target_name="T", reason="")
            assert entry is not None
            stored.append(entry.stored)
        assert stored[0] != stored[1]
        assert all(p.exists() for p in stored)
