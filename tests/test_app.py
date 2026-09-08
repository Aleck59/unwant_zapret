"""Проверки прикладного ядра: сценарии целиком, а не отдельные части."""

from __future__ import annotations

import json
from pathlib import Path

from strazh import paths
from strazh.app import Strazh
from strazh.core.models import FileFacts
from strazh.enforce.dryrun import DryRunEnforcer


class TestLifecycle:
    def test_apply_then_revert_leaves_nothing(self, core: Strazh) -> None:
        report = core.apply_protection()
        assert report.ok
        assert core.protection_on
        assert len(core.state.changes) > 100

        report = core.revert_protection()
        assert report.ok
        assert not core.protection_on
        assert core.state.changes == []

    def test_state_survives_restart(self, core: Strazh) -> None:
        core.apply_protection()
        again = Strazh(dry_run=True)
        assert again.protection_on
        assert len(again.state.changes) == len(core.state.changes)

    def test_builtin_catalog_is_loaded(self, core: Strazh) -> None:
        assert len(core.catalog.targets) >= 30
        assert not core.catalog.issues


class TestUserTargets:
    def test_quick_add_and_block(self, core: Strazh) -> None:
        target = Strazh.quick_target("Моя гадость", ["mybad.exe"])
        core.save_user_target(target)

        assert core.matcher.evaluate(FileFacts(image_name="mybad.exe")).allowed is False
        assert (paths.user_catalog_dir() / "custom.json").exists()

    def test_user_target_survives_restart(self, core: Strazh) -> None:
        core.save_user_target(Strazh.quick_target("Моя гадость", ["mybad.exe"]))
        again = Strazh(dry_run=True)
        assert not again.matcher.evaluate(FileFacts(image_name="mybad.exe")).allowed

    def test_delete_user_target(self, core: Strazh) -> None:
        target = Strazh.quick_target("Моя гадость", ["mybad.exe"])
        core.save_user_target(target)
        assert core.delete_user_target(target.id)
        assert core.matcher.evaluate(FileFacts(image_name="mybad.exe")).allowed

    def test_delete_of_builtin_target_is_refused(self, core: Strazh) -> None:
        assert core.delete_user_target("qihoo-360") is False
        assert "qihoo-360" in core.catalog.targets

    def test_disable_builtin_target(self, core: Strazh) -> None:
        assert not core.matcher.evaluate(FileFacts(image_name="360tray.exe")).allowed
        core.set_target_enabled("qihoo-360", False)
        assert core.matcher.evaluate(FileFacts(image_name="360tray.exe")).allowed

        # Выключение переживает перезапуск и хранится в настройках, а не в
        # каталоге: обновление программы его не затрёт.
        again = Strazh(dry_run=True)
        assert again.matcher.evaluate(FileFacts(image_name="360tray.exe")).allowed
        settings = json.loads(paths.settings_file().read_text(encoding="utf-8"))
        assert settings["overrides"]["qihoo-360"]["enabled"] is False


class TestScan:
    def test_scan_finds_running_target(self, home: Path) -> None:
        processes = [
            FileFacts(image_name="explorer.exe", image_path="C:\\Windows\\explorer.exe", pid=10),
            FileFacts(
                image_name="360tray.exe", image_path="C:\\Program Files\\360\\360tray.exe", pid=20
            ),
        ]
        core = Strazh(dry_run=True)
        core.enforcer = DryRunEnforcer(processes)
        result = core.scan()
        assert result.processes_seen == 2
        assert [f.verdict.target_id for f in result.findings] == ["qihoo-360"]

    def test_clean_machine(self, home: Path) -> None:
        core = Strazh(dry_run=True)
        core.enforcer = DryRunEnforcer([FileFacts(image_name="notepad.exe", pid=1)])
        assert core.scan().clean


class TestJournal:
    def test_events_are_written_and_read_back(self, core: Strazh) -> None:
        core.apply_protection()
        core.revert_protection()
        messages = [e.message for e in core.recent(10)]
        assert any("включена" in m for m in messages)
        assert any("выключена" in m for m in messages)

    def test_newest_event_comes_first(self, core: Strazh) -> None:
        core.apply_protection()
        core.revert_protection()
        assert "выключена" in core.recent(10)[0].message
