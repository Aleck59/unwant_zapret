"""Проверки наблюдателей.

Наблюдатель за загрузками проверяется целиком: положили файл в папку —
он уехал в карантин. Наблюдатель за процессами — на подставном списке
процессов: настоящий требует Windows, а решение «снимать или нет»
принимается тем же кодом.
"""

from __future__ import annotations

from pathlib import Path

from strazh.app import Strazh
from strazh.core.models import FileFacts
from strazh.enforce.dryrun import DryRunEnforcer
from strazh.watch.downloads import DownloadWatcher
from strazh.watch.processes import ProcessWatcher


class FakeEnforcer(DryRunEnforcer):
    """Распорядитель, который делает вид, что снимает процессы."""

    def __init__(self, processes: list[FileFacts]) -> None:
        super().__init__(processes)
        self.terminated: list[int] = []
        self.parsed = 0

    def terminate(self, pid: int) -> bool:
        self.terminated.append(pid)
        return True

    def facts_for_path(
        self, path: str, *, with_hash: bool = False, with_signature: bool = True
    ) -> FileFacts:
        self.parsed += 1
        return super().facts_for_path(path, with_hash=with_hash, with_signature=with_signature)


class TestDownloadWatcher:
    def test_known_installer_goes_to_quarantine(self, core: Strazh, tmp_path: Path) -> None:
        downloads = tmp_path / "downloads"
        downloads.mkdir()
        installer = downloads / "360TS_Setup_Mini.exe"
        installer.write_bytes(b"MZ")

        core.settings.watch_dirs = [str(downloads)]
        watcher = DownloadWatcher(core)
        caught = watcher.check(installer)

        assert caught is not None
        assert caught.verdict.target_id == "qihoo-360"
        assert caught.quarantined is not None
        assert not installer.exists()

    def test_ordinary_file_is_left_alone(self, core: Strazh, tmp_path: Path) -> None:
        ordinary = tmp_path / "my-report.exe"
        ordinary.write_bytes(b"MZ")
        assert DownloadWatcher(core).check(ordinary) is None
        assert ordinary.exists()

    def test_quarantine_can_be_switched_off(self, core: Strazh, tmp_path: Path) -> None:
        installer = tmp_path / "360TS_Setup_Mini.exe"
        installer.write_bytes(b"MZ")
        core.settings.quarantine = False

        caught = DownloadWatcher(core).check(installer)
        assert caught is not None
        assert caught.quarantined is None
        assert installer.exists(), "файл должен остаться на месте"

    def test_sweep_ignores_files_that_are_still_being_written(
        self, core: Strazh, tmp_path: Path
    ) -> None:
        downloads = tmp_path / "downloads"
        downloads.mkdir()
        (downloads / "360TS_Setup_Mini.exe").write_bytes(b"MZ")
        core.settings.watch_dirs = [str(downloads)]

        # Файл только что создан — наблюдатель обязан подождать, пока запись
        # закончится, иначе он утащит недокачанный установщик.
        assert DownloadWatcher(core).sweep() == []

    def test_sweep_catches_settled_file(self, core: Strazh, tmp_path: Path) -> None:
        import os
        import time

        downloads = tmp_path / "downloads"
        downloads.mkdir()
        installer = downloads / "360TS_Setup_Mini.exe"
        installer.write_bytes(b"MZ")
        old = time.time() - 60
        os.utime(installer, (old, old))

        core.settings.watch_dirs = [str(downloads)]
        caught = DownloadWatcher(core).sweep()
        assert len(caught) == 1
        assert not installer.exists()

    def test_non_executable_files_are_ignored(self, core: Strazh, tmp_path: Path) -> None:
        import os
        import time

        downloads = tmp_path / "downloads"
        downloads.mkdir()
        document = downloads / "360TS_Setup_Mini.txt"
        document.write_text("не установщик", encoding="utf-8")
        old = time.time() - 60
        os.utime(document, (old, old))

        core.settings.watch_dirs = [str(downloads)]
        assert DownloadWatcher(core).sweep() == []
        assert document.exists()


class TestProcessWatcher:
    def test_blocked_process_is_terminated(self, home: Path) -> None:
        core = Strazh(dry_run=True)
        enforcer = FakeEnforcer(
            [
                FileFacts(image_name="explorer.exe", pid=1),
                FileFacts(image_name="360tray.exe", pid=42),
            ]
        )
        core.enforcer = enforcer

        blocked = ProcessWatcher(core).sweep()
        assert [b.facts.pid for b in blocked] == [42]
        assert enforcer.terminated == [42]

    def test_renamed_process_is_caught_by_original_name(self, home: Path) -> None:
        """Исходное имя лежит в ресурсе версии файла, поэтому у процесса
        обязан быть путь: без него читать нечего. Так же будет и в бою."""
        core = Strazh(dry_run=True)
        enforcer = FakeEnforcer(
            [
                FileFacts(
                    image_name="not-suspicious.exe",
                    image_path="C:\\Users\\Пётр\\not-suspicious.exe",
                    original_filename="360Safe.exe",
                    pid=7,
                )
            ]
        )
        core.enforcer = enforcer
        assert ProcessWatcher(core).sweep()
        assert enforcer.terminated == [7]

    def test_expensive_parsing_happens_once_per_image(self, home: Path) -> None:
        """Наблюдатель работает постоянно, поэтому ресурс версии обязан
        читаться один раз на образ, а не каждую секунду заново."""
        core = Strazh(dry_run=True)
        enforcer = FakeEnforcer(
            [FileFacts(image_name="notepad.exe", image_path="C:\\Windows\\notepad.exe", pid=3)]
        )
        core.enforcer = enforcer
        watcher = ProcessWatcher(core)
        watcher.sweep()
        first = enforcer.parsed
        watcher._known_pids.clear()  # как будто процесс перезапустился
        watcher.sweep()
        assert enforcer.parsed == first, "образ разобран повторно"

    def test_allowed_process_is_not_rechecked(self, home: Path) -> None:
        core = Strazh(dry_run=True)
        core.enforcer = FakeEnforcer([FileFacts(image_name="notepad.exe", pid=3)])
        watcher = ProcessWatcher(core)
        assert watcher.sweep() == []
        assert watcher.sweep() == []

    def test_counter_grows(self, home: Path) -> None:
        core = Strazh(dry_run=True)
        core.enforcer = FakeEnforcer([FileFacts(image_name="360tray.exe", pid=9)])
        watcher = ProcessWatcher(core)
        watcher.sweep()
        assert watcher.blocked_count == 1
