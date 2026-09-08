"""Проверки наблюдателей.

Наблюдатель за загрузками проверяется целиком: положили файл в папку —
он уехал в карантин. Наблюдатель за процессами — на подставном списке
процессов: настоящий требует Windows, а решение «снимать или нет»
принимается тем же кодом.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

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
    """Наблюдатель разбирает по одному запуску, а не перебирает список.

    Проверяется именно это: `inspect` получает номер и имя — ровно то, что
    приходит от подписки Windows, — и всё остальное добывает сам.
    """

    def test_blocked_process_is_terminated(self, home: Path) -> None:
        core = Strazh(dry_run=True)
        enforcer = FakeEnforcer(
            [
                FileFacts(image_name="explorer.exe", pid=1),
                FileFacts(image_name="360tray.exe", pid=42),
            ]
        )
        core.enforcer = enforcer

        watcher = ProcessWatcher(core)
        assert watcher.inspect(1, "explorer.exe") is None
        assert watcher.inspect(42, "360tray.exe") is not None
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
        assert ProcessWatcher(core).inspect(7, "not-suspicious.exe") is not None
        assert enforcer.terminated == [7]

    def test_allowed_process_is_not_rechecked(self, home: Path) -> None:
        core = Strazh(dry_run=True)
        core.enforcer = FakeEnforcer([FileFacts(image_name="notepad.exe", pid=3)])
        watcher = ProcessWatcher(core)
        assert watcher.inspect(3, "notepad.exe") is None
        assert watcher.inspect(3, "notepad.exe") is None

    def test_expensive_parsing_happens_once_per_image(self, home: Path) -> None:
        """Разбор ресурса версии — самое дорогое в наблюдении. Один и тот же
        образ, запущенный десять раз, обязан разбираться один раз."""
        core = Strazh(dry_run=True)
        enforcer = FakeEnforcer(
            [FileFacts(image_name="notepad.exe", image_path="C:\\Windows\\notepad.exe", pid=3)]
        )
        core.enforcer = enforcer
        watcher = ProcessWatcher(core)
        for pid in range(3, 13):
            enforcer._processes[0] = FileFacts(
                image_name="notepad.exe", image_path="C:\\Windows\\notepad.exe", pid=pid
            )
            watcher.inspect(pid, "notepad.exe")
        assert enforcer.parsed == 1, f"образ разобран {enforcer.parsed} раз вместо одного"

    def test_cache_reset_after_catalog_change(self, home: Path) -> None:
        core = Strazh(dry_run=True)
        enforcer = FakeEnforcer(
            [FileFacts(image_name="mybad.exe", image_path="C:\\mybad.exe", pid=5)]
        )
        core.enforcer = enforcer
        watcher = ProcessWatcher(core)
        assert watcher.inspect(5, "mybad.exe") is None

        core.save_user_target(Strazh.quick_target("Моя гадость", ["mybad.exe"]))
        watcher.forget_cache()
        assert watcher.inspect(5, "mybad.exe") is not None

    def test_sweep_still_walks_everything(self, home: Path) -> None:
        core = Strazh(dry_run=True)
        core.enforcer = FakeEnforcer(
            [
                FileFacts(image_name="explorer.exe", pid=1),
                FileFacts(image_name="360tray.exe", pid=42),
                FileFacts(image_name="kxetray.exe", pid=43),
            ]
        )
        assert len(ProcessWatcher(core).sweep()) == 2

    def test_counter_grows(self, home: Path) -> None:
        core = Strazh(dry_run=True)
        core.enforcer = FakeEnforcer([FileFacts(image_name="360tray.exe", pid=9)])
        watcher = ProcessWatcher(core)
        watcher.inspect(9, "360tray.exe")
        assert watcher.blocked_count == 1

    def test_missing_process_does_not_raise(self, home: Path) -> None:
        """Процесс мог завершиться между событием и разбором — обычное дело."""
        core = Strazh(dry_run=True)
        core.enforcer = FakeEnforcer([])
        assert ProcessWatcher(core).inspect(999, "360tray.exe") is not None


class TestEventSources:
    """Откуда наблюдатель берёт сообщения о запуске."""

    def test_wmi_source_declines_outside_windows(self) -> None:
        """Отказ — не ошибка: наблюдатель обязан молча перейти на опрос."""
        import queue as queue_mod

        from strazh.watch.procevents import WmiEventSource

        assert WmiEventSource(queue_mod.Queue()).start() is False

    def test_polling_source_reports_only_new_processes(self) -> None:
        import queue as queue_mod

        from strazh.watch.procevents import PollingSource

        listing = [(1, "explorer.exe", None)]
        sink: queue_mod.Queue = queue_mod.Queue()
        source = PollingSource(sink, lambda: list(listing), interval=0.05)
        assert source.start()
        try:
            listing.append((42, "360tray.exe", None))
            event = sink.get(timeout=3)
            assert (event.pid, event.name) == (42, "360tray.exe")
            # Уже виденный процесс второй раз не приходит.
            with pytest.raises(queue_mod.Empty):
                sink.get(timeout=0.3)
        finally:
            source.stop()
        assert not source.alive

    def test_watcher_falls_back_and_still_catches(self, home: Path) -> None:
        """На машине без подписки наблюдатель обязан работать — медленнее,
        но работать."""
        core = Strazh(dry_run=True)
        listing = [FileFacts(image_name="explorer.exe", pid=1)]
        core.enforcer = FakeEnforcer(listing)

        watcher = ProcessWatcher(core, safety_sweep=0.2)
        watcher.start()
        try:
            assert watcher.running
            assert watcher.source_title == "опрос списка процессов"
            listing.append(FileFacts(image_name="360tray.exe", pid=42))
            deadline = time.time() + 5
            while time.time() < deadline and watcher.blocked_count == 0:
                time.sleep(0.05)
            assert watcher.blocked_count == 1
        finally:
            watcher.stop()
        assert not watcher.running


class TestIdleCost:
    """Проверки того, что в простое программа ничего не делает.

    Числа процессора здесь не измерить, но можно проверить структуру: не
    перечитывается ли папка, в которой ничего не менялось, и не перебирает
    ли наблюдатель список процессов, когда его никто не просил.
    """

    def test_unchanged_folder_is_not_listed_again(self, core: Strazh, tmp_path: Path) -> None:
        downloads = tmp_path / "downloads"
        downloads.mkdir()
        core.settings.watch_dirs = [str(downloads)]
        watcher = DownloadWatcher(core)

        assert watcher._folder_changed(downloads) is True
        assert watcher._folder_changed(downloads) is False, "папка перечитана без причины"

        (downloads / "новый.exe").write_bytes(b"MZ")
        assert watcher._folder_changed(downloads) is True

    def test_huge_folder_is_examined_in_parts(self, core: Strazh, tmp_path: Path) -> None:
        """Во временной папке бывают десятки тысяч файлов. Один проход не
        должен превращаться в обход всего диска."""
        from strazh.watch import downloads as downloads_mod

        folder = tmp_path / "temp"
        folder.mkdir()
        for index in range(50):
            (folder / f"файл-{index}.txt").write_bytes(b"x")

        monkey = downloads_mod.MAX_ENTRIES_PER_PASS
        try:
            downloads_mod.MAX_ENTRIES_PER_PASS = 10
            core.settings.watch_dirs = [str(folder)]
            watcher = DownloadWatcher(core)
            assert watcher._candidates(folder) == []
        finally:
            downloads_mod.MAX_ENTRIES_PER_PASS = monkey

    def test_watcher_waits_instead_of_spinning(self, home: Path) -> None:
        """Поток наблюдателя обязан стоять на очереди событий, а не крутить
        цикл. Проверяем косвенно: без событий полная выборка не случается
        чаще, чем раз в страховочный срок."""
        core = Strazh(dry_run=True)
        core.enforcer = FakeEnforcer([FileFacts(image_name="explorer.exe", pid=1)])
        watcher = ProcessWatcher(core, safety_sweep=3600)
        watcher.start()
        try:
            time.sleep(0.4)
            assert core.enforcer.parsed == 0, "наблюдатель работал, хотя ничего не запускалось"
        finally:
            watcher.stop()
