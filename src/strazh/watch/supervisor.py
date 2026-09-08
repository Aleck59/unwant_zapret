"""Фоновый страж: оба наблюдателя под одним выключателем."""

from __future__ import annotations

from collections.abc import Callable

from strazh import paths
from strazh.app import Strazh
from strazh.core.lock import SingleInstance
from strazh.watch.downloads import Caught, DownloadWatcher
from strazh.watch.processes import Blocked, ProcessWatcher


class Supervisor:
    """Запускает и останавливает наблюдателей согласно настройкам."""

    def __init__(
        self,
        core: Strazh,
        *,
        on_block: Callable[[Blocked], None] | None = None,
        on_catch: Callable[[Caught], None] | None = None,
    ) -> None:
        self.core = core
        self.processes = ProcessWatcher(core, on_block=on_block)
        self.downloads = DownloadWatcher(core, on_catch=on_catch)
        self._lock = SingleInstance(paths.machine_dir() / "watch.lock")
        self.deferred = False
        """Наблюдение уже ведёт кто-то другой — обычно фоновое задание."""

    def start(self) -> None:
        # Кто первый взял замок, тот и наблюдает. Иначе после установки за
        # одним и тем же следили бы двое: задание, запущенное системой, и
        # окно — с двойными записями в журнале и двойной работой впустую.
        if not self._lock.acquire():
            self.deferred = True
            return
        self.deferred = False
        if self.core.settings.mechanisms.process_watch:
            self.processes.start()
        if self.core.settings.mechanisms.download_watch:
            self.downloads.start()

    def stop(self) -> None:
        self.processes.stop()
        self.downloads.stop()
        self._lock.release()

    def restart(self) -> None:
        self.stop()
        self.processes.forget_cache()
        self.start()

    @property
    def running(self) -> bool:
        return self.processes.running or self.downloads.running

    @property
    def source_title(self) -> str:
        """Чем ловится запуск: подпиской на события, опросом или никем."""
        if self.deferred:
            return "фоновое наблюдение уже работает"
        return self.processes.source_title

    @property
    def stats(self) -> dict[str, int]:
        return {
            "blocked": self.processes.blocked_count,
            "caught": self.downloads.caught_count,
        }
