"""Фоновый страж: оба наблюдателя под одним выключателем."""

from __future__ import annotations

from collections.abc import Callable

from strazh.app import Strazh
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

    def start(self) -> None:
        if self.core.settings.mechanisms.process_watch:
            self.processes.start()
        if self.core.settings.mechanisms.download_watch:
            self.downloads.start()

    def stop(self) -> None:
        self.processes.stop()
        self.downloads.stop()

    def restart(self) -> None:
        self.stop()
        self.processes.forget_cache()
        self.start()

    @property
    def running(self) -> bool:
        return self.processes.running or self.downloads.running

    @property
    def source_title(self) -> str:
        """Чем ловится запуск: подпиской на события или опросом."""
        return self.processes.source_title

    @property
    def stats(self) -> dict[str, int]:
        return {
            "blocked": self.processes.blocked_count,
            "caught": self.downloads.caught_count,
        }
