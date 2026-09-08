"""Замок «работает только один».

После установки наблюдение ведёт задание, которое запускает система при
старте машины. Окно при этом тоже умеет наблюдать — и если оба возьмутся за
дело, каждая заблокированная программа получит по две записи в журнале, два
запроса на снятие и двойную работу впустую.

Замок решает это без переговоров между процессами: кто первый взял файл, тот
и наблюдает. Взятый замок держится файловым дескриптором и снимается
операционной системой, даже если процесс сняли без предупреждения, — поэтому
после падения он не остаётся «занятым», как случилось бы с обычным файлом-
признаком.
"""

from __future__ import annotations

import contextlib
import os
import sys
from pathlib import Path
from types import TracebackType


class SingleInstance:
    """Замок на файле. Освобождается при выходе — в том числе аварийном."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._fd: int | None = None

    def acquire(self) -> bool:
        """Занять замок. Ложь означает, что его уже держит кто-то другой."""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o644)
        except OSError:
            # Замок недоступен — не повод отказываться от наблюдения.
            # Хуже двойной работы только её отсутствие.
            return True
        try:
            _lock(fd)
        except OSError:
            os.close(fd)
            return False
        self._fd = fd
        with contextlib.suppress(OSError):
            os.write(fd, f"{os.getpid()}\n".encode())
        return True

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        with contextlib.suppress(OSError):
            _unlock(fd)
        with contextlib.suppress(OSError):
            os.close(fd)

    @property
    def held(self) -> bool:
        return self._fd is not None

    def __enter__(self) -> bool:
        return self.acquire()

    def __exit__(
        self,
        kind: type[BaseException] | None,
        value: BaseException | None,
        trace: TracebackType | None,
    ) -> None:
        self.release()


if sys.platform == "win32":  # pragma: no cover - проверяется на Windows

    def _lock(fd: int) -> None:
        import msvcrt

        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

    def _unlock(fd: int) -> None:
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

else:

    def _lock(fd: int) -> None:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(fd: int) -> None:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_UN)
