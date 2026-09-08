"""Откуда страж узнаёт о запуске программы.

Опрос списка процессов — самый простой способ и самый дорогой. Раз в секунду
он поднимает список из полутора-двух сотен записей, у каждой спрашивает путь,
и делает это вечно, даже когда на машине ничего не происходит. За это платят
процентами процессора в простое, и платят всегда.

Windows умеет рассказывать о запуске сама. Событие `Win32_ProcessStartTrace`
приходит в момент создания процесса; пока ничего не запускается, никто не
тратит ничего. Разница вдвойне важна для этой программы: опрос узнаёт о
запуске в среднем через полсекунды, а событие — через миллисекунды, и
нежелательная программа не успевает показать окно.

Подписка сделана через PowerShell, а не через `pywin32`. Причина не в
удобстве: программа работает с правами системы, и лишняя зависимость в ней —
это лишний способ ей навредить. PowerShell есть в любой Windows, а нужный
здесь код умещается в двадцать строк, которые видно целиком.
"""

from __future__ import annotations

import contextlib
import queue
import subprocess
import sys
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass

_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0

READY_MARK = "#strazh-ready"
"""Метка «подписка встала». Латиницей намеренно: строка проходит через
командную строку Windows и обратно через поток вывода PowerShell, и делать
опознавательный знак заложником кодировки незачем."""
STARTUP_TIMEOUT = 20.0
"""Сколько ждать первой строки от подписки. PowerShell поднимается неспешно,
но если за это время он не отозвался — переходим на опрос, а не ждём дальше."""


@dataclass(frozen=True, slots=True)
class ProcessEvent:
    pid: int
    name: str


# Первый запрос — событие ядра о создании процесса: приходит мгновенно и
# ничего не стоит, но требует прав администратора. Второй — запасной, он
# работает и без повышения, но внутри опрашивает WMI раз в секунду, то есть
# возвращает часть той же платы. Выбирается первый, который заработал.
_WATCHER_SCRIPT = """
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# $isTrace передаётся явно, а не выясняется по свойствам события. У двух
# запросов разная форма ответа, и «попробовать одно свойство, если нет —
# другое» здесь не работает: обращение к отсутствующему свойству объекта WMI
# в PowerShell не возвращает пустоту, а бросает исключение.
function Start-Watch($queryText, $isTrace) {
    $query = New-Object System.Management.WqlEventQuery $queryText
    $watcher = New-Object System.Management.ManagementEventWatcher $query
    $watcher.Start()
    [Console]::Out.WriteLine('@READY@')
    [Console]::Out.Flush()
    while ($true) {
        $item = $watcher.WaitForNextEvent()
        if ($isTrace) {
            $id = $item.ProcessID
            $label = $item.ProcessName
        } else {
            $target = $item.TargetInstance
            $id = $target.ProcessId
            $label = $target.Name
        }
        if ($id -and $label) {
            [Console]::Out.WriteLine("$id`t$label")
            [Console]::Out.Flush()
        }
    }
}

$fallback = "SELECT * FROM __InstanceCreationEvent WITHIN 1 " +
            "WHERE TargetInstance ISA 'Win32_Process'"

try {
    Start-Watch 'SELECT * FROM Win32_ProcessStartTrace' $true
} catch {
    Start-Watch $fallback $false
}
""".replace("@READY@", READY_MARK)


class EventSource(ABC):
    """Источник сообщений о запуске процессов."""

    title = ""

    @abstractmethod
    def start(self) -> bool:
        """Запуститься. Ложь означает «не вышло, берите следующий»."""

    @abstractmethod
    def stop(self) -> None: ...

    @property
    @abstractmethod
    def alive(self) -> bool: ...


class WmiEventSource(EventSource):
    """Подписка на событие Windows о создании процесса.

    В простое не стоит ничего: поток стоит на чтении строки, PowerShell — на
    ожидании события. Ни одного пробуждения, пока на машине ничего не
    запускают.
    """

    title = "события Windows"

    def __init__(self, sink: queue.Queue[ProcessEvent]) -> None:
        self._sink = sink
        self.dropped = 0
        self._process: subprocess.Popen[str] | None = None
        self._reader: threading.Thread | None = None
        self._ready = threading.Event()
        self._stopping = False

    def start(self) -> bool:
        if sys.platform != "win32":
            return False
        try:
            self._process = subprocess.Popen(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    _WATCHER_SCRIPT,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=_NO_WINDOW,
            )
        except (OSError, subprocess.SubprocessError):
            return False

        self._reader = threading.Thread(target=self._read, name="strazh-procevents", daemon=True)
        self._reader.start()
        # Ждём подтверждения, что подписка встала. Без него мы бы считали
        # источник рабочим, а он мог упасть на правах и молчать вечно.
        if not self._ready.wait(STARTUP_TIMEOUT):
            self.stop()
            return False
        return True

    def _read(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            return
        for line in process.stdout:  # блокирующее чтение: в простое — ноль
            line = line.strip()
            if not line:
                continue
            if line == READY_MARK:
                self._ready.set()
                continue
            pid_text, _, name = line.partition("\t")
            try:
                pid = int(pid_text)
            except ValueError:
                continue
            if name:
                # Складываем без ожидания. Полная очередь означает, что на
                # машине разом запустились тысячи процессов — сборка, установка
                # обновлений. Ждать здесь нельзя: поток чтения встанет, труба
                # от PowerShell забьётся, и мы потеряем не часть событий, а
                # все следующие. Пропущенное подберёт страховочная выборка.
                try:
                    self._sink.put_nowait(ProcessEvent(pid=pid, name=name))
                except queue.Full:
                    self.dropped += 1
        # Поток вывода закончился — значит, PowerShell завершился.
        self._ready.set()

    def stop(self) -> None:
        self._stopping = True
        process, self._process = self._process, None
        if process is not None:
            with contextlib.suppress(OSError):
                process.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired, OSError):
                process.wait(timeout=5)

    @property
    def alive(self) -> bool:
        return self._process is not None and self._process.poll() is None


class PollingSource(EventSource):
    """Запасной источник: тот же опрос списка процессов, но пореже.

    Нужен там, где подписка не поднялась: без прав администратора, на
    урезанной сборке Windows, при выключенной службе WMI. Работает хуже —
    и именно поэтому он запасной, а не основной.
    """

    title = "опрос списка процессов"

    def __init__(
        self,
        sink: queue.Queue[ProcessEvent],
        lister: Callable[[], list[tuple[int, str, str | None]]],
        interval: float = 2.0,
    ) -> None:
        self._sink = sink
        self._lister = lister
        self._interval = interval
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._known: set[int] = set()

    def start(self) -> bool:
        self._stop.clear()
        self._known = {pid for pid, _, _ in self._lister()}
        self._thread = threading.Thread(target=self._loop, name="strazh-procpoll", daemon=True)
        self._thread.start()
        return True

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                current: set[int] = set()
                for pid, name, _ in self._lister():
                    current.add(pid)
                    if pid not in self._known:
                        with contextlib.suppress(queue.Full):
                            self._sink.put_nowait(ProcessEvent(pid=pid, name=name))
                self._known = current
            except Exception:
                time.sleep(self._interval)
            self._stop.wait(self._interval)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None

    @property
    def alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
