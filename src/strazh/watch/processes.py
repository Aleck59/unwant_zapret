"""Наблюдатель за запуском процессов.

Слой, который ловит то, что не поймали остальные: файл, переименованный
перед запуском. Ключ реестра привязан к имени, правило по пути — к месту, а
здесь проверяется уже созданный процесс — со всеми признаками сразу, включая
исходное имя из ресурса версии и подпись издателя.

Наблюдатель ждёт события, а не опрашивает систему. Разница не в изяществе:
опрос стоит процентов процессора круглые сутки и узнаёт о запуске в среднем
через полсекунды, а подписка в простое не стоит ничего и срабатывает через
миллисекунды — нежелательная программа не успевает показать окно. Как
устроена подписка, описано в `procevents.py`; если она не поднялась, тот же
модуль отдаёт запасной опрос, и наблюдатель об этом даже не знает.
"""

from __future__ import annotations

import queue
import threading
from collections.abc import Callable
from dataclasses import dataclass

from strazh.app import Strazh
from strazh.core.journal import Event, EventKind
from strazh.core.models import FileFacts, Verdict
from strazh.watch.procevents import EventSource, PollingSource, ProcessEvent, WmiEventSource

SAFETY_SWEEP_SECONDS = 300.0
"""Раз в несколько минут — полная выборка на случай пропущенного события.
Это страховка, а не рабочий режим: пять минут между проходами не создают
заметной нагрузки, но не дают пропущенному запуску остаться незамеченным
навсегда."""

CACHE_LIMIT = 4096


@dataclass(slots=True)
class Blocked:
    facts: FileFacts
    verdict: Verdict
    terminated: bool


class ProcessWatcher:
    """Фоновый поток, который снимает запрещённые процессы."""

    def __init__(
        self,
        core: Strazh,
        *,
        on_block: Callable[[Blocked], None] | None = None,
        safety_sweep: float = SAFETY_SWEEP_SECONDS,
    ) -> None:
        self._core = core
        self._on_block = on_block
        self._safety_sweep = safety_sweep
        self._queue: queue.Queue[ProcessEvent] = queue.Queue(maxsize=4096)
        self._source: EventSource | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        # Что уже проверяли: путь → можно ли. Разбор ресурса версии стоит
        # дороже всего остального, и повторять его для того же файла незачем.
        self._seen: dict[str, bool] = {}
        self.blocked_count = 0

    # ── управление ────────────────────────────────────────────────────────────

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._source = self._open_source()
        self._thread = threading.Thread(target=self._loop, name="strazh-procwatch", daemon=True)
        self._thread.start()

    def _open_source(self) -> EventSource:
        """Подписка, если получилось; опрос, если нет."""
        events = WmiEventSource(self._queue)
        if events.start():
            self._core.log(
                Event(
                    kind=EventKind.PROTECTION_ON,
                    message="наблюдение за запуском: подписка на события Windows",
                )
            )
            return events
        polling = PollingSource(self._queue, self._core.enforcer.process_list)
        polling.start()
        self._core.log(
            Event(
                kind=EventKind.ERROR,
                message=(
                    "подписка на события Windows не поднялась — наблюдение перешло на опрос "
                    "списка процессов; он медленнее и заметнее для процессора"
                ),
            )
        )
        return polling

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._source is not None:
            self._source.stop()
            self._source = None
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def source_title(self) -> str:
        return self._source.title if self._source is not None else "не запущено"

    def forget_cache(self) -> None:
        """Сбросить память о проверенных образах — после правки каталога."""
        self._seen.clear()

    # ── работа ────────────────────────────────────────────────────────────────

    def _loop(self) -> None:
        """Ожидание события. В простое поток стоит здесь и не потребляет ничего."""
        while not self._stop.is_set():
            try:
                event = self._queue.get(timeout=self._safety_sweep)
            except queue.Empty:
                # Событий давно не было: делаем страховочный проход и
                # заодно проверяем, жив ли источник.
                self._guard_source()
                self._guarded(self.sweep)
                continue
            self._guarded(self.inspect, event.pid, event.name)

    def _guarded(self, action: Callable[..., object], *args: object) -> None:
        """Ошибка в разборе одного запуска не должна уносить весь поток."""
        try:
            action(*args)
        except Exception as exc:
            self._core.log(Event(kind=EventKind.ERROR, message=f"наблюдатель за процессами: {exc}"))

    def _guard_source(self) -> None:
        """Источник мог умереть — например, PowerShell сняли извне."""
        if self._source is not None and not self._source.alive:
            self._source.stop()
            self._source = self._open_source()

    def inspect(self, pid: int, name: str) -> Blocked | None:
        """Разобрать один запуск и, если он запрещён, снять процесс."""
        enforcer = self._core.enforcer
        path = enforcer.path_of(pid)

        key = (path or name).casefold()
        if self._seen.get(key) is True:
            return None

        if path:
            probe = enforcer.facts_for_path(path, with_signature=False)
            facts = FileFacts(
                image_name=name,
                image_path=path,
                original_filename=probe.original_filename,
                product_name=probe.product_name,
                company_name=probe.company_name,
                pid=pid,
            )
        else:
            facts = FileFacts(image_name=name, pid=pid)

        matcher = self._core.matcher
        verdict = matcher.evaluate(facts)
        if verdict.allowed and path and matcher.targets:
            # Дешёвые признаки молчат — разбираем подпись. Она дороже всего
            # остального вместе взятого, поэтому только здесь и только один
            # раз на образ.
            verdict = self._recheck_with_signature(facts, verdict)

        if verdict.allowed:
            if len(self._seen) < CACHE_LIMIT:
                self._seen[key] = True
            return None

        self._seen[key] = False
        terminated = enforcer.terminate(pid) if pid else False
        blocked = Blocked(facts=facts, verdict=verdict, terminated=terminated)
        self.blocked_count += 1
        self._core.log(
            Event(
                kind=EventKind.BLOCKED_PROCESS,
                message=(
                    f"{'остановлен' if terminated else 'обнаружен'} процесс "
                    f"{facts.image_name}: {verdict.reason}"
                ),
                target_id=verdict.target_id or "",
                target_name=verdict.target_name or "",
                detail={"path": path or "", "pid": pid, "terminated": terminated},
            )
        )
        if self._on_block is not None:
            self._on_block(blocked)
        return blocked

    def sweep(self) -> list[Blocked]:
        """Полный проход по списку процессов.

        Используется как страховка от пропущенного события и проверкой машины
        из окна. В рабочем режиме наблюдатель им не пользуется.
        """
        out: list[Blocked] = []
        for pid, name, _ in self._core.enforcer.process_list():
            blocked = self.inspect(pid, name)
            if blocked is not None:
                out.append(blocked)
        return out

    def _recheck_with_signature(self, facts: FileFacts, verdict: Verdict) -> Verdict:
        if facts.image_path is None:
            return verdict
        from strazh.enforce.windows.peinfo import signature_subject

        publisher = signature_subject(facts.image_path)
        if not publisher:
            return verdict
        enriched = FileFacts(
            image_name=facts.image_name,
            image_path=facts.image_path,
            original_filename=facts.original_filename,
            product_name=facts.product_name,
            company_name=facts.company_name,
            publisher=publisher,
            pid=facts.pid,
        )
        return self._core.matcher.evaluate(enriched)
