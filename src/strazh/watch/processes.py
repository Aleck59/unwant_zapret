"""Наблюдатель за запуском процессов.

Слой, который ловит то, что не поймали остальные: файл, переименованный
перед запуском. Ключ реестра привязан к имени, правило по пути — к месту,
а здесь проверяется уже запущенный образ — со всеми признаками сразу, включая
исходное имя из ресурса версии и подпись издателя.

Опрос, а не подписка на события. Подписка через WMI быстрее, но требует
дополнительных пакетов и прав, а опрос списка процессов раз в секунду стоит
доли процента и работает везде одинаково. Долгие проверки (сумма файла,
разбор подписи) делаются один раз на образ и запоминаются.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass

from strazh.app import Strazh
from strazh.core.journal import Event, EventKind
from strazh.core.models import FileFacts, Verdict

INTERVAL = 1.0
"""Пауза между снимками. Меньше — быстрее реакция и заметнее нагрузка;
секунда выбрана как порог, ниже которого выигрыш уже не виден человеку."""

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
        interval: float = INTERVAL,
        on_block: Callable[[Blocked], None] | None = None,
    ) -> None:
        self._core = core
        self._interval = interval
        self._on_block = on_block
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        # Что уже проверяли: путь → можно ли. Иначе каждую секунду пришлось бы
        # заново разбирать ресурсы версии у полутора сотен процессов.
        self._seen: dict[str, bool] = {}
        self._known_pids: set[int] = set()
        self.blocked_count = 0

    # ── управление ────────────────────────────────────────────────────────────

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="strazh-procwatch", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 3.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def forget_cache(self) -> None:
        """Сбросить память о проверенных образах — после правки каталога."""
        self._seen.clear()

    # ── работа ────────────────────────────────────────────────────────────────

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.sweep()
            except Exception as exc:
                self._core.log(
                    Event(kind=EventKind.ERROR, message=f"наблюдатель за процессами: {exc}")
                )
            self._stop.wait(self._interval)

    def sweep(self) -> list[Blocked]:
        """Один проход по списку процессов."""
        matcher = self._core.matcher
        out: list[Blocked] = []
        current: set[int] = set()

        for facts in self._core.enforcer.running_processes():
            if facts.pid is not None:
                current.add(facts.pid)
                if facts.pid in self._known_pids:
                    # Процесс уже видели и не тронули — значит, разрешён.
                    continue

            key = (facts.image_path or facts.image_name).casefold()
            cached = self._seen.get(key)
            if cached is True:
                continue

            verdict = matcher.evaluate(facts)
            if verdict.allowed and facts.image_path and matcher.targets:
                # Дешёвые признаки молчат — разбираем подпись. Она дороже
                # всего остального вместе взятого, поэтому только здесь и
                # только один раз на образ.
                verdict = self._recheck_with_signature(facts, verdict)

            if verdict.allowed:
                if len(self._seen) < CACHE_LIMIT:
                    self._seen[key] = True
                continue

            self._seen[key] = False
            terminated = self._core.enforcer.terminate(facts.pid) if facts.pid else False
            blocked = Blocked(facts=facts, verdict=verdict, terminated=terminated)
            out.append(blocked)
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
                    detail={
                        "path": facts.image_path or "",
                        "pid": facts.pid or 0,
                        "terminated": terminated,
                    },
                )
            )
            if self._on_block is not None:
                self._on_block(blocked)

        self._known_pids = current
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
