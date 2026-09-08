"""Наблюдатель за папками загрузок.

Запрет установки начинается раньше запуска: установщик сначала попадает на
диск. Наблюдатель смотрит за папками, куда его кладут, и проверяет каждый
новый исполняемый файл — по имени, по исходному имени в ресурсе версии, по
издателю и по контрольной сумме. Совпавший файл уезжает в карантин, то есть
двойной щелчок по нему уже ничего не запустит.

Опрос выбран сознательно: подписка на изменения каталога через
`ReadDirectoryChangesW` тянет отдельный поток на каждую папку и теряет
события при быстрой записи, а разница в пару секунд здесь не важна —
установщик всё равно сначала скачивается целиком.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from strazh import paths
from strazh.app import Strazh
from strazh.core.journal import Event, EventKind
from strazh.core.models import Action, FileFacts, Verdict
from strazh.core.quarantine import quarantine

INTERVAL = 5.0
SUFFIXES = {".exe", ".msi", ".com", ".scr", ".bat", ".cmd", ".ps1"}
# Ограничения на число просмотренных записей здесь нет намеренно. Оно
# напрашивается — во временной папке бывают десятки тысяч файлов, — но
# перечисление всегда начинается сначала, поэтому всё за пределом предела
# не «досматривалось бы следующим проходом», а не просматривалось никогда.
# Замер: обход 50 000 записей через os.scandir занимает около 22 мс, то есть
# меньше половины процента при проходе раз в пять секунд. Платить полнотой
# за такую экономию не за что.
SETTLE_SECONDS = 2.0
"""Файл, который прямо сейчас пишут, трогать нельзя: браузер ещё не закончил
скачивание. Ждём, пока размер перестанет меняться."""


@dataclass(slots=True)
class Caught:
    path: Path
    facts: FileFacts
    verdict: Verdict
    quarantined: str | None


def default_dirs() -> list[Path]:
    """Куда обычно попадают установщики."""
    found: list[Path] = []
    home = Path.home()
    for name in ("Downloads", "Загрузки", "Desktop", "Рабочий стол"):
        candidate = home / name
        if candidate.is_dir():
            found.append(candidate)
    temp = os.environ.get("TEMP") or os.environ.get("TMP")
    if temp and Path(temp).is_dir():
        found.append(Path(temp))
    # Загрузки остальных учётных записей: установщик мог скачать не тот, кто
    # сейчас за машиной.
    # Фоновое наблюдение работает от имени системы, и её собственные
    # «загрузки» и «временные» — не те, куда попадают установщики. Поэтому
    # папки берутся у всех учётных записей, а не только у текущей.
    users = Path(os.environ.get("SystemDrive", "C:") + "\\Users")
    if users.is_dir():
        try:
            for profile in users.iterdir():
                for tail in ("Downloads", "Загрузки", "Desktop", "AppData/Local/Temp"):
                    candidate = profile.joinpath(*tail.split("/"))
                    if candidate.is_dir() and candidate not in found:
                        found.append(candidate)
        except OSError:
            pass
    return found


class DownloadWatcher:
    def __init__(
        self,
        core: Strazh,
        *,
        interval: float = INTERVAL,
        on_catch: Callable[[Caught], None] | None = None,
    ) -> None:
        self._core = core
        self._interval = interval
        self._on_catch = on_catch
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._checked: dict[str, float] = {}
        self.caught_count = 0

    def dirs(self) -> list[Path]:
        configured = [Path(p) for p in self._core.settings.watch_dirs if p.strip()]
        return configured or default_dirs()

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="strazh-dlwatch", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 3.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.sweep()
            except Exception as exc:
                self._core.log(
                    Event(kind=EventKind.ERROR, message=f"наблюдатель за загрузками: {exc}")
                )
            self._stop.wait(self._interval)

    def sweep(self) -> list[Caught]:
        out: list[Caught] = []
        for folder in self.dirs():
            for path in self._candidates(folder):
                caught = self.check(path)
                if caught is not None:
                    out.append(caught)
        return out

    def _candidates(self, folder: Path) -> list[Path]:
        """Что в папке появилось нового.

        Через `os.scandir`, а не через перечисление с последующим опросом
        каждого файла. На Windows сведения о размере и времени приходят
        вместе со списком, и отдельный запрос к диску на каждый файл не
        нужен. Разница решает: во временной папке бывают тысячи файлов, а
        обход идёт круглые сутки.

        Сокращения «папка не менялась — не читаем» здесь нет намеренно. Оно
        напрашивается и стоило бы одного обращения вместо всего обхода, но на
        Windows отметка времени папки после появления в ней файла меняется не
        сразу. Наблюдатель, который экономит проход ценой пропущенного
        установщика, не нужен вовсе.
        """
        out: list[Path] = []
        now = time.time()
        try:
            with os.scandir(folder) as entries:
                for entry in entries:
                    name = entry.name
                    dot = name.rfind(".")
                    if dot < 0 or name[dot:].casefold() not in SUFFIXES:
                        continue
                    try:
                        stat = entry.stat()
                    except OSError:
                        continue
                    if not entry.is_file():
                        continue
                    if now - stat.st_mtime < SETTLE_SECONDS:
                        continue
                    key = entry.path.casefold()
                    if self._checked.get(key) == stat.st_mtime:
                        continue
                    self._checked[key] = stat.st_mtime
                    out.append(Path(entry.path))
        except OSError:
            return out
        return out

    def check(self, path: Path) -> Caught | None:
        """Проверить один файл и, если он из каталога, убрать его в карантин."""
        facts, verdict = self._core.check_file(path)
        if verdict.allowed:
            return None

        target = self._core.matcher.target_by_id(verdict.target_id or "")
        stored: str | None = None
        wants_quarantine = self._core.settings.quarantine and (
            target is None or target.has(Action.BLOCK_INSTALL) or target.has(Action.QUARANTINE)
        )
        if wants_quarantine:
            entry = quarantine(
                path,
                paths.quarantine_dir(),
                target_id=verdict.target_id or "",
                target_name=verdict.target_name or "",
                reason=verdict.reason,
            )
            stored = str(entry.stored) if entry is not None else None

        self.caught_count += 1
        self._core.log(
            Event(
                kind=EventKind.QUARANTINED if stored else EventKind.BLOCKED_INSTALLER,
                message=(
                    f"установщик {path.name} "
                    + ("убран в карантин" if stored else "опознан")
                    + f": {verdict.reason}"
                ),
                target_id=verdict.target_id or "",
                target_name=verdict.target_name or "",
                detail={"path": str(path), "quarantine": stored or ""},
            )
        )
        caught = Caught(path=path, facts=facts, verdict=verdict, quarantined=stored)
        if self._on_catch is not None:
            self._on_catch(caught)
        return caught
