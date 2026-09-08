"""Журнал событий.

Формат — JSONL: одна строка на событие. Так его можно и читать глазами, и
разбирать программой, и дописывать из двух процессов сразу (окно и служба
пишут в один файл), не рискуя испортить уже записанное.
"""

from __future__ import annotations

import contextlib
import json
import os
import threading
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

MAX_BYTES = 4 * 1024 * 1024
"""Больше — старый файл уезжает в `.1`. Одного поколения хватает: журнал
нужен, чтобы понять «что тут только что случилось», а не для расследований."""


class EventKind(StrEnum):
    BLOCKED_PROCESS = "blocked_process"
    BLOCKED_INSTALLER = "blocked_installer"
    QUARANTINED = "quarantined"
    PROTECTION_ON = "protection_on"
    PROTECTION_OFF = "protection_off"
    RULE_APPLIED = "rule_applied"
    RULE_REVERTED = "rule_reverted"
    CATALOG_CHANGED = "catalog_changed"
    SCAN_FINDING = "scan_finding"
    ERROR = "error"


@dataclass(slots=True)
class Event:
    kind: EventKind
    message: str
    target_id: str = ""
    target_name: str = ""
    detail: dict[str, Any] = field(default_factory=dict)
    at: str = ""

    def __post_init__(self) -> None:
        if not self.at:
            self.at = datetime.now(UTC).isoformat(timespec="seconds")

    def to_json(self) -> str:
        data = asdict(self)
        data["kind"] = self.kind.value
        return json.dumps(data, ensure_ascii=False)

    @property
    def local_time(self) -> str:
        try:
            return datetime.fromisoformat(self.at).astimezone().strftime("%d.%m.%Y %H:%M:%S")
        except ValueError:
            return self.at


class Journal:
    """Дописывающий журнал с одним поколением ротации.

    Замок нужен на случай двух потоков внутри одного процесса; между
    процессами достаточно того, что запись одной строки открытием в режиме
    `a` уходит целиком.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def write(self, event: Event) -> None:
        line = event.to_json() + "\n"
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self._rotate_if_needed()
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
            except OSError:
                # Журнал — вспомогательная вещь. Если писать некуда, защита
                # всё равно должна работать: молча продолжаем.
                pass

    def _rotate_if_needed(self) -> None:
        try:
            if self.path.stat().st_size < MAX_BYTES:
                return
        except OSError:
            return
        backup = self.path.with_suffix(self.path.suffix + ".1")
        try:
            if backup.exists():
                backup.unlink()
            os.replace(self.path, backup)
        except OSError:
            pass

    def read(self, limit: int = 500) -> list[Event]:
        """Последние события, свежие сверху."""
        return list(self.iter_events(limit=limit))

    def iter_events(self, limit: int = 500) -> Iterator[Event]:
        lines: list[str] = []
        for candidate in (self.path.with_suffix(self.path.suffix + ".1"), self.path):
            try:
                lines.extend(candidate.read_text(encoding="utf-8").splitlines())
            except OSError:
                continue
        for line in reversed(lines[-limit * 2 :] if limit else lines):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
                yield Event(
                    kind=EventKind(raw.get("kind", "error")),
                    message=str(raw.get("message", "")),
                    target_id=str(raw.get("target_id", "")),
                    target_name=str(raw.get("target_name", "")),
                    detail=raw.get("detail") or {},
                    at=str(raw.get("at", "")),
                )
            except (json.JSONDecodeError, ValueError):
                continue
            limit -= 1
            if limit <= 0:
                return

    def clear(self) -> None:
        for candidate in (self.path, self.path.with_suffix(self.path.suffix + ".1")):
            with contextlib.suppress(OSError):
                candidate.unlink()
