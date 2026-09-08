"""Карантин установщиков.

Найденный установщик не удаляется. Правило может ошибиться, а удаление —
единственное действие программы, которое нельзя отменить. Файл переносится
в закрытую папку, теряет расширение (двойной щелчок по нему больше ничего не
запустит) и сопровождается запиской: что это было, когда и почему.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass(frozen=True, slots=True)
class QuarantineEntry:
    stored: Path
    original: str
    target_id: str
    target_name: str
    reason: str
    at: str

    @property
    def note(self) -> Path:
        return self.stored.with_suffix(".json")


def _unique(path: Path) -> Path:
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    for index in range(1, 1000):
        candidate = path.with_name(f"{stem}-{index}{suffix}")
        if not candidate.exists():
            return candidate
    return path.with_name(f"{stem}-{datetime.now(UTC):%Y%m%d%H%M%S}{suffix}")


def quarantine(
    source: Path, folder: Path, *, target_id: str, target_name: str, reason: str
) -> QuarantineEntry | None:
    """Перенести файл в карантин. `None` — если перенести не удалось."""
    try:
        folder.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        # Расширение заменяется целиком: файл в карантине не должен уметь
        # запускаться ни двойным щелчком, ни по ассоциации.
        stored = _unique(folder / f"{stamp}-{source.name}.blocked")
        shutil.move(str(source), str(stored))
        entry = QuarantineEntry(
            stored=stored,
            original=str(source),
            target_id=target_id,
            target_name=target_name,
            reason=reason,
            at=datetime.now(UTC).isoformat(timespec="seconds"),
        )
        stored.with_suffix(".json").write_text(
            json.dumps(
                {
                    "original": entry.original,
                    "target_id": entry.target_id,
                    "target_name": entry.target_name,
                    "reason": entry.reason,
                    "at": entry.at,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        return entry
    except (OSError, shutil.Error):
        return None


def restore(stored: Path) -> str | None:
    """Вернуть файл на место. Возвращает путь или `None`, если не вышло."""
    note = stored.with_suffix(".json")
    try:
        data = json.loads(note.read_text(encoding="utf-8"))
        original = Path(str(data["original"]))
        original.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(stored), str(_unique(original)))
        note.unlink(missing_ok=True)
        return str(original)
    except (OSError, json.JSONDecodeError, KeyError, shutil.Error):
        return None


def entries(folder: Path) -> list[QuarantineEntry]:
    out: list[QuarantineEntry] = []
    if not folder.is_dir():
        return out
    for stored in sorted(folder.glob("*.blocked"), reverse=True):
        note = stored.with_suffix(".json")
        try:
            data = json.loads(note.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        out.append(
            QuarantineEntry(
                stored=stored,
                original=str(data.get("original", "")),
                target_id=str(data.get("target_id", "")),
                target_name=str(data.get("target_name", "")),
                reason=str(data.get("reason", "")),
                at=str(data.get("at", "")),
            )
        )
    return out
