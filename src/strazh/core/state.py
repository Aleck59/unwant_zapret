"""Что именно программа изменила в системе.

Единственный смысл файла — уметь всё вернуть назад. Правило брандмауэра,
ключ реестра, строка в hosts, отключённая служба: каждое изменение
записывается сюда до того, как будет применено, и снимается отсюда после
отката. Поэтому «Отключить защиту» — это не «попробовать угадать, что мы
натворили», а точный список.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(slots=True, frozen=True)
class Change:
    """Одно обратимое изменение системы."""

    mechanism: str
    """Кто его сделал: `ifeo`, `srp`, `firewall`, `hosts`, `service`, `task`."""

    key: str
    """Чем изменение опознаётся при откате: имя файла, GUID правила, адрес."""

    target_id: str = ""
    previous: str | None = None
    """Прежнее значение, если его затёрли. `None` — значения не было вовсе."""

    at: str = field(default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds"))

    def ident(self) -> tuple[str, str]:
        return (self.mechanism, self.key.casefold())


@dataclass(slots=True)
class State:
    """Снимок применённого. Хранится одним файлом рядом с каталогом."""

    protection_on: bool = False
    applied_at: str = ""
    changes: list[Change] = field(default_factory=list)

    def add(self, change: Change) -> None:
        ident = change.ident()
        self.changes = [c for c in self.changes if c.ident() != ident]
        self.changes.append(change)

    def remove(self, mechanism: str, key: str) -> None:
        ident = (mechanism, key.casefold())
        self.changes = [c for c in self.changes if c.ident() != ident]

    def by_mechanism(self, mechanism: str) -> list[Change]:
        return [c for c in self.changes if c.mechanism == mechanism]

    def to_json(self) -> dict[str, Any]:
        return {
            "protection_on": self.protection_on,
            "applied_at": self.applied_at,
            "changes": [asdict(c) for c in self.changes],
        }

    @staticmethod
    def from_json(raw: dict[str, Any]) -> State:
        changes = []
        for item in raw.get("changes") or []:
            if not isinstance(item, dict):
                continue
            try:
                changes.append(
                    Change(
                        mechanism=str(item["mechanism"]),
                        key=str(item["key"]),
                        target_id=str(item.get("target_id", "")),
                        previous=item.get("previous"),
                        at=str(item.get("at", "")),
                    )
                )
            except KeyError:
                continue
        return State(
            protection_on=bool(raw.get("protection_on", False)),
            applied_at=str(raw.get("applied_at", "")),
            changes=changes,
        )


def load_state(path: Path) -> State:
    try:
        return State.from_json(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, TypeError):
        return State()


def save_state(path: Path, state: State) -> None:
    """Запись через временный файл: обрыв питания посреди сохранения не должен
    оставлять программу без списка того, что она изменила."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        json.dumps(state.to_json(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    tmp.replace(path)
