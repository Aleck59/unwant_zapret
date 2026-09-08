"""Обработчик заблокированного запуска.

На него указывает значение «отладчика» в перехвате запуска: Windows
запускает этот файл вместо запрещённого и передаёт ему исходную строку
запуска. Задача обработчика — объяснить человеку, что произошло, и записать
событие. Он намеренно крошечный: его запускают вместо каждой заблокированной
программы, и тащить сюда весь интерфейс было бы расточительно.
"""

from __future__ import annotations

import ctypes
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

MB_OK = 0x0
MB_ICONWARNING = 0x30
MB_TOPMOST = 0x40000


def journal_path() -> Path:
    home = os.environ.get("STRAZH_HOME", "").strip()
    if home:
        return Path(home) / "journal.jsonl"
    return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Strazh" / "journal.jsonl"


def blocked_command() -> str:
    """Строка запуска, которую Windows передала вместо запуска программы."""
    return " ".join(sys.argv[1:]).strip()


def note(command: str) -> None:
    try:
        path = journal_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(
                json.dumps(
                    {
                        "kind": "blocked_process",
                        "message": f"перехват запуска: {command or 'неизвестная программа'}",
                        "target_id": "",
                        "target_name": "",
                        "detail": {"command": command, "by": "ifeo"},
                        "at": datetime.now(UTC).isoformat(timespec="seconds"),
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
    except OSError:
        # Журнал недоступен — сообщение человеку всё равно важнее.
        pass


def main() -> int:
    command = blocked_command()
    name = Path(command.split('"')[1] if command.startswith('"') else command.split(" ")[0]).name
    note(command)
    try:
        ctypes.windll.user32.MessageBoxW(  # type: ignore[attr-defined]
            None,
            f"Запуск программы «{name or 'неизвестно'}» остановлен.\n\n"
            "Она есть в каталоге нежелательного ПО. Если это ошибка, откройте «Страж» "
            "и выключите соответствующую запись или добавьте файл в исключения.",
            "Страж",
            MB_OK | MB_ICONWARNING | MB_TOPMOST,
        )
    except (AttributeError, OSError):
        sys.stderr.write("Запуск остановлен программой «Страж».\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
