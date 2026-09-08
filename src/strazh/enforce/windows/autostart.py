"""Запуск наблюдения вместе с системой.

Наблюдение имеет смысл только тогда, когда оно идёт всегда, а не пока
открыто окно. Поэтому фоновая часть заводится заданием планировщика: система
запускает её при старте машины, до входа кого бы то ни было, и от имени
самой системы — с правами, которых хватает и на снятие чужого процесса, и на
правку реестра.

Служба была бы правильнее по форме, но потребовала бы обёртки, отвечающей на
запросы диспетчера служб, и своего кода запуска и остановки. Задание даёт то
же самое одной командой, которую видно и можно снять привычным способом —
в планировщике заданий.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

TASK_NAME = "Strazh"
"""Имя задания. Оно же исключается из отключения службами и заданиями:
каталог не должен уметь выключить наблюдение сам."""

_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


def _run(args: list[str]) -> tuple[int, str]:
    try:
        done = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            creationflags=_NO_WINDOW,
        )
        return done.returncode, ((done.stdout or "") + (done.stderr or "")).strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, str(exc)


def watcher_command() -> str | None:
    """Чем запускать фоновое наблюдение.

    У собранной программы это `strazh-cli.exe watch` рядом с окном. При
    запуске из исходников — тот же Python с тем же модулем: разработчику
    автозапуск тоже может понадобиться, и подсовывать ему несуществующий файл
    неправильно.
    """
    if getattr(sys, "frozen", False):
        cli = Path(sys.executable).parent / "strazh-cli.exe"
        if cli.exists():
            return f'"{cli}" watch'
        return f'"{sys.executable}" watch'
    return f'"{sys.executable}" -m strazh watch'


def enabled() -> bool:
    """Заведено ли задание."""
    if sys.platform != "win32":
        return False
    code, _ = _run(["schtasks", "/Query", "/TN", TASK_NAME])
    return code == 0


def enable() -> tuple[bool, str]:
    """Завести задание. Возвращает признак успеха и пояснение для человека."""
    if sys.platform != "win32":
        return False, "автозапуск заводится только в Windows"
    command = watcher_command()
    if not command:
        return False, "не найдено, что запускать"
    code, output = _run(
        [
            "schtasks",
            "/Create",
            "/F",
            "/TN",
            TASK_NAME,
            "/TR",
            command,
            "/SC",
            "ONSTART",
            # От имени системы: наблюдению нужны права на снятие чужого
            # процесса, а входа пользователя оно ждать не должно.
            "/RU",
            "SYSTEM",
            "/RL",
            "HIGHEST",
        ]
    )
    if code != 0:
        return False, output[:200] or "планировщик отказал"
    return True, command


def disable() -> tuple[bool, str]:
    """Убрать задание и остановить то, что оно уже запустило.

    Одного удаления мало: снятое задание не трогает уже работающий процесс.
    Он продолжает наблюдать и держать свои файлы — а значит, обновление или
    удаление программы упрётся в занятый файл. Поэтому сначала «прекратить»,
    потом «удалить».
    """
    if sys.platform != "win32":
        return False, "автозапуск заводится только в Windows"
    _run(["schtasks", "/End", "/TN", TASK_NAME])
    code, output = _run(["schtasks", "/Delete", "/F", "/TN", TASK_NAME])
    # Задания нет — цель достигнута, а не провалена.
    if (
        code != 0
        and "cannot find" not in output.casefold()
        and "не найдено" not in output.casefold()
    ):
        return False, output[:200]
    return True, ""


def start_now() -> tuple[bool, str]:
    """Запустить задание, не дожидаясь перезагрузки."""
    if sys.platform != "win32":
        return False, "только в Windows"
    code, output = _run(["schtasks", "/Run", "/TN", TASK_NAME])
    return code == 0, output[:200]


def stop_now() -> tuple[bool, str]:
    if sys.platform != "win32":
        return False, "только в Windows"
    code, output = _run(["schtasks", "/End", "/TN", TASK_NAME])
    return code == 0, output[:200]
