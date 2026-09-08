"""Проверки замка «работает только один».

Замок нужен, чтобы после установки за одним и тем же не следили двое: задание,
запущенное системой, и открытое окно. Здесь проверяется, что он и правда
никого не пускает вторым — и, что важнее, что после гибели держателя он
освобождается сам.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

from strazh.core.lock import SingleInstance


def test_first_takes_it(tmp_path: Path) -> None:
    lock = SingleInstance(tmp_path / "watch.lock")
    assert lock.acquire()
    assert lock.held
    lock.release()
    assert not lock.held


def test_second_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "watch.lock"
    first = SingleInstance(path)
    second = SingleInstance(path)
    assert first.acquire()
    try:
        assert second.acquire() is False, "замок пустил второго"
    finally:
        first.release()


def test_released_lock_can_be_taken_again(tmp_path: Path) -> None:
    path = tmp_path / "watch.lock"
    first = SingleInstance(path)
    assert first.acquire()
    first.release()
    assert SingleInstance(path).acquire()


def test_context_manager(tmp_path: Path) -> None:
    path = tmp_path / "watch.lock"
    with SingleInstance(path) as taken:
        assert taken
        assert SingleInstance(path).acquire() is False
    assert SingleInstance(path).acquire()


def test_lock_dies_with_its_holder(tmp_path: Path) -> None:
    """Главное свойство: файл-признак после падения остался бы «занятым»
    навсегда, а замок операционная система снимает сама."""
    path = tmp_path / "watch.lock"
    script = textwrap.dedent(f"""
        import sys, time
        from pathlib import Path
        sys.path.insert(0, {str(Path(__file__).resolve().parent.parent / "src")!r})
        from strazh.core.lock import SingleInstance
        lock = SingleInstance(Path({str(path)!r}))
        assert lock.acquire()
        print("взял", flush=True)
        time.sleep(60)
    """)
    child = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout is not None
        assert child.stdout.readline().strip() == "взял"
        assert SingleInstance(path).acquire() is False, "замок не удержан живым процессом"
    finally:
        child.kill()
        child.wait(timeout=10)

    deadline = time.time() + 5
    taken = False
    while time.time() < deadline and not taken:
        taken = SingleInstance(path).acquire()
        if not taken:
            time.sleep(0.1)
    assert taken, "замок остался занятым после гибели держателя"


def test_unwritable_place_does_not_stop_watching(tmp_path: Path, monkeypatch) -> None:
    """Хуже двойной работы только её отсутствие: если замок не завести,
    наблюдение всё равно должно начаться."""

    def refuse(*args: object, **kwargs: object) -> int:
        raise OSError("некуда писать")

    monkeypatch.setattr(os, "open", refuse)
    assert SingleInstance(tmp_path / "watch.lock").acquire() is True
