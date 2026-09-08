"""Вывод по-русски в консоли Windows.

Консоль Windows по умолчанию работает не в UTF-8, а в кодовой странице вроде
866 или 1251. Питон честно пытается закодировать вывод в неё и падает с
`UnicodeEncodeError` на первом же слове — причём падает не в нашем коде, а
внутри argparse, когда тот печатает `--help` или `--version`, то есть до
того, как программа успела что-либо сделать.

Поэтому кодировка настраивается один раз в самом начале и сразу для всего
потока вывода: переключаем консоль на UTF-8 и заменяем непечатаемое вместо
падения. Оба действия необязательные — если что-то не вышло, программа
должна продолжить работу, а не остановиться из-за вывода.
"""

from __future__ import annotations

import contextlib
import sys

CP_UTF8 = 65001


def setup() -> None:
    """Сделать вывод по-русски безопасным. Вызывается один раз при запуске."""
    _switch_console_codepage()
    for stream in (sys.stdout, sys.stderr):
        _reconfigure(stream)


def _switch_console_codepage() -> None:
    if sys.platform != "win32":
        return
    # Программа могла быть запущена без консоли вовсе. Это не ошибка.
    with contextlib.suppress(AttributeError, OSError):
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        kernel32.SetConsoleOutputCP(CP_UTF8)
        kernel32.SetConsoleCP(CP_UTF8)


def _reconfigure(stream: object) -> None:
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is None:
        # У собранной без консоли программы потока вывода нет совсем.
        return
    with contextlib.suppress(ValueError, OSError):
        reconfigure(encoding="utf-8", errors="replace")
