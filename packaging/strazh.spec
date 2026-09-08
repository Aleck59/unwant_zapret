# -*- mode: python ; coding: utf-8 -*-
"""Сборка трёх самостоятельных файлов.

Их три, а не один, из-за устройства Windows.

* `Strazh.exe` — окно. Собирается без консоли, иначе за окном всегда висел бы
  чёрный прямоугольник. У программы без консоли нет потока вывода, поэтому
  командная строка в неё не помещается.
* `strazh-cli.exe` — та же программа для командной строки, с консолью. Ей
  повышение прав не запрашивается: `status` и `check` должны работать без
  окна контроля учётных записей.
* `strazh-deny.exe` — обработчик заблокированного запуска. Запускается вместо
  каждой остановленной программы, поэтому собран отдельно и остаётся мелким.
"""

import sys
from pathlib import Path

ROOT = Path(SPECPATH).parent
sys.path.insert(0, str(ROOT / "src"))

CATALOG = [
    (str(p), "strazh/data/catalog") for p in (ROOT / "src/strazh/data/catalog").glob("*.json")
]
EXCLUDES = ["pytest", "mypy", "ruff", "numpy", "PIL", "test", "unittest", "pydoc_data"]
VERSION = str(ROOT / "packaging" / "version_info.txt")


def build(script, name, *, console, uac, datas=(), excludes=EXCLUDES, version=None):
    analysis = Analysis(
        [str(ROOT / script)],
        pathex=[str(ROOT / "src")],
        datas=list(datas),
        excludes=excludes,
        noarchive=False,
    )
    return EXE(
        PYZ(analysis.pure),
        analysis.scripts,
        analysis.binaries,
        analysis.datas,
        [],
        name=name,
        console=console,
        uac_admin=uac,
        upx=False,
        version=version,
    )


# Перехват запуска правит общую ветку реестра — это главный слой защиты.
# Просить повышение прав сразу честнее, чем молча применить половину правил.
gui = build(
    "src/strazh/gui/app.py", "Strazh", console=False, uac=True, datas=CATALOG, version=VERSION
)

cli = build(
    "src/strazh/__main__.py", "strazh-cli", console=True, uac=False, datas=CATALOG, version=VERSION
)

# Обработчику окно рисовать нечем и незачем: он показывает одно системное
# сообщение. tkinter исключён — это половина веса сборки.
deny = build(
    "packaging/deny_stub.py",
    "strazh-deny",
    console=False,
    uac=False,
    excludes=[*EXCLUDES, "tkinter"],
)
