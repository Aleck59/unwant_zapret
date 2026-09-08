"""Контрольные суммы файлов.

Считаются лениво: наблюдатель за процессами вызывает подсчёт только тогда,
когда все дешёвые признаки не сработали, — читать мегабайты на каждый запуск
блокнота было бы заметно.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

CHUNK = 1024 * 1024
MAX_HASHED_BYTES = 512 * 1024 * 1024
"""Файлы крупнее не хешируются: установщик такого размера — редкость, а
чтение полугигабайта посреди запуска процесса заметно всем."""


def sha256_file(path: str | Path) -> str | None:
    """Сумма файла или `None`, если файл не прочитать.

    Ошибка чтения — не исключение, а обычное дело: файл могли удалить
    между запуском процесса и попыткой его разобрать.
    """
    try:
        p = Path(path)
        if p.stat().st_size > MAX_HASHED_BYTES:
            return None
        digest = hashlib.sha256()
        with p.open("rb") as fh:
            while chunk := fh.read(CHUNK):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None
