"""Формат файлов групповой политики (PReg).

`Registry.pol` — это то, во что редактор групповых политик складывает
настройки. Формат описан в [MS-GPREG] и устроен просто: заголовок `PReg`,
номер версии и дальше записи вида «ключ; имя значения; тип; длина; данные»,
разделённые квадратными скобками и точками с запятой. Всё в UTF-16.

Отдельный модуль нужен по той же причине, что и остальное ядро: разбор и
сборка файла — чистая работа с байтами, и её можно проверить на любой
машине. Ошибка здесь дороже обычной: испорченный `Registry.pol` — это
испорченная политика всей машины, и заметит это человек не сразу.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

SIGNATURE = b"PReg"
VERSION = 1

REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_MULTI_SZ = 7
REG_QWORD = 11

_OPEN = "[".encode("utf-16-le")
_CLOSE = "]".encode("utf-16-le")
_SEMI = ";".encode("utf-16-le")


class PregError(ValueError):
    """Файл политики не разобран. Читать его дальше нельзя — только заменить."""


@dataclass(frozen=True, slots=True)
class Entry:
    """Одна настройка политики."""

    key: str
    value: str
    kind: int
    data: bytes

    @staticmethod
    def dword(key: str, value: str, number: int) -> Entry:
        return Entry(key, value, REG_DWORD, struct.pack("<I", number & 0xFFFFFFFF))

    @staticmethod
    def qword(key: str, value: str, number: int) -> Entry:
        return Entry(key, value, REG_QWORD, struct.pack("<Q", number & 0xFFFFFFFFFFFFFFFF))

    @staticmethod
    def text(key: str, value: str, text: str, *, expand: bool = False) -> Entry:
        # Завершающий ноль входит в данные: без него Windows читает строку
        # до первого попавшегося нуля в соседней записи.
        return Entry(
            key,
            value,
            REG_EXPAND_SZ if expand else REG_SZ,
            (text + "\x00").encode("utf-16-le"),
        )

    def as_text(self) -> str:
        if self.kind not in (REG_SZ, REG_EXPAND_SZ):
            return ""
        return self.data.decode("utf-16-le", errors="replace").rstrip("\x00")


def _read_until(blob: bytes, start: int, stop: bytes) -> tuple[bytes, int]:
    """Прочитать до разделителя. Возвращает данные и место сразу за ним."""
    index = start
    while index + 1 < len(blob):
        if blob[index : index + 2] == stop:
            return blob[start:index], index + 2
        index += 2
    raise PregError("файл оборван: не найден разделитель")


def _read_string(blob: bytes, start: int, stop: bytes) -> tuple[str, int]:
    raw, position = _read_until(blob, start, stop)
    return raw.decode("utf-16-le", errors="replace").rstrip("\x00"), position


def loads(blob: bytes) -> list[Entry]:
    """Разобрать содержимое `Registry.pol`. Пустые байты — пустая политика."""
    if not blob:
        return []
    if len(blob) < 8 or blob[:4] != SIGNATURE:
        raise PregError("это не файл групповой политики: нет подписи PReg")
    version = struct.unpack_from("<I", blob, 4)[0]
    if version != VERSION:
        raise PregError(f"версия формата {version} не поддерживается")

    entries: list[Entry] = []
    position = 8
    while position < len(blob):
        if blob[position : position + 2] != _OPEN:
            # Хвост из выравнивающих нулей — не ошибка, просто конец.
            if blob[position:].strip(b"\x00") == b"":
                break
            raise PregError(f"ожидалась открывающая скобка в позиции {position}")
        position += 2
        key, position = _read_string(blob, position, _SEMI)
        value, position = _read_string(blob, position, _SEMI)
        raw_kind, position = _read_until(blob, position, _SEMI)
        raw_size, position = _read_until(blob, position, _SEMI)
        if len(raw_kind) < 4 or len(raw_size) < 4:
            raise PregError("повреждены поля типа или длины")
        kind = struct.unpack_from("<I", raw_kind, 0)[0]
        size = struct.unpack_from("<I", raw_size, 0)[0]
        data = blob[position : position + size]
        if len(data) != size:
            raise PregError("файл оборван на данных записи")
        position += size
        if blob[position : position + 2] != _CLOSE:
            raise PregError("не найдена закрывающая скобка записи")
        position += 2
        entries.append(Entry(key=key, value=value, kind=kind, data=data))
    return entries


def dumps(entries: list[Entry]) -> bytes:
    """Собрать `Registry.pol` из записей."""
    out = bytearray(SIGNATURE + struct.pack("<I", VERSION))
    for entry in entries:
        out += _OPEN
        out += (entry.key + "\x00").encode("utf-16-le")
        out += _SEMI
        out += (entry.value + "\x00").encode("utf-16-le")
        out += _SEMI
        out += struct.pack("<I", entry.kind)
        out += _SEMI
        out += struct.pack("<I", len(entry.data))
        out += _SEMI
        out += entry.data
        out += _CLOSE
    return bytes(out)


def without_keys(entries: list[Entry], prefixes: tuple[str, ...]) -> list[Entry]:
    """Убрать записи, чьи ключи начинаются с указанных путей.

    Так снимаются наши настройки, не задевая чужие: в `Registry.pol` рядом
    могут лежать политики, поставленные администратором или другой
    программой, и стирать файл целиком нельзя.
    """
    lowered = tuple(p.casefold().rstrip("\\") for p in prefixes)
    kept: list[Entry] = []
    for entry in entries:
        key = entry.key.casefold().rstrip("\\")
        if any(key == p or key.startswith(p + "\\") for p in lowered):
            continue
        kept.append(entry)
    return kept
