"""Обновление из выпусков GitHub.

Программа работает с правами системы, поэтому «скачать и запустить» — ровно
тот приём, который она сама и запрещает другим. Здесь он обставлен так, чтобы
это не было лицемерием.

Скачанное проверяется по контрольной сумме из того же выпуска: не сошлось —
файл удаляется и не запускается. Адрес загрузки принимается только с доменов
GitHub, а не любой, который вернул ответ. И самое главное: программа
проверяет наличие обновления сама, а ставит — только когда человек нажал.
Молча подменять себя с правами системы она не будет.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from strazh.version import __version__

REPO = "Aleck59/unwant_zapret"
LATEST_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_PAGE = f"https://github.com/{REPO}/releases"

ALLOWED_HOSTS = ("github.com", "api.github.com", "objects.githubusercontent.com")
"""Откуда позволено скачивать. Ответ сервера — не повод идти по любому
адресу, который в нём написан."""

SUMS_NAME = "SHA256SUMS.txt"
TIMEOUT = 15
MAX_ASSET_BYTES = 300 * 1024 * 1024

USER_AGENT = f"Strazh/{__version__} (+https://github.com/{REPO})"

_VERSION = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?")


class UpdateError(RuntimeError):
    """Обновление не получилось. Текст рассчитан на человека."""


@dataclass(frozen=True, slots=True)
class Update:
    """Найденный выпуск новее нынешнего."""

    version: str
    tag: str
    name: str
    notes: str
    page: str
    asset_name: str
    asset_url: str
    asset_size: int
    sums_url: str | None

    @property
    def size_text(self) -> str:
        return f"{self.asset_size / 1048576:.1f} МБ" if self.asset_size else "неизвестно"


# ── разбор версий ─────────────────────────────────────────────────────────────


def parse_version(text: str) -> tuple[int, int, int]:
    """`v1.2.3` → `(1, 2, 3)`. Непонятное считается нулевым."""
    match = _VERSION.match(text.strip())
    if match is None:
        return (0, 0, 0)
    return tuple(int(part) if part else 0 for part in match.groups())  # type: ignore[return-value]


def is_newer(candidate: str, current: str = __version__) -> bool:
    return parse_version(candidate) > parse_version(current)


def pick_asset(assets: list[dict]) -> dict | None:
    """Выбрать, что скачивать.

    Установщик предпочтительнее архива: он умеет остановить работающую
    программу, заменить файлы и оставить настройки на месте, а распаковка
    поверх работающих файлов на Windows просто не удастся.
    """
    installers = [a for a in assets if a.get("name", "").casefold().endswith(".exe")]
    if installers:
        return installers[0]
    archives = [a for a in assets if a.get("name", "").casefold().endswith(".zip")]
    return archives[0] if archives else None


def _checked_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise UpdateError(f"отказ: адрес {url[:80]} не принадлежит GitHub")
    return url


# ── сеть ──────────────────────────────────────────────────────────────────────


def _fetch(url: str, *, timeout: int = TIMEOUT, limit: int = 1024 * 1024) -> bytes:
    request = urllib.request.Request(_checked_url(url), headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read(limit)


def check(current: str = __version__, *, timeout: int = TIMEOUT) -> Update | None:
    """Есть ли выпуск новее. `None` — стоит свежее или столько же."""
    try:
        raw = json.loads(_fetch(LATEST_URL, timeout=timeout).decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise UpdateError(f"не удалось спросить GitHub: {exc}") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise UpdateError("GitHub ответил чем-то, что не разобрать") from exc

    return update_from_release(raw, current)


def update_from_release(raw: dict, current: str = __version__) -> Update | None:
    """Разобрать ответ GitHub. Отделено от сети, чтобы можно было проверить."""
    tag = str(raw.get("tag_name", "")).strip()
    if not tag or not is_newer(tag, current):
        return None

    assets = [a for a in raw.get("assets", []) if isinstance(a, dict)]
    asset = pick_asset(assets)
    if asset is None:
        return None
    size = int(asset.get("size") or 0)
    if size > MAX_ASSET_BYTES:
        raise UpdateError("файл выпуска неправдоподобно велик — обновление отклонено")

    sums = next((a for a in assets if a.get("name") == SUMS_NAME), None)
    return Update(
        version=tag.lstrip("v"),
        tag=tag,
        name=str(raw.get("name") or tag),
        notes=str(raw.get("body") or "").strip(),
        page=str(raw.get("html_url") or RELEASES_PAGE),
        asset_name=str(asset.get("name", "")),
        asset_url=str(asset.get("browser_download_url", "")),
        asset_size=size,
        sums_url=str(sums["browser_download_url"]) if sums else None,
    )


def parse_sums(text: str) -> dict[str, str]:
    """Разобрать `SHA256SUMS.txt`: «сумма  имя файла» построчно."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        digest, name = parts[0].strip().lower(), parts[-1].strip().lstrip("*")
        if len(digest) == 64 and all(c in "0123456789abcdef" for c in digest):
            out[name] = digest
    return out


def download(update: Update, folder: Path, *, timeout: int = 120) -> Path:
    """Скачать файл выпуска и сверить контрольную сумму.

    Не сошлась — скачанное удаляется. Программа, которая ставит с правами
    системы что-то, чью сумму не проверила, ничем не лучше тех, кого она
    запрещает.
    """
    if not update.sums_url:
        raise UpdateError("в выпуске нет файла контрольных сумм — обновление отклонено")

    try:
        sums = parse_sums(_fetch(update.sums_url, timeout=timeout).decode("utf-8", "replace"))
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise UpdateError(f"не удалось получить контрольные суммы: {exc}") from exc

    expected = sums.get(update.asset_name)
    if not expected:
        raise UpdateError(f"для {update.asset_name} нет контрольной суммы — обновление отклонено")

    folder.mkdir(parents=True, exist_ok=True)
    target = folder / update.asset_name
    digest = hashlib.sha256()
    request = urllib.request.Request(
        _checked_url(update.asset_url), headers={"User-Agent": USER_AGENT}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            written = 0
            with target.open("wb") as fh:
                while chunk := response.read(256 * 1024):
                    written += len(chunk)
                    if written > MAX_ASSET_BYTES:
                        raise UpdateError(
                            "файл оказался больше объявленного — обновление отклонено"
                        )
                    digest.update(chunk)
                    fh.write(chunk)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        target.unlink(missing_ok=True)
        raise UpdateError(f"не удалось скачать: {exc}") from exc

    if digest.hexdigest() != expected:
        target.unlink(missing_ok=True)
        raise UpdateError(
            "контрольная сумма скачанного не совпала с объявленной — файл удалён, "
            "обновление отменено"
        )
    return target


def install(path: Path, *, silent: bool = True) -> None:
    """Запустить установщик. Вызывается только по решению человека."""
    if sys.platform != "win32":
        raise UpdateError("установка возможна только в Windows")
    if path.suffix.casefold() != ".exe":
        raise UpdateError("это не установщик — распакуйте архив вручную")
    args = [str(path)]
    if silent:
        # Тихая установка с сохранением настроек: человек уже согласился,
        # переспрашивать теми же вопросами незачем.
        args += ["/SILENT", "/NORESTART", "/SUPPRESSMSGBOXES"]
    try:
        subprocess.Popen(args, close_fds=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise UpdateError(f"не удалось запустить установщик: {exc}") from exc
