"""Запрет на уровне локальной групповой политики.

Прямая запись в реестр действует сразу, но её так же сразу можно и стереть —
в том числе той программе, которую она запрещает. Групповая политика ведёт
себя иначе: Windows держит настройки в отдельных файлах и сама возвращает их
в реестр — при входе в систему, каждые полтора часа и по команде `gpupdate`.
Стереть ключ мало: через недолгое время он вернётся.

Второе отличие важно не машине, а человеку: то, что записано сюда, видно в
`gpedit.msc` наравне с остальными политиками. Запрет перестаёт быть чужой
самодеятельностью в реестре и становится обычной настройкой, которую видно и
можно снять привычным способом.

Записывается два файла. В машинный уходят правила ограниченного
использования программ (те же, что и у прямого механизма, но уже как
политика), в пользовательский — «Не запускать указанные приложения Windows».
Пользовательская часть локальной политики действует на всех, кто входит в
эту машину, чего прямая запись в ветку текущего пользователя не умеет.
"""

from __future__ import annotations

import configparser
import contextlib
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from strazh.core.models import Target
from strazh.core.state import Change, State
from strazh.enforce import plan as planner
from strazh.enforce.base import Mechanism, StepResult
from strazh.enforce.windows import preg
from strazh.enforce.windows.srp import BASE as SAFER_BASE
from strazh.enforce.windows.srp import DESCRIPTION_PREFIX, LEVEL_UNRESTRICTED, rule_guid

MECHANISM = "gpo"

EXPLORER_POLICY = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
DISALLOW_LIST = EXPLORER_POLICY + r"\DisallowRun"

DISALLOW_LIMIT = 200
"""Оболочка перестаёт учитывать список после нескольких сотен записей.
Переполнить его — значит потерять весь список, а не его хвост."""

# Расширение, которое применяет настройки реестра из файла политики. Без
# этой пары в gpt.ini Windows не станет читать Registry.pol вовсе.
REGISTRY_CSE = "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]"

_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0

SAFER_SETTINGS = ("DefaultLevel", "TransparentEnabled", "PolicyScope", "authenticodeenabled")


def strip_ours(entries: list[preg.Entry]) -> list[preg.Entry]:
    """Убрать из политики только наши записи.

    Соблазн был вырезать ветку целиком — по пути ключа. Так делать нельзя:
    в `Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer` рядом с нашим
    `DisallowRun` лежат десятки других настроек проводника, которые мог
    поставить администратор, а в ветке SAFER — правила, написанные вручную.
    Вырезание по пути стёрло бы их вместе с нашими и не вернуло обратно.

    Поэтому наши записи опознаются поимённо: четыре общие настройки SAFER,
    правила с нашей пометкой в описании и список запрета запуска. Всё
    остальное остаётся на месте, даже если лежит в том же ключе.
    """
    ours: set[str] = set()
    for entry in entries:
        if (
            entry.value == "Description"
            and entry.key.casefold().startswith((SAFER_BASE + "\\0\\paths\\").casefold())
            and entry.as_text().startswith(DESCRIPTION_PREFIX)
        ):
            ours.add(entry.key.casefold())

    kept: list[preg.Entry] = []
    for entry in entries:
        key = entry.key.casefold()
        if key in ours:
            continue
        if key == SAFER_BASE.casefold() and entry.value in SAFER_SETTINGS:
            continue
        if key == EXPLORER_POLICY.casefold() and entry.value == "DisallowRun":
            continue
        if key == DISALLOW_LIST.casefold():
            continue
        kept.append(entry)
    return kept


def policy_root() -> Path:
    override = os.environ.get("STRAZH_GPO_ROOT", "").strip()
    if override:
        return Path(override)
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    return Path(system_root) / "System32" / "GroupPolicy"


def machine_pol() -> Path:
    return policy_root() / "Machine" / "Registry.pol"


def user_pol() -> Path:
    return policy_root() / "User" / "Registry.pol"


def gpt_ini() -> Path:
    return policy_root() / "gpt.ini"


# ── сборка записей ────────────────────────────────────────────────────────────


def _filetime_now() -> int:
    epoch = datetime(1601, 1, 1, tzinfo=UTC)
    return int((datetime.now(UTC) - epoch).total_seconds() * 10_000_000)


def build_machine_entries(targets: list[Target]) -> list[preg.Entry]:
    """Правила ограниченного использования программ как политика."""
    entries: list[preg.Entry] = [
        # Уровень по умолчанию — «разрешено». Обратный порядок превратил бы
        # обычный компьютер в терминал.
        preg.Entry.dword(SAFER_BASE, "DefaultLevel", LEVEL_UNRESTRICTED),
        # Проверять только исполняемые файлы: проверка библиотек заметно
        # тормозит машину и ломает программы, грузящие модули из временных
        # папок.
        preg.Entry.dword(SAFER_BASE, "TransparentEnabled", 1),
        # Политика действует на всех, включая администраторов.
        preg.Entry.dword(SAFER_BASE, "PolicyScope", 0),
        preg.Entry.dword(SAFER_BASE, "authenticodeenabled", 0),
    ]
    stamp = _filetime_now()
    for op in planner.plan_srp(targets):
        key = f"{SAFER_BASE}\\0\\Paths\\{rule_guid(op.key)}"
        entries.append(preg.Entry.text(key, "ItemData", op.key, expand=True))
        entries.append(preg.Entry.dword(key, "SaferFlags", 0))
        entries.append(preg.Entry.text(key, "Description", DESCRIPTION_PREFIX + op.target_id))
        entries.append(preg.Entry.qword(key, "LastModified", stamp))
    return entries


def build_user_entries(targets: list[Target]) -> list[preg.Entry]:
    """«Не запускать указанные приложения Windows» — политика пользователя."""
    names = [op.key for op in planner.plan_ifeo(targets)][:DISALLOW_LIMIT]
    if not names:
        return []
    entries = [preg.Entry.dword(EXPLORER_POLICY, "DisallowRun", 1)]
    for index, name in enumerate(names, start=1):
        entries.append(preg.Entry.text(DISALLOW_LIST, str(index), name))
    return entries


# ── файл gpt.ini ──────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class GptVersion:
    """Номер версии политики: пользовательская часть в старшем слове,
    машинная — в младшем. Windows перечитывает файлы, только если номер
    вырос, поэтому его обязательно увеличить после правки."""

    user: int
    machine: int

    @staticmethod
    def unpack(number: int) -> GptVersion:
        return GptVersion(user=(number >> 16) & 0xFFFF, machine=number & 0xFFFF)

    def pack(self) -> int:
        return ((self.user & 0xFFFF) << 16) | (self.machine & 0xFFFF)

    def bumped(self, *, machine: bool, user: bool) -> GptVersion:
        return GptVersion(
            user=(self.user + 1) & 0xFFFF if user else self.user,
            machine=(self.machine + 1) & 0xFFFF if machine else self.machine,
        )


def read_gpt(path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    parser.optionxform = str  # type: ignore[method-assign, assignment]
    # Файла может не быть, а быть — испорченным. И то и другое поправимо:
    # ниже мы всё равно перепишем раздел General.
    with contextlib.suppress(OSError, configparser.Error):
        parser.read_string(path.read_text(encoding="utf-8-sig"))
    if not parser.has_section("General"):
        parser.add_section("General")
    return parser


def bump_gpt(path: Path, *, machine: bool, user: bool) -> None:
    """Поднять номер версии и объявить, какое расширение читает файлы."""
    parser = read_gpt(path)
    try:
        current = int(parser.get("General", "Version", fallback="0"))
    except ValueError:
        current = 0
    parser.set(
        "General",
        "Version",
        str(GptVersion.unpack(current).bumped(machine=machine, user=user).pack()),
    )
    if machine:
        parser.set("General", "gPCMachineExtensionNames", REGISTRY_CSE)
    if user:
        parser.set("General", "gPCUserExtensionNames", REGISTRY_CSE)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        parser.write(fh, space_around_delimiters=False)


def gpupdate() -> tuple[bool, str]:
    """Попросить Windows применить политику немедленно.

    Отказ не считается провалом: политика всё равно применится при следующем
    обновлении — при входе в систему или в течение полутора часов. Сообщать
    об этом человеку честнее, чем откатывать уже записанные файлы.
    """
    try:
        done = subprocess.run(
            ["gpupdate", "/force", "/wait:120"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
            creationflags=_NO_WINDOW,
        )
        return done.returncode == 0, ((done.stdout or "") + (done.stderr or "")).strip()[:200]
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)


# ── механизм ──────────────────────────────────────────────────────────────────


class GroupPolicyMechanism(Mechanism):
    key = MECHANISM
    title = "Локальная групповая политика"

    def __init__(self, backup_dir: Path | None = None) -> None:
        from strazh import paths

        self._backup_dir = backup_dir or (paths.machine_dir() / "backup")

    def available(self) -> tuple[bool, str]:
        if sys.platform != "win32" and not os.environ.get("STRAZH_GPO_ROOT"):
            return False, "механизм есть только в Windows"
        return True, ""

    def apply(self, targets: list[Target], state: State) -> StepResult:
        machine_entries = build_machine_entries(targets)
        user_entries = build_user_entries(targets)
        details: list[str] = []
        try:
            written = 0
            for path, entries, label in (
                (machine_pol(), machine_entries, "машина"),
                (user_pol(), user_entries, "пользователи"),
            ):
                self._backup_once(path, state)
                kept = strip_ours(self._load(path))
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(preg.dumps(kept + entries))
                written += len(entries)
                details.append(f"{label}: {len(entries)} настроек, чужих сохранено {len(kept)}")

            bump_gpt(gpt_ini(), machine=True, user=True)
            state.add(Change(mechanism=self.key, key="__gpt__"))
        except (OSError, preg.PregError) as exc:
            return StepResult(self.key, self.title, ok=False, count=0, message=str(exc))

        ok, output = gpupdate()
        if not ok:
            details.append("политика применится при следующем обновлении: " + output)
        return StepResult(
            mechanism=self.key,
            title=self.title,
            ok=True,
            count=written,
            message="" if ok else "gpupdate не отработал, но файлы записаны",
            details=details,
        )

    def revert(self, state: State) -> StepResult:
        changes = state.by_mechanism(self.key)
        if not changes:
            return StepResult(self.key, self.title, ok=True, count=0)
        restored = 0
        failed: list[str] = []
        for change in changes:
            if change.key == "__gpt__":
                continue
            path = Path(change.key)
            try:
                if change.previous:
                    # Файл был до нас — возвращаем его целиком.
                    shutil.copyfile(change.previous, path)
                else:
                    # Файла не было: вычищаем свои записи, а если ничего
                    # чужого не осталось — убираем и файл.
                    kept = strip_ours(self._load(path))
                    if kept:
                        path.write_bytes(preg.dumps(kept))
                    else:
                        path.unlink(missing_ok=True)
                restored += 1
            except (OSError, preg.PregError) as exc:
                failed.append(f"{path.name}: {exc}")

        try:
            bump_gpt(gpt_ini(), machine=True, user=True)
        except OSError as exc:
            failed.append(f"gpt.ini: {exc}")
        gpupdate()
        state.changes = [c for c in state.changes if c.mechanism != self.key]
        return StepResult(
            mechanism=self.key,
            title=self.title,
            ok=not failed,
            count=restored,
            message="; ".join(failed[:3]) if failed else "",
        )

    # ── вспомогательное ───────────────────────────────────────────────────────

    @staticmethod
    def _load(path: Path) -> list[preg.Entry]:
        try:
            return preg.loads(path.read_bytes())
        except FileNotFoundError:
            return []
        except preg.PregError:
            # Чужой файл повреждён. Собственные настройки в него дописывать
            # нельзя: мы не знаем, что там было, и не сможем это вернуть.
            raise

    def _backup_once(self, path: Path, state: State) -> None:
        """Сохранить прежний файл политики — один раз, при первом применении."""
        if any(c.key == str(path) for c in state.by_mechanism(self.key)):
            return
        previous: str | None = None
        if path.exists():
            self._backup_dir.mkdir(parents=True, exist_ok=True)
            copy = self._backup_dir / f"{path.parent.name}-{path.name}"
            shutil.copyfile(path, copy)
            previous = str(copy)
        state.add(Change(mechanism=self.key, key=str(path), previous=previous))
