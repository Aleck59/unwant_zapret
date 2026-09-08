"""Правила ограниченного использования программ (SAFER).

Второй слой после перехвата по имени. Умеет то, чего не умеет первый: маски
(`360*setup*.exe`) и запрет по месту установки. Работает на уровне загрузчика
образов, то есть до кода самой программы, и настраивается через реестр —
редактор групповых политик, которого нет в домашних изданиях, для этого не
нужен.

Уровень по умолчанию остаётся «разрешено», а запрещающие правила
добавляются точечно. Обратный порядок («запретить всё, разрешить нужное»)
надёжнее, но превращает обычный компьютер в терминал: здесь это неуместно.
"""

from __future__ import annotations

import sys
import uuid
from datetime import UTC, datetime

from strazh.core.models import Target, is_protected
from strazh.core.state import Change, State
from strazh.enforce import plan as planner
from strazh.enforce.base import Mechanism, StepResult
from strazh.enforce.windows import registry as reg

BASE = r"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
DISALLOWED = f"{BASE}\\0\\Paths"

LEVEL_UNRESTRICTED = 0x40000
MECHANISM = "srp"

DESCRIPTION_PREFIX = "Strazh: "
"""По этой пометке правило узнаётся при откате, даже если файл состояния
потеряли. Чужие правила SAFER программа не трогает никогда."""

_NAMESPACE = uuid.UUID("6f9619ff-8b86-d011-b42d-00c04fc964ff")


def rule_guid(pattern: str) -> str:
    """Опознаватель правила, выведенный из самой маски.

    Случайный опознаватель был бы проще, но означал бы, что повторное
    применение с потерянным файлом состояния заводит второе такое же
    правило, потом третье. Выведенный из маски — всегда один и тот же, и
    повторное применение просто переписывает то, что уже стоит.
    """
    return "{" + str(uuid.uuid5(_NAMESPACE, f"strazh:srp:{pattern.casefold()}")).upper() + "}"


def _filetime_now() -> int:
    epoch = datetime(1601, 1, 1, tzinfo=UTC)
    return int((datetime.now(UTC) - epoch).total_seconds() * 10_000_000)


class SrpMechanism(Mechanism):
    key = MECHANISM
    title = "Правила по пути и маске"

    def available(self) -> tuple[bool, str]:
        if sys.platform != "win32":
            return False, "механизм есть только в Windows"
        return True, ""

    def _ensure_base(self) -> None:
        """Общие настройки политики.

        `DefaultLevel` — «разрешено», иначе запрет накрыл бы всю систему.
        `TransparentEnabled=1` — проверять только исполняемые файлы, не
        библиотеки: проверка библиотек заметно тормозит машину и ломает
        программы, которые грузят свои модули из временных папок.
        """
        reg.write_value(reg.HKLM, BASE, "DefaultLevel", LEVEL_UNRESTRICTED)
        reg.write_value(reg.HKLM, BASE, "TransparentEnabled", 1)
        reg.write_value(reg.HKLM, BASE, "PolicyScope", 0)
        reg.write_value(reg.HKLM, BASE, "authenticodeenabled", 0)

    def apply(self, targets: list[Target], state: State) -> StepResult:
        ops = planner.plan_srp(targets)
        existing = {c.key.casefold(): c for c in state.by_mechanism(self.key)}
        done = 0
        failed: list[str] = []
        try:
            self._ensure_base()
        except OSError as exc:
            return StepResult(self.key, self.title, ok=False, count=0, message=str(exc))

        for op in ops:
            if is_protected(op.key) or op.key.casefold() in existing:
                continue
            rule_id = rule_guid(op.key)
            path = f"{DISALLOWED}\\{rule_id}"
            try:
                reg.write_value(reg.HKLM, path, "ItemData", op.key, kind=_expand_sz())
                reg.write_value(reg.HKLM, path, "SaferFlags", 0)
                reg.write_value(
                    reg.HKLM, path, "Description", DESCRIPTION_PREFIX + op.target_id, kind=_sz()
                )
                reg.write_value(reg.HKLM, path, "LastModified", _filetime_now(), kind=_qword())
                state.add(
                    Change(
                        mechanism=self.key,
                        key=op.key,
                        target_id=op.target_id,
                        previous=rule_id,
                    )
                )
                done += 1
            except OSError as exc:
                failed.append(f"{op.key}: {exc}")
        return StepResult(
            mechanism=self.key,
            title=self.title,
            ok=not failed,
            count=done,
            message="; ".join(failed[:3]) if failed else "",
            details=[op.description for op in ops[:200]],
        )

    def revert(self, state: State) -> StepResult:
        done = 0
        failed: list[str] = []
        for change in state.by_mechanism(self.key):
            rule_id = change.previous or ""
            if rule_id:
                reg.delete_tree(reg.HKLM, f"{DISALLOWED}\\{rule_id}")
            state.remove(self.key, change.key)
            done += 1

        # Подчищаем и то, что осталось от прошлых запусков: правило со своей
        # пометкой принадлежит нам, даже если запись о нём потерялась.
        for rule_id in reg.subkeys(reg.HKLM, DISALLOWED):
            path = f"{DISALLOWED}\\{rule_id}"
            description = reg.read_value(reg.HKLM, path, "Description")
            if isinstance(description, str) and description.startswith(DESCRIPTION_PREFIX):
                if reg.delete_tree(reg.HKLM, path):
                    done += 1
                else:
                    failed.append(rule_id)
        return StepResult(
            mechanism=self.key,
            title=self.title,
            ok=not failed,
            count=done,
            message="; ".join(failed[:3]) if failed else "",
        )


def _sz() -> int:
    import winreg

    return winreg.REG_SZ


def _expand_sz() -> int:
    import winreg

    return winreg.REG_EXPAND_SZ


def _qword() -> int:
    import winreg

    return winreg.REG_QWORD
