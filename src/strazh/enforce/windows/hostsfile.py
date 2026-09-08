"""Закрытие адресов через hosts.

Слой, который мешает скачать установщик и отправить собранное наружу.
Выключен по умолчанию: файл hosts общий для всей машины, и запись,
поставленная сгоряча, потом ищется часами.

Все строки живут внутри помеченного блока. Ничего вне блока программа не
читает и не переписывает, а откат сводится к вырезанию блока целиком.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from strazh.core.models import Target
from strazh.core.state import Change, State
from strazh.enforce import plan as planner
from strazh.enforce.base import Mechanism, StepResult

BEGIN = "# >>> Страж: закрытые адреса — не редактировать вручную"
END = "# <<< Страж"
MECHANISM = "hosts"
SINK = "0.0.0.0"


def hosts_path() -> Path:
    override = os.environ.get("STRAZH_HOSTS_FILE", "").strip()
    if override:
        return Path(override)
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    return Path(system_root) / "System32" / "drivers" / "etc" / "hosts"


def strip_block(text: str) -> str:
    """Убрать наш блок, не тронув остальное."""
    lines = text.splitlines()
    out: list[str] = []
    inside = False
    for line in lines:
        if line.strip() == BEGIN:
            inside = True
            continue
        if inside and line.strip() == END:
            inside = False
            continue
        if not inside:
            out.append(line)
    return "\n".join(out).rstrip("\n") + "\n" if out else ""


def build_block(domains: list[str]) -> str:
    if not domains:
        return ""
    rows = [BEGIN]
    for domain in domains:
        # Домены закрываются вместе с `www`: половина установщиков ходит
        # именно на него, и без второй строки запись бесполезна.
        rows.append(f"{SINK} {domain}")
        if not domain.startswith("www."):
            rows.append(f"{SINK} www.{domain}")
    rows.append(END)
    return "\n".join(rows) + "\n"


def render(existing: str, domains: list[str]) -> str:
    """Итоговое содержимое файла: чужое сверху, наш блок снизу."""
    body = strip_block(existing)
    block = build_block(domains)
    if not block:
        return body
    if body and not body.endswith("\n"):
        body += "\n"
    return f"{body}\n{block}" if body else block


class HostsMechanism(Mechanism):
    key = MECHANISM
    title = "Закрытие адресов"

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or hosts_path()

    def available(self) -> tuple[bool, str]:
        if sys.platform != "win32" and not os.environ.get("STRAZH_HOSTS_FILE"):
            return False, "механизм есть только в Windows"
        return True, ""

    def _read(self) -> str:
        try:
            return self._path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError):
            try:
                return self._path.read_bytes().decode("cp1251", errors="replace")
            except OSError:
                return ""

    def _write(self, text: str) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(text, encoding="utf-8")

    def apply(self, targets: list[Target], state: State) -> StepResult:
        ops = planner.plan_hosts(targets)
        domains = [op.key for op in ops]
        if not domains:
            return StepResult(self.key, self.title, ok=True, count=0, message="адресов нет")
        try:
            current = self._read()
            backup = state.by_mechanism(self.key)
            if not backup:
                # Прежнее содержимое сохраняем один раз — при первом
                # применении. Иначе повторный запуск записал бы в «прежнее»
                # уже наш собственный блок.
                state.add(
                    Change(mechanism=self.key, key="__file__", target_id="", previous=current)
                )
            self._write(render(current, domains))
            for op in ops:
                state.add(Change(mechanism=self.key, key=op.key, target_id=op.target_id))
        except OSError as exc:
            return StepResult(self.key, self.title, ok=False, count=0, message=str(exc))
        return StepResult(
            mechanism=self.key,
            title=self.title,
            ok=True,
            count=len(domains),
            details=[op.description for op in ops[:200]],
        )

    def revert(self, state: State) -> StepResult:
        changes = state.by_mechanism(self.key)
        if not changes:
            return StepResult(self.key, self.title, ok=True, count=0)
        try:
            self._write(strip_block(self._read()))
        except OSError as exc:
            return StepResult(self.key, self.title, ok=False, count=0, message=str(exc))
        count = sum(1 for c in changes if c.key != "__file__")
        state.changes = [c for c in state.changes if c.mechanism != self.key]
        return StepResult(self.key, self.title, ok=True, count=count)
