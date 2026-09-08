#!/usr/bin/env python3
"""Проверка каталога отдельной командой.

Тем же занимаются проверки в tests/, но эта команда нужна там, где их нет:
на чужой машине, в чужой сборке, перед отправкой своего файла в каталог.
Возвращает ненулевой код, если хоть одна запись не принята.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from strazh.core.catalog import CATEGORIES, load_dir  # noqa: E402
from strazh.core.models import pattern_touches_protected  # noqa: E402
from strazh.enforce import plan  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Проверить файлы каталога")
    parser.add_argument(
        "directory",
        nargs="?",
        default=str(ROOT / "src/strazh/data/catalog"),
        help="папка с файлами каталога",
    )
    args = parser.parse_args()

    targets, issues = load_dir(Path(args.directory), source="builtin")
    problems: list[str] = [str(i) for i in issues]

    seen: dict[str, str] = {}
    for target in targets:
        if target.id in seen:
            problems.append(f"{target.id}: повторяющийся код записи")
        seen[target.id] = target.name
        if target.category not in CATEGORIES:
            problems.append(f"{target.id}: неизвестный раздел «{target.category}»")
        if len(target.why) < 40:
            problems.append(f"{target.id}: слишком короткое пояснение «почему»")
        if not target.enabled and "выключен" not in target.why.casefold():
            problems.append(f"{target.id}: запись выключена, но не сказано почему")
        for pattern in (*target.match.executables, *target.match.installers):
            if pattern_touches_protected(pattern):
                problems.append(f"{target.id}: маска «{pattern}» задевает системные файлы")
        for name in target.match.executables:
            if not name.casefold().endswith((".exe", ".com", ".scr", ".pif")):
                problems.append(f"{target.id}: «{name}» не похоже на имя исполняемого файла")
        for domain in target.match.domains:
            if "/" in domain or ":" in domain:
                problems.append(f"{target.id}: «{domain}» — это не доменное имя")

    counts = {
        name: len(ops) for name, ops in plan.plan_all([t for t in targets if t.enabled]).items()
    }

    print(f"Файлов: {len(list(Path(args.directory).glob('*.json')))}")
    print(f"Целей: {len(targets)} (включено {sum(1 for t in targets if t.enabled)})")
    print("План: " + ", ".join(f"{k}={v}" for k, v in counts.items()))

    if problems:
        print("\nОшибки:")
        for problem in problems:
            print(f"  • {problem}")
        return 1
    print("\nОшибок нет.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
