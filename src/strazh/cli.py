"""Командная строка.

Нужна не как замена окну, а как то, чем пользуются автоматически: службой
`strazh watch`, проверкой каталога в сборке, разовым откатом с загрузочной
флешки. Всё, что делает окно, доступно и здесь.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from strazh import paths
from strazh.app import Strazh
from strazh.core.catalog import CATEGORIES
from strazh.core.models import Severity
from strazh.version import APP_NAME, __version__

SEVERITY_MARK = {Severity.HIGH: "!!", Severity.MEDIUM: " !", Severity.LOW: "  "}


def _out(text: str = "") -> None:
    # Консоль Windows по умолчанию не в UTF-8; подменяем непечатаемое, чтобы
    # программа не падала на выводе там, где ей нечего сказать по-английски.
    sys.stdout.write(
        text.encode(sys.stdout.encoding or "utf-8", "replace").decode(
            sys.stdout.encoding or "utf-8", "replace"
        )
        + "\n"
    )


def cmd_status(core: Strazh, args: argparse.Namespace) -> int:
    catalog = core.catalog
    _out(f"{APP_NAME} {__version__}")
    _out(f"Система:        {core.enforcer.platform}")
    _out(f"Права:          {'администратор' if core.enforcer.is_admin() else 'обычные'}")
    _out(f"Защита:         {'включена' if core.protection_on else 'выключена'}")
    if core.state.applied_at:
        _out(f"Применена:      {core.state.applied_at}")
    _out(f"Целей в каталоге: {len(catalog.targets)} (включено {len(catalog.enabled())})")
    _out(f"Изменений в системе: {len(core.state.changes)}")
    _out(f"Данные:         {paths.machine_dir()}")
    if catalog.issues:
        _out("")
        _out("Замечания по каталогу:")
        for issue in catalog.issues:
            _out(f"  • {issue}")
    return 0


def cmd_list(core: Strazh, args: argparse.Namespace) -> int:
    targets = core.catalog.as_list()
    if args.category:
        targets = [t for t in targets if t.category == args.category]
    if not args.all:
        targets = [t for t in targets if t.enabled]
    if args.search:
        needle = args.search.casefold()
        targets = [
            t
            for t in targets
            if needle in t.name.casefold()
            or needle in t.id.casefold()
            or needle in t.vendor.casefold()
        ]
    current = ""
    for target in targets:
        if target.category != current:
            current = target.category
            _out("")
            _out(f"── {CATEGORIES.get(current, current)} ──")
        mark = SEVERITY_MARK.get(target.severity, "  ")
        state = " " if target.enabled else "×"
        _out(f"{state}{mark} {target.id:<28} {target.name}")
    _out("")
    _out(f"Показано: {len(targets)}. «×» — выключено, «!!» — высокий уровень.")
    return 0


def cmd_show(core: Strazh, args: argparse.Namespace) -> int:
    target = core.catalog.targets.get(args.id)
    if target is None:
        _out(f"Цель «{args.id}» не найдена.")
        return 1
    _out(f"{target.name}  [{target.id}]")
    _out(f"Издатель:  {target.vendor or '—'}")
    _out(f"Раздел:    {CATEGORIES.get(target.category, target.category)}")
    _out(f"Уровень:   {target.severity.value}")
    _out(f"Состояние: {'включена' if target.enabled else 'выключена'} ({target.source})")
    _out(f"Действия:  {', '.join(a.value for a in target.actions)}")
    if target.why:
        _out("")
        _out("Почему в каталоге:")
        _out(f"  {target.why}")
    _out("")
    _out("Признаки:")
    for name, values in target.match.to_json().items():
        _out(f"  {name}: {', '.join(values)}")
    if target.references:
        _out("")
        _out("Источники:")
        for ref in target.references:
            _out(f"  {ref}")
    return 0


def cmd_apply(core: Strazh, args: argparse.Namespace) -> int:
    if args.dry_run:
        # Предпросмотр считает тот же план, но другим распорядителем — тем,
        # который ничего не умеет менять. Так «показать» и «сделать» не могут
        # разойтись: план один и тот же.
        from strazh.core.state import State
        from strazh.enforce import get_enforcer

        _out("Разбор без изменений в системе:")
        report = get_enforcer(force_dry_run=True).apply(core.catalog, core.settings, State())
    else:
        if not core.enforcer.is_admin() and core.enforcer.platform == "windows":
            _out("Нужны права администратора: запустите командную строку от имени администратора.")
            return 2
        report = core.apply_protection()
    _out(report.text())
    if args.verbose:
        for step in report.steps:
            for line in step.details:
                _out(f"    {line}")
    return 0 if report.ok else 1


def cmd_revert(core: Strazh, args: argparse.Namespace) -> int:
    if not core.enforcer.is_admin() and core.enforcer.platform == "windows":
        _out("Нужны права администратора.")
        return 2
    report = core.revert_protection()
    _out(report.text())
    return 0 if report.ok else 1


def cmd_scan(core: Strazh, args: argparse.Namespace) -> int:
    result = core.scan()
    _out(f"Просмотрено процессов: {result.processes_seen}, программ: {result.programs_seen}")
    if result.clean:
        _out("Ничего из каталога не найдено.")
        return 0
    _out("")
    for finding in result.findings:
        _out(f"[{finding.where}] {finding.title}")
        _out(f"    {finding.verdict.target_name} — {finding.verdict.reason}")
    _out("")
    _out(f"Найдено: {len(result.findings)}")
    return 1


def cmd_check(core: Strazh, args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.exists():
        _out(f"Файла нет: {path}")
        return 2
    facts, verdict = core.check_file(path)
    _out(f"Файл:      {path}")
    _out(f"Исходное имя: {facts.original_filename or '—'}")
    _out(f"Издатель:  {facts.publisher or facts.company_name or '—'}")
    _out(f"Сумма:     {facts.sha256 or '—'}")
    _out("")
    if verdict.allowed:
        _out("Разрешён." + (f" ({verdict.reason})" if verdict.reason else ""))
        return 0
    _out(f"ЗАПРЕЩЁН: {verdict.target_name} — {verdict.reason}")
    return 1


def cmd_add(core: Strazh, args: argparse.Namespace) -> int:
    target = Strazh.quick_target(args.name, args.exe, category=args.category)
    core.save_user_target(target)
    _out(f"Добавлено: {target.name} [{target.id}], файлов: {len(target.match.executables)}")
    _out("Чтобы запрет вступил в силу, выполните: strazh apply")
    return 0


def cmd_toggle(core: Strazh, args: argparse.Namespace) -> int:
    if args.id not in core.catalog.targets:
        _out(f"Цель «{args.id}» не найдена.")
        return 1
    core.set_target_enabled(args.id, args.enable)
    _out(f"«{args.id}»: {'включена' if args.enable else 'выключена'}")
    return 0


def cmd_journal(core: Strazh, args: argparse.Namespace) -> int:
    events = core.recent(args.number)
    if not events:
        _out("Журнал пуст.")
        return 0
    for event in events:
        _out(f"{event.local_time}  {event.kind.value:<20} {event.message}")
    return 0


def cmd_watch(core: Strazh, args: argparse.Namespace) -> int:
    """Фоновый страж переднего плана: этим же запускается служба."""
    from strazh.watch.supervisor import Supervisor

    supervisor = Supervisor(core)
    supervisor.start()
    if not supervisor.running:
        _out("Наблюдатели выключены в настройках — нечего запускать.")
        return 1
    _out("Страж работает. Остановка — Ctrl+C.")
    try:
        while supervisor.running:
            time.sleep(1.0)
    except KeyboardInterrupt:
        _out("Остановка…")
    finally:
        supervisor.stop()
    return 0


def cmd_gui(core: Strazh, args: argparse.Namespace) -> int:
    from strazh.gui.app import main as gui_main

    return gui_main()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="strazh",
        description=f"{APP_NAME} — запрет запуска и установки нежелательного и шпионского ПО",
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    parser.add_argument(
        "--dry-run-enforcer",
        action="store_true",
        help="работать без изменений в системе (для проверки на любой машине)",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("status", help="состояние защиты и каталога").set_defaults(func=cmd_status)

    p_list = sub.add_parser("list", help="список целей")
    p_list.add_argument("--all", action="store_true", help="показать и выключенные")
    p_list.add_argument("--category", choices=sorted(CATEGORIES), help="только этот раздел")
    p_list.add_argument("--search", help="искать по названию, издателю или коду")
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", help="подробности о цели")
    p_show.add_argument("id")
    p_show.set_defaults(func=cmd_show)

    p_apply = sub.add_parser("apply", help="включить защиту")
    p_apply.add_argument("--dry-run", action="store_true", help="показать план, ничего не меняя")
    p_apply.add_argument("-v", "--verbose", action="store_true", help="перечислить все изменения")
    p_apply.set_defaults(func=cmd_apply)

    sub.add_parser("revert", help="выключить защиту и снять все изменения").set_defaults(
        func=cmd_revert
    )
    sub.add_parser("scan", help="найти цели среди установленного и запущенного").set_defaults(
        func=cmd_scan
    )

    p_check = sub.add_parser("check", help="проверить один файл")
    p_check.add_argument("path")
    p_check.set_defaults(func=cmd_check)

    p_add = sub.add_parser("add", help="добавить свою цель")
    p_add.add_argument("name", help="название программы")
    p_add.add_argument("--exe", action="append", default=[], required=True, help="имя файла")
    p_add.add_argument("--category", default="other", choices=sorted(CATEGORIES))
    p_add.set_defaults(func=cmd_add)

    p_enable = sub.add_parser("enable", help="включить цель")
    p_enable.add_argument("id")
    p_enable.set_defaults(func=cmd_toggle, enable=True)

    p_disable = sub.add_parser("disable", help="выключить цель")
    p_disable.add_argument("id")
    p_disable.set_defaults(func=cmd_toggle, enable=False)

    p_journal = sub.add_parser("journal", help="последние события")
    p_journal.add_argument("-n", "--number", type=int, default=40)
    p_journal.set_defaults(func=cmd_journal)

    sub.add_parser("watch", help="запустить фонового стража").set_defaults(func=cmd_watch)
    sub.add_parser("gui", help="открыть окно").set_defaults(func=cmd_gui)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    core = Strazh(dry_run=args.dry_run_enforcer)
    return int(args.func(core, args))


if __name__ == "__main__":
    raise SystemExit(main())
