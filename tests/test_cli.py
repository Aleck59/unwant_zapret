"""Проверки командной строки: коды возврата и то, что попадает в вывод."""

from __future__ import annotations

from pathlib import Path

from strazh.cli import main


def run(capsys, *args: str) -> tuple[int, str]:
    code = main(["--dry-run-enforcer", *args])
    return code, capsys.readouterr().out


def test_status(home: Path, capsys) -> None:
    code, out = run(capsys, "status")
    assert code == 0
    assert "Целей в каталоге" in out
    assert "Защита:" in out


def test_list_filters_by_category(home: Path, capsys) -> None:
    code, out = run(capsys, "list", "--category", "stalkerware")
    assert code == 0
    assert "mspy" in out
    assert "qihoo-360" not in out


def test_list_search(home: Path, capsys) -> None:
    _, out = run(capsys, "list", "--search", "360")
    assert "qihoo-360" in out


def test_show_unknown_target(home: Path, capsys) -> None:
    code, out = run(capsys, "show", "нет-такой")
    assert code == 1
    assert "не найдена" in out


def test_apply_dry_run_changes_nothing(home: Path, capsys) -> None:
    code, out = run(capsys, "apply", "--dry-run")
    assert code == 0
    assert "без изменений" in out

    from strazh.app import Strazh

    assert Strazh(dry_run=True).protection_on is False


def test_apply_then_revert(home: Path, capsys) -> None:
    assert run(capsys, "apply")[0] == 0
    from strazh.app import Strazh

    assert Strazh(dry_run=True).protection_on is True
    assert run(capsys, "revert")[0] == 0
    assert Strazh(dry_run=True).protection_on is False


def test_add_then_check(home: Path, tmp_path: Path, capsys) -> None:
    code, out = run(capsys, "add", "Моя гадость", "--exe", "mybad.exe")
    assert code == 0
    assert "Добавлено" in out

    suspect = tmp_path / "mybad.exe"
    suspect.write_bytes(b"MZ")
    code, out = run(capsys, "check", str(suspect))
    assert code == 1
    assert "ЗАПРЕЩЁН" in out


def test_check_of_missing_file(home: Path, capsys) -> None:
    code, out = run(capsys, "check", "/нет/такого/файла.exe")
    assert code == 2
    assert "Файла нет" in out


def test_enable_disable(home: Path, capsys) -> None:
    assert run(capsys, "disable", "qihoo-360")[0] == 0
    out = run(capsys, "list")[1]
    assert "qihoo-360" not in out
    assert run(capsys, "enable", "qihoo-360")[0] == 0
    assert "qihoo-360" in run(capsys, "list")[1]


def test_journal(home: Path, capsys) -> None:
    run(capsys, "apply")
    code, out = run(capsys, "journal", "-n", "5")
    assert code == 0
    assert "защита включена" in out


def test_no_command_prints_help(home: Path, capsys) -> None:
    code = main([])
    assert code == 0
    assert "usage" in capsys.readouterr().out.lower()
