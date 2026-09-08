"""Проверки групповой политики.

Испорченный `Registry.pol` — это испорченная политика всей машины, и человек
заметит это не сразу. Поэтому и разбор формата, и сборка записей проверяются
подробно, а сам механизм — на настоящих файлах во временной папке.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from strazh.core.models import Action, MatchSpec, Target
from strazh.core.state import State
from strazh.enforce.windows import preg
from strazh.enforce.windows.gpo import (
    DISALLOW_LIST,
    EXPLORER_POLICY,
    GptVersion,
    GroupPolicyMechanism,
    build_machine_entries,
    build_user_entries,
    bump_gpt,
    read_gpt,
)
from strazh.enforce.windows.srp import BASE as SAFER_BASE
from strazh.enforce.windows.srp import rule_guid


def target(**kwargs) -> Target:
    return Target(
        id=kwargs.pop("id", "sample"),
        name=kwargs.pop("name", "Пример"),
        match=kwargs.pop("match", MatchSpec(executables=("bad.exe",), paths=("*\\bad\\*",))),
        actions=kwargs.pop("actions", (Action.BLOCK_EXEC, Action.BLOCK_INSTALL)),
        **kwargs,
    )


class TestPregFormat:
    def test_round_trip(self) -> None:
        entries = [
            preg.Entry.dword("Software\\A", "Number", 42),
            preg.Entry.text("Software\\A", "Line", "значение"),
            preg.Entry.text("Software\\B", "Path", "*\\360\\*", expand=True),
            preg.Entry.qword("Software\\B", "Stamp", 2**40),
        ]
        back = preg.loads(preg.dumps(entries))
        assert back == entries

    def test_header_is_written(self) -> None:
        blob = preg.dumps([preg.Entry.dword("K", "V", 1)])
        assert blob[:4] == b"PReg"
        assert struct.unpack_from("<I", blob, 4)[0] == 1

    def test_empty_file_is_empty_policy(self) -> None:
        assert preg.loads(b"") == []

    def test_strings_keep_their_terminator(self) -> None:
        """Без завершающего нуля Windows читает строку до первого нуля в
        соседней записи — то есть склеивает две настройки в одну."""
        entry = preg.Entry.text("K", "V", "abc")
        assert entry.data.endswith(b"\x00\x00")
        assert entry.as_text() == "abc"

    def test_dword_is_four_bytes_little_endian(self) -> None:
        assert preg.Entry.dword("K", "V", 1).data == b"\x01\x00\x00\x00"

    def test_foreign_file_is_refused_not_overwritten(self) -> None:
        with pytest.raises(preg.PregError, match="PReg"):
            preg.loads("это не политика".encode())

    def test_truncated_file_is_refused(self) -> None:
        blob = preg.dumps([preg.Entry.dword("K", "V", 1)])
        with pytest.raises(preg.PregError):
            preg.loads(blob[:-4])

    def test_future_version_is_refused(self) -> None:
        with pytest.raises(preg.PregError, match="версия"):
            preg.loads(b"PReg" + struct.pack("<I", 2))

    def test_trailing_zeroes_are_tolerated(self) -> None:
        blob = preg.dumps([preg.Entry.dword("K", "V", 1)]) + b"\x00\x00\x00\x00"
        assert len(preg.loads(blob)) == 1

    def test_without_keys_spares_foreign_settings(self) -> None:
        entries = [
            preg.Entry.dword("Software\\Policies\\Microsoft\\Windows\\Safer", "A", 1),
            preg.Entry.dword("Software\\Policies\\Microsoft\\Windows\\Safer\\X", "B", 1),
            preg.Entry.dword("Software\\Policies\\Чужая\\Программа", "C", 1),
        ]
        kept = preg.without_keys(entries, ("Software\\Policies\\Microsoft\\Windows\\Safer",))
        assert [e.key for e in kept] == ["Software\\Policies\\Чужая\\Программа"]

    def test_without_keys_does_not_match_by_prefix_of_a_name(self) -> None:
        """`...\\SaferSomethingElse` — чужой ключ, а не наш с хвостом."""
        entries = [preg.Entry.dword("Software\\Policies\\SaferSomethingElse", "A", 1)]
        assert preg.without_keys(entries, ("Software\\Policies\\Safer",)) == entries


class TestEntries:
    def test_machine_entries_declare_a_permissive_default(self) -> None:
        """Уровень по умолчанию обязан остаться «разрешено»: обратный порядок
        превратил бы обычный компьютер в терминал."""
        entries = build_machine_entries([target()])
        default = next(e for e in entries if e.value == "DefaultLevel")
        assert struct.unpack("<I", default.data)[0] == 0x40000

    def test_machine_entries_carry_the_path_rules(self) -> None:
        entries = build_machine_entries([target()])
        data = {e.key: e for e in entries if e.value == "ItemData"}
        assert any(e.as_text() == "*\\bad\\*" for e in data.values())
        assert all(rule_guid("*\\bad\\*") in k for k in data if "bad" in k.casefold())

    def test_rule_guid_is_stable(self) -> None:
        """Опознаватель выводится из маски, поэтому повторное применение
        переписывает то же правило, а не заводит второе такое же."""
        assert rule_guid("*\\360\\*") == rule_guid("*\\360\\*")
        assert rule_guid("*\\360\\*") != rule_guid("*\\other\\*")

    def test_user_entries_are_the_disallow_run_policy(self) -> None:
        entries = build_user_entries([target()])
        assert any(e.key == EXPLORER_POLICY and e.value == "DisallowRun" for e in entries)
        names = [e.as_text() for e in entries if e.key == DISALLOW_LIST]
        assert names == ["bad.exe"]

    def test_user_entries_are_empty_without_names(self) -> None:
        assert build_user_entries([target(match=MatchSpec(paths=("*\\x\\*",)))]) == []

    def test_system_files_never_reach_the_policy(self) -> None:
        entries = build_machine_entries([target(match=MatchSpec(executables=("*.exe",)))])
        text = " ".join(e.as_text() for e in entries)
        assert "lsass" not in text.casefold()


class TestGptVersion:
    def test_pack_and_unpack(self) -> None:
        version = GptVersion(user=3, machine=7)
        assert GptVersion.unpack(version.pack()) == version

    def test_bump_touches_only_what_changed(self) -> None:
        version = GptVersion(user=3, machine=7)
        assert version.bumped(machine=True, user=False) == GptVersion(user=3, machine=8)
        assert version.bumped(machine=False, user=True) == GptVersion(user=4, machine=7)

    def test_bump_writes_the_extension_names(self, tmp_path: Path) -> None:
        """Без объявленного расширения Windows не станет читать Registry.pol
        вовсе — файл будет лежать и не работать."""
        path = tmp_path / "gpt.ini"
        bump_gpt(path, machine=True, user=True)
        parser = read_gpt(path)
        assert "35378EAC" in parser.get("General", "gPCMachineExtensionNames")
        assert "35378EAC" in parser.get("General", "gPCUserExtensionNames")
        assert int(parser.get("General", "Version")) == GptVersion(user=1, machine=1).pack()

    def test_existing_version_grows(self, tmp_path: Path) -> None:
        path = tmp_path / "gpt.ini"
        path.write_text("[General]\nVersion=65540\n", encoding="utf-8")
        bump_gpt(path, machine=True, user=True)
        assert int(read_gpt(path).get("General", "Version")) == GptVersion(user=2, machine=5).pack()

    def test_broken_gpt_does_not_stop_us(self, tmp_path: Path) -> None:
        path = tmp_path / "gpt.ini"
        path.write_text("не ini вовсе", encoding="utf-8")
        bump_gpt(path, machine=True, user=True)
        assert int(read_gpt(path).get("General", "Version")) > 0


class TestMechanism:
    @pytest.fixture
    def mechanism(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("STRAZH_GPO_ROOT", str(tmp_path / "GroupPolicy"))
        # gpupdate на этой машине не существует; механизм обязан пережить это.
        return GroupPolicyMechanism(backup_dir=tmp_path / "backup")

    def test_apply_writes_both_files(self, mechanism, tmp_path: Path) -> None:
        from strazh.enforce.windows import gpo

        state = State()
        result = mechanism.apply([target()], state)
        assert result.ok and result.count > 0
        assert gpo.machine_pol().exists()
        assert gpo.user_pol().exists()
        assert gpo.gpt_ini().exists()

        machine = preg.loads(gpo.machine_pol().read_bytes())
        assert any(e.key.startswith(SAFER_BASE) for e in machine)

    def test_foreign_settings_survive(self, mechanism) -> None:
        from strazh.enforce.windows import gpo

        foreign = preg.Entry.dword("Software\\Policies\\Чужая", "Настройка", 1)
        gpo.machine_pol().parent.mkdir(parents=True, exist_ok=True)
        gpo.machine_pol().write_bytes(preg.dumps([foreign]))

        state = State()
        mechanism.apply([target()], state)
        assert foreign in preg.loads(gpo.machine_pol().read_bytes())

    def test_revert_restores_the_previous_file(self, mechanism) -> None:
        from strazh.enforce.windows import gpo

        foreign = preg.Entry.dword("Software\\Policies\\Чужая", "Настройка", 1)
        gpo.machine_pol().parent.mkdir(parents=True, exist_ok=True)
        before = preg.dumps([foreign])
        gpo.machine_pol().write_bytes(before)

        state = State()
        mechanism.apply([target()], state)
        mechanism.revert(state)
        assert gpo.machine_pol().read_bytes() == before
        assert state.by_mechanism("gpo") == []

    def test_revert_removes_a_file_we_created(self, mechanism) -> None:
        from strazh.enforce.windows import gpo

        state = State()
        mechanism.apply([target()], state)
        assert gpo.machine_pol().exists()
        mechanism.revert(state)
        assert not gpo.machine_pol().exists()

    def test_applying_twice_does_not_double_the_rules(self, mechanism) -> None:
        from strazh.enforce.windows import gpo

        state = State()
        mechanism.apply([target()], state)
        first = len(preg.loads(gpo.machine_pol().read_bytes()))
        mechanism.apply([target()], state)
        assert len(preg.loads(gpo.machine_pol().read_bytes())) == first

    def test_backup_is_taken_once(self, mechanism) -> None:
        from strazh.enforce.windows import gpo

        gpo.machine_pol().parent.mkdir(parents=True, exist_ok=True)
        original = preg.dumps([preg.Entry.dword("Software\\Policies\\Чужая", "A", 1)])
        gpo.machine_pol().write_bytes(original)

        state = State()
        mechanism.apply([target()], state)
        mechanism.apply([target()], state)
        mechanism.revert(state)
        assert gpo.machine_pol().read_bytes() == original

    def test_corrupt_policy_is_not_overwritten(self, mechanism) -> None:
        """Чужой повреждённый файл трогать нельзя: мы не знаем, что там было,
        и не сможем это вернуть."""
        from strazh.enforce.windows import gpo

        gpo.machine_pol().parent.mkdir(parents=True, exist_ok=True)
        gpo.machine_pol().write_bytes("мусор, но чей-то".encode())

        result = mechanism.apply([target()], State())
        assert not result.ok
        assert gpo.machine_pol().read_bytes() == "мусор, но чей-то".encode()
