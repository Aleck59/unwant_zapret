"""Проверки обновления.

Программа ставится с правами системы, поэтому «скачать и запустить» здесь —
самое опасное, что она делает. Проверяется прежде всего то, при каких
условиях она откажется: чужой адрес, отсутствующая или несошедшаяся сумма,
неправдоподобный размер.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from strazh import update as upd
from strazh.update import (
    Update,
    UpdateError,
    is_newer,
    parse_sums,
    parse_version,
    pick_asset,
    update_from_release,
)


def release(tag: str = "v2.0.0", assets: list[dict] | None = None) -> dict:
    if assets is None:
        assets = [
            {
                "name": "strazh-setup-v2.0.0.exe",
                "browser_download_url": "https://github.com/Aleck59/unwant_zapret/releases/download/v2.0.0/strazh-setup-v2.0.0.exe",
                "size": 30 * 1024 * 1024,
            },
            {
                "name": "SHA256SUMS.txt",
                "browser_download_url": "https://github.com/Aleck59/unwant_zapret/releases/download/v2.0.0/SHA256SUMS.txt",
                "size": 200,
            },
        ]
    return {"tag_name": tag, "name": f"Страж {tag}", "body": "заметки", "assets": assets}


class TestVersions:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [("v1.2.3", (1, 2, 3)), ("1.2.3", (1, 2, 3)), ("v2", (2, 0, 0)), ("v1.10", (1, 10, 0))],
    )
    def test_parse(self, text: str, expected: tuple[int, int, int]) -> None:
        assert parse_version(text) == expected

    def test_nonsense_is_zero(self) -> None:
        assert parse_version("непонятно") == (0, 0, 0)

    def test_ordering(self) -> None:
        assert is_newer("v1.2.0", "1.1.9")
        assert is_newer("v1.10.0", "1.9.0"), "числа, а не строки"
        assert not is_newer("v1.0.0", "1.0.0")
        assert not is_newer("v0.9.0", "1.0.0")


class TestAssetChoice:
    def test_installer_wins_over_archive(self) -> None:
        assets = [{"name": "strazh.zip"}, {"name": "strazh-setup.exe"}]
        chosen = pick_asset(assets)
        assert chosen is not None and chosen["name"] == "strazh-setup.exe"

    def test_archive_when_no_installer(self) -> None:
        chosen = pick_asset([{"name": "strazh.zip"}])
        assert chosen is not None and chosen["name"] == "strazh.zip"

    def test_nothing_suitable(self) -> None:
        assert pick_asset([{"name": "SHA256SUMS.txt"}]) is None


class TestReleaseParsing:
    def test_newer_release_is_reported(self) -> None:
        found = update_from_release(release(), current="1.1.0")
        assert found is not None
        assert found.version == "2.0.0"
        assert found.asset_name.endswith(".exe")
        assert found.sums_url

    def test_same_version_is_silence(self) -> None:
        assert update_from_release(release("v1.1.0"), current="1.1.0") is None

    def test_older_version_is_silence(self) -> None:
        assert update_from_release(release("v1.0.0"), current="1.1.0") is None

    def test_release_without_files_is_silence(self) -> None:
        assert update_from_release(release(assets=[]), current="1.0.0") is None

    def test_absurd_size_is_refused(self) -> None:
        assets = [
            {"name": "big.exe", "browser_download_url": "https://github.com/x", "size": 10**10}
        ]
        with pytest.raises(UpdateError, match="велик"):
            update_from_release(release(assets=assets), current="1.0.0")


class TestSums:
    def test_parse(self) -> None:
        text = "a" * 64 + "  strazh-setup.exe\n" + "b" * 64 + " *archive.zip\n"
        sums = parse_sums(text)
        assert sums["strazh-setup.exe"] == "a" * 64
        assert sums["archive.zip"] == "b" * 64

    def test_junk_lines_are_skipped(self) -> None:
        assert parse_sums("мусор\n\nкороткая сумма  x.exe\n") == {}


class TestDownloadGuards:
    """Самое важное: при каких условиях программа откажется ставить."""

    def test_foreign_host_is_refused(self, tmp_path: Path) -> None:
        found = Update(
            version="2.0.0",
            tag="v2.0.0",
            name="",
            notes="",
            page="",
            asset_name="x.exe",
            asset_url="https://зловред.example/x.exe",
            asset_size=10,
            sums_url="https://зловред.example/SHA256SUMS.txt",
        )
        with pytest.raises(UpdateError, match="не принадлежит GitHub"):
            upd.download(found, tmp_path)

    def test_release_without_sums_is_refused(self, tmp_path: Path) -> None:
        found = update_from_release(
            release(
                assets=[
                    {"name": "s.exe", "browser_download_url": "https://github.com/a", "size": 5}
                ]
            ),
            current="1.0.0",
        )
        assert found is not None
        with pytest.raises(UpdateError, match="контрольных сумм"):
            upd.download(found, tmp_path)

    def test_mismatched_sum_deletes_the_file(self, tmp_path: Path, monkeypatch) -> None:
        payload = "поддельная сборка".encode()
        wrong = "0" * 64

        def fake_fetch(url: str, **kwargs: object) -> bytes:
            return f"{wrong}  strazh-setup.exe\n".encode()

        class FakeResponse:
            def __init__(self) -> None:
                self._sent = False

            def read(self, size: int) -> bytes:
                if self._sent:
                    return b""
                self._sent = True
                return payload

            def __enter__(self):
                return self

            def __exit__(self, *args: object) -> None:
                return None

        monkeypatch.setattr(upd, "_fetch", fake_fetch)
        monkeypatch.setattr(upd.urllib.request, "urlopen", lambda *a, **k: FakeResponse())

        found = Update(
            version="2.0.0",
            tag="v2.0.0",
            name="",
            notes="",
            page="",
            asset_name="strazh-setup.exe",
            asset_url="https://github.com/Aleck59/unwant_zapret/releases/download/v2/strazh-setup.exe",
            asset_size=len(payload),
            sums_url="https://github.com/Aleck59/unwant_zapret/releases/download/v2/SHA256SUMS.txt",
        )
        with pytest.raises(UpdateError, match="не совпала"):
            upd.download(found, tmp_path)
        assert not (tmp_path / "strazh-setup.exe").exists(), "несошедшийся файл остался на диске"

    def test_matching_sum_is_accepted(self, tmp_path: Path, monkeypatch) -> None:
        payload = "настоящая сборка".encode()
        digest = hashlib.sha256(payload).hexdigest()

        class FakeResponse:
            def __init__(self) -> None:
                self._sent = False

            def read(self, size: int) -> bytes:
                if self._sent:
                    return b""
                self._sent = True
                return payload

            def __enter__(self):
                return self

            def __exit__(self, *args: object) -> None:
                return None

        monkeypatch.setattr(upd, "_fetch", lambda url, **k: f"{digest}  s.exe\n".encode())
        monkeypatch.setattr(upd.urllib.request, "urlopen", lambda *a, **k: FakeResponse())

        found = Update(
            version="2.0.0",
            tag="v2.0.0",
            name="",
            notes="",
            page="",
            asset_name="s.exe",
            asset_url="https://github.com/Aleck59/unwant_zapret/releases/download/v2/s.exe",
            asset_size=len(payload),
            sums_url="https://github.com/Aleck59/unwant_zapret/releases/download/v2/SHA256SUMS.txt",
        )
        saved = upd.download(found, tmp_path)
        assert saved.read_bytes() == payload


def test_check_survives_a_broken_answer(monkeypatch) -> None:
    monkeypatch.setattr(upd, "_fetch", lambda url, **k: "{это не json".encode())
    with pytest.raises(UpdateError, match="разобрать"):
        upd.check("1.0.0")


def test_check_reports_a_real_release(monkeypatch) -> None:
    monkeypatch.setattr(upd, "_fetch", lambda url, **k: json.dumps(release()).encode())
    found = upd.check("1.0.0")
    assert found is not None and found.tag == "v2.0.0"
