"""Проверки правки hosts.

Файл общий для всей машины, поэтому от механизма требуется ровно одно: не
задеть ничего, кроме собственного блока, и уметь убрать его целиком.
"""

from __future__ import annotations

from pathlib import Path

from strazh.core.models import Action, MatchSpec, Target
from strazh.core.state import State
from strazh.enforce.windows.hostsfile import (
    BEGIN,
    END,
    HostsMechanism,
    build_block,
    render,
    strip_block,
)

ORIGINAL = "127.0.0.1 localhost\n::1 localhost\n# чужой комментарий\n10.0.0.1 nas.local\n"


def target(domains: tuple[str, ...]) -> Target:
    return Target(
        id="t",
        name="T",
        match=MatchSpec(domains=domains),
        actions=(Action.BLOCK_DOMAINS,),
    )


def test_block_covers_www_too() -> None:
    block = build_block(["example.com"])
    assert "0.0.0.0 example.com" in block
    assert "0.0.0.0 www.example.com" in block


def test_www_domain_is_not_doubled() -> None:
    assert build_block(["www.example.com"]).count("www.example.com") == 1


def test_render_keeps_foreign_lines() -> None:
    result = render(ORIGINAL, ["bad.example"])
    assert "10.0.0.1 nas.local" in result
    assert "# чужой комментарий" in result
    assert BEGIN in result and END in result


def test_strip_returns_the_original() -> None:
    with_block = render(ORIGINAL, ["bad.example"])
    assert strip_block(with_block).strip() == ORIGINAL.strip()


def test_repeated_render_does_not_stack_blocks() -> None:
    once = render(ORIGINAL, ["a.example"])
    twice = render(once, ["a.example", "b.example"])
    assert twice.count(BEGIN) == 1
    assert "b.example" in twice


def test_apply_and_revert_round_trip(tmp_path: Path, monkeypatch) -> None:
    hosts = tmp_path / "hosts"
    hosts.write_text(ORIGINAL, encoding="utf-8")
    monkeypatch.setenv("STRAZH_HOSTS_FILE", str(hosts))

    mechanism = HostsMechanism(hosts)
    state = State()
    result = mechanism.apply([target(("bad.example",))], state)
    assert result.ok and result.count == 1
    assert "0.0.0.0 bad.example" in hosts.read_text(encoding="utf-8")

    mechanism.revert(state)
    assert hosts.read_text(encoding="utf-8").strip() == ORIGINAL.strip()
    assert state.by_mechanism("hosts") == []


def test_apply_twice_keeps_one_backup(tmp_path: Path) -> None:
    hosts = tmp_path / "hosts"
    hosts.write_text(ORIGINAL, encoding="utf-8")
    mechanism = HostsMechanism(hosts)
    state = State()
    mechanism.apply([target(("a.example",))], state)
    mechanism.apply([target(("a.example", "b.example"))], state)
    saved = [c for c in state.by_mechanism("hosts") if c.key == "__file__"]
    assert len(saved) == 1
    assert BEGIN not in (saved[0].previous or "")
