"""Проверки счёта плана: что именно попадёт в реестр и брандмауэр."""

from __future__ import annotations

from strazh.core.models import Action, MatchSpec, Target
from strazh.enforce import plan


def t(**kwargs) -> Target:
    return Target(
        id=kwargs.pop("id", "x"),
        name=kwargs.pop("name", "X"),
        match=kwargs.pop("match", MatchSpec()),
        actions=kwargs.pop("actions", (Action.BLOCK_EXEC, Action.BLOCK_INSTALL)),
        **kwargs,
    )


class TestIfeo:
    def test_only_exact_names(self) -> None:
        """Ключ перехвата называется именем файла: маске там места нет."""
        ops = plan.plan_ifeo([t(match=MatchSpec(executables=("a.exe", "b*.exe")))])
        assert [op.key for op in ops] == ["a.exe"]

    def test_generic_names_are_skipped(self) -> None:
        ops = plan.plan_ifeo([t(match=MatchSpec(executables=("setup.exe", "360tray.exe")))])
        assert [op.key for op in ops] == ["360tray.exe"]

    def test_protected_names_never_reach_the_plan(self) -> None:
        ops = plan.plan_ifeo([t(match=MatchSpec(executables=("lsass.exe",)))])
        assert ops == []

    def test_installers_included_only_with_the_action(self) -> None:
        with_action = t(match=MatchSpec(installers=("thing.exe",)))
        without = t(
            id="y", match=MatchSpec(installers=("thing.exe",)), actions=(Action.BLOCK_EXEC,)
        )
        assert len(plan.plan_ifeo([with_action])) == 1
        assert plan.plan_ifeo([without]) == []

    def test_no_duplicates_across_targets(self) -> None:
        a = t(id="a", match=MatchSpec(executables=("same.exe",)))
        b = t(id="b", match=MatchSpec(executables=("SAME.EXE",)))
        assert len(plan.plan_ifeo([a, b])) == 1

    def test_non_executable_extension_skipped(self) -> None:
        assert plan.plan_ifeo([t(match=MatchSpec(executables=("readme.txt",)))]) == []


class TestSrp:
    def test_masks_go_to_path_rules(self) -> None:
        ops = plan.plan_srp([t(match=MatchSpec(executables=("a.exe", "b*.exe")))])
        assert [op.key for op in ops] == ["b*.exe"]

    def test_paths_are_included(self) -> None:
        ops = plan.plan_srp([t(match=MatchSpec(paths=("*\\360\\*",)))])
        assert [op.key for op in ops] == ["*\\360\\*"]

    def test_generic_name_is_not_promoted_to_a_path_rule(self) -> None:
        assert plan.plan_srp([t(match=MatchSpec(installers=("setup.exe",)))]) == []


class TestOtherMechanisms:
    def test_hosts_only_with_the_action(self) -> None:
        yes = t(match=MatchSpec(domains=("a.example",)), actions=(Action.BLOCK_DOMAINS,))
        no = t(id="n", match=MatchSpec(domains=("b.example",)), actions=(Action.BLOCK_EXEC,))
        assert [op.key for op in plan.plan_hosts([yes, no])] == ["a.example"]

    def test_hosts_skips_broken_entries(self) -> None:
        target = t(
            match=MatchSpec(domains=("ok.example", "http://bad.example", "with space")),
            actions=(Action.BLOCK_DOMAINS,),
        )
        assert [op.key for op in plan.plan_hosts([target])] == ["ok.example"]

    def test_hashes_must_be_full_length(self) -> None:
        target = t(match=MatchSpec(sha256=("a" * 64, "short")))
        assert [op.key for op in plan.plan_hashes([target])] == ["a" * 64]

    def test_services_and_tasks_need_the_action(self) -> None:
        target = t(
            match=MatchSpec(services=("svc",), scheduled_tasks=("task",)),
            actions=(Action.NEUTRALIZE_SERVICES,),
        )
        assert [op.key for op in plan.plan_services([target])] == ["svc"]
        assert [op.key for op in plan.plan_tasks([target])] == ["task"]
        assert plan.plan_services([t(match=MatchSpec(services=("svc",)))]) == []

    def test_plan_all_covers_every_mechanism(self) -> None:
        keys = set(plan.plan_all([]))
        assert keys == {"ifeo", "srp", "hash", "firewall", "hosts", "service", "task"}
