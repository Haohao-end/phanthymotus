"""V44V machine inventory, approval guidance, and runtime image regressions.

All Agent Core and GitHub boundaries are mocked. Inventory assertions consume
the production machine inventory interface; they never probe physical machines.
"""

from __future__ import annotations

import asyncio
import copy
import html
import inspect
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from ..github_state_proxy import _build_hidden_state_body, _build_history_block
from .. import comments
from ..commands import parse_command
from ..machine_inventory import get_machine_inventory
from ..models import BuildInfo, MachineInfo
from ..service import (
    RUNTIME_IMAGE_CHECK_INTERVAL_SECONDS,
    DeployController,
    DeployControllerError,
)


REPO = "test-owner/phanthymotus"
HEAD = "a" * 40


def _field(record, *names, default=None):
    return comments._record_value(record, *names, default=default)


def _machine_rows():
    return get_machine_inventory()


def _machine_alias(record):
    value = _field(record, "alias", "machine_alias", "machine_name", "name")
    return value.strip() if isinstance(value, str) else ""


def _primary_ip(record):
    value = _field(record, "main_ip", "primary_ip", "node_host", "ip")
    return value.strip() if isinstance(value, str) else ""


def _label(record):
    return " ".join(
        str(_field(record, name, default=""))
        for name in ("brand", "model", "alias", "machine_alias", "machine_name", "name")
    ).casefold()


def _find_machine(rows, token):
    token = token.casefold()
    matches = [row for row in rows if token in _label(row)]
    assert len(matches) == 1, f"expected one inventory row containing {token!r}"
    return matches[0]


def _component(component_id="a" * 16, **overrides):
    component = {
        "component_id": component_id,
        "target": "perception",
        "driver_path": "",
        "variant": "5.11",
        "review_image_tag": "registry.example/perception:v1",
        "image_ref": "registry.example/perception@sha256:" + "a" * 64,
        "resolved_platform": "linux/arm64",
        "runtime_id": "perception",
    }
    component.update(overrides)
    return component


def _core_component(component_id="c" * 16, image_ref="registry.example/core:v1"):
    return _component(
        component_id,
        target="core",
        driver_path="",
        image_ref=image_ref,
        review_image_tag="registry.example/core:v1",
        runtime_id="core",
    )


def _machine(alias, ip, *, node_id=None, owners=None, targets=None, variants=None):
    return MachineInfo(
        alias=alias,
        node_id=node_id or f"node-{alias}",
        owners=list(owners or []),
        node_host=ip,
        targets=list(targets or ["perception"]),
        platforms=["linux/arm64"],
        variants=list(variants or ["5.11"]),
    )


def _runtime_check(machine, ip, component, status, observed_image, checked_at=None):
    return {
        "machine": machine,
        "ip": ip,
        "component_id": component["component_id"],
        "runtime_id": component["runtime_id"],
        "target_image": component["image_ref"],
        "observed_image": observed_image,
        "status": status,
        "checked_at": checked_at or datetime.now(timezone.utc).isoformat(),
    }


def _valid_review_evidence():
    return {
        "build_comment_id": 101,
        "build_comment_updated_at": "2026-11-09T00:00:00Z",
        "commit_prefix": HEAD[:12],
        "resolved_head_sha": HEAD,
        "test_comment_id": 102,
        "test_comment_updated_at": "2026-11-09T00:00:00Z",
        "code_review_comment_id": 103,
        "code_review_comment_updated_at": "2026-11-09T00:00:00Z",
        "review_author_id": "7950763",
    }


@pytest.fixture
def controller(config, policy):
    """Use the repository's shared Config/Policy fixtures and mock I/O."""
    return DeployController(
        config,
        MagicMock(),
        policy,
        MagicMock(),
        agent_core_factory=lambda _node_id: None,
    )


def _set_repo_machines(controller, machines):
    by_alias = {machine.alias: machine for machine in machines}
    tokens = dict(getattr(controller.config, "agent_core_tokens", {}) or {})
    tokens.update({machine.alias: "offline-test-token" for machine in machines})
    controller.config.agent_core_tokens = tokens
    controller.policy.repo_policy_status = MagicMock(return_value={
        "status": "configured",
        "authorized": True,
        "machines_configured": True,
        "reviewers_configured": True,
        "missing_files": [],
    })
    controller.policy.get_machines = MagicMock(return_value=list(machines))
    controller.policy.get_machine = MagicMock(
        side_effect=lambda alias, repo=None: by_alias.get(alias)
    )
    return by_alias


def _physical_record(alias, ip, *, node_id=None, platform_status="verified",
                     platforms=("linux/arm64",), platform_verified=True,
                     number="001"):
    raw = {
        "number": number,
        "alias": alias,
        "brand": "test",
        "model": alias,
        "primary_ip": ip,
        "secondary_ips": [],
        "owners": [],
    }
    return {
        "alias": alias,
        "primary_ip": ip,
        "node_id": node_id or "",
        "platform_status": platform_status,
        "platforms": list(platforms),
        "platform_verified": platform_verified,
        "raw": raw,
    }


def _render_service_machine_context(components, groups, context):
    return html.unescape(comments.deploy_requested(
        REPO,
        1,
        HEAD,
        components,
        groups,
        machine_inventory=context["machine_inventory"],
        machine_diagnostics=context["machine_diagnostics"],
        repository_policy_status=context["repository_policy_status"],
    ))


def _runtime_state(controller, components, deployments, runtime_checks=None):
    state = controller._init_hidden_state(
        head_sha=HEAD,
        status="testing",
        review_evidence=_valid_review_evidence(),
        components=components,
        deployments=deployments,
    )
    state["round_id"] = f"{HEAD}-1"
    state["runtime_checks"] = list(runtime_checks or [])
    return state


async def _scan_core_runtime(controller, image_status):
    target_image = "registry.example/core:v1"
    component = _core_component(image_ref=target_image)
    machine = _machine(
        "core-runtime-machine", "10.90.0.51", owners=["test-owner"],
        targets=["core"],
    )
    _set_repo_machines(controller, [machine])
    controller._physical_machine_inventory = MagicMock(return_value=[])
    controller.proxy.get_pr = AsyncMock(return_value={
        "state": "open", "merged": False, "draft": False,
        "head": {"sha": HEAD},
    })
    controller._fresh_review_evidence_matches_state = AsyncMock(return_value=True)
    controller._write_lifecycle_with_history = AsyncMock(return_value=True)
    controller._post_bound_notice = AsyncMock(return_value=True)
    controller.proxy.find_trusted_lifecycle_comment = AsyncMock(
        return_value={"body": "summary"},
    )
    core = MagicMock()
    core.core_update_check = AsyncMock(return_value=image_status)
    controller._core_for_node = AsyncMock(return_value=core)
    state = _runtime_state(
        controller, [component], [{
            "machine": machine.alias, "ip": machine.node_host,
            "component_ids": [component["component_id"]], "phase": "deployed",
        }],
    )
    result = await controller._reconcile_runtime_image_checks(
        REPO, 51, state, {"head": {"sha": HEAD}}, force=True,
    )
    return result, component, machine


def _build(component_id="a" * 16):
    return BuildInfo(
        target="perception",
        driver_path="",
        variant="5.11",
        success=True,
        image_tag="registry.example/perception:v1",
        deployable=True,
        component_id=component_id,
    )


def _authorized_policy(aliases, **overrides):
    status = {
        "authorized": True,
        "machines_configured": True,
        "reviewers_configured": True,
        "authorized_machines": list(aliases),
        "missing_files": [],
    }
    status.update(overrides)
    return status


def _safe_diagnostic(machine, component_id="a" * 16, **overrides):
    diagnostic = {
        "alias": machine["alias"],
        "ip": machine["primary_ip"],
        "repository_authorized": True,
        "identity_confirmed": True,
        "agent_core_credentials_available": True,
        "platform_confirmed": True,
        "component_compatible": True,
        "component_ids": [component_id],
        "safe_to_approve": True,
    }
    diagnostic.update(overrides)
    return diagnostic


def _render_inventory(
    *, machines=None, diagnostics=None, policy_status=None, groups=None,
    runtime_checks=None, component=None,
):
    component = component or _component()
    return html.unescape(comments.deploy_requested(
        REPO,
        1,
        HEAD,
        [component],
        groups or [],
        machine_inventory=_machine_rows() if machines is None else machines,
        machine_diagnostics=diagnostics,
        repository_policy_status=policy_status or _authorized_policy([]),
        runtime_checks=runtime_checks,
    ))


def _runtime_section(markdown):
    start = markdown.index("### Runtime Image Status")
    end = markdown.index("### Workflow", start)
    return html.unescape(markdown[start:end])


def _render_runtime_status(status, observed_image, *, ip="10.90.0.20"):
    machine = {
        "number": "001", "alias": "runtime-machine", "brand": "test",
        "model": "runtime", "primary_ip": ip, "secondary_ips": [],
        "owners": ["runtime-owner"],
    }
    component = _component()
    diagnostic = _safe_diagnostic(
        machine, policy_owners=["runtime-owner"], primary_ip=ip,
        policy_node_host=ip, agent_core_credentials_configured=True,
        agent_core_status="available",
    )
    check = _runtime_check(
        machine["alias"], ip, component, status, observed_image,
    )
    check.update({
        "primary_ip": ip, "command_selector": ip,
        "identity_confirmed": True,
    })
    markdown = comments.deploy_requested(
        REPO,
        1,
        HEAD,
        [component],
        [{
            "alias": machine["alias"], "ip": ip, "primary_ip": ip,
            "node_host": ip, "node_id": "node-runtime-machine",
            "repo_authorized": True, "identity_confirmed": True,
            "approval_available": True, "ip_command_safe": True,
            "command_selector": ip, "owners": ["runtime-owner"],
            "component_ids": [component["component_id"]],
        }],
        machine_inventory=[machine],
        machine_diagnostics=[diagnostic],
        repository_policy_status=_authorized_policy([machine["alias"]]),
        runtime_checks=[check],
    )
    return _runtime_section(markdown)


def _runtime_case_records(
    alias, ip, component_ids, selector, *, owner="repo-owner",
    duplicate=False, identity_confirmed=True, safe_to_approve=None,
):
    if safe_to_approve is None:
        safe_to_approve = not duplicate
    machine = {
        "number": "001", "alias": alias, "brand": "test", "model": alias,
        "primary_ip": ip, "secondary_ips": [], "owners": ["inventory-owner"],
        "owner_status": "verified",
    }
    diagnostic = {
        "alias": alias,
        "primary_ip": ip,
        "ip": ip,
        "owners": ["负责人待配置"],
        "physical_owners": ["inventory-owner"],
        "policy_owners": [owner],
        "repository_authorized": True,
        "identity_confirmed": identity_confirmed,
        "agent_core_credentials_configured": True,
        "agent_core_credentials_available": True,
        "agent_core_status": "available",
        "platform_confirmed": True,
        "component_compatible": bool(component_ids),
        "component_ids": list(component_ids),
        "safe_to_approve": safe_to_approve,
        "duplicate_ip": duplicate,
    }
    group = {
        "alias": alias,
        "ip": ip,
        "primary_ip": ip,
        "node_host": ip,
        "owners": [owner],
        "repo_authorized": True,
        "identity_confirmed": identity_confirmed,
        "approval_available": True,
        "command_selector": selector,
        "component_ids": list(component_ids),
    }
    return machine, diagnostic, group


def _runtime_check_with_selector(machine, ip, component, status, observed_image,
                                 selector, *, identity_confirmed=True):
    check = _runtime_check(machine, ip, component, status, observed_image)
    check.update({
        "primary_ip": ip,
        "command_selector": selector,
        "identity_confirmed": identity_confirmed,
    })
    return check


def _render_runtime_lifecycle(
    components, groups, machines, diagnostics, checks, *, test_only=False,
):
    policy_status = _authorized_policy([group["alias"] for group in groups])
    policy_status["test_only"] = test_only
    return comments.deploy_requested(
        REPO, 1, HEAD, components, groups,
        machine_inventory=machines,
        machine_diagnostics=diagnostics,
        repository_policy_status=policy_status,
        runtime_checks=checks,
    )


def _render_runtime_checks(components, groups, machines, diagnostics, checks,
                           *, test_only=False, machine_context=None):
    return html.unescape(comments.runtime_image_checks_block(
        checks, components,
        machine_groups=groups,
        machine_inventory=machines,
        machine_diagnostics=diagnostics,
        machine_context=machine_context,
        test_only=test_only,
    ))


# ── Production physical inventory ────────────────────────────────────

def test_machine_inventory_contains_exactly_21_physical_machines():
    assert len(_machine_rows()) == 21


def test_machine_inventory_numbering_is_complete_001_through_021():
    rows = _machine_rows()
    numbers = [
        str(_field(row, "number", "index", "ordinal", "display_number", default=""))
        .strip().zfill(3)
        for row in rows
    ]
    assert sorted(numbers) == [f"{number:03d}" for number in range(1, 22)]


def test_machine_inventory_aliases_are_unique_case_insensitively():
    aliases = [_machine_alias(row).casefold() for row in _machine_rows()]
    assert all(aliases)
    assert len(aliases) == len(set(aliases)) == 21


def test_machine_inventory_primary_ips_match_the_user_supplied_21_machine_list():
    """Pin the complete V44D supplied alias→primary-IP list."""
    expected = {
        "beijing-g1-001": "10.100.129.168",
        "unitree-r1-002": "10.100.130.6",
        "unitree-go2-003": "10.100.129.166",
        "unitree-go1-004": "10.100.130.4",
        "tianyi2-005": "10.100.129.72",
        "bumi-006": "10.100.128.245",
        "m20pro-007": "10.110.15.219",
        "t800-008": "10.110.10.96",
        "shanghai-g1-009": "10.110.12.110",
        "q5-010": "10.100.128.225",
        "x2-011": "10.100.129.195",
        "adam-pro-012": "10.100.128.154",
        "rm75-013": "10.100.130.37",
        "as2w-014": "10.100.129.146",
        "r1-blue-015": "10.100.129.73",
        "a3ultra-016": "10.100.129.135",
        "u1pro-017": "10.100.129.28",
        "piper-018": "10.110.10.46",
        "tron2-019": "",
        "s10pro-020": "10.100.128.127",
        "c23-021": "10.100.128.229",
    }
    actual = {_machine_alias(row): _primary_ip(row) for row in _machine_rows()}
    assert actual == expected


def test_bumi_primary_ip_is_the_configured_primary_address():
    bumi = _find_machine(_machine_rows(), "bumi")
    assert _machine_alias(bumi) == "bumi-006"
    assert _primary_ip(bumi) == "10.100.128.245"


def test_rm75_primary_ip_is_not_taken_from_an_auxiliary_address():
    rm75 = _find_machine(_machine_rows(), "rm75")
    assert _machine_alias(rm75) == "rm75-013"
    assert _primary_ip(rm75) == "10.100.130.37"


def test_x2_uses_its_canonical_machine_alias():
    x2 = _find_machine(_machine_rows(), "x2")
    assert _machine_alias(x2) == "x2-011"
    assert "x2-012" in x2["legacy_aliases"]


def test_unlisted_p200_alias_is_not_added_to_the_physical_inventory():
    rows = _machine_rows()
    labels = " ".join(
        " ".join([
            _machine_alias(row), str(row.get("model", "")),
            *row.get("legacy_aliases", []),
        ]).casefold()
        for row in rows
    )
    assert "p200" not in labels
    assert "p200pro-011" not in labels


def test_r1_blue_white_machine_is_distinct_from_bumi():
    rows = _machine_rows()
    r1 = _find_machine(rows, "r1蓝白")
    bumi = _find_machine(rows, "bumi")
    assert _machine_alias(r1) == "r1-blue-015"
    assert _machine_alias(r1) != _machine_alias(bumi)
    assert _primary_ip(r1) != _primary_ip(bumi)
    assert r1["model"] == "R1蓝白"


def test_tron2_and_rm75_are_distinct_physical_machines():
    rows = _machine_rows()
    tron2 = _find_machine(rows, "tron2上海")
    rm75 = _find_machine(rows, "rm75-6f-v")
    assert _machine_alias(tron2) == "tron2-019"
    assert _machine_alias(rm75) == "rm75-013"
    assert _machine_alias(tron2) != _machine_alias(rm75)
    assert _primary_ip(tron2) != _primary_ip(rm75)


def test_as2w_auxiliary_ip_does_not_replace_its_primary_ip():
    as2w = _find_machine(_machine_rows(), "as2w")
    primary_ip = _primary_ip(as2w)
    auxiliary_ips = comments._display_values(_field(
        as2w, "auxiliary_ips", "aux_ips", "secondary_ips", "auxiliary_ip", default=[]
    ))
    assert primary_ip
    assert primary_ip == "10.100.129.146"
    assert auxiliary_ips == ["10.100.128.245"]
    assert primary_ip not in auxiliary_ips
    assert _field(as2w, "main_ip", "primary_ip", "node_host", "ip") == primary_ip


def test_c23_driver_path_is_not_fabricated_while_unconfirmed():
    c23 = _find_machine(_machine_rows(), "c23")
    assert _machine_alias(c23) == "c23-021"
    assert c23["driver_path_verified"] is False
    assert c23["driver_path"] is None


# ── Owner and authorization display ───────────────────────────────────

def test_machine_inventory_never_supplies_deployment_owners():
    rows = _machine_rows()
    assert len(rows) == 21
    for machine in rows:
        assert machine["owners"] == []
        assert machine["owner_status"] == "pending"
        assert machine["owner_source"] == "pending"
        assert comments._owner_names(machine) == []


def test_all_static_inventory_owner_fields_are_pending():
    rows = [row for row in _machine_rows() if row["owner_status"] == "pending"]
    assert len(rows) == 21
    for row in rows:
        assert not comments._owner_names(row)
    markdown = _render_inventory(
        policy_status={
            "authorized": True, "machines_configured": False,
            "reviewers_configured": False,
            "missing_files": ["machines.yaml", "test_reviewers.yaml"],
            "authorized_machine_count": 0,
        },
    )
    assert markdown.count("负责人待配置") >= 9


def test_test_only_inventory_shows_owner_without_mention():
    machine = _find_machine(_machine_rows(), "beijing-g1-001")
    diag = _safe_diagnostic(machine, owners=["test-owner"])
    markdown = _render_inventory(
        diagnostics=[diag],
        policy_status=_authorized_policy(
            [machine["alias"]], test_only=True,
        ),
        groups=[{"alias": machine["alias"], "ip": machine["primary_ip"],
                 "component_ids": ["a" * 16]}],
    )
    assert "test-owner" in markdown
    assert "@test-owner" not in markdown


def test_regular_pr_inventory_mentions_the_owner():
    machine = _find_machine(_machine_rows(), "beijing-g1-001")
    diag = _safe_diagnostic(machine, owners=["test-owner"])
    markdown = _render_inventory(
        diagnostics=[diag],
        policy_status=_authorized_policy([machine["alias"]]),
        groups=[{"alias": machine["alias"], "ip": machine["primary_ip"],
                 "component_ids": ["a" * 16]}],
    )
    assert "@test-owner" in markdown


def test_ssh_username_is_never_used_as_machine_owner():
    row = {
        "number": "999", "alias": "ssh-only", "brand": "test", "model": "test",
        "primary_ip": "10.99.0.1", "secondary_ips": [], "owners": [],
        "owner_status": "pending", "ssh_username": "robotadmin",
        "ssh_user": "robotadmin",
    }
    owners = comments._owner_names(row)
    assert owners == []
    markdown = _render_inventory(
        machines=[row], policy_status={
            "authorized": True, "machines_configured": False,
            "reviewers_configured": False,
            "missing_files": ["machines.yaml", "test_reviewers.yaml"],
            "authorized_machine_count": 0,
        },
    )
    assert "robotadmin" not in markdown
    assert "负责人待配置" in markdown


def test_missing_machines_yaml_does_not_hide_the_21_machine_physical_inventory():
    rows = _machine_rows()
    markdown = comments.deploy_requested(
        REPO,
        1,
        HEAD,
        [_component()],
        [],
        repository_policy_status={
            "authorized": True,
            "machines_configured": False,
            "reviewers_configured": True,
            "missing_files": ["machines.yaml"],
            "authorized_machine_count": 0,
            "machines_yaml_status": "missing",
            "test_reviewers_yaml_status": "valid",
            "test_reviewers_source": "main",
            "source_sha": {"test_reviewers.yaml": "b" * 40},
            "last_attempt_status": {
                "machines.yaml": "not_found",
                "test_reviewers.yaml": "success",
            },
            "last_attempt_source": {"machines.yaml": "local_fallback"},
        },
    )
    assert len(rows) == 21
    assert all(_machine_alias(machine) in markdown for machine in rows)
    assert "machines.yaml：正式 main 尚未提供该文件" in markdown
    assert "已授权机器数量：0" in markdown
    assert "没有授权的机器不生成可执行审批命令。" in markdown
    assert "/approve_deploy machine=" not in markdown


def test_unconfigured_machine_is_not_given_an_approval_command():
    machine = _find_machine(_machine_rows(), "beijing-g1-001")
    diag = _safe_diagnostic(machine, repository_authorized=False)
    markdown = _render_inventory(
        diagnostics=[diag],
        policy_status=_authorized_policy([], machines_configured=True),
        groups=[{"alias": machine["alias"], "ip": machine["primary_ip"],
                 "component_ids": ["a" * 16]}],
    )
    assert "未授权" in markdown
    assert "/approve_deploy machine=10.100.129.168" not in markdown


def test_missing_reviewers_yaml_is_reported_separately_from_machine_policy():
    markdown = _render_inventory(policy_status={
        "authorized": True,
        "machines_configured": True,
        "reviewers_configured": False,
        "authorized_machine_count": 12,
        "missing_files": ["test_reviewers.yaml"],
        "machines_yaml_status": "valid",
        "test_reviewers_yaml_status": "missing",
        "machines_source": "main",
        "source_sha": {"machines.yaml": "a" * 40},
        "last_attempt_status": {"test_reviewers.yaml": "not_found"},
        "last_attempt_source": {"test_reviewers.yaml": "local_fallback"},
    })
    assert "machines.yaml：正式 main：已使用正式仓库 main 配置" in markdown
    assert "test_reviewers.yaml：正式 main 尚未提供该文件" in markdown


def test_physical_machine_count_is_independent_of_authorized_machine_count():
    rows = _machine_rows()
    authorized_aliases = [f"policy-machine-{index}" for index in range(12)]
    markdown = _render_inventory(policy_status=_authorized_policy(authorized_aliases))
    assert len(rows) == 21
    assert len(authorized_aliases) == 12
    assert all(_machine_alias(machine) in markdown for machine in rows)
    assert "已授权机器数量：12" in markdown


def test_owner_propagation_through_service_machine_comment_context(controller):
    rows = _machine_rows()
    historical = rows[:12]
    pending = rows[12:]
    policy_machines = [
        _machine(
            row["alias"], row["primary_ip"], owners=["test-owner"],
        )
        for row in historical
    ]
    _set_repo_machines(controller, policy_machines)
    components = [_component()]
    groups = controller._get_machine_groups_for_components(components, REPO)

    # This is the production adapter whose owner mapping must survive the
    # physical inventory -> machine groups -> comment diagnostics conversion.
    context = controller._machine_comment_context(
        components, groups, REPO, test_only=False,
    )
    assert len(context["machine_inventory"]) == 21
    diagnostics = {row["alias"]: row for row in context["machine_diagnostics"]}
    assert len(diagnostics) == 21
    for row in historical:
        assert diagnostics[row["alias"]]["owners"] == ["test-owner"]
    for row in pending:
        assert diagnostics[row["alias"]]["owners"] == ["负责人待配置"]

    regular_pr = _render_service_machine_context(components, groups, context)
    assert regular_pr.count("@test-owner") >= 12
    for row in pending:
        assert row["alias"] in regular_pr
    assert regular_pr.count("负责人待配置") >= 9

    test_only_context = controller._machine_comment_context(
        components, groups, REPO, test_only=True,
    )
    test_only_markdown = _render_service_machine_context(
        components, groups, test_only_context,
    )
    assert "test-owner" in test_only_markdown
    assert "@test-owner" not in test_only_markdown


def test_authorization_context_keeps_physical_machines_without_machines_yaml(
    controller,
):
    controller.policy.repo_policy_status = MagicMock(return_value={
        "status": "partially_configured",
        "authorized": True,
        "machines_configured": False,
        "reviewers_configured": True,
        "missing_files": ["machines.yaml"],
        "machines_yaml_status": "missing",
        "test_reviewers_yaml_status": "valid",
        "test_reviewers_source": "main",
        "source_sha": {"test_reviewers.yaml": "b" * 40},
        "last_attempt_status": {
            "machines.yaml": "not_found",
            "test_reviewers.yaml": "success",
        },
        "last_attempt_source": {"machines.yaml": "local_fallback"},
    })
    controller.policy.get_machines = MagicMock(return_value=[])
    controller.policy.get_machine = MagicMock(return_value=None)
    components = [_component()]
    groups = controller._get_machine_groups_for_components(components, REPO)
    context = controller._machine_comment_context(
        components, groups, REPO, test_only=False,
    )

    assert len(context["machine_inventory"]) == 21
    assert len(context["machine_diagnostics"]) == 21
    assert context["repository_policy_status"]["authorized_machine_count"] == 0
    assert all(row["repository_authorized"] is False
               for row in context["machine_diagnostics"])
    markdown = _render_service_machine_context(components, groups, context)
    assert all(_machine_alias(row) in markdown for row in _machine_rows())
    assert "machines.yaml：正式 main 尚未提供该文件" in markdown
    assert "没有授权的机器不生成可执行审批命令。" in markdown
    assert "/approve_deploy machine=" not in markdown


def test_reviewers_for_repo_returns_actual_repository_acceptance_list(controller):
    reviewers = ["actual-reviewer", "acceptance-owner"]
    state = controller.policy._repository_policies._state("4paradigm/phanthymotus")
    state.reviewers = reviewers
    state.source_sha["test_reviewers.yaml"] = "a" * 40
    state.file_source["test_reviewers.yaml"] = "main"
    controller.policy._repository_policies._set_file_status(
        state, "test_reviewers.yaml", "valid",
    )

    assert controller.policy.reviewers_for_repo(REPO) == reviewers
    assert controller.policy.repo_policy_status(REPO)["reviewers_configured"] is True


# ── Compatibility and safe approval selection ────────────────────────

def test_platform_unverified_and_component_incompatible_remain_distinct():
    first, second = _machine_rows()[:2]
    diagnostics = [
        _safe_diagnostic(
            first, platform_confirmed=False,
            reasons=["platform validation has not completed"],
        ),
        _safe_diagnostic(
            second, component_compatible=False,
            reasons=["target perception 5.11 is not supported"],
        ),
    ]
    groups = [
        {"alias": machine["alias"], "ip": machine["primary_ip"],
         "component_ids": ["a" * 16]}
        for machine in (first, second)
    ]
    markdown = _render_inventory(
        diagnostics=diagnostics,
        policy_status=_authorized_policy([first["alias"], second["alias"]]),
        groups=groups,
    )
    assert "未确认" in markdown
    assert "不兼容" in markdown


@pytest.mark.asyncio
async def test_agent_core_timeout_and_missing_machine_have_distinct_runtime_statuses(
    controller,
):
    component = _component()
    machine = _machine("runtime-node", "10.90.0.1")
    controller._fresh_review_evidence_matches_state = AsyncMock(return_value=True)
    controller._write_lifecycle_with_history = AsyncMock(return_value=True)
    controller._post_bound_notice = AsyncMock()
    controller.proxy.find_trusted_lifecycle_comment = AsyncMock(return_value={"body": "summary"})
    controller.proxy.get_pr = AsyncMock(return_value={
        "state": "open", "merged": False, "draft": False,
        "head": {"sha": HEAD},
    })

    async def observe(machine_alias, machine_ip, policy_machines, *, core_error=None):
        _set_repo_machines(controller, policy_machines)
        controller._physical_machine_inventory = MagicMock(return_value=[
            _physical_record(
                item.alias, item.node_host, node_id=item.node_id,
                number=f"{index:03d}",
            )
            for index, item in enumerate(policy_machines, 1)
        ])
        controller._core_for_node = AsyncMock(side_effect=core_error)
        state = _runtime_state(controller, [component], [{
            "machine": machine_alias,
            "ip": machine_ip,
            "component_ids": [component["component_id"]],
            "phase": "deployed",
        }])
        return await controller._reconcile_runtime_image_checks(
            REPO, 1, state, {"head": {"sha": HEAD}}, force=True,
        )

    timeout_state = await observe(
        machine.alias, machine.node_host, [machine],
        core_error=asyncio.TimeoutError(),
    )
    missing_state = await observe(
        "removed-machine", "10.90.0.13",
        [_machine("remaining-machine", "10.90.0.14")],
    )

    assert timeout_state["runtime_checks"][0]["status"] == "unavailable"
    assert missing_state["runtime_checks"][0]["status"] == "identity_changed"
    timeout_display = _runtime_section(comments.deploy_requested(
        REPO, 1, HEAD, [component], [], machine_inventory=[],
        repository_policy_status=_authorized_policy([]),
        runtime_checks=timeout_state["runtime_checks"],
    ))
    missing_display = _runtime_section(comments.deploy_requested(
        REPO, 1, HEAD, [component], [], machine_inventory=[],
        repository_policy_status=_authorized_policy([]),
        runtime_checks=missing_state["runtime_checks"],
    ))
    assert "UNAVAILABLE" in timeout_display
    assert "不能判断是否需要重新部署" in timeout_display
    assert "IDENTITY_CHANGED" in missing_display
    assert "等待重新确认" in missing_display


def test_component_mismatch_diagnostic_retains_the_specific_reason():
    machine = _find_machine(_machine_rows(), "unitree-r1-002")
    reason = "driver path unitree/r1 is not allowed by this machine"
    markdown = _render_inventory(
        diagnostics=[_safe_diagnostic(
            machine,
            component_compatible=False,
            reasons=[reason],
        )],
        policy_status=_authorized_policy([machine["alias"]]),
        groups=[{"alias": machine["alias"], "ip": machine["primary_ip"],
                 "component_ids": ["a" * 16]}],
    )
    assert reason in markdown
    assert "不兼容" in markdown


def test_duplicate_ip_does_not_produce_an_ambiguous_approval_command(
    controller,
):
    first = _machine("first-machine", "10.90.0.2", owners=["owner-one"])
    second = _machine("second-machine", "10.90.0.2", owners=["owner-two"])
    _set_repo_machines(controller, [first, second])
    physical = [
        _physical_record(first.alias, first.node_host, node_id=first.node_id,
                         number="001"),
        _physical_record(second.alias, second.node_host, node_id=second.node_id,
                         number="002"),
    ]
    controller._physical_machine_inventory = MagicMock(return_value=physical)
    groups = controller._get_machine_groups_for_components([_component()], REPO)
    assert len(groups) == 2
    assert {group["alias"] for group in groups} == {first.alias, second.alias}
    assert all(group["approval_available"] for group in groups)
    assert all(not group["ip_command_safe"] for group in groups)
    assert {group["command_selector"] for group in groups} == {
        first.alias, second.alias,
    }

    # Exercise the service-to-renderer adapter with the complete physical
    # diagnostics. The exact alias is safe because each policy identity maps
    # to its own physical record; the shared IP is ambiguous.
    context = controller._machine_comment_context(
        [_component()], groups, REPO, test_only=True,
    )
    assert len(context["machine_diagnostics"]) == 2
    assert all(item["safe_to_approve"] is True
               for item in context["machine_diagnostics"])
    markdown = _render_service_machine_context([_component()], groups, context)
    rendered = html.unescape(markdown)
    assert "主 IP 存在冲突" in rendered
    assert f"`/approve_deploy machine={first.alias}`" in rendered
    assert f"`/approve_deploy machine={second.alias}`" in rendered
    assert "/approve_deploy machine=10.90.0.2" not in rendered


def test_machine_identity_and_owner_come_only_from_repository_policy(controller):
    physical_ip = "10.90.0.30"
    policy_ip = "10.90.0.31"
    machine = _machine(
        "identity-mismatch-machine", policy_ip, node_id="node-identity",
        owners=["test-owner"],
    )
    _set_repo_machines(controller, [machine])
    physical = _physical_record(
        machine.alias, physical_ip, node_id="stale-node-id",
        platform_status="unverified", platforms=("windows/amd64",),
        platform_verified=False,
    )
    physical["raw"]["owners"] = ["stale-inventory-owner"]
    physical["raw"]["owner_status"] = "verified"
    controller._physical_machine_inventory = MagicMock(return_value=[physical])
    controller._record_agent_core_health(REPO, machine, "available")
    components = [_component()]
    groups = controller._get_machine_groups_for_components(components, REPO)
    context = controller._machine_comment_context(
        components, groups, REPO, test_only=True,
    )
    diagnostic = context["machine_diagnostics"][0]

    assert diagnostic["primary_ip"] == policy_ip
    assert diagnostic["owners"] == ["test-owner"]
    assert diagnostic["identity_confirmed"] is True
    assert diagnostic["safe_to_approve"] is True
    assert groups[0]["approval_available"] is True
    assert groups[0]["command_selector"] == policy_ip
    markdown = _render_service_machine_context(components, groups, context)
    rendered = html.unescape(markdown)
    assert f"/approve_deploy machine={policy_ip}" in rendered
    assert f"/approve_deploy machine={physical_ip}" not in rendered
    assert "stale-inventory-owner" not in rendered


def test_alias_selector_and_ip_selector_are_not_mixed_for_unique_identity(
    controller,
):
    machine = _machine(
        "unique-ip-machine", "10.90.0.32", node_id="node-unique-ip",
        owners=["machine-owner"],
    )
    _set_repo_machines(controller, [machine])
    controller._physical_machine_inventory = MagicMock(return_value=[
        _physical_record(
            machine.alias, machine.node_host, node_id=machine.node_id,
        ),
    ])
    components = [_component()]
    groups = controller._get_machine_groups_for_components(components, REPO)
    context = controller._machine_comment_context(
        components, groups, REPO, test_only=True,
    )

    assert len(context["machine_diagnostics"]) == 1
    assert groups[0]["ip_command_safe"] is True
    assert groups[0]["command_selector"] == machine.node_host
    markdown = _render_service_machine_context(components, groups, context)
    assert f"`/approve_deploy machine={machine.node_host}`" in markdown
    assert f"`/approve_deploy machine={machine.alias}`" not in markdown


def test_platform_compatibility_comes_only_from_repository_policy(controller):
    verified = _machine(
        "platform-evidence-verified", "10.90.0.33",
        node_id="node-platform-verified", owners=["machine-owner"],
    )
    unverified = _machine(
        "platform-evidence-unverified", "10.90.0.34",
        node_id="node-platform-unverified", owners=["machine-owner"],
    )
    _set_repo_machines(controller, [verified, unverified])
    controller._physical_machine_inventory = MagicMock(return_value=[
        _physical_record(
            verified.alias, verified.node_host, node_id=verified.node_id,
            platform_status="verified", platforms=("linux/arm64",),
            platform_verified=True,
        ),
        _physical_record(
            unverified.alias, unverified.node_host, node_id=unverified.node_id,
            platform_status="unverified", platforms=(), platform_verified=False,
            number="002",
        ),
    ])
    components = [_component()]
    groups = controller._get_machine_groups_for_components(components, REPO)
    context = controller._machine_comment_context(
        components, groups, REPO, test_only=True,
    )
    diagnostics = {row["alias"]: row for row in context["machine_diagnostics"]}

    assert diagnostics[verified.alias]["platform_confirmed"] is True
    assert diagnostics[unverified.alias]["platform_confirmed"] is True
    assert "PLATFORM_UNVERIFIED" not in groups[1]["blocking_reasons"]
    assert groups[0]["platform_status"] == "compatible"


def test_agent_core_unknown_and_available_are_distinct(controller):
    machine = _machine("agent-health-machine", "10.90.0.35")

    assert controller._agent_core_status_for_machine(REPO, machine) == "unknown"
    controller._record_agent_core_health(REPO, machine, "available")
    assert controller._agent_core_status_for_machine(REPO, machine) == "available"
    controller._record_agent_core_health(REPO, machine, "unavailable")
    assert controller._agent_core_status_for_machine(REPO, machine) == "unavailable"


@pytest.mark.asyncio
async def test_agent_core_unavailable_preflight_never_sends_deploy_post(controller):
    machine = _machine(
        "agent-core-timeout-machine", "10.90.0.36",
        node_id="node-agent-timeout", owners=["machine-owner"],
    )
    _set_repo_machines(controller, [machine])
    controller._physical_machine_inventory = MagicMock(return_value=[
        _physical_record(
            machine.alias, machine.node_host, node_id=machine.node_id,
        ),
    ])
    state = _runtime_state(
        controller,
        [_component()],
        [],
    )
    state["status"] = "deploy-requested"
    pr_data = {
        "state": "open",
        "merged": False,
        "draft": False,
        "head": {"sha": HEAD},
        "base": {"repo": {"full_name": REPO}},
    }
    controller.proxy.get_pr = AsyncMock(return_value=pr_data)
    controller.proxy.read_hidden_state = AsyncMock(return_value=copy.deepcopy(state))
    controller._check_approval_permissions = AsyncMock()
    controller._write_lifecycle_with_history = AsyncMock(return_value=True)
    controller._post_command_reply = AsyncMock()
    controller._core_for_node = AsyncMock(side_effect=TimeoutError())
    controller._deploy_component = AsyncMock()

    result = await controller.handle_approve_deploy(
        REPO, 37, 901, machine.alias, "approver", "approver-id",
    )

    assert result is True
    assert controller._agent_core_status_for_machine(REPO, machine) == "unavailable"
    controller._post_command_reply.assert_awaited()
    controller._deploy_component.assert_not_awaited()


def test_single_compatible_machine_accepts_short_approve_command():
    command = parse_command("/approve_deploy")
    assert command.kind == "approve_deploy"
    assert command.error == ""
    assert command.machine_alias == ""
    markdown = comments.deploy_ready(
        REPO, 3, HEAD, [_build()],
        machine_groups=[{
            "alias": "only-machine", "ip": "10.90.0.3",
            "primary_ip": "10.90.0.3", "node_host": "10.90.0.3",
            "node_id": "node-only-machine", "repo_authorized": True,
            "identity_confirmed": True, "approval_available": True,
            "ip_command_safe": True, "command_selector": "10.90.0.3",
            "component_ids": ["a" * 16],
        }],
        review_evidence=_valid_review_evidence(),
        components=[_component()],
    )
    assert "`/approve_deploy machine=10.90.0.3`" in markdown
    assert "`/approve_deploy`" in markdown


@pytest.mark.asyncio
async def test_deploy_ready_can_be_approved_without_request_deploy(controller):
    component = _component()
    machine = _machine("ready-machine", "10.90.0.40", owners=["test-owner"])
    _set_repo_machines(controller, [machine])
    controller._physical_machine_inventory = MagicMock(return_value=[])
    controller._record_agent_core_health(REPO, machine, "available")
    state = _runtime_state(controller, [component], [])
    state["status"] = "deploy-ready"
    state["last_processed_comment_id"] = 10
    controller.proxy.get_pr = AsyncMock(return_value={
        "state": "open", "merged": False, "draft": False,
        "head": {"sha": HEAD},
        "base": {"repo": {"full_name": REPO}},
    })
    persisted = {"state": copy.deepcopy(state)}
    controller.proxy.read_hidden_state = AsyncMock(
        side_effect=lambda *_args, **_kwargs: copy.deepcopy(persisted["state"]),
    )
    controller._fresh_review_evidence_matches_state = AsyncMock(return_value=True)
    controller._check_approval_permissions = AsyncMock()
    written_states = []

    async def write_lifecycle(_repo, _pr_number, new_state, *_args, **_kwargs):
        persisted["state"] = copy.deepcopy(new_state)
        written_states.append(copy.deepcopy(new_state))
        return True

    controller._write_lifecycle_with_history = AsyncMock(side_effect=write_lifecycle)
    controller._post_bound_notice = AsyncMock(return_value=True)
    controller._core_for_node = AsyncMock(return_value=MagicMock())
    controller._preflight_running_images = AsyncMock(side_effect=TimeoutError())
    controller._deploy_component = AsyncMock()
    controller._post_command_reply = AsyncMock(return_value=True)

    guidance = await controller._approval_command_guidance(REPO, 1)
    handled = await controller.handle_approve_deploy(
        REPO, 1, 11, machine.node_host, "test-owner", "test-owner-id",
    )

    assert handled is True
    assert written_states[0]["status"] == "deploying"
    assert written_states[0]["command"]["kind"] == "approve_deploy"
    controller._preflight_running_images.assert_awaited_once()
    controller._deploy_component.assert_not_awaited()
    controller._post_bound_notice.assert_awaited_once()
    assert "test-owner" in guidance
    assert "@test-owner" not in guidance
    assert "`/approve_deploy machine=10.90.0.40`" in guidance
    assert "直接执行 `/approve_deploy`" in guidance
    assert "/request_deploy" not in guidance


def test_multiple_compatible_machines_require_explicit_selector():
    markdown = comments.deploy_ready(
        REPO, 4, HEAD, [_build()],
        machine_groups=[
            {
                "alias": "machine-one", "ip": "10.90.0.4",
                "primary_ip": "10.90.0.4", "node_host": "10.90.0.4",
                "node_id": "node-machine-one", "repo_authorized": True,
                "identity_confirmed": True, "approval_available": True,
                "ip_command_safe": True, "command_selector": "10.90.0.4",
                "component_ids": ["a" * 16],
            },
            {
                "alias": "machine-two", "ip": "10.90.0.5",
                "primary_ip": "10.90.0.5", "node_host": "10.90.0.5",
                "node_id": "node-machine-two", "repo_authorized": True,
                "identity_confirmed": True, "approval_available": True,
                "ip_command_safe": True, "command_selector": "10.90.0.5",
                "component_ids": ["a" * 16],
            },
        ],
        review_evidence=_valid_review_evidence(),
        components=[_component()],
    )
    assert "`/approve_deploy machine=10.90.0.4`" in markdown
    assert "`/approve_deploy machine=10.90.0.5`" in markdown
    assert "`/approve_deploy`" not in markdown


# ── Runtime image drift monitoring ───────────────────────────────────

@pytest.mark.asyncio
async def test_runtime_checks_reconcile_all_deployed_machines_each_cycle(controller):
    approved = "registry.example/perception@sha256:" + "a" * 64
    stale = "registry.example/perception@sha256:" + "b" * 64
    first_component = _component("a" * 16, image_ref=approved)
    second_component = _component("b" * 16, image_ref=approved)
    first_machine = _machine(
        "machine-one", "10.90.0.6", owners=["first-machine-owner"],
    )
    second_machine = _machine(
        "machine-two", "10.90.0.7", owners=["test-owner"],
    )
    _set_repo_machines(controller, [first_machine, second_machine])
    controller._physical_machine_inventory = MagicMock(return_value=[
        _physical_record(first_machine.alias, first_machine.node_host,
                         node_id=first_machine.node_id, number="001"),
        _physical_record(second_machine.alias, second_machine.node_host,
                         node_id=second_machine.node_id, number="002"),
    ])
    controller.proxy.get_pr = AsyncMock(return_value={
        "state": "open", "merged": False, "draft": False,
        "head": {"sha": HEAD},
    })
    controller._fresh_review_evidence_matches_state = AsyncMock(return_value=True)
    controller._write_lifecycle_with_history = AsyncMock(return_value=True)
    controller._post_bound_notice = AsyncMock()
    controller.proxy.find_trusted_lifecycle_comment = AsyncMock(return_value={"body": "summary"})

    first_core = MagicMock()
    first_core.list_drivers = AsyncMock(return_value=[{
        "id": "perception", "image": "registry.example/perception:v1",
    }])
    first_core.driver_status = AsyncMock(return_value={
        "status": "running", "running_image": approved,
    })
    second_core = MagicMock()
    second_core.list_drivers = AsyncMock(return_value=[{
        "id": "perception", "image": "registry.example/perception:v1",
    }])
    second_core.driver_status = AsyncMock(return_value={
        "status": "running", "running_image": stale,
    })
    controller._core_for_node = AsyncMock(side_effect=lambda node_id, *_args, **_kwargs: {
        first_machine.node_id: first_core,
        second_machine.node_id: second_core,
    }[node_id])

    state = _runtime_state(
        controller,
        [first_component, second_component],
        [
            {"machine": first_machine.alias, "ip": first_machine.node_host,
             "component_ids": [first_component["component_id"]], "phase": "deployed"},
            {"machine": second_machine.alias, "ip": second_machine.node_host,
             "component_ids": [second_component["component_id"]], "phase": "deployed"},
        ],
    )
    result = await controller._reconcile_runtime_image_checks(
        REPO, 5, state, {"head": {"sha": HEAD}}, force=True,
        machine_filter=(first_machine.alias, first_machine.node_host),
    )

    checks = {check["machine"]: check for check in result["runtime_checks"]}
    assert set(checks) == {first_machine.alias, second_machine.alias}
    assert checks[first_machine.alias]["target_image"] == approved
    assert checks[first_machine.alias]["observed_image"] == approved
    assert checks[first_machine.alias]["status"] == "match"
    assert checks[second_machine.alias]["target_image"] == approved
    assert checks[second_machine.alias]["observed_image"] == stale
    assert checks[second_machine.alias]["status"] == "mismatch"
    assert controller._core_for_node.await_count == 2
    runtime_notices = [
        call.kwargs["message"] for call in controller._post_bound_notice.await_args_list
        if str(call.kwargs.get("topic", "")).startswith("runtime-image:")
    ]
    assert runtime_notices
    assert any("test-owner" in message for message in runtime_notices)
    assert all("@test-owner" not in message for message in runtime_notices)

    rendered = comments.deploy_requested(
        REPO,
        5,
        HEAD,
        [first_component, second_component],
        [],
        machine_inventory=[
            {"number": "001", "alias": first_machine.alias, "brand": "test",
             "model": "one", "primary_ip": first_machine.node_host,
             "secondary_ips": [], "owners": []},
            {"number": "002", "alias": second_machine.alias, "brand": "test",
             "model": "two", "primary_ip": second_machine.node_host,
             "secondary_ips": [], "owners": []},
        ],
        repository_policy_status=_authorized_policy([]),
        runtime_checks=result["runtime_checks"],
    )
    runtime = _runtime_section(rendered)
    assert "sha256:" + "a" * 64 in runtime
    assert "sha256:" + "b" * 64 in runtime
    assert first_machine.alias in runtime
    assert second_machine.alias in runtime


@pytest.mark.asyncio
async def test_core_runtime_match_displays_full_verified_image_without_changing_hidden_state(
    controller, monkeypatch,
):
    target_image = "registry.example/core:v1"
    result, component, _machine_info = await _scan_core_runtime(
        controller, {"current_image": target_image, "status": "running"},
    )
    check = result["runtime_checks"][0]
    assert check["status"] == "match"
    assert check["target_image"] == target_image
    # Hidden-state v1 keeps the legacy Core tag representation.
    assert check["observed_image"] == "v1"

    captured = {}

    def capture_display_checks(markdown, checks, _components, **_kwargs):
        captured["checks"] = copy.deepcopy(checks)
        return markdown

    monkeypatch.setattr(comments, "update_runtime_image_checks", capture_display_checks)
    markdown = "<!-- deploy-approval-runtime-checks:end -->"
    displayed = controller._render_runtime_checks_for_display(
        markdown, result["runtime_checks"], [component], REPO, "testing",
        {"title": "ordinary PR"},
    )

    assert captured["checks"][0]["target_image"] == target_image
    assert captured["checks"][0]["observed_image"] == target_image
    assert f"批准镜像 `{target_image}`" in displayed
    assert f"实际运行镜像 `{target_image}`" in displayed
    assert "MATCH" in displayed
    assert "test-owner" in displayed
    assert "@test-owner" not in displayed
    assert result["runtime_checks"][0]["observed_image"] == "v1"


@pytest.mark.asyncio
async def test_core_runtime_full_image_mismatch_exposes_direct_redeploy_command(controller):
    target_image = "registry.example/core:v1"
    actual_image = "mirror.example/core:v1"
    result, _component_info, machine = await _scan_core_runtime(
        controller, {"current_image": actual_image, "status": "running"},
    )

    check = result["runtime_checks"][0]
    assert check["target_image"] == target_image
    assert check["observed_image"] == actual_image
    assert check["status"] == "mismatch"
    assert controller._runtime_drift_command_lines(result, REPO) == [
        f"/approve_deploy machine={machine.node_host}",
    ]
    summary_guidance = "\n".join(controller._runtime_owner_guidance(
        result["runtime_checks"], result["components"], REPO,
        {"title": "ordinary PR"}, "testing",
    ))
    assert f"批准镜像 `{target_image}`" in summary_guidance
    assert f"实际运行镜像 `{actual_image}`" in summary_guidance
    assert f"/approve_deploy machine={machine.node_host}" in summary_guidance
    assert "MISMATCH" in summary_guidance
    assert "@test-owner" not in summary_guidance
    mismatch_notices = [
        call.kwargs["message"] for call in controller._post_bound_notice.await_args_list
        if str(call.kwargs.get("topic", "")).startswith("runtime-image:")
    ]
    assert any(target_image in message and actual_image in message for message in mismatch_notices)
    assert any(
        f"/approve_deploy machine={machine.node_host}" in message
        and "`/request_deploy` 可选" in message
        for message in mismatch_notices
    )


@pytest.mark.asyncio
async def test_core_runtime_without_full_image_is_unavailable(controller):
    result, _component_info, _machine_info = await _scan_core_runtime(
        controller, {"current_tag": "v1", "status": "running"},
    )

    check = result["runtime_checks"][0]
    assert check["status"] == "unavailable"
    assert check["observed_image"] == ""
    assert controller._runtime_drift_command_lines(result, REPO) == []
    guidance = controller._runtime_owner_guidance(
        result["runtime_checks"], result["components"], REPO,
        {"title": "[TEST ONLY] unavailable Core image"}, "testing",
    )
    rendered = "\n".join(guidance)
    assert "批准镜像 `registry.example/core:v1`" in rendered
    assert "实际运行镜像 `unavailable`" in rendered
    assert "UNAVAILABLE" in rendered
    assert "@test-owner" not in rendered


@pytest.mark.asyncio
async def test_runtime_scan_invalidates_observations_when_policy_changes_mid_cycle(controller):
    approved = "registry.example/perception@sha256:" + "a" * 64
    component = _component(image_ref=approved)
    machine = _machine("snapshot-machine", "10.90.0.12")
    replacement = _machine(
        machine.alias, machine.node_host, node_id="replacement-node",
    )
    _set_repo_machines(controller, [machine])
    controller.policy.get_machines = MagicMock(
        side_effect=[[machine], [replacement]],
    )
    controller.proxy.get_pr = AsyncMock(return_value={
        "state": "open", "merged": False, "draft": False,
        "head": {"sha": HEAD},
    })
    controller._fresh_review_evidence_matches_state = AsyncMock(return_value=True)
    controller._write_lifecycle_with_history = AsyncMock(return_value=True)
    controller.proxy.find_trusted_lifecycle_comment = AsyncMock(
        return_value={"body": "summary"},
    )
    core = MagicMock()
    core.list_drivers = AsyncMock(return_value=[{
        "id": "perception", "image": "registry.example/perception:v1",
    }])
    core.driver_status = AsyncMock(return_value={
        "status": "running", "running_image": approved,
    })
    controller._core_for_node = AsyncMock(return_value=core)
    state = _runtime_state(
        controller, [component], [{
            "machine": machine.alias, "ip": machine.node_host,
            "component_ids": [component["component_id"]], "phase": "deployed",
        }],
    )

    result = await controller._reconcile_runtime_image_checks(
        REPO, 6, state, {"head": {"sha": HEAD}}, force=True,
    )

    check = result["runtime_checks"][0]
    assert check["status"] == "identity_changed"
    assert check["machine"] == machine.alias
    assert check["observed_image"] == ""
    assert controller._core_for_node.await_args.args[:2] == (machine.node_id, REPO)


def test_runtime_match_does_not_show_a_redeployment_command():
    component = _component()
    block = _render_runtime_status("match", component["image_ref"], ip="10.90.0.8")
    assert "运行镜像与审批目标一致" in block
    assert "无需重新部署" in block
    assert "/approve_deploy machine=10.90.0.8" not in block


def test_runtime_mismatch_shows_the_direct_approval_command():
    block = _render_runtime_status(
        "mismatch", "registry.example/perception@sha256:" + "b" * 64,
        ip="10.90.0.9",
    )
    assert "MISMATCH" in block
    assert "`/approve_deploy machine=10.90.0.9`" in block


def test_runtime_drift_exposes_direct_redeploy_command():
    approved = _component()["image_ref"]
    running = "registry.example/perception@sha256:" + "b" * 64
    block = _render_runtime_status("mismatch", running, ip="10.90.0.41")
    assert "runtime-machine" in block
    assert "10.90.0.41" in block
    assert approved in block
    assert running in block
    assert "MISMATCH" in block
    assert "`/approve_deploy machine=10.90.0.41`" in block
    assert "`/request_deploy` 可选" in block


def test_runtime_redeployment_does_not_require_request_deploy_first():
    block = _render_runtime_status(
        "mismatch", "registry.example/perception@sha256:" + "b" * 64,
        ip="10.90.0.10",
    )
    assert "`/approve_deploy machine=10.90.0.10`" in block
    assert "`/request_deploy` 可选" in block


def test_runtime_unavailable_is_not_reported_as_mismatch_or_approval():
    block = _render_runtime_status("unavailable", "", ip="10.90.0.11")
    assert "UNAVAILABLE" in block
    assert "MISMATCH" not in block
    assert "/approve_deploy machine=10.90.0.11" not in block


def test_runtime_image_checks_are_due_every_30_minutes():
    assert RUNTIME_IMAGE_CHECK_INTERVAL_SECONDS == 30 * 60
    now = datetime(2026, 11, 9, 0, 30, tzinfo=timezone.utc)
    fresh = {"checked_at": "2026-11-09T00:00:01+00:00"}
    due = {"checked_at": "2026-11-09T00:00:00+00:00"}
    assert not DeployController._runtime_check_is_due(fresh, now)
    assert DeployController._runtime_check_is_due(due, now)


def test_deployment_path_performs_an_immediate_runtime_verification():
    source = inspect.getsource(DeployController.handle_approve_deploy)
    deploy_position = source.index("await self._deploy_component(")
    verify_position = source.index("await self._verify_deployed_runtime(")
    assert deploy_position < verify_position
    assert "target image not observed running" in source


@pytest.mark.asyncio
async def test_repeated_scan_of_same_head_does_not_write_a_duplicate_comment(controller):
    component = _component()
    machine = _machine("machine-one", "10.90.0.12")
    _set_repo_machines(controller, [machine])
    current_check = _runtime_check(
        machine.alias, machine.node_host, component, "match", component["image_ref"],
    )
    controller._write_lifecycle_with_history = AsyncMock(return_value=True)
    controller._post_bound_notice = AsyncMock()
    controller._fresh_review_evidence_matches_state = AsyncMock(return_value=True)
    controller.proxy.find_trusted_lifecycle_comment = AsyncMock(return_value={"body": "summary"})
    controller._core_for_node = AsyncMock()
    state = _runtime_state(
        controller,
        [component],
        [{"machine": machine.alias, "ip": machine.node_host,
          "component_ids": [component["component_id"]], "phase": "deployed"}],
        [current_check],
    )

    result = await controller._reconcile_runtime_image_checks(
        REPO, 6, state, {"head": {"sha": HEAD}}, force=False,
    )

    assert result is state
    controller._core_for_node.assert_not_awaited()
    controller._write_lifecycle_with_history.assert_not_awaited()
    controller._post_bound_notice.assert_not_awaited()


def test_already_matching_machine_is_not_selected_for_redeployment(controller):
    state = {"runtime_checks": [{"status": "match"}]}
    assert controller._confirmed_runtime_drift(state) == []
    assert controller._runtime_drift_command_lines(state) == []
    with pytest.raises(DeployControllerError, match="no confirmed runtime image drift"):
        controller._new_runtime_redeploy_round(
            {"runtime_checks": [{"status": "match"}]},
            comment_id=7,
            command_kind="approve_deploy",
        )


@pytest.mark.asyncio
async def test_history_is_preserved_when_lifecycle_summary_is_rewritten(controller):
    state = controller._init_hidden_state(
        head_sha=HEAD,
        status="deploy-requested",
        review_evidence=_valid_review_evidence(),
        components=[_component()],
    )
    previous_history = _build_history_block([{
        "event": "previous deployment history",
        "timestamp": "2026-11-08T10:00:00Z",
    }])
    previous_visible = (
        "<!-- deploy-approval-agent -->\n# Deploy Approval\n\n"
        "**Status:** `deploy-requested`\n\n### Workflow\n\nprevious summary\n\n"
        + previous_history
    )
    previous_comment = {
        "id": 902,
        "body": _build_hidden_state_body(previous_visible, state),
    }
    controller.proxy.find_trusted_lifecycle_comment = AsyncMock(
        return_value=previous_comment,
    )
    controller.proxy.get_pr = AsyncMock(return_value={
        "state": "open",
        "merged": False,
        "draft": False,
        "head": {"sha": HEAD},
        "base": {"repo": {"full_name": REPO}},
    })
    written_markdown = []

    async def capture_write(_repo, _pr, visible, _state, **_kwargs):
        written_markdown.append(visible)
        return {"id": previous_comment["id"], "body": "updated lifecycle"}

    controller.proxy.write_hidden_state = AsyncMock(side_effect=capture_write)
    controller.proxy.read_evidence_records = AsyncMock(return_value=[])
    result = await controller._write_lifecycle_with_history(
        REPO,
        1,
        copy.deepcopy(state),
        "<!-- deploy-approval-agent -->\n# Deploy Approval\n\n"
        "**Status:** `deploy-requested`\n\n### Workflow\n\nrefreshed summary",
        event={
            "event": "new lifecycle refresh",
            "timestamp": "2026-11-09T10:00:00Z",
        },
    )

    assert result is True
    assert len(written_markdown) == 1
    assert "previous deployment history" in written_markdown[0]
    assert "new lifecycle refresh" in written_markdown[0]


# ── V45D runtime selector and approval eligibility regressions ─────────

def test_v45d_t01_unique_ip_runtime_check_uses_the_real_ip_selector():
    component = _component()
    ip = "10.90.1.1"
    machine, diagnostic, group = _runtime_case_records(
        "unique-runtime", ip, [component["component_id"]], ip,
    )
    check = _runtime_check_with_selector(
        machine["alias"], ip, component, "mismatch",
        "registry.example/perception@sha256:" + "b" * 64, ip,
    )

    markdown = _render_runtime_lifecycle(
        [component], [group], [machine], [diagnostic], [check],
    )
    runtime = _runtime_section(markdown)
    row = next(line for line in runtime.splitlines() if machine["alias"] in line)

    assert machine["alias"] in row
    assert ip in row
    assert "@repo-owner" in row
    assert "perception 5.11" in row
    assert "sha256:" + "a" * 64 in row
    assert f"`/approve_deploy machine={ip}`" in row
    assert f"machine={machine['alias']}`" not in row


def test_v45d_t02_duplicate_ip_uses_verified_alias_in_lifecycle_runtime_table():
    component = _component()
    ip = "10.90.1.2"
    first, first_diag, first_group = _runtime_case_records(
        "duplicate-runtime-a", ip, [component["component_id"]],
        "duplicate-runtime-a", duplicate=True,
    )
    second, second_diag, second_group = _runtime_case_records(
        "duplicate-runtime-b", ip, [component["component_id"]],
        "duplicate-runtime-b", duplicate=True,
    )
    check = _runtime_check_with_selector(
        first["alias"], ip, component, "mismatch",
        "registry.example/perception@sha256:" + "b" * 64,
        first["alias"],
    )

    markdown = _render_runtime_lifecycle(
        [component], [first_group, second_group], [first, second],
        [first_diag, second_diag], [check],
    )
    runtime = _runtime_section(markdown)
    row = next(line for line in runtime.splitlines() if first["alias"] in line)

    assert first["alias"] in row
    assert ip in row
    assert "@repo-owner" in row
    assert "perception 5.11" in row
    assert "sha256:" + "a" * 64 in row
    assert f"`/approve_deploy machine={first['alias']}`" in row
    assert f"/approve_deploy machine={ip}" not in row


def test_v45d_t03_missing_or_nonunique_physical_alias_never_gets_a_command():
    component = _component()
    ip = "10.90.1.3"
    target, diagnostic, target_group = _runtime_case_records(
        "unverified-alias", ip, [component["component_id"]],
        "unverified-alias", duplicate=True,
    )
    peer, peer_diagnostic, peer_group = _runtime_case_records(
        "ip-peer", ip, [component["component_id"]], "ip-peer",
        duplicate=True,
    )
    check = _runtime_check_with_selector(
        target["alias"], ip, component, "mismatch",
        "registry.example/perception@sha256:" + "b" * 64,
        target["alias"],
    )
    group_rows = [target_group, peer_group]

    missing_inventory = _render_runtime_checks(
        [component], group_rows, [], [diagnostic, peer_diagnostic], [check],
    )
    duplicate_alias_inventory = _render_runtime_checks(
        [component], group_rows,
        [target, dict(target), peer], [diagnostic, peer_diagnostic], [check],
    )

    assert "MISMATCH" in missing_inventory
    assert "MISMATCH" in duplicate_alias_inventory
    assert f"`{target['alias']}`" in missing_inventory
    assert f"`{ip}`" in missing_inventory
    assert f"`{target['alias']}`" in duplicate_alias_inventory
    assert f"`{ip}`" in duplicate_alias_inventory
    assert f"/approve_deploy machine={target['alias']}" not in missing_inventory
    assert f"/approve_deploy machine={target['alias']}" not in duplicate_alias_inventory
    assert f"/approve_deploy machine={ip}" not in missing_inventory
    assert f"/approve_deploy machine={ip}" not in duplicate_alias_inventory


def test_v45d_t04_explicit_empty_selector_does_not_restore_a_historical_ip_command():
    component = _component()
    ip = "10.90.1.4"
    machine, diagnostic, group = _runtime_case_records(
        "revoked-selector", ip, [component["component_id"]], ip,
    )
    check = _runtime_check_with_selector(
        machine["alias"], ip, component, "mismatch",
        "registry.example/perception@sha256:" + "b" * 64, ip,
    )
    check["command_selector"] = ""

    previous_lifecycle = "\n".join([
        "### Machine Inventory",
        "| 编号 | 品牌 | 型号 | 别名 | 主 IP | 辅助 IP | Owner |",
        "|---|---|---|---|---|---|---|",
        f"| 001 | test | {machine['alias']} | {machine['alias']} | {ip} | — | @repo-owner |",
        "### Compatible Machines",
        "| 机器 | 主 IP | Owner | 审批命令 |",
        "|---|---|---|---|",
        f"| {machine['alias']} | {ip} | @repo-owner | `/approve_deploy machine={ip}` |",
    ])
    updated = comments.update_runtime_image_checks(
        previous_lifecycle, [check], [component],
        machine_groups=[group], machine_inventory=[machine],
        machine_diagnostics=[diagnostic], test_only=False,
    )
    runtime_start = updated.index("### 已部署组件镜像检查")
    runtime_end = updated.index("<!-- deploy-approval-runtime-checks:end -->", runtime_start)
    runtime = updated[runtime_start:runtime_end]

    assert f"`{machine['alias']}`" in runtime
    assert "MISMATCH" in runtime
    assert "/approve_deploy machine=" not in runtime
    assert f"`/approve_deploy machine={ip}`" in updated


def test_v45d_t05_test_only_runtime_owner_is_not_mentioned():
    component = _component()
    ip = "10.90.1.5"
    machine, diagnostic, group = _runtime_case_records(
        "test-only-runtime", ip, [component["component_id"]], ip,
    )
    check = _runtime_check_with_selector(
        machine["alias"], ip, component, "mismatch",
        "registry.example/perception@sha256:" + "b" * 64, ip,
    )

    block = _render_runtime_checks(
        [component], [group], [machine], [diagnostic], [check], test_only=True,
    )
    row = next(line for line in block.splitlines() if machine["alias"] in line)

    assert f"`{ip}`" in row
    assert "repo-owner" in row
    assert "@repo-owner" not in row
    assert "inventory-owner" not in row
    assert f"`/approve_deploy machine={ip}`" in row


def test_v45d_t06_regular_runtime_table_shows_the_repository_machine_owner():
    component = _component()
    ip = "10.90.1.6"
    machine, diagnostic, group = _runtime_case_records(
        "regular-runtime", ip, [component["component_id"]], ip,
        owner="current-repo-owner",
    )
    check = _runtime_check_with_selector(
        machine["alias"], ip, component, "mismatch",
        "registry.example/perception@sha256:" + "b" * 64, ip,
    )

    block = _render_runtime_checks(
        [component], [group], [machine], [diagnostic], [check],
    )
    row = next(line for line in block.splitlines() if machine["alias"] in line)

    assert "@current-repo-owner" in row
    assert "inventory-owner" not in row
    assert "负责人待配置" not in row
    assert f"`/approve_deploy machine={ip}`" in row


@pytest.mark.asyncio
async def test_v45d_t07_unknown_health_enters_read_only_preflight_and_never_skips_it(
    controller,
):
    machine = _machine(
        "unknown-health-preflight", "10.90.1.7", owners=["machine-owner"],
    )
    _set_repo_machines(controller, [machine])
    controller._physical_machine_inventory = MagicMock(return_value=[
        _physical_record(machine.alias, machine.node_host, node_id=machine.node_id),
    ])
    component = _component()
    assert controller._agent_core_status_for_machine(REPO, machine) == "unknown"
    assert controller._machine_is_deployable(machine, REPO) is True
    groups = controller._get_machine_groups_for_components([component], REPO)
    context = controller._machine_comment_context(
        [component], groups, REPO, test_only=False,
    )
    diagnostic = next(
        row for row in context["machine_diagnostics"]
        if row["alias"] == machine.alias
    )
    assert diagnostic["agent_core_credentials_configured"] is True
    assert diagnostic["agent_core_status"] == "unknown"
    assert groups[0]["approval_available"] is True

    state = _runtime_state(controller, [component], [])
    state["status"] = "deploy-requested"
    controller.proxy.get_pr = AsyncMock(return_value={
        "state": "open", "merged": False, "draft": False,
        "head": {"sha": HEAD}, "base": {"repo": {"full_name": REPO}},
    })
    controller.proxy.read_hidden_state = AsyncMock(return_value=copy.deepcopy(state))
    controller._fresh_review_evidence_matches_state = AsyncMock(return_value=True)
    controller._check_approval_permissions = AsyncMock()
    controller._write_lifecycle_with_history = AsyncMock(return_value=True)
    controller._post_command_reply = AsyncMock()
    controller._core_for_node = AsyncMock(return_value=MagicMock())
    controller._preflight_running_images = AsyncMock(side_effect=TimeoutError())
    controller._deploy_component = AsyncMock()

    handled = await controller.handle_approve_deploy(
        REPO, 71, 1701, machine.alias, "approver", "approver-id",
    )

    assert handled is True
    controller._core_for_node.assert_awaited_once_with(machine.node_id, REPO)
    controller._preflight_running_images.assert_awaited_once()
    controller._deploy_component.assert_not_awaited()
    controller._post_command_reply.assert_awaited()


def test_v45d_t08_unavailable_and_missing_credentials_block_approval(controller):
    machine = _machine(
        "blocked-agent-core", "10.90.1.8", owners=["machine-owner"],
    )
    component = _component()
    # The fixture's injected factory is a local stub; no credentials or network are read.
    _set_repo_machines(controller, [machine])
    controller._physical_machine_inventory = MagicMock(return_value=[
        _physical_record(machine.alias, machine.node_host, node_id=machine.node_id),
    ])

    for status in ("unavailable", "credential_missing"):
        controller._record_agent_core_health(REPO, machine, status)
        assert controller._machine_is_deployable(machine, REPO) is False
        groups = controller._get_machine_groups_for_components([component], REPO)
        assert len(groups) == 1
        assert groups[0]["approval_available"] is False
        assert groups[0]["component_ids"] == []
        assert groups[0]["command_selector"] == ""
        assert controller._machine_notice_lines(
            groups, REPO, mention_owners=False,
        ) == []


def test_v45d_t09_not_running_alone_is_unavailable_and_not_redeployable(controller):
    component = _component()
    ip = "10.90.1.9"
    machine, diagnostic, group = _runtime_case_records(
        "stopped-runtime", ip, [component["component_id"]], ip,
    )
    check = _runtime_check_with_selector(
        machine["alias"], ip, component, "not_running", "", ip,
    )
    block = _render_runtime_checks(
        [component], [group], [machine], [diagnostic], [check],
    )
    row = next(line for line in block.splitlines() if machine["alias"] in line)
    state = {"components": [component], "runtime_checks": [check]}

    assert "UNAVAILABLE" in row
    assert "组件未运行" in row
    assert "/approve_deploy machine=" not in row
    assert controller._confirmed_runtime_drift(state) == []
    assert controller._runtime_drift_command_lines(state, REPO) == []


def test_v45d_t10_only_mismatch_component_enters_redeploy_collection(controller):
    first = _component("a" * 16)
    second = _component("b" * 16, runtime_id="perception-stopped")
    ip = "10.90.1.10"
    machine = _machine(
        "mixed-runtime", ip, owners=["machine-owner"],
    )
    _set_repo_machines(controller, [machine])
    controller._physical_machine_inventory = MagicMock(return_value=[
        _physical_record(machine.alias, ip, node_id=machine.node_id),
    ])
    checks = [
        _runtime_check_with_selector(
            machine.alias, ip, first, "mismatch",
            "registry.example/perception@sha256:" + "b" * 64, ip,
        ),
        _runtime_check_with_selector(
            machine.alias, ip, second, "not_running", "", ip,
        ),
    ]
    state_checks = [
        _runtime_check(
            machine.alias, ip, first, "mismatch",
            "registry.example/perception@sha256:" + "b" * 64,
        ),
        _runtime_check(machine.alias, ip, second, "not_running", ""),
    ]
    state = _runtime_state(
        controller, [first, second], [{
            "machine": machine.alias, "ip": ip,
            "component_ids": [first["component_id"], second["component_id"]],
            "phase": "deployed",
        }], state_checks,
    )
    redeploy_state = controller._new_runtime_redeploy_round(
        state, comment_id=72, command_kind="approve_deploy",
        actor="approver", machine=machine.alias,
    )
    group = {
        "alias": machine.alias, "primary_ip": ip, "node_host": ip,
        "ip": ip, "owners": ["machine-owner"], "repo_authorized": True,
        "identity_confirmed": True, "approval_available": True,
        "command_selector": ip,
        "component_ids": [first["component_id"], second["component_id"]],
    }
    diagnostic = _safe_diagnostic(
        {"alias": machine.alias, "primary_ip": ip},
        first["component_id"],
        policy_owners=["machine-owner"], agent_core_credentials_configured=True,
        agent_core_status="available", component_ids=[
            first["component_id"], second["component_id"],
        ],
    )
    diagnostic.update({"primary_ip": ip, "identity_confirmed": True})
    rendered = _render_runtime_checks(
        [first, second], [group], [
            {"alias": machine.alias, "primary_ip": ip, "owners": ["machine-owner"]},
        ], [diagnostic], checks,
    )
    rows = [line for line in rendered.splitlines() if machine.alias in line]
    mismatch_row = next(line for line in rows if "MISMATCH" in line)
    stopped_row = next(line for line in rows if "UNAVAILABLE" in line)

    assert redeploy_state["runtime_redeploy"] == [{
        "machine": machine.alias, "ip": ip,
        "component_ids": [first["component_id"]],
    }]
    assert redeploy_state["deployments"][0]["component_ids"] == [
        second["component_id"],
    ]
    assert f"`/approve_deploy machine={ip}`" in mismatch_row
    assert "/approve_deploy machine=" not in stopped_row
    assert controller._runtime_drift_command_lines(redeploy_state, REPO) == [
        f"/approve_deploy machine={ip}",
    ]


def test_v45d_t11_all_matching_components_need_no_redeployment(controller):
    first = _component("a" * 16)
    second = _component("b" * 16, runtime_id="perception-two")
    ip = "10.90.1.11"
    machine, diagnostic, group = _runtime_case_records(
        "all-match-runtime", ip,
        [first["component_id"], second["component_id"]], ip,
    )
    checks = [
        _runtime_check_with_selector(
            machine["alias"], ip, component, "match", component["image_ref"], ip,
        )
        for component in (first, second)
    ]
    state_checks = [
        _runtime_check(
            machine["alias"], ip, component, "match", component["image_ref"],
        )
        for component in (first, second)
    ]
    state = _runtime_state(
        controller, [first, second], [{
            "machine": machine["alias"], "ip": ip,
            "component_ids": [first["component_id"], second["component_id"]],
            "phase": "deployed",
        }], state_checks,
    )
    block = _render_runtime_checks(
        [first, second], [group], [machine], [diagnostic], checks,
    )

    assert controller._confirmed_runtime_drift(state) == []
    assert controller._runtime_drift_command_lines(state, REPO) == []
    assert "MATCH" in block
    assert "无需重新部署" in block
    assert "/approve_deploy machine=" not in block
    with pytest.raises(DeployControllerError, match="no confirmed runtime image drift"):
        controller._new_runtime_redeploy_round(
            state, comment_id=73, command_kind="approve_deploy",
        )


def test_v45d_t12_identity_changed_cannot_reuse_the_old_machine_command():
    component = _component()
    old_ip = "10.90.1.12"
    machine, diagnostic, group = _runtime_case_records(
        "rebound-runtime", old_ip, [component["component_id"]], old_ip,
        identity_confirmed=False,
    )
    check = _runtime_check_with_selector(
        machine["alias"], old_ip, component, "identity_changed",
        "registry.example/perception@sha256:" + "b" * 64, old_ip,
        identity_confirmed=False,
    )
    block = _render_runtime_checks(
        [component], [group], [machine], [diagnostic], [check],
        machine_context={machine["alias"].casefold(): {
            "primary_ip": old_ip,
            "command_selector": old_ip,
        }},
    )
    row = next(line for line in block.splitlines() if machine["alias"] in line)

    assert "身份绑定变化" in row
    assert f"`{old_ip}`" in row
    assert "/approve_deploy machine=" not in row


def test_v45d_t13_unique_and_duplicate_ip_machines_use_distinct_selectors():
    unique_component = _component("a" * 16)
    duplicate_component = _component("b" * 16, runtime_id="perception-duplicate")
    unique_ip = "10.90.1.13"
    shared_ip = "10.90.1.14"
    unique, unique_diag, unique_group = _runtime_case_records(
        "ordinary-ip-machine", unique_ip,
        [unique_component["component_id"]], unique_ip,
        owner="ordinary-owner",
    )
    duplicate_a, duplicate_a_diag, duplicate_a_group = _runtime_case_records(
        "shared-ip-a", shared_ip, [duplicate_component["component_id"]],
        "shared-ip-a", owner="alias-owner", duplicate=True,
    )
    duplicate_b, duplicate_b_diag, duplicate_b_group = _runtime_case_records(
        "shared-ip-b", shared_ip, [duplicate_component["component_id"]],
        "shared-ip-b", owner="alias-owner", duplicate=True,
    )
    checks = [
        _runtime_check_with_selector(
            unique["alias"], unique_ip, unique_component, "mismatch",
            "registry.example/perception@sha256:" + "c" * 64, unique_ip,
        ),
        _runtime_check_with_selector(
            duplicate_a["alias"], shared_ip, duplicate_component, "mismatch",
            "registry.example/perception@sha256:" + "d" * 64,
            duplicate_a["alias"],
        ),
    ]

    markdown = _render_runtime_lifecycle(
        [unique_component, duplicate_component],
        [unique_group, duplicate_a_group, duplicate_b_group],
        [unique, duplicate_a, duplicate_b],
        [unique_diag, duplicate_a_diag, duplicate_b_diag], checks,
    )
    runtime = _runtime_section(markdown)
    unique_row = next(line for line in runtime.splitlines()
                      if unique["alias"] in line)
    duplicate_row = next(line for line in runtime.splitlines()
                         if duplicate_a["alias"] in line)

    assert unique_ip in unique_row
    assert "@ordinary-owner" in unique_row
    assert f"`/approve_deploy machine={unique_ip}`" in unique_row
    assert shared_ip in duplicate_row
    assert "@alias-owner" in duplicate_row
    assert f"`/approve_deploy machine={duplicate_a['alias']}`" in duplicate_row
    assert f"/approve_deploy machine={shared_ip}" not in runtime


def test_test_only_request_deploy_notice_mentions_repository_yaml_owners(controller):
    ip = "10.90.1.12"
    component = _component()
    machine = _machine(
        "test-only-owner-machine", ip,
        owners=["test-owner", "other-machine-owner"],
    )
    _set_repo_machines(controller, [machine])
    controller._physical_machine_inventory = MagicMock(return_value=[
        _physical_record(machine.alias, ip, node_id=machine.node_id),
    ])
    controller._record_agent_core_health(REPO, machine, "available")

    groups = controller._get_machine_groups_for_components([component], REPO)
    lines = controller._machine_notice_lines(
        groups, REPO, mention_owners=True, test_only=True,
        components=[component],
    )

    rendered = "\n".join(lines)
    assert "@test-owner" in rendered
    assert "@other-machine-owner" in rendered
    assert "/approve_deploy machine=10.90.1.12" in rendered


def test_test_only_request_deploy_mentions_the_current_policy_owner(controller):
    ip = "10.90.1.13"
    component = _component()
    machine = _machine(
        "test-only-other-owner-machine", ip,
        owners=["other-machine-owner"],
    )
    _set_repo_machines(controller, [machine])
    controller._physical_machine_inventory = MagicMock(return_value=[
        _physical_record(machine.alias, ip, node_id=machine.node_id),
    ])
    controller._record_agent_core_health(REPO, machine, "available")

    groups = controller._get_machine_groups_for_components([component], REPO)
    lines = controller._machine_notice_lines(
        groups, REPO, mention_owners=True, test_only=True,
        components=[component],
    )

    rendered = "\n".join(lines)
    assert "@other-machine-owner" in rendered
    assert "/approve_deploy machine=10.90.1.13" in rendered


@pytest.mark.asyncio
async def test_only_request_deploy_posts_yaml_owner_mentions(controller):
    ip = "10.90.1.16"
    component = _component()
    machine = _machine(
        "request-deploy-yaml-owner", ip, owners=["test-owner"],
    )
    _set_repo_machines(controller, [machine])
    controller._physical_machine_inventory = MagicMock(return_value=[])
    controller._record_agent_core_health(REPO, machine, "available")

    comment_id = 2016
    state = _runtime_state(controller, [component], [])
    state["status"] = "deploy-requested"
    state["round_id"] = f"{HEAD}-{comment_id}"
    state["command"] = {
        "comment_id": comment_id,
        "kind": "request_deploy",
        "phase": "completed",
        "args": {},
    }
    state["last_processed_comment_id"] = comment_id
    api_base = controller.config.github_api_url.rstrip("/")
    controller.proxy.get_pr = AsyncMock(return_value={
        "number": 16,
        "state": "open",
        "merged": False,
        "draft": False,
        "title": "[TEST ONLY] request deployment",
        "head": {"sha": HEAD},
        "base": {"repo": {"full_name": REPO}},
        "user": {"id": 42},
    })
    controller.proxy.read_hidden_state = AsyncMock(return_value=state)
    controller.proxy.get_comment = AsyncMock(return_value={
        "id": comment_id,
        "body": "/request_deploy",
        "user": {"id": 42},
        "created_at": "2026-11-14T00:00:00Z",
        "updated_at": "2026-11-14T00:00:00Z",
        "url": f"{api_base}/repos/{REPO}/issues/comments/{comment_id}",
        "issue_url": f"{api_base}/repos/{REPO}/issues/16",
    })
    controller.proxy.is_bot_comment = MagicMock(return_value=False)
    controller._post_bound_notice = AsyncMock(return_value=True)

    posted = await controller._ensure_request_deploy_notice(REPO, 16, comment_id)

    assert posted is True
    notice = controller._post_bound_notice.await_args.kwargs["message"]
    assert "@test-owner" in notice
    assert f"/approve_deploy machine={ip}" in notice


def test_runtime_transition_displays_yaml_owners_without_mentioning_them(controller):
    assert controller._runtime_transition_owner_labels(
        ["test-owner", "other-machine-owner"],
    ) == ["other-machine-owner", "test-owner"]


def test_test_only_mentions_use_repository_yaml_without_hardcoded_login(controller):
    controller.policy.reviewers_for_repo = MagicMock(return_value=[
        "test-owner", "another-reviewer",
    ])
    pr = {
        "title": "[TEST ONLY] acceptance request",
        "user": {"login": "different-author", "id": 42, "type": "User"},
    }

    configured, eligible = controller._eligible_acceptance_reviewers(REPO, pr)
    guidance = controller._acceptance_reviewer_guidance(
        REPO, pr, configured, eligible,
    )

    assert configured is True
    assert eligible == ["test-owner", "another-reviewer"]
    assert "@test-owner" in guidance
    assert "@another-reviewer" in guidance
    assert "PR 作者身份不影响" in guidance

    machine = _machine(
        "yaml-owner-machine", "10.90.1.15", owners=["test-owner"],
    )
    _set_repo_machines(controller, [machine])
    controller._physical_machine_inventory = MagicMock(return_value=[])
    controller._record_agent_core_health(REPO, machine, "available")
    groups = controller._get_machine_groups_for_components([_component()], REPO)
    lines = controller._machine_notice_lines(
        groups, REPO, mention_owners=True, test_only=True,
        components=[_component()],
    )
    assert any("@test-owner" in line for line in lines)
    assert any("/approve_deploy machine=10.90.1.15" in line for line in lines)


@pytest.mark.asyncio
async def test_rejected_in_progress_approval_has_structured_error_context(controller):
    controller.proxy.get_pr = AsyncMock(return_value={
        "state": "open",
        "merged": False,
        "draft": False,
        "head": {"sha": HEAD},
    })
    controller.proxy.read_hidden_state = AsyncMock(return_value={
        "head_sha": HEAD,
        "round_id": f"{HEAD}-74",
        "status": "deploying",
    })
    command = "/approve_deploy machine=10.90.1.14"
    controller.proxy.get_comment = AsyncMock(return_value={"body": command})
    controller._post_bound_notice = AsyncMock(return_value=True)

    await controller._post_command_reply(
        REPO, 1, 75,
        "A deployment POST is in progress; no retry was started.",
        topic="deployment-already-in-progress",
    )

    kwargs = controller._post_bound_notice.await_args.kwargs
    notice = kwargs["message"]
    assert command in notice
    assert "**具体错误：** 当前生命周期不允许：部署已在进行或结果待确认" in notice
    assert "**失败原因：**" in notice
    assert "**当前生命周期：** `deploying`" in notice
    assert "**下一步：**" in notice
    assert "不要重发审批命令或盲目重试部署 POST" in notice


@pytest.mark.asyncio
async def test_test_only_repository_yaml_reminders_do_not_change_record_test_authorization(controller):
    controller.policy.reviewers_for_repo = MagicMock(return_value=[
        "test-owner", "another-reviewer",
    ])
    state = {
        "status": "testing",
        "head_sha": HEAD,
        "round_id": f"{HEAD}-71",
        "acceptance_request": {
            "status": "pending",
            "head_sha": HEAD,
            "round_id": f"{HEAD}-71",
        },
    }

    await controller._check_record_test_permissions(
        REPO, "another-reviewer", state,
        actor_id="42", comment_id=73, result="pass",
    )
