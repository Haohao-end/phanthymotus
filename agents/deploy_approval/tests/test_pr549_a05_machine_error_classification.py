"""PR549_A05: machine lookup errors stay distinct and leave lifecycle untouched."""

from __future__ import annotations

import copy
from unittest.mock import AsyncMock, MagicMock

import pytest

from ..commands import parse_command
from ..models import MachineInfo
from ..service import DeployController, _is_machine_not_found_error


REPO = "Haohao-end/phanthymotus"
HEAD = "a" * 40
# Synthetic verified-policy fixture for checking the requested guidance text.
# Production guidance still comes from the live repository compatibility policy.
MACHINE_ALIAS = "rm75-014"
MACHINE_IP = "10.110.8.244"
COMPONENT_ID = "component-001"


def _component():
    return {
        "component_id": COMPONENT_ID,
        "target": "perception",
        "driver_path": "",
        "variant": "5.11",
        "review_image_tag": "registry.example/perception:v1",
        "image_ref": "registry.example/perception@sha256:" + "a" * 64,
        "resolved_platform": "linux/arm64",
        "runtime_id": "perception",
    }


def _machine():
    return MachineInfo(
        alias=MACHINE_ALIAS,
        node_id="node-rm75-014",
        owners=["machine-owner"],
        node_host=MACHINE_IP,
        targets=["perception"],
        platforms=["linux/arm64"],
        variants=["5.11"],
    )


def _state():
    return {
        "head_sha": HEAD,
        "round_id": f"{HEAD}-8",
        "status": "deploy-requested",
        "last_processed_comment_id": 8,
        "command": {
            "comment_id": 8,
            "kind": "request_deploy",
            "phase": "completed",
            "args": {},
        },
        "review_evidence": {"resolved_head_sha": HEAD},
        "components": [_component()],
        "deployments": [],
        "runtime_checks": [],
        "runtime_redeploy": [],
    }


def _controller(config, policy, command_body, *, compatible=True):
    machine = _machine()
    state = _state()
    pr = {
        "state": "open",
        "merged": False,
        "draft": False,
        "head": {"sha": HEAD},
        "base": {"repo": {"full_name": REPO}},
        "title": "Deploy test",
    }
    proxy = MagicMock()
    proxy.get_pr = AsyncMock(return_value=pr)
    proxy.read_hidden_state = AsyncMock(
        side_effect=lambda *_args, **_kwargs: copy.deepcopy(state),
    )
    proxy.get_comment = AsyncMock(return_value={"body": command_body})
    proxy.collaborator_permission = AsyncMock(return_value="read")
    controller = DeployController(
        config, proxy, policy, MagicMock(), agent_core_factory=lambda _node: None,
    )

    policy.repo_policy_status = MagicMock(return_value={
        "status": "configured",
        "authorized": True,
        "machines_configured": True,
        "reviewers_configured": True,
        "missing_files": [],
    })
    policy.get_machines = MagicMock(return_value=[machine])
    policy.get_machine = MagicMock(
        side_effect=lambda alias, repo=None: machine if alias == MACHINE_ALIAS else None,
    )

    group = {
        "alias": MACHINE_ALIAS,
        "primary_ip": MACHINE_IP,
        "command_selector": MACHINE_IP,
        "owners": ["machine-owner"],
        "approval_available": True,
        "component_ids": [COMPONENT_ID],
    }
    controller._get_machine_groups_for_components = MagicMock(return_value=[group])
    controller._machine_is_deployable = MagicMock(return_value=True)
    controller._machine_command_selector = MagicMock(return_value=MACHINE_IP)
    controller._get_component_ids_for_machine = MagicMock(
        return_value=[COMPONENT_ID] if compatible else [],
    )
    controller._fresh_review_evidence_matches_state = AsyncMock(return_value=True)
    controller._post_bound_notice = AsyncMock(return_value=True)
    controller._write_lifecycle_with_history = AsyncMock(return_value=True)
    controller._deploy_component = AsyncMock()
    controller._core_for_node = AsyncMock()
    controller._preflight_running_images = AsyncMock()
    return controller, state, machine


def _posted_notice(controller):
    return controller._post_bound_notice.await_args.kwargs["message"]


def _assert_lifecycle_unchanged(controller, state, head=HEAD):
    assert state == _state()
    assert state["head_sha"] == head
    controller._write_lifecycle_with_history.assert_not_awaited()
    controller._deploy_component.assert_not_awaited()


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("invalid machine selector 'missing-alias': not a known alias", True),
        ("unknown machine alias 'missing-alias'", True),
        ("no machine found with IP '203.0.113.77'", True),
        (
            "invalid machine selector '999.999.999.999': not a known alias or valid IPv4 address",
            False,
        ),
        ("unknown machine alias '999.999.999.999'", False),
    ],
    ids=[
        "selector", "unknown-alias", "unknown-ipv4",
        "invalid-selector-ip", "invalid-alias-ip",
    ],
)
def test_machine_lookup_cues_exclude_malformed_ip(message, expected):
    assert _is_machine_not_found_error(message) is expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "selector",
    [
        "not-registered-alias",
        "203.0.113.77",
    ],
    ids=["unknown-alias", "unknown-ipv4"],
)
async def test_unknown_machine_selector_has_specific_reply_and_no_lifecycle_write(
    config, policy, selector,
):
    command = f"/approve_deploy machine={selector}"
    controller, state, _machine_info = _controller(config, policy, command)

    handled = await controller.handle_approve_deploy(
        REPO, 1, 42, selector, "machine-owner", "owner-id",
    )

    assert handled is True
    notice = _posted_notice(controller)
    assert "**具体错误：** 机器不存在。" in notice
    assert "**失败原因：** 当前仓库机器配置中不存在该 alias 或 IP。" in notice
    assert "机器 `rm75-014`（主 IP：`10.110.8.244`）" in notice
    assert "`/approve_deploy machine=10.110.8.244`" in notice
    assert f"machine={selector}" in notice
    _assert_lifecycle_unchanged(controller, state)


@pytest.mark.asyncio
async def test_malformed_ipv4_is_a_format_error_not_a_missing_machine(config, policy):
    selector = "999.999.999.999"
    command = f"/approve_deploy machine={selector}"
    parsed = parse_command(command)
    assert parsed.error == "invalid_ip_format"

    controller, state, _machine_info = _controller(config, policy, command)
    await controller._post_command_reply(
        REPO, 1, 43,
        f"`machine=` must be a valid IPv4 address: {selector}",
        error=True,
    )

    notice = _posted_notice(controller)
    assert (
        "**具体错误：** IP 格式错误：machine 必须是有效 IPv4 地址或当前策略中的 alias"
        in notice
    )
    assert "**具体错误：** 机器不存在。" not in notice
    _assert_lifecycle_unchanged(controller, state)


@pytest.mark.asyncio
async def test_unauthorized_machine_is_not_classified_as_missing(config, policy):
    command = f"/approve_deploy machine={MACHINE_ALIAS}"
    controller, state, _machine_info = _controller(config, policy, command)

    handled = await controller.handle_approve_deploy(
        REPO, 1, 44, MACHINE_ALIAS, "unauthorized-user", "user-id",
    )

    assert handled is True
    notice = _posted_notice(controller)
    assert "**具体错误：** 无权限：当前账号不满足命令授权规则" in notice
    assert "**具体错误：** 机器不存在。" not in notice
    _assert_lifecycle_unchanged(controller, state)


@pytest.mark.asyncio
async def test_incompatible_machine_is_not_classified_as_missing_or_written(config, policy):
    command = f"/approve_deploy machine={MACHINE_ALIAS}"
    controller, state, _machine_info = _controller(
        config, policy, command, compatible=False,
    )

    handled = await controller.handle_approve_deploy(
        REPO, 1, 45, MACHINE_ALIAS, "machine-owner", "owner-id",
    )

    assert handled is True
    notice = _posted_notice(controller)
    assert "**具体错误：** 机器不兼容：当前机器不能部署剩余组件" in notice
    assert "**具体错误：** 机器不存在。" not in notice
    _assert_lifecycle_unchanged(controller, state)
