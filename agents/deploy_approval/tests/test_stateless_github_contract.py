"""Stateless GitHub contract tests."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from unittest.mock import AsyncMock, MagicMock

from ..config import Config
from ..github_state_proxy import GitHubStateProxy, MalformedHiddenStateError, _validate_hidden_state
from ..models import MachineInfo
from ..policy import Policy
from ..review_client import ReviewJobInfo
from ..service import DeployController, DeployControllerError


@pytest.fixture
def config():
    return Config(
        github_token="tok",
        api_token="tok",
        agent_core_token="tok",
        github_repos=["repo"],
        machine_owners_file="/dev/null",
        github_command_poll_interval_seconds=60,
    )


@pytest.fixture
def mock_github():
    client = MagicMock()
    client.get_comment = AsyncMock()
    client.get_issue_comments = AsyncMock()
    client.post_issue_comment = AsyncMock(return_value={"id": 42})
    client.update_comment = AsyncMock()
    client.get_pr = AsyncMock()
    client.collaborator_permission = AsyncMock()
    client.get_issue_labels = AsyncMock(return_value=[])
    client.set_issue_labels = AsyncMock()
    client.list_open_prs = AsyncMock()
    return client


@pytest.fixture
def proxy(config, mock_github):
    return GitHubStateProxy(config, mock_github, bot_user_id="12345", bot_login="test-bot")


@pytest.fixture
def policy(config):
    p = Policy(config)
    p.machines = {
        "test-machine": MachineInfo(
            alias="test-machine",
            node_id="node-1",
            owners=["owner1"],
            node_host="127.0.0.1",
            targets=["perception"],
            platforms=["linux/arm64"],
            variants=["5.11"],
        ),
        "driver-machine": MachineInfo(
            alias="driver-machine",
            node_id="node-2",
            owners=["driver-owner"],
            node_host="127.0.0.2",
            targets=["driver"],
            platforms=["linux/arm64"],
            variants=[""],
            driver_paths=["custom/driver"],
        ),
    }
    return p


@pytest.fixture
def controller(config, proxy, policy, mock_github):
    review = MagicMock()
    review.list_jobs = AsyncMock()
    review.get_job = AsyncMock()
    registry = MagicMock()
    registry.resolve = AsyncMock()
    return DeployController(config, proxy, policy, mock_github, review, registry)


def _component(**overrides):
    component = {
        "component_id": "comp-001",
        "target": "perception",
        "driver_path": "",
        "variant": "5.11",
        "image_ref": "registry/repo@sha256:" + "a" * 64,
        "resolved_platform": "linux/arm64",
        "runtime_id": "perception",
    }
    component.update(overrides)
    return component


def _state(**overrides):
    state = {
        "version": 1,
        "head_sha": "a" * 40,
        "status": "deploy-requested",
        "review_job_id": "job-1",
        "components": [_component()],
        "deployments": [],
        "case_results": {},
        "test_result": "",
        "cos": {"object_key": "", "sha256": "", "size": 0},
        "command": {"comment_id": 0, "kind": "", "phase": "completed", "args": {}},
        "last_processed_comment_id": 0,
    }
    state.update(overrides)
    return state


def _review_job(job_id: str, head_sha: str, builds: list[dict], *, completed_at: str = "", updated_at: str = "", created_at: str = ""):
    raw = {
        "id": job_id,
        "repo": "repo",
        "pr_number": 1,
        "head_sha": head_sha,
        "status": "review_done",
        "review_text": "review complete",
        "options": {"build_only": False},
        "build_results": builds,
    }
    if completed_at:
        raw["completed_at"] = completed_at
    if updated_at:
        raw["updated_at"] = updated_at
    if created_at:
        raw["created_at"] = created_at
    return ReviewJobInfo(raw)


@pytest.mark.asyncio
async def test_request_deploy_re_reads_command_identity_from_github(controller, proxy, mock_github):
    mock_github.get_comment.return_value = {"id": 101, "user": {"id": 111, "login": "alice"}, "body": "/request_deploy"}
    mock_github.get_pr.return_value = {
        "state": "open",
        "merged": False,
        "head": {"sha": "a" * 40},
        "user": {"id": 111, "login": "alice"},
    }
    review_job = _review_job("job-1", "a" * 40, [{"target": "perception", "driver_path": "", "variant": "5.11", "success": True, "image_tag": "tag"}], completed_at="2026-09-01T10:00:00Z")
    controller.review.list_jobs = AsyncMock(return_value=[review_job])
    controller.review.get_job = AsyncMock(return_value=review_job)
    controller.registry.resolve.return_value = SimpleNamespace(image_ref="registry/repo@sha256:" + "b" * 64, platform="linux/arm64")
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    await controller.handle_request_deploy("repo", 1, 101)

    mock_github.get_comment.assert_called_once_with("repo", 101)


@pytest.mark.asyncio
async def test_request_deploy_allows_current_pr_author_id(controller, proxy, mock_github):
    mock_github.get_comment.return_value = {"id": 101, "user": {"id": 111, "login": "alice"}, "body": "/request_deploy"}
    mock_github.get_pr.return_value = {
        "state": "open",
        "merged": False,
        "head": {"sha": "a" * 40},
        "user": {"id": 111, "login": "alice"},
    }
    proxy.read_hidden_state = AsyncMock(return_value=_state(status="deploy-ready", review_job_id="job-1", components=[]))
    review_job = _review_job("job-1", "a" * 40, [{"target": "perception", "driver_path": "", "variant": "5.11", "success": True, "image_tag": "tag"}], completed_at="2026-09-01T10:00:00Z")
    controller.review.list_jobs = AsyncMock(return_value=[review_job])
    controller.review.get_job = AsyncMock(return_value=review_job)
    controller.registry.resolve.return_value = SimpleNamespace(image_ref="registry/repo@sha256:" + "b" * 64, platform="linux/arm64")
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    result = await controller.handle_request_deploy("repo", 1, 101)

    assert result is True
    proxy.write_hidden_state.assert_called_once()
    proxy.project_status_label.assert_called_once_with("repo", 1, "deploy-requested")


@pytest.mark.asyncio
async def test_request_deploy_rejects_non_pr_author_id(controller, proxy, mock_github):
    mock_github.get_comment.return_value = {"id": 101, "user": {"id": 222, "login": "mallory"}, "body": "/request_deploy"}
    mock_github.get_pr.return_value = {
        "state": "open",
        "merged": False,
        "head": {"sha": "a" * 40},
        "user": {"id": 111, "login": "alice"},
    }
    proxy.write_hidden_state = AsyncMock()
    proxy.post_issue_comment = AsyncMock()

    await controller.handle_request_deploy("repo", 1, 101)

    controller.review.list_jobs.assert_not_called()
    controller.registry.resolve.assert_not_called()
    proxy.write_hidden_state.assert_not_called()
    proxy.post_issue_comment.assert_called_once()


@pytest.mark.asyncio
async def test_request_deploy_missing_comment_identity_fails_closed(controller, proxy, mock_github):
    mock_github.get_comment.return_value = {"id": 101, "body": "/request_deploy", "user": {}}
    mock_github.get_pr.return_value = {
        "state": "open",
        "merged": False,
        "head": {"sha": "a" * 40},
        "user": {"id": 111, "login": "alice"},
    }
    proxy.write_hidden_state = AsyncMock()
    proxy.post_issue_comment = AsyncMock()

    await controller.handle_request_deploy("repo", 1, 101)

    controller.review.list_jobs.assert_not_called()
    controller.registry.resolve.assert_not_called()
    proxy.write_hidden_state.assert_not_called()
    proxy.post_issue_comment.assert_called_once()


@pytest.mark.asyncio
async def test_request_deploy_unauthorized_has_zero_registry_and_deploy_side_effects(controller, proxy, mock_github):
    mock_github.get_comment.return_value = {"id": 101, "user": {"id": 222, "login": "mallory"}, "body": "/request_deploy"}
    mock_github.get_pr.return_value = {
        "state": "open",
        "merged": False,
        "head": {"sha": "a" * 40},
        "user": {"id": 111, "login": "alice"},
    }
    proxy.write_hidden_state = AsyncMock()
    proxy.post_issue_comment = AsyncMock()

    await controller.handle_request_deploy("repo", 1, 101)

    controller.review.list_jobs.assert_not_called()
    controller.registry.resolve.assert_not_called()
    proxy.write_hidden_state.assert_not_called()


@pytest.mark.asyncio
async def test_latest_exact_head_review_done_selects_newest_completed_timestamp(controller):
    head_sha = "a" * 40
    job_new = _review_job("job-new", head_sha, [{"target": "perception", "driver_path": "", "variant": "6.1", "success": True, "image_tag": "tag-new"}], completed_at="2026-09-01T11:00:00Z")
    controller.review.list_jobs = AsyncMock(return_value=[
        _review_job("job-old", head_sha, [{"target": "perception", "driver_path": "", "variant": "5.11", "success": True, "image_tag": "tag-old"}], completed_at="2026-09-01T10:00:00Z"),
        job_new,
    ])
    controller.review.get_job = AsyncMock(return_value=job_new)

    job_id, builds = await controller.get_builds_for_pr("repo", 1, head_sha)

    assert job_id == "job-new"
    assert [b.variant for b in builds] == ["6.1"]


@pytest.mark.asyncio
async def test_latest_exact_head_review_done_binds_builds_from_same_selected_job(controller):
    head_sha = "a" * 40
    job_new = _review_job("job-new", head_sha, [{"target": "actucore", "driver_path": "", "variant": "6.1", "success": True, "image_tag": "tag-new"}], completed_at="2026-09-01T11:00:00Z")
    controller.review.list_jobs = AsyncMock(return_value=[
        _review_job("job-old", head_sha, [{"target": "perception", "driver_path": "", "variant": "5.11", "success": True, "image_tag": "tag-old"}], completed_at="2026-09-01T10:00:00Z"),
        job_new,
    ])
    controller.review.get_job = AsyncMock(return_value=job_new)

    job_id, builds = await controller.get_builds_for_pr("repo", 1, head_sha)

    assert job_id == "job-new"
    assert [b.target for b in builds] == ["actucore"]
    assert builds[0].image_tag == "tag-new"


@pytest.mark.asyncio
async def test_latest_exact_head_review_done_equal_timestamp_distinct_jobs_fails_closed(controller):
    head_sha = "a" * 40
    controller.review.list_jobs = AsyncMock(return_value=[
        _review_job("job-a", head_sha, [{"target": "perception", "driver_path": "", "variant": "5.11", "success": True, "image_tag": "tag-a"}], completed_at="2026-09-01T11:00:00Z"),
        _review_job("job-b", head_sha, [{"target": "perception", "driver_path": "", "variant": "6.1", "success": True, "image_tag": "tag-b"}], completed_at="2026-09-01T11:00:00Z"),
    ])

    assert await controller.get_builds_for_pr("repo", 1, head_sha) is None


@pytest.mark.asyncio
async def test_restart_executing_changes_only_command_phase_to_uncertain(controller, proxy):
    proxy.read_hidden_state = AsyncMock(return_value=_state(command={"comment_id": 1, "kind": "approve_deploy", "phase": "executing", "args": {"machine": "test-machine"}}))
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}, "user": {"id": 111, "login": "alice"}})

    await controller.reconcile_pr("repo", 1)

    written_state = proxy.write_hidden_state.call_args.args[3]
    markdown = proxy.write_hidden_state.call_args.args[2]
    assert written_state["status"] == "deploy-requested"
    assert written_state["command"]["phase"] == "uncertain"
    assert "**Status:** `deploy-requested`" in markdown
    assert "**Command phase:** `uncertain`" in markdown


@pytest.mark.asyncio
async def test_uncertain_preserves_business_status(controller, proxy):
    proxy.read_hidden_state = AsyncMock(return_value=_state(command={"comment_id": 1, "kind": "approve_deploy", "phase": "executing", "args": {"machine": "test-machine"}}))
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}, "user": {"id": 111, "login": "alice"}})

    await controller.reconcile_pr("repo", 1)

    assert proxy.write_hidden_state.call_args.args[3]["status"] == "deploy-requested"
    assert proxy.project_status_label.call_args_list[-1].args == ("repo", 1, "deploy-requested")


@pytest.mark.asyncio
async def test_uncertain_visible_status_matches_hidden_status(controller, proxy):
    proxy.read_hidden_state = AsyncMock(return_value=_state(command={"comment_id": 1, "kind": "approve_deploy", "phase": "executing", "args": {"machine": "test-machine"}}))
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}, "user": {"id": 111, "login": "alice"}})

    await controller.reconcile_pr("repo", 1)

    markdown = proxy.write_hidden_state.call_args.args[2]
    assert "**Status:** `deploy-requested`" in markdown
    assert "**Command phase:** `uncertain`" in markdown


@pytest.mark.asyncio
async def test_uncertain_never_auto_replays_agent_core(controller, proxy):
    proxy.read_hidden_state = AsyncMock(return_value=_state(command={"comment_id": 1, "kind": "approve_deploy", "phase": "executing", "args": {"machine": "test-machine"}}))
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}, "user": {"id": 111, "login": "alice"}})
    controller._core_for_node = AsyncMock()
    controller._deploy_component = AsyncMock()

    await controller.reconcile_pr("repo", 1)

    controller._core_for_node.assert_not_called()
    controller._deploy_component.assert_not_called()


def test_hidden_state_rejects_empty_review_job_for_deploy_requested():
    with pytest.raises(MalformedHiddenStateError, match="review_job_id"):
        _validate_hidden_state(_state(review_job_id=""))


def test_hidden_state_rejects_empty_platform_for_deploy_requested():
    with pytest.raises(MalformedHiddenStateError, match="resolved_platform"):
        _validate_hidden_state(_state(components=[_component(resolved_platform="")]))


def test_hidden_state_rejects_mutable_image_ref():
    with pytest.raises(MalformedHiddenStateError, match="image_ref"):
        _validate_hidden_state(_state(components=[_component(image_ref="registry/repo:latest")]))


def test_hidden_state_rejects_duplicate_component_ids():
    comp = _component()
    with pytest.raises(MalformedHiddenStateError, match="duplicate"):
        _validate_hidden_state(_state(components=[comp, dict(comp)]))


def test_hidden_state_rejects_unknown_deployment_component_id():
    with pytest.raises(MalformedHiddenStateError, match="unknown component"):
        _validate_hidden_state(_state(deployments=[{"machine": "test-machine", "component_ids": ["missing"], "phase": "deployed"}]))


def test_hidden_state_rejects_component_deployed_on_two_machines():
    with pytest.raises(MalformedHiddenStateError, match="deployed more than once"):
        _validate_hidden_state(
            _state(
                deployments=[
                    {"machine": "test-machine", "component_ids": ["comp-001"], "phase": "deployed"},
                    {"machine": "driver-machine", "component_ids": ["comp-001"], "phase": "deployed"},
                ]
            )
        )


def test_hidden_state_rejects_invalid_case_result():
    with pytest.raises(MalformedHiddenStateError, match="case_results"):
        _validate_hidden_state(_state(case_results={"comp-001": "boom"}))


def test_hidden_state_rejects_cos_extra_secret_key():
    with pytest.raises(MalformedHiddenStateError, match="cos keys"):
        _validate_hidden_state(_state(cos={"object_key": "", "sha256": "", "size": 0, "secret": "x"}))


def test_hidden_state_rejects_signed_url():
    with pytest.raises(MalformedHiddenStateError, match="cos keys"):
        _validate_hidden_state(_state(cos={"object_key": "", "sha256": "", "size": 0, "signed_url": "https://example"}))


def test_hidden_state_rejects_invalid_command_phase():
    with pytest.raises(MalformedHiddenStateError, match="command.phase"):
        _validate_hidden_state(_state(command={"comment_id": 1, "kind": "approve_deploy", "phase": "bogus", "args": {"machine": "test-machine"}}))


@pytest.mark.asyncio
async def test_machine_missing_node_host_fails_closed(controller, policy):
    policy.machines["broken"] = MachineInfo(
        alias="broken",
        node_id="node-x",
        owners=["owner1"],
        node_host="",
        targets=["perception"],
        platforms=["linux/arm64"],
    )

    with pytest.raises(DeployControllerError):
        await controller._resolve_core_client("node-x")


def test_machine_missing_targets_fails_closed(controller, policy):
    policy.machines["broken"] = MachineInfo(
        alias="broken",
        node_id="node-x",
        owners=["owner1"],
        node_host="127.0.0.9",
        targets=[],
        platforms=["linux/arm64"],
    )
    assert controller._get_component_ids_for_machine("broken", [_component()]) == []


def test_machine_missing_platforms_fails_closed(controller, policy):
    policy.machines["broken"] = MachineInfo(
        alias="broken",
        node_id="node-x",
        owners=["owner1"],
        node_host="127.0.0.9",
        targets=["perception"],
        platforms=[],
    )
    assert controller._get_component_ids_for_machine("broken", [_component()]) == []


def test_machine_variant_required_fails_closed(controller, policy):
    policy.machines["broken"] = MachineInfo(
        alias="broken",
        node_id="node-x",
        owners=["owner1"],
        node_host="127.0.0.9",
        targets=["perception"],
        platforms=["linux/arm64"],
        variants=["jetson-jp5.11"],
    )
    assert controller._get_component_ids_for_machine("broken", [_component(variant="")]) == []


def test_driver_machine_missing_driver_path_mapping_fails_closed(controller, policy):
    policy.machines["broken"] = MachineInfo(
        alias="broken",
        node_id="node-x",
        owners=["owner1"],
        node_host="127.0.0.9",
        targets=["driver"],
        platforms=["linux/arm64"],
        driver_paths=[],
    )
    assert controller._get_component_ids_for_machine("broken", [_component(target="driver", driver_path="custom/driver")]) == []


def test_unrelated_machine_hidden(controller, policy):
    policy.machines["unrelated"] = MachineInfo(
        alias="unrelated",
        node_id="node-y",
        owners=["owner2"],
        node_host="127.0.0.8",
        targets=["driver"],
        platforms=["linux/arm64"],
    )

    aliases = {g["alias"] for g in controller._get_machine_groups_for_components([_component()])}

    assert "test-machine" in aliases
    assert "unrelated" not in aliases
