"""Offline regressions for lifecycle recovery after interrupted deployments."""
from __future__ import annotations

import copy
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from ..github_command_watcher import ACTIVE_PROJECTION_STATUS_LABELS
from ..policy import Policy
from ..service import DeployController, DEPLOYMENT_UNCERTAIN_ESCALATION_SECONDS
from .conftest import make_config


REPO = "Haohao-end/phanthymotus"
PR = 573
HEAD = "a" * 40
ROUND_ID = f"{HEAD}-1"
COMMENT_ID = 1701
MACHINE = "rm75-test-01"
MACHINE_IP = "10.110.8.244"
TARGET_IMAGE = "registry.example/phanthymotus/perception@sha256:" + "b" * 64
UPLOAD_URL = "https://evidence.example/pr/573/upload"
API = "https://api.github.com"


def _component(**overrides) -> dict:
    value = {
        "component_id": "component-perception",
        "target": "perception",
        "driver_path": "",
        "variant": "v1",
        "review_image_tag": "registry.example/phanthymotus/perception:v1",
        "image_ref": TARGET_IMAGE,
        "resolved_platform": "linux/arm64",
        "runtime_id": "perception",
    }
    value.update(overrides)
    return value


def _state(*, status="deploying", phase="uncertain", args=None,
           deployments=None, components=None, **overrides) -> dict:
    value = {
        "version": 1,
        "head_sha": HEAD,
        "round_id": ROUND_ID,
        "round_started_at": "2026-11-25T00:00:00Z",
        "status": status,
        "review_evidence": {
            "build_comment_id": 101,
            "build_comment_updated_at": "2026-11-25T00:00:00Z",
            "commit_prefix": HEAD[:12],
            "resolved_head_sha": HEAD,
            "test_comment_id": 102,
            "test_comment_updated_at": "2026-11-25T00:00:01Z",
            "code_review_comment_id": 103,
            "code_review_comment_updated_at": "2026-11-25T00:00:02Z",
            "review_author_id": "7950763",
        },
        "components": copy.deepcopy(components or [_component()]),
        "deployments": copy.deepcopy(deployments or []),
        "approve_attempts": [],
        "approve_attempts_total": 0,
        "approve_attempts_truncated": False,
        "case_results": {},
        "test_result": "",
        "cos": {"object_key": "", "sha256": "", "size": 0},
        "command": {
            "comment_id": COMMENT_ID,
            "kind": "approve_deploy",
            "phase": phase,
            "args": copy.deepcopy(args or {
                "machine": MACHINE,
                "actor": "machine-owner",
                "node_id": "node-test-01",
                "node_host": MACHINE_IP,
                "deployment_request_submitted": True,
                "pending_component_ids": ["component-perception"],
                "uncertain_since": time.time(),
            }),
        },
        "last_processed_comment_id": COMMENT_ID,
    }
    value.update(overrides)
    return value


class FakeProxy:
    """In-memory GitHub boundary; never performs network I/O."""

    def __init__(self, state=None):
        self.state = copy.deepcopy(state)
        self.pr = {
            "number": PR,
            "state": "open",
            "merged": False,
            "draft": False,
            "head": {"sha": HEAD},
        }
        self.labels = []
        self.comments = []
        self.posted_comments = []
        self.source_comment = {
            "id": COMMENT_ID,
            "body": "/approve_deploy machine=10.110.8.244",
            "created_at": "2026-11-25T00:01:00Z",
            "updated_at": "2026-11-25T00:01:00Z",
            "url": f"{API}/repos/{REPO}/issues/comments/{COMMENT_ID}",
            "issue_url": f"{API}/repos/{REPO}/issues/{PR}",
            "user": {"id": 8, "login": "machine-owner", "type": "User"},
        }

    async def read_hidden_state(self, repo, pr_number):
        return copy.deepcopy(self.state)

    async def get_pr(self, repo, pr_number):
        return copy.deepcopy(self.pr)

    async def project_status_label(self, repo, pr_number, status):
        self.labels.append(status)

    async def get_comment(self, repo, comment_id):
        if comment_id == COMMENT_ID:
            return copy.deepcopy(self.source_comment)
        return next((copy.deepcopy(item) for item in self.comments
                     if item.get("id") == comment_id), None)

    async def get_issue_comments(self, repo, pr_number):
        return copy.deepcopy([self.source_comment, *self.comments])

    async def post_issue_comment(self, repo, pr_number, body):
        comment = {
            "id": 9000 + len(self.posted_comments),
            "body": body,
            "created_at": "2026-11-25T00:20:00Z",
            "updated_at": "2026-11-25T00:20:00Z",
            "url": f"{API}/repos/{repo}/issues/comments/9000",
            "issue_url": f"{API}/repos/{repo}/issues/{pr_number}",
            "user": {"id": 999, "login": "deploy-approval-bot", "type": "Bot"},
        }
        self.posted_comments.append(copy.deepcopy(comment))
        self.comments.append(copy.deepcopy(comment))
        return copy.deepcopy(comment)

    @staticmethod
    def is_bot_comment(comment):
        return (isinstance(comment, dict)
                and isinstance(comment.get("user"), dict)
                and comment["user"].get("type") == "Bot")


def _controller(state=None, *, proxy=None):
    config = make_config(github_repos=[REPO], active_repos=[REPO])
    proxy = proxy or FakeProxy(state)
    controller = DeployController(
        config, proxy, Policy(config), MagicMock(),
    )
    return controller, proxy


def _quiet_tick(controller):
    controller._write_lifecycle_with_history = AsyncMock(return_value=True)
    controller._project_status_best_effort = AsyncMock()
    controller._approval_retry_markdown = AsyncMock(return_value="retry summary")
    controller._get_machine_groups_for_components = MagicMock(return_value=[])
    controller._runtime_redeploy_machine_groups = MagicMock(return_value=[])
    controller._is_test_only_pr = MagicMock(return_value=False)
    controller._enrich_deployments_for_render = MagicMock(
        side_effect=lambda deployments, repo: deployments,
    )
    controller._save_deployed_machine_log = AsyncMock(return_value=True)
    controller._current_testing_upload_url = AsyncMock(return_value=UPLOAD_URL)


def _preflight_state(*, started_at=None, status="deploy-requested") -> dict:
    args = {
        "machine": MACHINE,
        "actor": "machine-owner",
        "deployment_request_submitted": True,
        "preflight_pending": True,
        "preflight_started_at": (
            time.time() - 1200 if started_at is None else started_at
        ),
    }
    return _state(status=status, phase="completed", args=args)


def _tick_pr():
    return {"state": "open", "merged": False, "draft": False,
            "head": {"sha": HEAD}}


def test_reviewing_status_is_kept_in_active_projection_scan():
    assert "status: reviewing" in ACTIVE_PROJECTION_STATUS_LABELS


def test_deploy_ready_status_is_kept_in_active_projection_scan():
    assert "status: deploy-ready" in ACTIVE_PROJECTION_STATUS_LABELS


def test_deploying_status_remains_active():
    assert "status: deploying" in ACTIVE_PROJECTION_STATUS_LABELS


@pytest.mark.asyncio
async def test_preflight_pending_reconcile_preserves_original_state():
    original = _preflight_state(started_at=time.time())
    controller, proxy = _controller(original)
    controller._restore_interrupted_approval_preflight = AsyncMock(return_value=False)
    controller._project_status_best_effort = AsyncMock()
    controller._write_lifecycle_with_history = AsyncMock()
    controller._build_component_snapshot = AsyncMock()

    await controller.reconcile_pr(REPO, PR)

    controller._restore_interrupted_approval_preflight.assert_awaited_once()
    controller._project_status_best_effort.assert_awaited_once_with(
        REPO, PR, "deploying",
    )
    controller._write_lifecycle_with_history.assert_not_awaited()
    controller._build_component_snapshot.assert_not_awaited()
    assert proxy.state == original


@pytest.mark.asyncio
async def test_preflight_pending_reconcile_does_not_overwrite_concurrent_testing_state():
    original = _preflight_state(started_at=time.time())
    controller, proxy = _controller(original)
    concurrent = _state(
        status="testing",
        phase="completed",
        deployments=[{
            "machine": MACHINE,
            "ip": MACHINE_IP,
            "component_ids": ["component-perception"],
            "phase": "deployed",
        }],
        args={"machine": MACHINE, "actor": "machine-owner"},
    )

    async def observe_concurrent_state(*args, **kwargs):
        proxy.state = copy.deepcopy(concurrent)
        return False

    controller._restore_interrupted_approval_preflight = AsyncMock(
        side_effect=observe_concurrent_state,
    )
    controller._project_status_best_effort = AsyncMock()
    controller._write_lifecycle_with_history = AsyncMock()
    controller._build_component_snapshot = AsyncMock()

    await controller.reconcile_pr(REPO, PR)

    assert proxy.state == concurrent
    controller._write_lifecycle_with_history.assert_not_awaited()
    controller._build_component_snapshot.assert_not_awaited()


@pytest.mark.asyncio
async def test_preflight_pending_reconcile_restores_after_timeout():
    original = _preflight_state(started_at=time.time() - 1200)
    controller, proxy = _controller(original)
    writes = []

    async def persist(repo, pr_number, new_state, markdown, **kwargs):
        writes.append(copy.deepcopy(new_state))
        proxy.state = copy.deepcopy(new_state)
        return True

    controller._approval_retry_status = MagicMock(return_value="deploy-ready")
    controller._get_machine_groups_for_components = MagicMock(return_value=[])
    controller._is_test_only_pr = MagicMock(return_value=False)
    controller._enrich_deployments_for_render = MagicMock(return_value=[])
    controller._approval_retry_markdown = AsyncMock(return_value="restored summary")
    controller._write_lifecycle_with_history = AsyncMock(side_effect=persist)
    controller._project_status_best_effort = AsyncMock()
    controller._post_command_reply = AsyncMock()
    controller._build_component_snapshot = AsyncMock()

    await controller.reconcile_pr(REPO, PR)

    assert len(writes) == 1
    assert writes[0]["status"] == "deploy-ready"
    assert writes[0]["command"]["args"].get("preflight_pending") is not True
    assert writes[0]["command"]["phase"] == "completed"
    controller._post_command_reply.assert_awaited_once()
    controller._build_component_snapshot.assert_not_awaited()


@pytest.mark.asyncio
async def test_uncertain_deploy_ready_state_recovers_read_only():
    state = _state(status="deploy-ready", phase="uncertain")
    controller, proxy = _controller(state)
    _quiet_tick(controller)
    controller._recover_uncertain_deployments = AsyncMock(return_value=False)
    controller._deploy_component = AsyncMock()
    controller._core_for_machine_endpoint = AsyncMock()

    await controller._recover_uncertain_deployment_tick(
        REPO, PR, state, _tick_pr(),
    )

    old_state, refreshed_state = controller._recover_uncertain_deployments.await_args.args[1:]
    assert old_state["status"] == "deploy-ready"
    assert refreshed_state["status"] == "deploying"
    assert state["status"] == "deploy-ready"
    controller._deploy_component.assert_not_awaited()
    controller._core_for_machine_endpoint.assert_not_awaited()
    assert proxy.posted_comments == []


@pytest.mark.asyncio
async def test_uncertain_deployment_posts_one_escalation_after_threshold():
    state = _state()
    state["command"]["args"]["uncertain_since"] = (
        time.time() - DEPLOYMENT_UNCERTAIN_ESCALATION_SECONDS - 1
    )
    controller, proxy = _controller(state)
    _quiet_tick(controller)
    controller._recover_uncertain_deployments = AsyncMock(return_value=False)

    await controller._recover_uncertain_deployment_tick(
        REPO, PR, state, _tick_pr(),
    )
    await controller._recover_uncertain_deployment_tick(
        REPO, PR, state, _tick_pr(),
    )

    assert len(proxy.posted_comments) == 1
    message = proxy.posted_comments[0]["body"]
    for expected in (
        MACHINE,
        MACHINE_IP,
        "component-perception",
        TARGET_IMAGE,
        "15 分钟",
        "Agent Core",
        "不要重复执行 `/approve_deploy`",
        "只读核对",
        "自动更新状态",
    ):
        assert expected in message
    assert "<!-- deploy-approval-notice:v1:" in message


@pytest.mark.asyncio
async def test_uncertain_deployment_does_not_escalate_before_threshold():
    state = _state()
    state["command"]["args"]["uncertain_since"] = (
        time.time() - DEPLOYMENT_UNCERTAIN_ESCALATION_SECONDS + 1
    )
    controller, proxy = _controller(state)
    _quiet_tick(controller)
    controller._recover_uncertain_deployments = AsyncMock(return_value=False)

    await controller._recover_uncertain_deployment_tick(
        REPO, PR, state, _tick_pr(),
    )

    assert proxy.posted_comments == []


@pytest.mark.asyncio
async def test_uncertain_deployment_does_not_repeat_deploy_post():
    state = _state()
    state["command"]["args"]["uncertain_since"] = time.time() - 10
    controller, proxy = _controller(state)
    _quiet_tick(controller)
    controller._recover_uncertain_deployments = AsyncMock(return_value=False)
    controller._deploy_component = AsyncMock()
    controller._core_for_machine_endpoint = AsyncMock()
    controller.deploy_driver = AsyncMock()

    await controller._recover_uncertain_deployment_tick(
        REPO, PR, state, _tick_pr(),
    )

    controller._deploy_component.assert_not_awaited()
    controller._core_for_machine_endpoint.assert_not_awaited()
    controller.deploy_driver.assert_not_awaited()
    assert proxy.posted_comments == []


async def _recover_target_to_testing(controller, state):
    async def confirm_target(repo, old_state, refreshed_state):
        component = refreshed_state["components"][0]
        assert component["image_ref"] == TARGET_IMAGE
        refreshed_state["deployments"] = [{
            "machine": MACHINE,
            "ip": MACHINE_IP,
            "component_ids": [component["component_id"]],
            "phase": "deployed",
        }]
        refreshed_state["status"] = "testing"
        refreshed_state["command"]["phase"] = "completed"
        refreshed_state["command"]["args"]["pending_component_ids"] = []
        return True

    controller._recover_uncertain_deployments = AsyncMock(
        side_effect=confirm_target,
    )
    controller._post_bound_notice = AsyncMock(return_value=True)
    await controller._recover_uncertain_deployment_tick(
        REPO, PR, state, _tick_pr(),
    )


@pytest.mark.asyncio
async def test_recovered_target_image_moves_to_testing():
    state = _state()
    state["command"]["args"]["uncertain_since"] = time.time()
    controller, _ = _controller(state)
    _quiet_tick(controller)
    await _recover_target_to_testing(controller, state)

    saved_state = controller._write_lifecycle_with_history.await_args.args[2]
    assert saved_state["status"] == "testing"
    assert saved_state["deployments"][0]["component_ids"] == [
        "component-perception",
    ]
    notice_kwargs = controller._post_bound_notice.await_args.kwargs
    assert notice_kwargs["topic"] == "deployment-recovered-complete"
    assert notice_kwargs["result"] == "accepted"
    assert UPLOAD_URL in notice_kwargs["message"]
    assert "/request_acceptance" in notice_kwargs["message"]


@pytest.mark.asyncio
async def test_recovered_deployment_does_not_post_escalation():
    state = _state()
    state["command"]["args"]["uncertain_since"] = (
        time.time() - DEPLOYMENT_UNCERTAIN_ESCALATION_SECONDS - 100
    )
    controller, _ = _controller(state)
    _quiet_tick(controller)
    await _recover_target_to_testing(controller, state)

    topics = [call.kwargs["topic"]
              for call in controller._post_bound_notice.await_args_list]
    assert "deployment-recovered-complete" in topics
    assert "deployment-recovery-escalation" not in topics
