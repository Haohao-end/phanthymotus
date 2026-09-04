"""Final recovery/outcome regressions for Deploy Approval."""

from __future__ import annotations

import inspect
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from .. import agent_core_client as agent_core_client_module
from .. import comments as comments_mod
from ..agent_core_client import (
    AgentCoreClient,
    AgentCoreDeployOutcomeUncertain,
    AgentCoreError,
)
from ..clients_common import SecurityError
from ..config import Config, validate_config
from ..github_state_proxy import GitHubStateProxy, _validate_hidden_state
from ..models import BuildInfo, MachineInfo
from ..policy import Policy
from ..review_client import ReviewJobInfo
from ..github_command_watcher import GitHubCommandWatcher
from ..router_webhook import webhook
from ..service import DeployController, DeployControllerError, DeployOutcomeUncertain
from .conftest import make_config


def _component(**overrides) -> dict:
    component = {
        "component_id": "comp-001",
        "target": "perception",
        "driver_path": "",
        "variant": "5.11",
        "review_image_tag": "registry.example/repo:v1",
        "image_ref": "registry.example/repo@sha256:" + "a" * 64,
        "resolved_platform": "linux/arm64",
        "runtime_id": "perception",
    }
    component.update(overrides)
    return component


def _state(**overrides) -> dict:
    state = {
        "version": 1,
        "head_sha": "a" * 40,
        "status": "deploy-requested",
        "review_job_id": "job-old",
        "components": [_component()],
        "deployments": [],
        "approve_attempts": [],
        "approve_attempts_total": 0,
        "approve_attempts_truncated": False,
        "case_results": {},
        "test_result": "",
        "cos": {"object_key": "", "sha256": "", "size": 0},
        "command": {
            "comment_id": 17,
            "kind": "approve_deploy",
            "phase": "uncertain",
            "args": {"machine": "test-machine"},
        },
        "last_processed_comment_id": 17,
    }
    state.update(overrides)
    return state


def _build(*, target: str = "perception", driver_path: str = "", variant: str = "5.11",
           success: bool = True, image_tag: str = "registry.example/repo:v1") -> BuildInfo:
    return BuildInfo(
        idx=0,
        target=target,
        driver_path=driver_path,
        variant=variant,
        success=success,
        image_tag=image_tag,
        deployable=True,
    )


def _controller():
    config = make_config()
    config.github_token = "tok"
    proxy = MagicMock()
    proxy.read_hidden_state = AsyncMock(return_value=_state())
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
    proxy.comment_identity = AsyncMock(return_value=("111", "alice"))
    proxy.get_pr = AsyncMock(
        return_value={
            "state": "open",
            "merged": False,
            "head": {"sha": "a" * 40},
            "user": {"id": 111, "login": "alice"},
        }
    )
    proxy.get_issue_comments = AsyncMock(return_value=[])
    proxy.post_issue_comment = AsyncMock(return_value={"id": 1})
    proxy.collaborator_permission = AsyncMock(return_value="admin")
    policy = Policy(config)
    policy.machines = {
        "test-machine": MachineInfo(
            alias="test-machine",
            node_id="node-1",
            owners=["owner1"],
            node_host="127.0.0.1",
            targets=["perception", "actucore", "driver"],
            platforms=["linux/arm64"],
            variants=["5.11", "6.1"],
            driver_paths=["custom/driver"],
        )
    }
    github = MagicMock()
    github.get_current_user = AsyncMock(return_value={"id": 123, "login": "bot"})
    review = MagicMock()
    review.list_jobs = AsyncMock()
    review.get_job = AsyncMock()
    registry = MagicMock()
    registry.resolve = AsyncMock()
    controller = DeployController(config, proxy, policy, github, review, registry)
    return controller, proxy, policy, github, review, registry, config


def _request_payload(comment_body: str) -> dict:
    return {
        "action": "created",
        "repository": {"full_name": "repo"},
        "issue": {"number": 1, "pull_request": {}},
        "comment": {"id": 99},
    }


def _webhook_request(config, proxy, controller, payload, signature: str):
    body = json.dumps(payload).encode("utf-8")

    class _Request:
        def __init__(self):
            self.app = SimpleNamespace(
                state=SimpleNamespace(config=config, proxy=proxy, controller=controller)
            )
            self.headers = {
                "X-GitHub-Event": "issue_comment",
                "X-Hub-Signature-256": signature,
            }

        async def stream(self):
            yield body

    return _Request()


def _driver_client(transport: httpx.AsyncBaseTransport) -> AgentCoreClient:
    cfg = make_config(allow_private_http=True)
    cfg.github_token = "tok"
    return AgentCoreClient(
        cfg,
        base_url="http://10.0.0.1:15678",
        node_host="10.0.0.1",
        http=httpx.AsyncClient(transport=transport),
    )


def _fresh_component(**overrides) -> dict:
    component = _component(**overrides)
    component.pop("runtime_id", None)
    return component


@pytest.mark.asyncio
async def test_driver_status_current_no_container_shape_normalizes_to_empty_running_image():
    class Transport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            return httpx.Response(
                200,
                json={"code": 200, "data": {"status": "stopped", "logs": "no container"}},
                request=request,
            )

    client = _driver_client(Transport())
    result = await client.driver_status("driver")
    assert result == {"running_image": ""}


@pytest.mark.asyncio
async def test_driver_status_existing_container_ignores_status_value():
    class Transport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            return httpx.Response(
                200,
                json={
                    "code": 200,
                    "data": {
                        "status": 123,
                        "running_image": "registry.example/repo@sha256:" + "a" * 64,
                    },
                },
                request=request,
            )

    client = _driver_client(Transport())
    result = await client.driver_status("driver")
    assert result == {"running_image": "registry.example/repo@sha256:" + "a" * 64}


@pytest.mark.asyncio
async def test_driver_status_error_shape_without_running_image_fails_closed():
    class Transport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            return httpx.Response(
                200,
                json={"code": 200, "data": {"status": "error", "error": "docker unavailable"}},
                request=request,
            )

    client = _driver_client(Transport())
    with pytest.raises(AgentCoreError):
        await client.driver_status("driver")


@pytest.mark.asyncio
async def test_driver_status_malformed_missing_running_image_fails_closed():
    class Transport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            return httpx.Response(
                200,
                json={"code": 200, "data": {"status": "stopped"}},
                request=request,
            )

    client = _driver_client(Transport())
    with pytest.raises(AgentCoreError):
        await client.driver_status("driver")


@pytest.mark.asyncio
async def test_request_deploy_uses_canonical_component_snapshot_helper():
    controller, proxy, policy, github, review, registry, config = _controller()
    review_job = ReviewJobInfo(
        {
            "id": "job-new",
            "repo": "repo",
            "pr_number": 1,
            "head_sha": "a" * 40,
            "status": "review_done",
            "review_text": "review complete",
            "options": {"build_only": False},
            "completed_at": "2026-09-03T10:00:00Z",
            "build_results": [
                {"idx": 0, "target": "perception", "driver_path": "", "variant": "5.11", "success": True, "image_tag": "registry.example/repo:v1"},
            ],
        }
    )
    builds = [BuildInfo(0, "perception", "", "5.11", True, "registry.example/repo:v1", True)]
    controller.get_builds_for_pr = AsyncMock(return_value=("job-new", builds))
    controller._build_component_snapshot = AsyncMock(
        return_value=[
            {
                "component_id": "comp-123",
                "target": "perception",
                "driver_path": "",
                "variant": "5.11",
                "review_image_tag": "registry.example/repo:v1",
                "image_ref": "registry.example/repo@sha256:" + "b" * 64,
                "resolved_platform": "linux/arm64",
            }
        ]
    )
    review.list_jobs = AsyncMock(return_value=[review_job])
    review.get_job = AsyncMock(return_value=review_job)
    proxy.read_hidden_state = AsyncMock(
        return_value={
            "version": 1,
            "head_sha": "a" * 40,
            "status": "deploy-ready",
            "review_job_id": "",
            "components": [],
            "deployments": [],
            "case_results": {},
            "test_result": "",
            "cos": {"object_key": "", "sha256": "", "size": 0},
            "approve_attempts": [],
            "approve_attempts_total": 0,
            "approve_attempts_truncated": False,
            "command": {"comment_id": 0, "kind": "", "phase": "completed", "args": {}},
            "last_processed_comment_id": 0,
        }
    )
    mock_comment = {"id": 101, "user": {"id": 111, "login": "alice"}, "body": "/request_deploy"}
    proxy.get_comment = AsyncMock(return_value=mock_comment)
    proxy.get_pr = AsyncMock(
        return_value={
            "state": "open",
            "merged": False,
            "head": {"sha": "a" * 40},
            "user": {"id": 111, "login": "alice"},
        }
    )
    proxy.comment_identity = AsyncMock(return_value=("111", "alice"))
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    await controller.handle_request_deploy("repo", 1, 101)

    controller._build_component_snapshot.assert_awaited_once_with(
        "repo", 1, "a" * 40, builds
    )
    registry.resolve.assert_not_called()
    written_state = proxy.write_hidden_state.call_args.args[3]
    assert written_state["components"][0]["component_id"] == "comp-123"


@pytest.mark.asyncio
async def test_uncertain_recovery_rebuilds_fresh_component_snapshot():
    controller, proxy, policy, github, review, registry, config = _controller()
    state = _state(
        review_job_id="job-old",
        components=[_component(component_id="comp-old", image_ref="registry.example/repo@sha256:" + "c" * 64)],
        deployments=[],
    )
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}})
    controller.get_builds_for_pr = AsyncMock(return_value=("job-new", [_build()]))
    controller._build_component_snapshot = AsyncMock(
        return_value=[_component(component_id="comp-new", image_ref="registry.example/repo@sha256:" + "d" * 64)]
    )
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    result = await controller._refresh_uncertain_state("repo", 1, state)

    assert result == "deploy-requested"
    written_state = proxy.write_hidden_state.call_args.args[3]
    assert written_state["review_job_id"] == "job-new"
    assert written_state["components"][0]["component_id"] == "comp-new"


@pytest.mark.asyncio
async def test_uncertain_recovery_new_job_never_keeps_old_components():
    controller, proxy, policy, github, review, registry, config = _controller()
    state = _state(
        review_job_id="job-old",
        components=[_component(component_id="comp-old")],
        deployments=[],
    )
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}})
    controller.get_builds_for_pr = AsyncMock(return_value=("job-new", [_build()]))
    controller._build_component_snapshot = AsyncMock(return_value=[_component(component_id="comp-new")])
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    await controller._refresh_uncertain_state("repo", 1, state)

    written_state = proxy.write_hidden_state.call_args.args[3]
    assert [c["component_id"] for c in written_state["components"]] == ["comp-new"]


@pytest.mark.asyncio
async def test_uncertain_recovery_snapshot_change_resets_deployments():
    controller, proxy, policy, github, review, registry, config = _controller()
    state = _state(
        review_job_id="job-old",
        components=[_component(component_id="comp-old")],
        deployments=[{"machine": "test-machine", "component_ids": ["comp-old"], "phase": "deployed"}],
    )
    state["command"]["phase"] = "completed"
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}})
    controller.get_builds_for_pr = AsyncMock(return_value=("job-new", [_build(image_tag="registry.example/repo:v2")]))
    controller._build_component_snapshot = AsyncMock(
        return_value=[_component(component_id="comp-new", review_image_tag="registry.example/repo:v2")]
    )
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    await controller._refresh_uncertain_state("repo", 1, state)

    written_state = proxy.write_hidden_state.call_args.args[3]
    assert written_state["deployments"] == []
    assert written_state["components"] == [
        {
            "component_id": "comp-new",
            "target": "perception",
            "driver_path": "",
            "variant": "5.11",
            "review_image_tag": "registry.example/repo:v2",
            "image_ref": "registry.example/repo@sha256:" + "a" * 64,
            "resolved_platform": "linux/arm64",
        }
    ]


@pytest.mark.asyncio
async def test_uncertain_recovery_same_snapshot_preserves_known_successful_deployments():
    controller, proxy, policy, github, review, registry, config = _controller()
    state = _state(
        review_job_id="job-old",
        components=[
            _component(component_id="comp-1", runtime_id="perception"),
            _component(component_id="comp-2", runtime_id="actucore", target="actucore"),
        ],
        deployments=[{"machine": "test-machine", "component_ids": ["comp-1"], "phase": "deployed"}],
    )
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}})
    fresh_components = [
        _fresh_component(component_id="comp-1"),
        _fresh_component(component_id="comp-2", target="actucore"),
    ]
    controller.get_builds_for_pr = AsyncMock(return_value=("job-old", [_build(), _build(target="actucore")]))
    controller._build_component_snapshot = AsyncMock(return_value=fresh_components)
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    await controller._refresh_uncertain_state("repo", 1, state)

    written_state = proxy.write_hidden_state.call_args.args[3]
    assert written_state["deployments"] == state["deployments"]
    assert written_state["components"][0]["runtime_id"] == "perception"
    assert "runtime_id" not in written_state["components"][1]


@pytest.mark.asyncio
async def test_uncertain_recovery_clears_runtime_id_for_ambiguous_component():
    controller, proxy, policy, github, review, registry, config = _controller()
    state = _state(
        review_job_id="job-old",
        components=[
            _component(component_id="comp-1", runtime_id="perception"),
            _component(component_id="comp-2", target="actucore", runtime_id="actucore"),
        ],
        deployments=[{"machine": "test-machine", "component_ids": ["comp-1"], "phase": "deployed"}],
    )
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}})
    controller.get_builds_for_pr = AsyncMock(return_value=("job-old", [_build(), _build(target="actucore")]))
    controller._build_component_snapshot = AsyncMock(
        return_value=[
            _component(component_id="comp-1"),
            _component(component_id="comp-2", target="actucore"),
        ]
    )
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    await controller._refresh_uncertain_state("repo", 1, state)

    written_state = proxy.write_hidden_state.call_args.args[3]
    assert written_state["components"][0]["runtime_id"] == "perception"
    assert "runtime_id" not in written_state["components"][1]


@pytest.mark.asyncio
async def test_uncertain_recovery_registry_failure_stays_uncertain():
    controller, proxy, policy, github, review, registry, config = _controller()
    state = _state(
        review_job_id="job-old",
        components=[_component()],
        deployments=[{"machine": "test-machine", "component_ids": ["comp-001"], "phase": "deployed"}],
    )
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}})
    controller.get_builds_for_pr = AsyncMock(return_value=("job-new", [_build()]))
    controller._build_component_snapshot = AsyncMock(return_value=None)
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    result = await controller._refresh_uncertain_state("repo", 1, state)

    assert result == "uncertain"
    written_state = proxy.write_hidden_state.call_args.args[3]
    assert written_state["review_job_id"] == "job-old"
    assert written_state["components"] == [_component()]


@pytest.mark.asyncio
async def test_new_approve_from_uncertain_refreshes_before_clean_gate():
    controller, proxy, policy, github, review, registry, config = _controller()
    state = _state()
    refreshed_state = _state(
        review_job_id="job-new",
        components=[_component()],
        deployments=[],
        command={"comment_id": 17, "kind": "approve_deploy", "phase": "completed", "args": {"machine": "test-machine"}},
    )
    proxy.read_hidden_state = AsyncMock(side_effect=[state, refreshed_state, refreshed_state])
    events: list[str] = []

    async def _refresh(*args, **kwargs):
        events.append("refresh")
        return "deploy-requested"

    async def _list_drivers():
        events.append("list_drivers")
        return [{"id": "perception", "target": "perception", "image": "registry.example/repo:v1"}]

    async def _driver_status(runtime_id):
        events.append(f"driver_status:{runtime_id}")
        return {"status": "running", "running_image": "registry.example/repo@sha256:" + "a" * 64}

    controller._refresh_uncertain_state = AsyncMock(side_effect=_refresh)
    core = AsyncMock()
    core.list_drivers = AsyncMock(side_effect=_list_drivers)
    core.driver_status = AsyncMock(side_effect=_driver_status)
    core.deploy_driver = AsyncMock(return_value={"code": 0})
    controller._core_for_node = AsyncMock(return_value=core)
    controller._wait_for_deploy_health = AsyncMock(return_value={"passed": True, "running_image": "registry.example/repo@sha256:" + "a" * 64})
    controller._run_automated_case = AsyncMock(return_value={})
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}, "user": {"id": 111, "login": "alice"}})

    await controller.handle_approve_deploy("repo", 1, 17, "test-machine", "owner1", "111")

    assert events[0] == "refresh"
    assert "list_drivers" in events
    assert events.index("refresh") < events.index("list_drivers")


@pytest.mark.asyncio
async def test_watcher_uncertain_without_new_approve_does_not_refresh_review():
    controller, proxy, policy, github, review, registry, config = _controller()
    state = _state()
    state["command"]["phase"] = "uncertain"
    state["last_processed_comment_id"] = 17

    async def _read_hidden_state(*args, **kwargs):
        return state

    proxy.read_hidden_state = AsyncMock(side_effect=_read_hidden_state)
    proxy.get_pr = AsyncMock(
        return_value={
            "state": "open",
            "merged": False,
            "head": {"sha": "a" * 40},
            "user": {"id": 111, "login": "alice"},
        }
    )
    proxy.get_issue_comments = AsyncMock(
        return_value=[
            {
                "id": 17,
                "body": "/approve_deploy machine=test-machine",
                "user": {"id": 111, "login": "owner1"},
            }
        ]
    )
    proxy.is_bot_comment = MagicMock(return_value=False)
    controller.review.list_jobs = AsyncMock(side_effect=AssertionError("unexpected review refresh"))
    controller.review.get_job = AsyncMock(side_effect=AssertionError("unexpected review refresh"))
    controller.registry.resolve = AsyncMock(side_effect=AssertionError("unexpected registry refresh"))
    controller._core_for_node = AsyncMock(side_effect=AssertionError("unexpected Agent Core lookup"))
    controller._deploy_component = AsyncMock(side_effect=AssertionError("unexpected deploy"))
    controller._wait_for_deploy_health = AsyncMock(side_effect=AssertionError("unexpected health check"))
    controller._run_automated_case = AsyncMock(side_effect=AssertionError("unexpected case run"))
    controller.on_command = AsyncMock(return_value=True)

    watcher = GitHubCommandWatcher(config, proxy, controller)

    await watcher._process_pr("repo", 1)

    assert state["command"]["phase"] == "uncertain"
    assert controller.on_command.await_count == 0
    assert controller.review.list_jobs.await_count == 0
    assert controller.review.get_job.await_count == 0
    assert controller.registry.resolve.await_count == 0
    assert controller._core_for_node.await_count == 0
    assert controller._deploy_component.await_count == 0
    assert proxy.write_hidden_state.await_count == 0


@pytest.mark.asyncio
async def test_watcher_uncertain_new_approve_refreshes_review_before_clean_gate():
    controller, proxy, policy, github, review, registry, config = _controller()
    state = _state()
    state["command"]["phase"] = "uncertain"
    state["last_processed_comment_id"] = 17
    review_job = ReviewJobInfo(
        {
            "id": "job-new",
            "repo": "repo",
            "pr_number": 1,
            "head_sha": "a" * 40,
            "status": "review_done",
            "review_text": "review complete",
            "options": {"build_only": False},
            "completed_at": "2026-09-03T10:00:00Z",
            "build_results": [
                {
                    "target": "perception",
                    "driver_path": "",
                    "variant": "5.11",
                    "success": True,
                    "image_tag": "registry.example/repo:v1",
                }
            ],
        }
    )
    events: list[str] = []

    async def _read_hidden_state(*args, **kwargs):
        events.append("read_hidden_state")
        return state

    async def _get_pr(*args, **kwargs):
        events.append("get_pr")
        return {
            "state": "open",
            "merged": False,
            "head": {"sha": "a" * 40},
            "user": {"id": 111, "login": "alice"},
        }

    async def _get_issue_comments(*args, **kwargs):
        events.append("get_issue_comments")
        return [
            {
                "id": 17,
                "body": "/approve_deploy machine=test-machine",
                "user": {"id": 111, "login": "owner1"},
            },
            {
                "id": 99,
                "body": "/approve_deploy machine=test-machine",
                "user": {"id": 111, "login": "owner1"},
            },
        ]

    async def _list_jobs(*args, **kwargs):
        events.append("review.list_jobs")
        return [review_job]

    async def _get_job(*args, **kwargs):
        events.append("review.get_job")
        return review_job

    async def _resolve(*args, **kwargs):
        events.append("registry.resolve")
        return SimpleNamespace(
            image_ref="registry.example/repo@sha256:" + "b" * 64,
            platform="linux/arm64",
        )

    async def _list_drivers():
        events.append("list_drivers")
        return [
            {
                "id": "perception",
                "target": "perception",
                "image": "registry.example/repo:v1",
            }
        ]

    async def _driver_status(runtime_id):
        events.append(f"driver_status:{runtime_id}")
        return {"status": "running", "running_image": "occupied@sha256:" + "c" * 64}

    async def _deploy_component(*args, **kwargs):
        events.append("deploy")
        return {"result": {"code": 0}}

    proxy.read_hidden_state = AsyncMock(side_effect=_read_hidden_state)
    proxy.get_pr = AsyncMock(side_effect=_get_pr)
    proxy.get_issue_comments = AsyncMock(side_effect=_get_issue_comments)
    proxy.is_bot_comment = MagicMock(return_value=False)
    proxy.comment_identity = AsyncMock(return_value=("111", "owner1"))
    proxy.persist_cursor = AsyncMock()
    controller.review.list_jobs = AsyncMock(side_effect=_list_jobs)
    controller.review.get_job = AsyncMock(side_effect=_get_job)
    controller.registry.resolve = AsyncMock(side_effect=_resolve)
    core = AsyncMock()
    core.list_drivers = AsyncMock(side_effect=_list_drivers)
    core.driver_status = AsyncMock(side_effect=_driver_status)
    controller._core_for_node = AsyncMock(return_value=core)
    controller._deploy_component = AsyncMock(side_effect=_deploy_component)
    controller._wait_for_deploy_health = AsyncMock(side_effect=AssertionError("deploy health should not run on occupied gate"))
    controller._run_automated_case = AsyncMock(side_effect=AssertionError("automated case should not run on occupied gate"))
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
    real_on_command = controller.on_command
    controller.on_command = AsyncMock(wraps=real_on_command)

    watcher = GitHubCommandWatcher(config, proxy, controller)

    await watcher._process_pr("repo", 1)

    assert controller.on_command.await_count == 1
    assert controller.on_command.call_args.args[3] == 99
    assert state["command"]["phase"] == "completed"
    assert "review.list_jobs" in events
    assert "get_issue_comments" in events
    assert events.index("get_issue_comments") < events.index("review.list_jobs")
    assert events.index("review.list_jobs") < events.index("list_drivers")
    assert events.index("list_drivers") < events.index("driver_status:perception")
    assert "deploy" not in events
    assert proxy.write_hidden_state.await_count >= 1


@pytest.mark.asyncio
async def test_deploy_post_transport_timeout_becomes_uncertain():
    class Transport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            raise httpx.ReadTimeout("boom", request=request)

    client = _driver_client(Transport())
    with pytest.raises(AgentCoreDeployOutcomeUncertain):
        await client.deploy_driver("driver", "registry.example/repo@sha256:" + "a" * 64)


@pytest.mark.asyncio
async def test_deploy_post_non_success_response_becomes_uncertain():
    class Transport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            return httpx.Response(500, json={"code": 500, "message": "boom"}, request=request)

    client = _driver_client(Transport())
    with pytest.raises(AgentCoreDeployOutcomeUncertain):
        await client.deploy_driver("driver", "registry.example/repo@sha256:" + "a" * 64)


@pytest.mark.asyncio
async def test_deploy_post_malformed_response_becomes_uncertain():
    class Transport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            return httpx.Response(200, content=b"not-json", request=request)

    client = _driver_client(Transport())
    with pytest.raises(AgentCoreDeployOutcomeUncertain):
        await client.deploy_driver("driver", "registry.example/repo@sha256:" + "a" * 64)


@pytest.mark.asyncio
async def test_deploy_post_prevalidation_error_is_not_outcome_uncertain():
    class Transport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            raise AssertionError("POST should not be attempted")

    client = _driver_client(Transport())
    with pytest.raises(AgentCoreError) as excinfo:
        await client.deploy_driver("driver", "registry.example/repo:latest")
    assert not isinstance(excinfo.value, AgentCoreDeployOutcomeUncertain)


@pytest.mark.asyncio
async def test_uncertain_post_stops_later_components():
    controller, proxy, policy, github, review, registry, config = _controller()
    state = _state(
        components=[
            _component(component_id="comp-1", target="perception"),
            _component(component_id="comp-2", target="actucore", runtime_id="actucore"),
            _component(component_id="comp-3", target="driver", runtime_id="driver"),
        ],
        deployments=[],
    )
    state["command"]["phase"] = "completed"
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}, "user": {"id": 111, "login": "alice"}})
    core = AsyncMock()
    core.list_drivers = AsyncMock(
        return_value=[
            {"id": "perception", "target": "perception", "image": "registry.example/repo:v1"},
            {"id": "actucore", "target": "actucore", "image": "registry.example/repo:v1"},
            {"id": "driver", "target": "driver", "image": "registry.example/repo:v1"},
        ]
    )
    core.driver_status = AsyncMock(
        side_effect=[
            {"status": "running", "running_image": ""},
            {"status": "running", "running_image": ""},
        ]
    )
    controller._core_for_node = AsyncMock(return_value=core)
    deploy_calls = 0

    async def _deploy_component(*args, **kwargs):
        nonlocal deploy_calls
        deploy_calls += 1
        if deploy_calls == 2:
            raise DeployOutcomeUncertain("network timeout")
        return {"result": {"code": 0}}

    controller._deploy_component = AsyncMock(side_effect=_deploy_component)
    controller._wait_for_deploy_health = AsyncMock(return_value={"passed": True, "running_image": "registry.example/repo@sha256:" + "a" * 64})
    controller._run_automated_case = AsyncMock(return_value={})
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    await controller.handle_approve_deploy("repo", 1, 17, "test-machine", "owner1", "111")

    assert deploy_calls == 2
    assert proxy.write_hidden_state.call_args.args[3]["command"]["phase"] == "uncertain"


@pytest.mark.asyncio
async def test_uncertain_post_preserves_prior_health_passed_deployments():
    controller, proxy, policy, github, review, registry, config = _controller()
    state = _state(
        components=[
            _component(component_id="comp-1", target="perception"),
            _component(component_id="comp-2", target="actucore", runtime_id="actucore"),
        ],
        deployments=[],
    )
    state["command"]["phase"] = "completed"
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}, "user": {"id": 111, "login": "alice"}})
    core = AsyncMock()
    core.list_drivers = AsyncMock(
        return_value=[
            {"id": "perception", "target": "perception", "image": "registry.example/repo:v1"},
            {"id": "actucore", "target": "actucore", "image": "registry.example/repo:v1"},
        ]
    )
    core.driver_status = AsyncMock(
        side_effect=[
            {"status": "running", "running_image": ""},
            {"status": "running", "running_image": ""},
        ]
    )
    controller._core_for_node = AsyncMock(return_value=core)

    async def _deploy_component(*args, **kwargs):
        if args[3] == "actucore":
            raise DeployOutcomeUncertain("connection reset")
        return {"result": {"code": 0}}

    controller._deploy_component = AsyncMock(side_effect=_deploy_component)
    controller._wait_for_deploy_health = AsyncMock(return_value={"passed": True, "running_image": "registry.example/repo@sha256:" + "a" * 64})
    controller._run_automated_case = AsyncMock(return_value={})
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    await controller.handle_approve_deploy("repo", 1, 17, "test-machine", "owner1", "111")

    written_state = proxy.write_hidden_state.call_args.args[3]
    assert written_state["deployments"] == [{"machine": "test-machine", "component_ids": ["comp-1"], "phase": "deployed"}]


@pytest.mark.asyncio
async def test_uncertain_post_does_not_upload_failed_cos():
    controller, proxy, policy, github, review, registry, config = _controller()
    state = _state(
        components=[_component(component_id="comp-1"), _component(component_id="comp-2", target="actucore", runtime_id="actucore")],
        deployments=[],
    )
    state["command"]["phase"] = "completed"
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}, "user": {"id": 111, "login": "alice"}})
    core = AsyncMock()
    core.list_drivers = AsyncMock(
        return_value=[
            {"id": "perception", "target": "perception", "image": "registry.example/repo:v1"},
            {"id": "actucore", "target": "actucore", "image": "registry.example/repo:v1"},
        ]
    )
    core.driver_status = AsyncMock(
        side_effect=[
            {"status": "running", "running_image": ""},
            {"status": "running", "running_image": ""},
        ]
    )
    controller._core_for_node = AsyncMock(return_value=core)
    controller._deploy_component = AsyncMock(side_effect=DeployOutcomeUncertain("timeout"))
    controller._wait_for_deploy_health = AsyncMock(return_value={"passed": True, "running_image": "registry.example/repo@sha256:" + "a" * 64})
    controller._run_automated_case = AsyncMock(return_value={})
    controller._upload_evidence = AsyncMock()
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    await controller.handle_approve_deploy("repo", 1, 17, "test-machine", "owner1", "111")

    controller._upload_evidence.assert_not_called()


@pytest.mark.asyncio
async def test_uncertain_post_advances_cursor():
    controller, proxy, policy, github, review, registry, config = _controller()
    state = _state(
        components=[_component()],
        deployments=[],
    )
    state["command"]["phase"] = "completed"
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}, "user": {"id": 111, "login": "alice"}})
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[{"id": "perception", "target": "perception", "image": "registry.example/repo:v1"}])
    core.driver_status = AsyncMock(return_value={"status": "running", "running_image": ""})
    controller._core_for_node = AsyncMock(return_value=core)
    controller._deploy_component = AsyncMock(side_effect=DeployOutcomeUncertain("timeout"))
    controller._wait_for_deploy_health = AsyncMock(return_value={"passed": True, "running_image": "registry.example/repo@sha256:" + "a" * 64})
    controller._run_automated_case = AsyncMock(return_value={})
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    await controller.handle_approve_deploy("repo", 1, 19, "test-machine", "owner1", "111")

    written_state = proxy.write_hidden_state.call_args.args[3]
    assert written_state["last_processed_comment_id"] == 19
    assert written_state["command"]["phase"] == "uncertain"


@pytest.mark.asyncio
async def test_uncertain_post_write_failure_leaves_executing_for_restart_recovery():
    controller, proxy, policy, github, review, registry, config = _controller()
    state = _state(
        components=[_component()],
        deployments=[],
    )
    state["command"]["phase"] = "completed"
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}, "user": {"id": 111, "login": "alice"}})
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[{"id": "perception", "target": "perception", "image": "registry.example/repo:v1"}])
    core.driver_status = AsyncMock(return_value={"status": "running", "running_image": ""})
    controller._core_for_node = AsyncMock(return_value=core)
    controller._deploy_component = AsyncMock(side_effect=DeployOutcomeUncertain("timeout"))
    controller._wait_for_deploy_health = AsyncMock(return_value={"passed": True, "running_image": "registry.example/repo@sha256:" + "a" * 64})
    controller._run_automated_case = AsyncMock(return_value={})
    proxy.write_hidden_state = AsyncMock(side_effect=[{"id": 1}, RuntimeError("write failed")])
    proxy.project_status_label = AsyncMock()

    with pytest.raises(RuntimeError, match="write failed"):
        await controller.handle_approve_deploy("repo", 1, 21, "test-machine", "owner1", "111")

    assert proxy.write_hidden_state.call_args_list[0].args[2] == "Deploying..."
    assert "Restart Recovery" in proxy.write_hidden_state.call_args_list[-1].args[2]
    proxy.project_status_label.assert_not_called()


@pytest.mark.asyncio
async def test_health_failure_after_validated_post_remains_terminal_failed():
    controller, proxy, policy, github, review, registry, config = _controller()
    state = _state(
        components=[_component()],
        deployments=[],
    )
    state["command"]["phase"] = "completed"
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}, "user": {"id": 111, "login": "alice"}})
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[{"id": "perception", "target": "perception", "image": "registry.example/repo:v1"}])
    core.driver_status = AsyncMock(return_value={"status": "running", "running_image": ""})
    controller._core_for_node = AsyncMock(return_value=core)
    controller._deploy_component = AsyncMock(return_value={"result": {"code": 0}})
    controller._wait_for_deploy_health = AsyncMock(return_value={"passed": False, "running_image": ""})
    controller._run_automated_case = AsyncMock(return_value={})
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    await controller.handle_approve_deploy("repo", 1, 23, "test-machine", "owner1", "111")

    written_state = proxy.write_hidden_state.call_args.args[3]
    assert written_state["status"] == "failed"
    assert written_state["command"]["phase"] == "completed"


def test_poll_disabled_webhook_enabled_fails_config():
    with pytest.raises(ValueError, match="requires polling"):
        validate_config(
            Config(
                github_token="tok",
                github_repos=[
                    "4paradigm/phanthymotus",
                    "4paradigm/phanthymotus-driver",
                ],
                poll_enabled=False,
                webhook_enabled=True,
                github_webhook_secret="secret",
            )
        )


@pytest.mark.asyncio
async def test_webhook_remains_supplementary_zero_dispatch():
    controller, proxy, policy, github, review, registry, config = _controller()
    config.webhook_enabled = True
    payload = {
        "action": "created",
        "repository": {"full_name": "4paradigm/phanthymotus"},
        "issue": {"number": 1, "pull_request": {}},
        "comment": {"id": 99},
    }
    proxy.get_comment = AsyncMock(return_value={"id": 99, "body": "/request_deploy", "user": {"id": 111, "login": "alice"}})
    controller.on_command = AsyncMock()
    request = _webhook_request(config, proxy, controller, payload, "sha256=" + "0" * 64)

    with patch("agents.deploy_approval.router_webhook._verify_signature_impl", return_value=True):
        result = await webhook(request)

    assert result["status"] == "deferred"
    controller.on_command.assert_not_called()


def test_hidden_state_accepts_uncertain_approve_attempt():
    state = _state(
        approve_attempts=[
            {
                "comment_id": 101,
                "actor": "alice",
                "machine": "test-machine",
                "preflight": [],
                "outcome": "uncertain",
                "health": [],
            }
        ],
        approve_attempts_total=1,
        command={
            "comment_id": 101,
            "kind": "approve_deploy",
            "phase": "uncertain",
            "args": {"machine": "test-machine"},
        },
    )
    state["status"] = "deploy-requested"
    _validate_hidden_state(state)


def test_hidden_state_rejects_unknown_approve_attempt_outcome():
    state = _state(
        approve_attempts=[
            {
                "comment_id": 101,
                "actor": "alice",
                "machine": "test-machine",
                "preflight": [],
                "outcome": "bogus",
                "health": [],
            }
        ],
        command={
            "comment_id": 101,
            "kind": "approve_deploy",
            "phase": "uncertain",
            "args": {"machine": "test-machine"},
        },
    )
    state["status"] = "deploy-requested"
    with pytest.raises(Exception):
        _validate_hidden_state(state)


def test_uncertain_post_state_passes_real_hidden_state_validator():
    state = _state(
        approve_attempts=[
            {
                "comment_id": 17,
                "actor": "alice",
                "machine": "test-machine",
                "preflight": [
                    {"component_id": "comp-001", "runtime_id": "perception", "running_image": ""}
                ],
                "outcome": "uncertain",
                "health": [
                    {
                        "component_id": "comp-001",
                        "runtime_id": "perception",
                        "running_image": "registry.example/repo@sha256:" + "a" * 64,
                        "passed": True,
                    }
                ],
            }
        ],
        approve_attempts_total=1,
        command={
            "comment_id": 17,
            "kind": "approve_deploy",
            "phase": "uncertain",
            "args": {"machine": "test-machine"},
        },
    )
    state["status"] = "deploy-requested"
    _validate_hidden_state(state)


@pytest.mark.asyncio
async def test_build_component_snapshot_never_contains_runtime_id():
    controller, proxy, policy, github, review, registry, config = _controller()
    controller._resolve_image_ref = AsyncMock(
        return_value=("registry.example/repo@sha256:" + "b" * 64, "linux/arm64")
    )
    result = await controller._build_component_snapshot(
        "repo",
        1,
        "a" * 40,
        [_build(), _build(target="actucore")],
    )
    assert result is not None
    assert result
    assert all("runtime_id" not in component for component in result)


def test_uncertain_same_snapshot_preserves_runtime_id_from_old_deployed_component():
    controller, proxy, policy, github, review, registry, config = _controller()
    fresh = [
        _fresh_component(component_id="comp-1"),
        _fresh_component(component_id="comp-2", target="actucore"),
    ]
    rebuilt = controller._components_with_preserved_runtime_bindings(
        fresh,
        [
            _component(component_id="comp-1", runtime_id="perception"),
            _component(component_id="comp-2", target="actucore", runtime_id="actucore"),
        ],
        [{"machine": "test-machine", "component_ids": ["comp-1"], "phase": "deployed"}],
    )
    assert rebuilt is not None
    assert rebuilt[0]["runtime_id"] == "perception"
    assert "runtime_id" not in rebuilt[1]


@pytest.mark.asyncio
async def test_uncertain_same_snapshot_real_snapshot_helper_preserves_deployed_runtime_binding():
    controller, proxy, policy, github, review, registry, config = _controller()
    controller._resolve_image_ref = AsyncMock(
        side_effect=[
            ("registry.example/repo@sha256:" + "a" * 64, "linux/arm64"),
            ("registry.example/repo@sha256:" + "a" * 64, "linux/arm64"),
        ]
    )
    fresh_components = await controller._build_component_snapshot(
        "repo",
        1,
        "a" * 40,
        [_build(), _build(target="actucore")],
    )
    assert fresh_components is not None
    state = _state(
        review_job_id="job-old",
        components=[
            dict(fresh_components[0], runtime_id="perception"),
            dict(fresh_components[1], runtime_id="actucore"),
        ],
        deployments=[{"machine": "test-machine", "component_ids": [fresh_components[0]["component_id"]], "phase": "deployed"}],
    )
    state["command"]["phase"] = "completed"
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}})
    controller.get_builds_for_pr = AsyncMock(return_value=("job-old", [_build(), _build(target="actucore")]))
    controller._resolve_image_ref = AsyncMock(
        side_effect=[
            ("registry.example/repo@sha256:" + "a" * 64, "linux/arm64"),
            ("registry.example/repo@sha256:" + "a" * 64, "linux/arm64"),
        ]
    )
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    result = await controller._refresh_uncertain_state("repo", 1, state)

    assert result == "deploy-requested"
    written_state = proxy.write_hidden_state.call_args.args[3]
    assert written_state["components"][0]["runtime_id"] == "perception"
    assert "runtime_id" not in written_state["components"][1]


def test_uncertain_same_snapshot_clears_old_runtime_id_for_undeployed_component():
    controller, proxy, policy, github, review, registry, config = _controller()
    rebuilt = controller._components_with_preserved_runtime_bindings(
        [
            _fresh_component(component_id="comp-1"),
            _fresh_component(component_id="comp-2", target="actucore"),
        ],
        [
            _component(component_id="comp-1", runtime_id="perception"),
            _component(component_id="comp-2", target="actucore", runtime_id="actucore"),
        ],
        [{"machine": "test-machine", "component_ids": ["comp-1"], "phase": "deployed"}],
    )
    assert rebuilt is not None
    assert rebuilt[0]["runtime_id"] == "perception"
    assert "runtime_id" not in rebuilt[1]


@pytest.mark.asyncio
async def test_uncertain_same_snapshot_missing_old_deployed_runtime_binding_stays_uncertain():
    controller, proxy, policy, github, review, registry, config = _controller()
    controller._resolve_image_ref = AsyncMock(
        side_effect=[
            ("registry.example/repo@sha256:" + "a" * 64, "linux/arm64"),
            ("registry.example/repo@sha256:" + "a" * 64, "linux/arm64"),
        ]
    )
    fresh_components = await controller._build_component_snapshot(
        "repo",
        1,
        "a" * 40,
        [_build(), _build(target="actucore")],
    )
    assert fresh_components is not None
    state = _state(
        review_job_id="job-old",
        components=[
            dict(fresh_components[0], runtime_id=""),
            dict(fresh_components[1]),
        ],
        deployments=[{"machine": "test-machine", "component_ids": [fresh_components[0]["component_id"]], "phase": "deployed"}],
    )
    state["command"]["phase"] = "completed"
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}})
    controller.get_builds_for_pr = AsyncMock(return_value=("job-old", [_build(), _build(target="actucore")]))
    controller._resolve_image_ref = AsyncMock(
        side_effect=[
            ("registry.example/repo@sha256:" + "a" * 64, "linux/arm64"),
            ("registry.example/repo@sha256:" + "a" * 64, "linux/arm64"),
        ]
    )
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    result = await controller._refresh_uncertain_state("repo", 1, state)

    assert result == "uncertain"
    written_state = proxy.write_hidden_state.call_args.args[3]
    assert written_state["command"]["phase"] == "uncertain"
    assert written_state["review_job_id"] == "job-old"
    assert written_state["deployments"] == [
        {
            "machine": "test-machine",
            "component_ids": [fresh_components[0]["component_id"]],
            "phase": "deployed",
        }
    ]


@pytest.mark.asyncio
async def test_uncertain_changed_snapshot_ignores_missing_old_runtime_binding_and_resets_validation():
    controller, proxy, policy, github, review, registry, config = _controller()
    state = _state(
        review_job_id="job-old",
        components=[
            _component(component_id="comp-1", runtime_id=""),
            _component(component_id="comp-2", target="actucore"),
        ],
        deployments=[{"machine": "test-machine", "component_ids": ["comp-1"], "phase": "deployed"}],
        approve_attempts=[
            {
                "comment_id": 11,
                "actor": "alice",
                "machine": "test-machine",
                "preflight": [],
                "outcome": "deployed",
                "health": [],
            }
        ],
        approve_attempts_total=1,
        case_results={"comp-1": "pass"},
        test_result="pass",
        cos={"object_key": "deploy-1", "sha256": "a" * 64, "size": 123},
    )
    state["command"]["phase"] = "completed"
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}})
    controller.get_builds_for_pr = AsyncMock(return_value=("job-new", [_build(), _build(target="actucore")]))
    controller._resolve_image_ref = AsyncMock(
        side_effect=[
            ("registry.example/repo@sha256:" + "a" * 64, "linux/arm64"),
            ("registry.example/repo@sha256:" + "a" * 64, "linux/arm64"),
        ]
    )
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    result = await controller._refresh_uncertain_state("repo", 1, state)

    assert result == "deploy-requested"
    written_state = proxy.write_hidden_state.call_args.args[3]
    assert written_state["review_job_id"] == "job-new"
    assert written_state["status"] == "deploy-requested"
    assert written_state["command"]["phase"] == "completed"
    assert all("runtime_id" not in component for component in written_state["components"])
    assert written_state["deployments"] == []
    assert written_state["approve_attempts"] == []
    assert written_state["approve_attempts_total"] == 0
    assert written_state["approve_attempts_truncated"] is False
    assert written_state["case_results"] == {}
    assert written_state["test_result"] == ""
    assert written_state["cos"] == {"object_key": "", "sha256": "", "size": 0}


def test_driver_status_logs_only_shape_fails_closed():
    class Transport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            return httpx.Response(
                200,
                json={"code": 200, "data": {"logs": "no container"}},
                request=request,
            )

    client = _driver_client(Transport())
    with pytest.raises(AgentCoreError):
        asyncio.run(client.driver_status("driver"))


def test_driver_status_no_container_shape_ignores_status_value():
    for status_value in ("stopped", "running", "busy", "error", 123, None):
        class Transport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request):
                return httpx.Response(
                    200,
                    json={"code": 200, "data": {"status": status_value, "logs": "no container"}},
                    request=request,
                )

        client = _driver_client(Transport())
        result = asyncio.run(client.driver_status("driver"))
        assert result == {"running_image": ""}


def test_agent_core_request_has_no_http_policy_bypass_parameter():
    params = inspect.signature(AgentCoreClient.request).parameters
    assert "validate_http_policy" not in params
    assert list(params) == ["self", "method", "path", "json"]


@pytest.mark.asyncio
async def test_deploy_policy_prevalidation_error_is_agent_core_error_and_zero_post(monkeypatch):
    calls = 0

    class Transport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            nonlocal calls
            calls += 1
            raise AssertionError("POST should not be attempted")

    def deny(*args, **kwargs):
        raise SecurityError("blocked")

    monkeypatch.setattr(agent_core_client_module, "require_http_policy", deny)
    client = _driver_client(Transport())
    with pytest.raises(AgentCoreError) as excinfo:
        await client.deploy_driver("driver", "registry.example/repo@sha256:" + "a" * 64)
    assert not isinstance(excinfo.value, AgentCoreDeployOutcomeUncertain)
    assert calls == 0


@pytest.mark.asyncio
async def test_generic_request_policy_error_is_agent_core_error_and_zero_request(monkeypatch):
    calls = 0

    class Transport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            nonlocal calls
            calls += 1
            raise AssertionError("request should not be attempted")

    def deny(*args, **kwargs):
        raise SecurityError("blocked")

    monkeypatch.setattr(agent_core_client_module, "require_http_policy", deny)
    client = _driver_client(Transport())
    with pytest.raises(AgentCoreError):
        await client.request("GET", "/api/drivers")
    assert calls == 0


def test_docs_define_no_container_adapter_contract():
    text = Path("DEPLOY_APPROVAL_AGENT.md").read_text(encoding="utf-8")
    assert "POLL_ENABLED must be true." in text
    assert "Webhook is supplementary only." in text
    assert "Agent Core no-container response" in text
    assert "unsafe deploy POST" in text
    assert "approve_attempt.outcome=uncertain" in text
    assert 'running_image=""' in text
    assert "status VALUE has zero CLEAN/health/case business influence" in text
    assert "error/malformed shapes fail closed" in text


def test_uncertain_is_not_documented_as_top_level_status():
    docs = Path("docs/deploy-approval-github-driven-architecture.md").read_text(encoding="utf-8")
    comments = Path("agents/deploy_approval/comments.py").read_text(encoding="utf-8")
    assert "`uncertain` 只能出现在 `command.phase`" not in docs
    assert "approve_attempt.outcome=uncertain" in docs
    assert "status: uncertain" not in comments
    assert "deploy-requested lifecycle with command.phase=uncertain" in comments
    top_level_statuses = {
        "review-required",
        "reviewing",
        "deploy-ready",
        "deploy-requested",
        "testing",
        "succeeded",
        "failed",
    }
    assert "uncertain" not in top_level_statuses


def test_svg_footer_is_removed_from_final_diagram():
    import xml.etree.ElementTree as ET

    text = Path("docs/deploy-sequence.svg").read_text(encoding="utf-8")
    root = ET.fromstring(text)
    assert root.attrib["viewBox"] == "0 0 1400 2500"
    assert root.attrib["width"] == "1400"
    assert root.attrib["height"] == "2500"
    removed_footer_texts = {
        "no-container response -> running_image empty",
        "POST outcome unknown -> command.phase=uncertain",
        "fresh Review build_results + Registry snapshot",
        "POLL_ENABLED=true required; webhook supplementary",
    }
    all_text_nodes = []
    footer_ys = {}
    for el in root.iter():
        if not isinstance(el.tag, str) or not el.tag.endswith("text"):
            continue
        txt = "".join(el.itertext()).strip()
        all_text_nodes.append(txt)
        if txt in removed_footer_texts:
            footer_ys[txt] = int(float(el.attrib["y"]))
    for footer_text in removed_footer_texts:
        assert footer_text not in text
    assert not footer_ys
    assert all(
        txt not in removed_footer_texts
        for txt in all_text_nodes
    )
    for el in root.iter():
        if not isinstance(el.tag, str) or not el.tag.endswith("text"):
            continue
        y = int(float(el.attrib["y"]))
        if y >= 2400:
            txt = "".join(el.itertext()).strip()
            assert txt not in removed_footer_texts


def test_docs_define_unsafe_post_uncertain_contract():
    text = Path("docs/deploy-approval-github-driven-architecture.md").read_text(encoding="utf-8")
    assert "fresh Review Agent build_results + fresh Registry immutable resolution" in text
    assert "command.phase=uncertain" in text
    assert "status: deploy-requested" in text
    assert "ZERO later POST" in text
    assert "NEW approve only" in text


def test_docs_define_poll_required_webhook_supplementary_contract():
    text = Path("docs/deploy-approval-github-driven-architecture.md").read_text(encoding="utf-8")
    assert "POLL_ENABLED must be true." in text
    assert "Webhook is supplementary only." in text


def test_uncertain_comment_requires_new_approve_before_validation_refresh():
    text = comments_mod.uncertain_comment("repo", 1, "a" * 40)
    assert "**Status:** `deploy-requested`" in text
    assert "**Command phase:** `uncertain`" in text
    assert "ZERO automatic replay" in text
    assert "**Next action \u2014 Machine Owner**" in text
    assert "`/approve_deploy machine=<alias>`" in text
    assert "NEW `/approve_deploy`" in text
    assert "running_image-only CLEAN GATE" in text
    assert "Background polling keeps this command `uncertain`" in text
    assert "list_jobs(repo,status=review_done)" not in text
    assert "Manual intervention required." not in text
    assert "restart / next poll" not in text


def test_svg_contains_final_recovery_outcome_contract():
    text = Path("docs/deploy-sequence.svg").read_text(encoding="utf-8")
    expected_flow_texts = {
        "restart / next poll -> read hidden state",
        "executing -> uncertain · ZERO automatic replay",
        "last_processed_comment_id >= command.comment_id",
        "fresh current full HEAD + hidden state",
        "HEAD drift OR validation unavailable",
        "status: review-required",
        "Developer: /request_bot_review",
        "same HEAD -> refresh validation snapshot",
        "status: deploy-requested",
        "Machine Owner clears occupied runtime image",
        "NEW /approve_deploy machine=<alias>",
        "fresh HEAD + actor → CLEAN GATE",
    }
    for snippet in expected_flow_texts:
        assert snippet in text
    stale_terms = {
        "list_jobs",
        "Review Job",
        "review_done",
        "build_results",
        "Review Agent API",
        "/api/jobs",
        "GitHub-published review/build result",
        "publish review/build result",
    }
    for term in stale_terms:
        assert term not in text
    assert "status == stopped" not in text
