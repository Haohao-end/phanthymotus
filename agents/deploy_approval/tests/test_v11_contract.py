"""V11 regression tests for deploy-approval production gaps."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

from .. import comments as comments_mod
from ..agent_core_client import AgentCoreClient, AgentCoreError
from ..config import Config
from ..github_command_watcher import GitHubCommandWatcher
from ..github_state_proxy import (
    GitHubStateProxy,
    TrustedIdentityRequiredError,
)
from ..models import MachineInfo
from ..policy import MachineLoadError, Policy, load_machines
from ..service import DeployController, _extract_visible_markdown
from ..server import _STATUS_LABEL_SPECS, create_app
from .conftest import make_config


class FakeGitHub:
    def __init__(
        self,
        *,
        current_user: dict | None = None,
        pr: dict | None = None,
        comments: list[dict] | None = None,
    ):
        self.current_user = current_user or {"id": 123, "login": "bot"}
        self.pr = pr or {
            "state": "open",
            "merged": False,
            "head": {"sha": "a" * 40},
            "user": {"id": 1, "login": "alice"},
        }
        self.comments: dict[int, dict] = {}
        for comment in comments or []:
            self.comments[int(comment["id"])] = dict(comment)
        self.next_comment_id = max(self.comments.keys(), default=0) + 1
        self.issue_labels: list[str] = []
        self.posted: list[dict] = []
        self.updated: list[dict] = []
        self.list_open_prs_result: list[dict] = [{"number": 1}]

    async def get_current_user(self) -> dict:
        return self.current_user

    async def get_issue_comments(self, repo: str, pr_number: int) -> list[dict]:
        return [self.comments[cid] for cid in sorted(self.comments)]

    async def get_comment(self, repo: str, comment_id: int) -> dict:
        return self.comments.get(comment_id, {})

    async def post_issue_comment(self, repo: str, pr_number: int, body: str) -> dict:
        comment = {
            "id": self.next_comment_id,
            "body": body,
            "user": {"id": 123, "login": "bot"},
        }
        self.comments[self.next_comment_id] = comment
        self.next_comment_id += 1
        self.posted.append(comment)
        return comment

    async def update_comment(self, repo: str, comment_id: int, body: str) -> dict:
        comment = self.comments[comment_id]
        comment["body"] = body
        self.updated.append({"id": comment_id, "body": body})
        return comment

    async def get_pr(self, repo: str, pr_number: int) -> dict:
        return self.pr

    async def collaborator_permission(self, repo: str, actor: str) -> str:
        return "admin"

    async def get_issue_labels(self, repo: str, issue_number: int) -> list[str]:
        return list(self.issue_labels)

    async def set_issue_labels(self, repo: str, issue_number: int, labels: list[str]) -> None:
        self.issue_labels = list(labels)

    async def list_open_prs(self, repo: str) -> list[dict]:
        return list(self.list_open_prs_result)

    async def list_repository_labels(self, repo: str) -> list[dict]:
        return [
            {
                "name": name,
                "color": color,
                "description": description,
            }
            for name, color, description in _STATUS_LABEL_SPECS
        ]

    async def create_repository_label(
        self, repo: str, name: str, color: str, description: str
    ) -> dict:
        return {"name": name, "color": color, "description": description}


def _component(**overrides):
    component = {
        "component_id": "comp-001",
        "target": "perception",
        "driver_path": "",
        "variant": "5.11",
        "review_image_tag": "registry/repo:v1",
        "image_ref": "registry/repo@sha256:" + "a" * 64,
        "resolved_platform": "linux/arm64",
        "runtime_id": "perception",
    }
    component.update(overrides)
    return component


def _deploy_requested_state(**overrides):
    state = {
        "version": 1,
        "head_sha": "a" * 40,
        "status": "deploy-requested",
        "review_job_id": "job-1",
        "components": [_component()],
        "deployments": [],
        "approve_attempts": [],
        "approve_attempts_total": 0,
        "approve_attempts_truncated": False,
        "case_results": {},
        "test_result": "",
        "cos": {"object_key": "", "sha256": "", "size": 0},
        "command": {"comment_id": 0, "kind": "", "phase": "completed", "args": {}},
        "last_processed_comment_id": 0,
    }
    state.update(overrides)
    return state


def _policy(config: Config) -> Policy:
    p = Policy(config)
    p.machines = {
        "test-machine": MachineInfo(
            alias="test-machine",
            node_id="node-1",
            owners=["owner1"],
            node_host="127.0.0.1",
            targets=["perception", "actucore"],
            platforms=["linux/arm64"],
            variants=["5.11", "6.1"],
        ),
        "driver-machine": MachineInfo(
            alias="driver-machine",
            node_id="node-2",
            owners=["owner1"],
            node_host="127.0.0.2",
            targets=["driver"],
            platforms=["linux/arm64"],
            variants=["5.11"],
            driver_paths=["custom/driver"],
        ),
        "multi-machine": MachineInfo(
            alias="multi-machine",
            node_id="node-3",
            owners=["owner1"],
            node_host="127.0.0.3",
            targets=["perception", "actucore", "driver"],
            platforms=["linux/arm64"],
            variants=["5.11", "6.1"],
            driver_paths=["custom/driver"],
        ),
    }
    return p


@pytest.fixture
def config():
    return make_config()


@pytest.fixture
def mock_github():
    return FakeGitHub()


@pytest.fixture
def proxy(config, mock_github):
    return GitHubStateProxy(config, mock_github)


@pytest.fixture
def bound_proxy(config, mock_github):
    proxy = GitHubStateProxy(config, mock_github)
    proxy.bind_trusted_identity("123", "bot")
    return proxy


@pytest.fixture
def policy(config):
    return _policy(config)


@pytest.fixture
def controller(config, bound_proxy, policy, mock_github):
    review = MagicMock()
    review.list_jobs = AsyncMock()
    review.get_job = AsyncMock()
    registry = MagicMock()
    registry.resolve = AsyncMock()
    return DeployController(config, bound_proxy, policy, mock_github, review, registry)


def _write_machine_yaml(tmp_path: Path, data: dict) -> str:
    path = tmp_path / "machines.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return str(path)


@pytest.mark.asyncio
async def test_server_binds_authenticated_bot_identity_before_watcher_start(tmp_path, config, monkeypatch):
    config.machine_owners_file = _write_machine_yaml(
        tmp_path,
        {
            "version": 1,
            "machines": {
                "test-machine": {
                    "node_id": "node-1",
                    "node_host": "127.0.0.1",
                    "owners": ["owner1"],
                    "targets": ["perception"],
                    "platforms": ["linux/arm64"],
                }
            },
        },
    )
    fake_github = FakeGitHub(current_user={"id": 999, "login": "bot-user"})
    order: list[str] = []
    original_bind = GitHubStateProxy.bind_trusted_identity

    def _bind(self, user_id, login):
        order.append("bind")
        return original_bind(self, user_id, login)

    def _watcher_start(self):
        order.append("watcher.start")

    monkeypatch.setattr("agents.deploy_approval.server.GitHubClient", lambda cfg: fake_github)
    monkeypatch.setattr(GitHubStateProxy, "bind_trusted_identity", _bind)
    monkeypatch.setattr(GitHubCommandWatcher, "start", _watcher_start)
    app = create_app(config)

    async with app.router.lifespan_context(app):
        assert app.state.proxy._bot_user_id == "999"
        assert app.state.proxy._bot_login == "bot-user"

    assert order == ["bind", "watcher.start"]


@pytest.mark.asyncio
async def test_server_refuses_start_when_authenticated_bot_identity_invalid(tmp_path, config, monkeypatch):
    config.machine_owners_file = _write_machine_yaml(
        tmp_path,
        {
            "version": 1,
            "machines": {
                "test-machine": {
                    "node_id": "node-1",
                    "node_host": "127.0.0.1",
                    "owners": ["owner1"],
                    "targets": ["perception"],
                    "platforms": ["linux/arm64"],
                }
            },
        },
    )
    fake_github = FakeGitHub(current_user={"id": False, "login": "bot-user"})
    started = []

    def _watcher_start(self):
        started.append(True)

    monkeypatch.setattr("agents.deploy_approval.server.GitHubClient", lambda cfg: fake_github)
    monkeypatch.setattr(GitHubCommandWatcher, "start", _watcher_start)
    app = create_app(config)

    with pytest.raises(ValueError):
        async with app.router.lifespan_context(app):
            pass

    assert started == []


@pytest.mark.asyncio
async def test_server_refuses_start_when_get_current_user_fails(tmp_path, config, monkeypatch):
    config.machine_owners_file = _write_machine_yaml(
        tmp_path,
        {
            "version": 1,
            "machines": {
                "test-machine": {
                    "node_id": "node-1",
                    "node_host": "127.0.0.1",
                    "owners": ["owner1"],
                    "targets": ["perception"],
                    "platforms": ["linux/arm64"],
                }
            },
        },
    )

    class _BrokenGitHub(FakeGitHub):
        async def get_current_user(self) -> dict:
            raise RuntimeError("boom")

    started = []

    def _watcher_start(self):
        started.append(True)

    monkeypatch.setattr("agents.deploy_approval.server.GitHubClient", lambda cfg: _BrokenGitHub())
    monkeypatch.setattr(GitHubCommandWatcher, "start", _watcher_start)
    app = create_app(config)

    with pytest.raises(RuntimeError):
        async with app.router.lifespan_context(app):
            pass

    assert started == []


@pytest.mark.asyncio
async def test_proxy_requires_trusted_identity_before_lifecycle_read(proxy):
    proxy._github.comments[1] = {
        "id": 1,
        "body": comments_mod.review_required("repo", 1, "a" * 40)
        + "\n\n<!-- deploy-approval-state:v1\n{\"version\":1,\"head_sha\":\""
        + "a" * 40
        + "\",\"status\":\"review-required\",\"review_job_id\":\"\",\"components\":[],\"deployments\":[],\"approve_attempts\":[],\"approve_attempts_total\":0,\"approve_attempts_truncated\":false,\"case_results\":{},\"test_result\":\"\",\"cos\":{\"object_key\":\"\",\"sha256\":\"\",\"size\":0},\"command\":{\"comment_id\":0,\"kind\":\"\",\"phase\":\"\",\"args\":{}},\"last_processed_comment_id\":0}\n-->",
        "user": {"id": 123, "login": "bot"},
    }

    with pytest.raises(TrustedIdentityRequiredError):
        await proxy.read_hidden_state("repo", 1)


@pytest.mark.asyncio
async def test_trusted_lifecycle_comment_requires_exact_bot_user_id(bound_proxy):
    bound_proxy._github.comments[1] = {
        "id": 1,
        "body": comments_mod.review_required("repo", 1, "a" * 40)
        + "\n\n<!-- deploy-approval-state:v1\n{\"version\":1,\"head_sha\":\""
        + "a" * 40
        + "\",\"status\":\"review-required\",\"review_job_id\":\"\",\"components\":[],\"deployments\":[],\"approve_attempts\":[],\"approve_attempts_total\":0,\"approve_attempts_truncated\":false,\"case_results\":{},\"test_result\":\"\",\"cos\":{\"object_key\":\"\",\"sha256\":\"\",\"size\":0},\"command\":{\"comment_id\":0,\"kind\":\"\",\"phase\":\"\",\"args\":{}},\"last_processed_comment_id\":0}\n-->",
        "user": {"id": 999, "login": "bot"},
    }

    assert await bound_proxy.find_trusted_lifecycle_comment("repo", 1) is None


@pytest.mark.asyncio
async def test_login_match_cannot_override_bot_user_id_mismatch(bound_proxy):
    bound_proxy._github.comments[1] = {
        "id": 1,
        "body": comments_mod.review_required("repo", 1, "a" * 40)
        + "\n\n<!-- deploy-approval-state:v1\n{\"version\":1,\"head_sha\":\""
        + "a" * 40
        + "\",\"status\":\"review-required\",\"review_job_id\":\"\",\"components\":[],\"deployments\":[],\"approve_attempts\":[],\"approve_attempts_total\":0,\"approve_attempts_truncated\":false,\"case_results\":{},\"test_result\":\"\",\"cos\":{\"object_key\":\"\",\"sha256\":\"\",\"size\":0},\"command\":{\"comment_id\":0,\"kind\":\"\",\"phase\":\"\",\"args\":{}},\"last_processed_comment_id\":0}\n-->",
        "user": {"id": 999, "login": "bot"},
    }

    assert await bound_proxy.read_hidden_state("repo", 1) is None


def test_trusted_identity_rebind_to_different_user_fails_closed(bound_proxy):
    with pytest.raises(TrustedIdentityRequiredError):
        bound_proxy.bind_trusted_identity("456", "bot-2")


async def _seed_review_required(proxy: GitHubStateProxy) -> None:
    state = {
        "version": 1,
        "head_sha": "a" * 40,
        "status": "review-required",
        "review_job_id": "",
        "components": [],
        "deployments": [],
        "approve_attempts": [],
        "approve_attempts_total": 0,
        "approve_attempts_truncated": False,
        "case_results": {},
        "test_result": "",
        "cos": {"object_key": "", "sha256": "", "size": 0},
        "command": {"comment_id": 0, "kind": "", "phase": "completed", "args": {}},
        "last_processed_comment_id": 0,
    }
    await proxy.write_hidden_state("repo", 1, comments_mod.review_required("repo", 1, "a" * 40), state)


async def _seed_deploy_requested(proxy: GitHubStateProxy, state: dict) -> None:
    await proxy.write_hidden_state(
        "repo",
        1,
        comments_mod.deploy_requested("repo", 1, state["head_sha"], state["components"], []),
        state,
    )


def _hidden_state_from_comment_body(body: str) -> dict:
    return json.loads(
        body.split("<!-- deploy-approval-state:v1\n", 1)[1].split("\n-->", 1)[0]
    )


@pytest.mark.asyncio
async def test_bot_lifecycle_comment_is_reused_across_poll_cycles(bound_proxy, controller, config):
    await _seed_review_required(bound_proxy)
    bound_proxy._github.comments[11] = {
        "id": 11,
        "body": "/approve_deploy machine=driver-machine",
        "user": {"id": 111, "login": "alice"},
    }
    watcher = GitHubCommandWatcher(config, bound_proxy, controller)
    controller.on_command = AsyncMock(return_value=True)

    await watcher._process_pr("repo", 1)
    await watcher._process_pr("repo", 1)

    assert controller.on_command.await_count == 1
    assert bound_proxy._github.updated
    assert bound_proxy._github.updated[-1]["id"] == 1
    assert "last_processed_comment_id" in bound_proxy._github.comments[1]["body"]


@pytest.mark.asyncio
async def test_watcher_deterministic_rejection_advances_cursor_and_does_not_replay(controller, bound_proxy, config):
    await _seed_review_required(bound_proxy)
    bound_proxy.collaborator_permission = AsyncMock(return_value="read")
    bound_proxy._github.comments[11] = {
        "id": 11,
        "body": "/approve_deploy machine=driver-machine",
        "user": {"id": 111, "login": "alice"},
    }
    watcher = GitHubCommandWatcher(config, bound_proxy, controller)
    error_count_before = len(bound_proxy._github.posted)

    await watcher._process_pr("repo", 1)
    await watcher._process_pr("repo", 1)

    error_comments = [c for c in bound_proxy._github.posted[error_count_before:] if "Error" in c["body"]]
    assert len(error_comments) == 1
    assert "last_processed_comment_id" in bound_proxy._github.comments[1]["body"]


@pytest.mark.asyncio
async def test_watcher_transient_exception_leaves_cursor_for_retry(bound_proxy, config):
    await _seed_review_required(bound_proxy)
    bound_proxy._github.comments[11] = {
        "id": 11,
        "body": "/approve_deploy machine=driver-machine",
        "user": {"id": 111, "login": "alice"},
    }
    controller = MagicMock()
    controller.reconcile_pr = AsyncMock()
    controller.on_command = AsyncMock(side_effect=RuntimeError("boom"))
    watcher = GitHubCommandWatcher(config, bound_proxy, controller)

    await watcher._process_pr("repo", 1)
    await watcher._process_pr("repo", 1)

    assert controller.on_command.await_count == 2


@pytest.mark.asyncio
async def test_watcher_no_state_deterministic_rejection_bootstraps_cursor_state(controller, bound_proxy, config):
    bound_proxy._github.pr = {
        "state": "closed",
        "merged": False,
        "head": {"sha": "a" * 40},
        "user": {"id": 1, "login": "alice"},
    }
    bound_proxy.collaborator_permission = AsyncMock(return_value="read")
    bound_proxy._github.comments[11] = {
        "id": 11,
        "body": "/approve_deploy machine=driver-machine",
        "user": {"id": 111, "login": "alice"},
    }
    watcher = GitHubCommandWatcher(config, bound_proxy, controller)

    await watcher._process_pr("repo", 1)

    assert not bound_proxy._github.posted
    assert not bound_proxy._github.updated


@pytest.mark.asyncio
async def test_invalid_approve_is_not_replayed_next_poll(controller, bound_proxy, config):
    await _seed_review_required(bound_proxy)
    bound_proxy.collaborator_permission = AsyncMock(return_value="read")
    bound_proxy._github.comments[11] = {
        "id": 11,
        "body": "/approve_deploy machine=driver-machine",
        "user": {"id": 111, "login": "alice"},
    }
    watcher = GitHubCommandWatcher(config, bound_proxy, controller)
    before = len(bound_proxy._github.posted)

    await watcher._process_pr("repo", 1)
    await watcher._process_pr("repo", 1)

    assert len([c for c in bound_proxy._github.posted[before:] if "Error" in c["body"]]) == 1


@pytest.mark.asyncio
async def test_request_deploy_without_completed_review_is_not_replayed_next_poll(controller, bound_proxy, config):
    bound_proxy._github.comments[11] = {
        "id": 11,
        "body": "/request_deploy",
        "user": {"id": 1, "login": "alice"},
    }
    controller.review.list_jobs = AsyncMock(return_value=[])
    controller.review.get_job = AsyncMock(return_value=None)
    controller.registry.resolve = AsyncMock()
    watcher = GitHubCommandWatcher(config, bound_proxy, controller)
    before = len(bound_proxy._github.posted)

    await watcher._process_pr("repo", 1)
    await watcher._process_pr("repo", 1)

    assert len([c for c in bound_proxy._github.posted[before:] if "Error" in c["body"]]) == 1


@pytest.mark.asyncio
async def test_handle_partial_approval_renders_only_remaining_components(controller, bound_proxy):
    state = _deploy_requested_state(
        components=[
            _component(component_id="comp-perception", target="perception", runtime_id="perception"),
            _component(
                component_id="comp-driver",
                target="driver",
                driver_path="custom/driver",
                image_ref="registry/custom/driver@sha256:" + "b" * 64,
                runtime_id="driver-runtime",
            ),
            _component(component_id="comp-actucore", target="actucore", runtime_id="actucore"),
        ],
        deployments=[
            {"machine": "test-machine", "component_ids": ["comp-perception"], "phase": "deployed"},
        ],
    )
    await _seed_deploy_requested(bound_proxy, state)
    core = MagicMock()
    core.list_drivers = AsyncMock(return_value=[
        {"id": "driver-runtime", "category": "driver", "image": "registry/custom/driver:latest"},
    ])
    calls = {"driver-runtime": 0}

    async def _status(runtime_id):
        calls[runtime_id] += 1
        if calls[runtime_id] == 1:
            return {"status": "stopped", "running_image": ""}
        return {"status": "running", "running_image": "registry/custom/driver@sha256:" + "b" * 64}

    core.driver_status = AsyncMock(side_effect=_status)
    core.deploy_driver = AsyncMock(return_value={"ok": True})
    controller._core_for_node = AsyncMock(return_value=core)

    await controller.handle_approve_deploy("repo", 1, 12, "driver-machine", "owner1", "111")

    visible = _extract_visible_markdown(bound_proxy._github.updated[-1]["body"])
    assert "comp-actucore" in visible
    assert "comp-driver" not in visible
    assert "comp-perception" not in visible


@pytest.mark.asyncio
async def test_health_failure_prevents_later_component_deploy_post(controller, bound_proxy):
    state = _deploy_requested_state(
        components=[
            _component(component_id="comp-perception", target="perception", runtime_id="perception"),
            _component(component_id="comp-actucore", target="actucore", runtime_id="actucore"),
        ]
    )
    await _seed_deploy_requested(bound_proxy, state)
    core = MagicMock()
    core.list_drivers = AsyncMock(return_value=[
        {"id": "perception", "category": "driver", "image": "registry/perception:latest"},
        {"id": "actucore", "category": "driver", "image": "registry/actucore:latest"},
    ])
    core.deploy_driver = AsyncMock(return_value={"ok": True})

    async def _status(_runtime_id):
        return {"status": "starting", "running_image": ""}

    core.driver_status = AsyncMock(side_effect=_status)
    controller._core_for_node = AsyncMock(return_value=core)

    await controller.handle_approve_deploy("repo", 1, 13, "test-machine", "owner1", "111")

    assert core.deploy_driver.await_count == 1
    visible = _extract_visible_markdown(bound_proxy._github.updated[-1]["body"])
    assert "comp-actucore" not in visible


@pytest.mark.asyncio
async def test_handle_approve_health_failure_persists_prior_successful_component_in_hidden_state(controller, bound_proxy):
    state = _deploy_requested_state(
        components=[
            _component(component_id="comp-perception", target="perception", runtime_id="perception"),
            _component(component_id="comp-actucore", target="actucore", runtime_id="actucore"),
        ]
    )
    await _seed_deploy_requested(bound_proxy, state)
    core = MagicMock()
    core.list_drivers = AsyncMock(return_value=[
        {"id": "perception", "category": "driver", "image": "registry/perception:latest"},
        {"id": "actucore", "category": "driver", "image": "registry/actucore:latest"},
    ])
    core.deploy_driver = AsyncMock(return_value={"ok": True})
    calls = {"perception": 0, "actucore": 0}

    async def _status(runtime_id):
        calls[runtime_id] += 1
        if runtime_id == "perception":
            if calls[runtime_id] == 1:
                return {"status": "stopped", "running_image": ""}
            return {"status": "running", "running_image": state["components"][0]["image_ref"]}
        if calls[runtime_id] == 1:
            return {"status": "stopped", "running_image": ""}
        return {"status": "starting", "running_image": ""}

    core.driver_status = AsyncMock(side_effect=_status)
    controller._core_for_node = AsyncMock(return_value=core)

    await controller.handle_approve_deploy("repo", 1, 14, "test-machine", "owner1", "111")

    hidden_state = _hidden_state_from_comment_body(bound_proxy._github.updated[-1]["body"])
    deployed = [cid for dep in hidden_state["deployments"] for cid in dep.get("component_ids", [])]
    assert deployed == ["comp-perception"]
    assert hidden_state["status"] == "failed"


@pytest.mark.asyncio
async def test_handle_approve_health_failure_does_not_record_failed_component_as_deployed(controller, bound_proxy):
    state = _deploy_requested_state(
        components=[
            _component(component_id="comp-perception", target="perception", runtime_id="perception"),
            _component(component_id="comp-actucore", target="actucore", runtime_id="actucore"),
        ]
    )
    await _seed_deploy_requested(bound_proxy, state)
    core = MagicMock()
    core.list_drivers = AsyncMock(return_value=[
        {"id": "perception", "category": "driver", "image": "registry/perception:latest"},
        {"id": "actucore", "category": "driver", "image": "registry/actucore:latest"},
    ])
    core.deploy_driver = AsyncMock(return_value={"ok": True})
    calls = {"perception": 0, "actucore": 0}

    async def _status(runtime_id):
        calls[runtime_id] += 1
        if runtime_id == "perception":
            if calls[runtime_id] == 1:
                return {"status": "stopped", "running_image": ""}
            return {"status": "running", "running_image": state["components"][0]["image_ref"]}
        if calls[runtime_id] == 1:
            return {"status": "stopped", "running_image": ""}
        return {"status": "starting", "running_image": ""}

    core.driver_status = AsyncMock(side_effect=_status)
    controller._core_for_node = AsyncMock(return_value=core)

    await controller.handle_approve_deploy("repo", 1, 15, "test-machine", "owner1", "111")

    hidden_state = _hidden_state_from_comment_body(bound_proxy._github.updated[-1]["body"])
    deployed = [cid for dep in hidden_state["deployments"] for cid in dep.get("component_ids", [])]
    assert deployed == ["comp-perception"]
    assert all("comp-actucore" not in dep.get("component_ids", []) for dep in hidden_state["deployments"])


@pytest.mark.asyncio
async def test_failed_deploy_cos_metadata_is_rebound_to_terminal_state(controller, bound_proxy):
    state = _deploy_requested_state(
        components=[_component(component_id="comp-perception", target="perception", runtime_id="perception")]
    )
    await _seed_deploy_requested(bound_proxy, state)
    core = MagicMock()
    core.list_drivers = AsyncMock(return_value=[
        {"id": "perception", "category": "driver", "image": "registry/perception:latest"},
    ])
    core.deploy_driver = AsyncMock(return_value={"ok": True})
    core.driver_status = AsyncMock(side_effect=[
        {"status": "starting", "running_image": ""},
    ])
    controller._core_for_node = AsyncMock(return_value=core)
    controller._upload_evidence = AsyncMock(return_value={
        "object_key": "deploy-approval/failed.tar.gz",
        "sha256": "b" * 64,
        "size": 123,
    })

    await controller.handle_approve_deploy("repo", 1, 16, "test-machine", "owner1", "111")

    assert len(bound_proxy._github.updated) >= 2
    assert "deploy-approval/failed.tar.gz" in bound_proxy._github.updated[-1]["body"]
    assert "@sha256:" in bound_proxy._github.updated[-1]["body"]
    assert "signed_url" not in bound_proxy._github.updated[-1]["body"]


@pytest.mark.asyncio
async def test_failed_deploy_cos_upload_failure_keeps_terminal_failed(controller, bound_proxy):
    state = _deploy_requested_state(
        components=[_component(component_id="comp-perception", target="perception", runtime_id="perception")]
    )
    await _seed_deploy_requested(bound_proxy, state)
    core = MagicMock()
    core.list_drivers = AsyncMock(return_value=[
        {"id": "perception", "category": "driver", "image": "registry/perception:latest"},
    ])
    core.deploy_driver = AsyncMock(return_value={"ok": True})
    core.driver_status = AsyncMock(side_effect=[
        {"status": "starting", "running_image": ""},
    ])
    controller._core_for_node = AsyncMock(return_value=core)
    controller._upload_evidence = AsyncMock(side_effect=RuntimeError("cos failed"))

    await controller.handle_approve_deploy("repo", 1, 17, "test-machine", "owner1", "111")

    assert len(bound_proxy._github.updated) == 1
    assert "failed" in bound_proxy._github.comments[1]["body"]


@pytest.mark.asyncio
async def test_failed_deploy_cos_rebind_never_persists_signed_url(controller, bound_proxy):
    state = _deploy_requested_state(
        components=[_component(component_id="comp-perception", target="perception", runtime_id="perception")]
    )
    await _seed_deploy_requested(bound_proxy, state)
    core = MagicMock()
    core.list_drivers = AsyncMock(return_value=[
        {"id": "perception", "category": "driver", "image": "registry/perception:latest"},
    ])
    core.deploy_driver = AsyncMock(return_value={"ok": True})
    core.driver_status = AsyncMock(side_effect=[
        {"status": "starting", "running_image": ""},
    ])
    controller._core_for_node = AsyncMock(return_value=core)
    controller._upload_evidence = AsyncMock(return_value={
        "object_key": "deploy-approval/failed.tar.gz",
        "sha256": "b" * 64,
        "size": 123,
        "signed_url": "https://example.invalid/signed",
    })

    await controller.handle_approve_deploy("repo", 1, 18, "test-machine", "owner1", "111")

    assert "signed_url" not in bound_proxy._github.updated[-1]["body"]
    assert "signed_url" not in json.dumps(bound_proxy._github.comments[1])


def test_driver_paths_required_for_driver_machine(tmp_path):
    path = _write_machine_yaml(
        tmp_path,
        {
            "version": 1,
            "machines": {
                "driver-machine": {
                    "node_id": "node-1",
                    "node_host": "127.0.0.1",
                    "owners": ["owner1"],
                    "targets": ["driver"],
                    "platforms": ["linux/arm64"],
                }
            },
        },
    )

    with pytest.raises(MachineLoadError):
        load_machines(path)


def test_driver_paths_reject_string_scalar(tmp_path):
    path = _write_machine_yaml(
        tmp_path,
        {
            "version": 1,
            "machines": {
                "driver-machine": {
                    "node_id": "node-1",
                    "node_host": "127.0.0.1",
                    "owners": ["owner1"],
                    "targets": ["driver"],
                    "platforms": ["linux/arm64"],
                    "driver_paths": "custom/driver",
                }
            },
        },
    )

    with pytest.raises(MachineLoadError):
        load_machines(path)


def test_driver_paths_reject_absolute_parent_backslash_and_empty_segments(tmp_path):
    invalid_values = [
        ["/abs/path"],
        ["../driver"],
        ["custom\\driver"],
        ["custom//driver"],
        ["custom/./driver"],
        ["custom/../driver"],
    ]
    for idx, driver_paths in enumerate(invalid_values):
        path = _write_machine_yaml(
            tmp_path,
            {
                "version": 1,
                "machines": {
                    f"driver-machine-{idx}": {
                        "node_id": f"node-{idx}",
                        "node_host": "127.0.0.1",
                        "owners": ["owner1"],
                        "targets": ["driver"],
                        "platforms": ["linux/arm64"],
                        "driver_paths": driver_paths,
                    }
                },
            },
        )
        with pytest.raises(MachineLoadError):
            load_machines(path)


def test_driver_paths_are_trimmed_deduped_and_exact_case_preserved(tmp_path):
    path = _write_machine_yaml(
        tmp_path,
        {
            "version": 1,
            "machines": {
                "driver-machine": {
                    "node_id": "node-1",
                    "node_host": "127.0.0.1",
                    "owners": ["owner1"],
                    "targets": ["driver"],
                    "platforms": ["linux/arm64"],
                    "driver_paths": [" custom/driver ", "custom/driver", "Custom/Driver"],
                }
            },
        },
    )

    machines = load_machines(path)
    assert machines["driver-machine"].driver_paths == ["custom/driver", "Custom/Driver"]


def test_driver_machine_policy_never_uses_substring_membership(policy):
    controller = DeployController(
        make_config(),
        bound_proxy=MagicMock(),
        policy=policy,
        github=MagicMock(),
        review=MagicMock(),
        registry=MagicMock(),
    )
    components = [
        {"component_id": "comp-1", "target": "driver", "driver_path": "custom/driv", "resolved_platform": "linux/arm64", "variant": "5.11"},
    ]
    assert controller._get_component_ids_for_machine("driver-machine", components) == []


def test_machine_node_host_ipv6_fails_closed(tmp_path):
    path = _write_machine_yaml(
        tmp_path,
        {
            "version": 1,
            "machines": {
                "test-machine": {
                    "node_id": "node-1",
                    "node_host": "::1",
                    "owners": ["owner1"],
                    "targets": ["perception"],
                    "platforms": ["linux/arm64"],
                }
            },
        },
    )

    with pytest.raises(MachineLoadError):
        load_machines(path)


def test_agent_core_client_ipv6_node_host_fails_closed():
    config = make_config()
    with pytest.raises(AgentCoreError):
        AgentCoreClient(config, "http://[::1]:15678", node_host="::1")


@pytest.mark.asyncio
async def test_approve_attempt_history_is_bounded(controller, bound_proxy):
    state = _deploy_requested_state(
        components=[
            _component(
                component_id="comp-driver",
                target="driver",
                driver_path="custom/driver",
                image_ref="registry/custom/driver@sha256:" + "d" * 64,
                runtime_id="driver-runtime",
            )
        ]
    )
    await _seed_deploy_requested(bound_proxy, state)
    core = MagicMock()
    core.list_drivers = AsyncMock(return_value=[
        {"id": "driver-runtime", "category": "driver", "image": "registry/custom/driver:latest"},
    ])
    core.deploy_driver = AsyncMock(return_value={"ok": True})
    core.driver_status = AsyncMock(return_value={"status": "running", "running_image": "registry/custom/driver@sha256:" + "d" * 64})
    controller._core_for_node = AsyncMock(return_value=core)

    for idx in range(100):
        await controller.handle_approve_deploy("repo", 1, 1000 + idx, "driver-machine", "owner1", "111")

    hidden_bytes = json.dumps(state, separators=(",", ":")).encode("utf-8")
    assert len(hidden_bytes) < 8192
    assert len(bound_proxy._github.comments[1]["body"]) < 8192
    hidden = json.loads(bound_proxy._github.comments[1]["body"].split("<!-- deploy-approval-state:v1\n", 1)[1].split("\n-->", 1)[0])
    assert hidden["approve_attempts_total"] == 100
    assert len(hidden["approve_attempts"]) <= 4
    assert hidden["approve_attempts_truncated"] is True


def test_approve_attempt_total_counts_trimmed_attempts():
    state = _deploy_requested_state(
        approve_attempts=[{"comment_id": 1}, {"comment_id": 2}, {"comment_id": 3}, {"comment_id": 4}],
        approve_attempts_total=7,
    )
    controller = DeployController(make_config(), MagicMock(), _policy(make_config()), MagicMock(), MagicMock(), MagicMock())
    controller._record_approve_attempt(state, {"comment_id": 5})
    assert state["approve_attempts_total"] == 8
    assert len(state["approve_attempts"]) == 4
    assert state["approve_attempts"][-1]["comment_id"] == 5


@pytest.mark.asyncio
async def test_many_occupied_approvals_never_exceed_hidden_state_limit(controller, bound_proxy):
    state = _deploy_requested_state(
        components=[
            _component(
                component_id="comp-driver",
                target="driver",
                driver_path="custom/driver",
                image_ref="registry/custom/driver@sha256:" + "e" * 64,
                runtime_id="driver-runtime",
            )
        ]
    )
    await _seed_deploy_requested(bound_proxy, state)
    core = MagicMock()
    core.list_drivers = AsyncMock(return_value=[
        {"id": "driver-runtime", "category": "driver", "image": "registry/custom/driver:latest"},
    ])
    core.deploy_driver = AsyncMock(return_value={"ok": True})
    core.driver_status = AsyncMock(return_value={"status": "running", "running_image": "registry/custom/driver@sha256:" + "e" * 64})
    controller._core_for_node = AsyncMock(return_value=core)

    for idx in range(100):
        await controller.handle_approve_deploy("repo", 1, 2000 + idx, "driver-machine", "owner1", "111")

    raw = json.loads(bound_proxy._github.comments[1]["body"].split("<!-- deploy-approval-state:v1\n", 1)[1].split("\n-->", 1)[0])
    assert len(json.dumps(raw).encode("utf-8")) < 8192


def test_head_drift_resets_bounded_approve_history(bound_proxy, controller):
    state = _deploy_requested_state(
        approve_attempts=[{"comment_id": 1}, {"comment_id": 2}],
        approve_attempts_total=12,
        approve_attempts_truncated=True,
        head_sha="a" * 40,
    )
    asyncio_state = comments_mod.deploy_requested("repo", 1, "a" * 40, state["components"], [])
    import asyncio

    asyncio.get_event_loop().run_until_complete(bound_proxy.write_hidden_state("repo", 1, asyncio_state, state))
    bound_proxy._github.pr["head"]["sha"] = "b" * 40

    controller.review.list_jobs = AsyncMock(return_value=[])
    controller.review.get_job = AsyncMock(return_value=None)
    controller.registry.resolve = AsyncMock()
    controller._core_for_node = AsyncMock(return_value=MagicMock())

    import asyncio as _asyncio
    _asyncio.get_event_loop().run_until_complete(
        controller.handle_approve_deploy("repo", 1, 77, "test-machine", "owner1", "111")
    )

    hidden = json.loads(bound_proxy._github.comments[1]["body"].split("<!-- deploy-approval-state:v1\n", 1)[1].split("\n-->", 1)[0])
    assert hidden["approve_attempts"] == []
    assert hidden["approve_attempts_total"] == 0


@pytest.mark.asyncio
async def test_deploy_requested_comment_shows_short_immutable_digest(controller, bound_proxy):
    bound_proxy._github.comments[5] = {"id": 5, "body": "/request_deploy", "user": {"id": 1, "login": "alice"}}
    job = {
        "id": "job-1",
        "repo": "repo",
        "pr_number": 1,
        "head_sha": "a" * 40,
        "status": "review_done",
        "review_text": "approved",
        "options": {"build_only": False},
        "completed_at": "2026-01-01T00:00:00Z",
        "build_results": [
            {
                "idx": 0,
                "target": "perception",
                "driver_path": "",
                "success": True,
                "image_tag": "private.example.com/perception:v1",
                "variant": "5.11",
            }
        ],
    }
    controller.review.list_jobs = AsyncMock(return_value=[job])
    controller.review.get_job = AsyncMock(return_value=job)
    controller.registry.resolve = AsyncMock(return_value=MagicMock(image_ref="private.example.com/perception@sha256:" + "c" * 64, platform="linux/arm64"))

    await controller.handle_request_deploy("repo", 1, 5)

    visible = _extract_visible_markdown(bound_proxy._github.posted[-1]["body"])
    assert "@sha256:cccccccccccc" in visible
    assert "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" not in visible


@pytest.mark.asyncio
async def test_deploy_requested_comment_does_not_expose_registry_credentials_or_node_host(controller, bound_proxy):
    bound_proxy._github.comments[5] = {"id": 5, "body": "/request_deploy", "user": {"id": 1, "login": "alice"}}
    job = {
        "id": "job-1",
        "repo": "repo",
        "pr_number": 1,
        "head_sha": "a" * 40,
        "status": "review_done",
        "review_text": "approved",
        "options": {"build_only": False},
        "completed_at": "2026-01-01T00:00:00Z",
        "build_results": [
            {
                "idx": 0,
                "target": "perception",
                "driver_path": "",
                "success": True,
                "image_tag": "private.example.com/perception:v1",
                "variant": "5.11",
            }
        ],
    }
    controller.review.list_jobs = AsyncMock(return_value=[job])
    controller.review.get_job = AsyncMock(return_value=job)
    controller.registry.resolve = AsyncMock(return_value=MagicMock(image_ref="private.example.com/perception@sha256:" + "c" * 64, platform="linux/arm64"))

    await controller.handle_request_deploy("repo", 1, 5)

    visible = _extract_visible_markdown(bound_proxy._github.posted[-1]["body"])
    assert "10.0.0.1" not in visible
    assert "http://" not in visible
    assert "signed_url" not in visible


@pytest.mark.asyncio
async def test_approve_attempt_history_is_bounded(controller, bound_proxy, mock_github):
    components = [_component(target="driver", driver_path="custom/driver", variant="5.11")]
    state = _deploy_requested_state(components=components)
    bound_proxy.read_hidden_state = AsyncMock(return_value=state)
    bound_proxy.write_hidden_state = AsyncMock()
    bound_proxy.project_status_label = AsyncMock()
    mock_github.pr = {
        "state": "open",
        "merged": False,
        "head": {"sha": "a" * 40},
        "user": {"id": 1, "login": "alice"},
    }
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[{"id": "driver-1", "category": "driver", "image": "registry/repo"}])
    core.driver_status = AsyncMock(return_value={"status": "running", "running_image": "registry/repo@sha256:" + "f" * 64})
    core.deploy_driver = AsyncMock()
    controller._core_for_node = AsyncMock(return_value=core)

    for idx in range(100):
        await controller.handle_approve_deploy("repo", 1, 1000 + idx, "driver-machine", "owner1", "1")

    assert state["approve_attempts_total"] == 100
    assert len(state["approve_attempts"]) <= 4
    assert state["approve_attempts_truncated"] is True


@pytest.mark.asyncio
async def test_approve_attempt_total_counts_trimmed_attempts(controller, bound_proxy, mock_github):
    components = [_component(target="driver", driver_path="custom/driver", variant="5.11")]
    state = _deploy_requested_state(components=components)
    bound_proxy.read_hidden_state = AsyncMock(return_value=state)
    bound_proxy.write_hidden_state = AsyncMock()
    bound_proxy.project_status_label = AsyncMock()
    mock_github.pr = {
        "state": "open",
        "merged": False,
        "head": {"sha": "a" * 40},
        "user": {"id": 1, "login": "alice"},
    }
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[{"id": "driver-1", "category": "driver", "image": "registry/repo"}])
    core.driver_status = AsyncMock(return_value={"status": "running", "running_image": "registry/repo@sha256:" + "f" * 64})
    core.deploy_driver = AsyncMock()
    controller._core_for_node = AsyncMock(return_value=core)

    for idx in range(6):
        await controller.handle_approve_deploy("repo", 1, 2000 + idx, "driver-machine", "owner1", "1")

    assert state["approve_attempts_total"] == 6
    assert len(state["approve_attempts"]) == 4
    assert state["approve_attempts_truncated"] is True


@pytest.mark.asyncio
async def test_many_occupied_approvals_never_exceed_hidden_state_limit(controller, bound_proxy, mock_github):
    components = [_component(target="driver", driver_path="custom/driver", variant="5.11")]
    state = _deploy_requested_state(components=components)
    bound_proxy.read_hidden_state = AsyncMock(return_value=state)
    bound_proxy.write_hidden_state = AsyncMock()
    bound_proxy.project_status_label = AsyncMock()
    mock_github.pr = {
        "state": "open",
        "merged": False,
        "head": {"sha": "a" * 40},
        "user": {"id": 1, "login": "alice"},
    }
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[{"id": "driver-1", "category": "driver", "image": "registry/repo"}])
    core.driver_status = AsyncMock(return_value={"status": "running", "running_image": "registry/repo@sha256:" + "f" * 64})
    core.deploy_driver = AsyncMock()
    controller._core_for_node = AsyncMock(return_value=core)

    for idx in range(100):
        await controller.handle_approve_deploy("repo", 1, 3000 + idx, "driver-machine", "owner1", "1")

    hidden = json.dumps(state, separators=(",", ":")).encode("utf-8")
    assert len(hidden) < 8192


@pytest.mark.asyncio
async def test_head_drift_resets_bounded_approve_history(controller, bound_proxy, mock_github):
    components = [_component(target="driver", driver_path="custom/driver", variant="5.11")]
    state = _deploy_requested_state(
        head_sha="b" * 40,
        components=components,
        approve_attempts=[{"comment_id": 1, "actor": "owner1", "machine": "driver-machine", "preflight": [], "outcome": "blocked_occupied", "health": []}],
        approve_attempts_total=1,
        approve_attempts_truncated=False,
    )
    bound_proxy.read_hidden_state = AsyncMock(return_value=state)
    bound_proxy.write_hidden_state = AsyncMock()
    bound_proxy.project_status_label = AsyncMock()
    mock_github.pr = {
        "state": "open",
        "merged": False,
        "head": {"sha": "a" * 40},
        "user": {"id": 1, "login": "alice"},
    }

    await controller.handle_approve_deploy("repo", 1, 4001, "driver-machine", "owner1", "1")

    assert state["status"] == "review-required"
    assert state["approve_attempts"] == []
    assert state["approve_attempts_total"] == 0
    assert state["approve_attempts_truncated"] is False


@pytest.mark.asyncio
async def test_deploy_requested_comment_shows_short_immutable_digest(controller, bound_proxy, mock_github):
    components = [
        _component(component_id="comp-001", target="perception", image_ref="registry/repo@sha256:" + "a" * 64),
        _component(component_id="comp-002", target="driver", variant="", driver_path="custom/driver", image_ref="registry/repo@sha256:" + "b" * 64),
        _component(component_id="comp-003", target="actucore", image_ref="registry/repo@sha256:" + "c" * 64),
    ]
    state = _deploy_requested_state(
        components=components,
        deployments=[{"machine": "test-machine", "component_ids": ["comp-001"], "phase": "deployed"}],
    )
    bound_proxy.read_hidden_state = AsyncMock(return_value=state)
    bound_proxy.write_hidden_state = AsyncMock()
    bound_proxy.project_status_label = AsyncMock()
    mock_github.pr = {
        "state": "open",
        "merged": False,
        "head": {"sha": "a" * 40},
        "user": {"id": 1, "login": "alice"},
    }
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[{"id": "driver-1", "category": "driver", "image": "registry/repo"}])
    core.driver_status = AsyncMock(side_effect=[
        {"status": "stopped", "running_image": ""},
        {"status": "running", "running_image": components[1]["image_ref"]},
    ])
    core.deploy_driver = AsyncMock(return_value={"ok": True})
    controller._core_for_node = AsyncMock(return_value=core)
    controller._run_automated_case = AsyncMock(return_value={})

    await controller.handle_approve_deploy("repo", 1, 5001, "driver-machine", "owner1", "1")

    markdown = bound_proxy.write_hidden_state.call_args.args[2]
    assert "@sha256:" in markdown
    assert "a" * 64 not in markdown


@pytest.mark.asyncio
async def test_deploy_requested_comment_does_not_expose_registry_credentials_or_node_host(controller, bound_proxy, mock_github):
    components = [
        _component(component_id="comp-001", target="perception", image_ref="registry.example.com/priv/repo@sha256:" + "a" * 64),
        _component(component_id="comp-002", target="driver", variant="", driver_path="custom/driver", image_ref="registry.example.com/priv/repo@sha256:" + "b" * 64),
    ]
    state = _deploy_requested_state(
        components=components,
        deployments=[{"machine": "test-machine", "component_ids": ["comp-001"], "phase": "deployed"}],
    )
    bound_proxy.read_hidden_state = AsyncMock(return_value=state)
    bound_proxy.write_hidden_state = AsyncMock()
    bound_proxy.project_status_label = AsyncMock()
    mock_github.pr = {
        "state": "open",
        "merged": False,
        "head": {"sha": "a" * 40},
        "user": {"id": 1, "login": "alice"},
    }
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[{"id": "driver-1", "category": "driver", "image": "registry.example.com/priv/repo"}])
    core.driver_status = AsyncMock(side_effect=[
        {"status": "stopped", "running_image": ""},
        {"status": "running", "running_image": components[1]["image_ref"]},
    ])
    core.deploy_driver = AsyncMock(return_value={"ok": True})
    controller._core_for_node = AsyncMock(return_value=core)
    controller._run_automated_case = AsyncMock(return_value={})

    await controller.handle_approve_deploy("repo", 1, 5002, "driver-machine", "owner1", "1")

    markdown = bound_proxy.write_hidden_state.call_args.args[2]
    assert "registry.example.com" not in markdown
    assert "node_host" not in markdown


@pytest.mark.asyncio
async def test_failed_deploy_cos_metadata_is_rebound_to_terminal_state(controller, bound_proxy, mock_github):
    components = [
        _component(component_id="comp-001", target="perception", image_ref="registry/repo@sha256:" + "a" * 64),
        _component(component_id="comp-002", target="driver", variant="", driver_path="custom/driver", image_ref="registry/repo@sha256:" + "b" * 64),
    ]
    state = _deploy_requested_state(components=components)
    bound_proxy.read_hidden_state = AsyncMock(return_value=state)
    bound_proxy.write_hidden_state = AsyncMock()
    bound_proxy.project_status_label = AsyncMock()
    mock_github.pr = {
        "state": "open",
        "merged": False,
        "head": {"sha": "a" * 40},
        "user": {"id": 1, "login": "alice"},
    }
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[
        {"id": "perception", "target": "perception", "image": "registry/repo"},
        {"id": "driver-1", "category": "driver", "image": "registry/repo"},
    ])
    call_count = 0

    async def _status(runtime_id):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return {"status": "stopped", "running_image": ""}
        if call_count == 2:
            return {"status": "stopped", "running_image": ""}
        if call_count == 3:
            return {"status": "running", "running_image": components[0]["image_ref"]}
        return {"status": "starting", "running_image": ""}

    core.driver_status = AsyncMock(side_effect=_status)
    core.deploy_driver = AsyncMock(side_effect=lambda runtime_id, image_ref: {"ok": True})
    controller._core_for_node = AsyncMock(return_value=core)
    controller._upload_evidence = AsyncMock(return_value={
        "object_key": "deploy-approval/repo/pr1/head/evidence.tar.gz",
        "sha256": "f" * 64,
        "size": 123,
    })

    await controller.handle_approve_deploy("repo", 1, 6001, "multi-machine", "owner1", "1")

    final_state = bound_proxy.write_hidden_state.call_args.args[3]
    markdown = bound_proxy.write_hidden_state.call_args.args[2]
    assert final_state["status"] == "failed"
    assert final_state["cos"] == {
        "object_key": "deploy-approval/repo/pr1/head/evidence.tar.gz",
        "sha256": "f" * 64,
        "size": 123,
    }
    assert "deploy-approval/repo/pr1/head/evidence.tar.gz" in markdown
    assert "@sha256:" in markdown
    assert "signed_url" not in markdown


@pytest.mark.asyncio
async def test_failed_deploy_cos_upload_failure_keeps_terminal_failed(controller, bound_proxy, mock_github):
    components = [
        _component(component_id="comp-001", target="perception", image_ref="registry/repo@sha256:" + "a" * 64),
        _component(component_id="comp-002", target="driver", variant="", driver_path="custom/driver", image_ref="registry/repo@sha256:" + "b" * 64),
    ]
    state = _deploy_requested_state(components=components)
    bound_proxy.read_hidden_state = AsyncMock(return_value=state)
    bound_proxy.write_hidden_state = AsyncMock()
    bound_proxy.project_status_label = AsyncMock()
    mock_github.pr = {
        "state": "open",
        "merged": False,
        "head": {"sha": "a" * 40},
        "user": {"id": 1, "login": "alice"},
    }
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[
        {"id": "perception", "target": "perception", "image": "registry/repo"},
        {"id": "driver-1", "category": "driver", "image": "registry/repo"},
    ])
    call_count = 0

    async def _status(runtime_id):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return {"status": "stopped", "running_image": ""}
        if call_count == 2:
            return {"status": "stopped", "running_image": ""}
        if call_count == 3:
            return {"status": "running", "running_image": components[0]["image_ref"]}
        return {"status": "starting", "running_image": ""}

    core.driver_status = AsyncMock(side_effect=_status)
    core.deploy_driver = AsyncMock(side_effect=lambda runtime_id, image_ref: {"ok": True})
    controller._core_for_node = AsyncMock(return_value=core)
    controller._upload_evidence = AsyncMock(return_value={"object_key": "", "sha256": "", "size": 0})

    await controller.handle_approve_deploy("repo", 1, 6002, "multi-machine", "owner1", "1")

    final_state = bound_proxy.write_hidden_state.call_args.args[3]
    markdown = bound_proxy.write_hidden_state.call_args.args[2]
    assert final_state["status"] == "failed"
    assert final_state["cos"] == {"object_key": "", "sha256": "", "size": 0}
    assert "signed_url" not in markdown


@pytest.mark.asyncio
async def test_failed_deploy_cos_rebind_never_persists_signed_url(controller, bound_proxy, mock_github):
    components = [
        _component(component_id="comp-001", target="perception", image_ref="registry/repo@sha256:" + "a" * 64),
        _component(component_id="comp-002", target="driver", variant="", driver_path="custom/driver", image_ref="registry/repo@sha256:" + "b" * 64),
    ]
    state = _deploy_requested_state(components=components)
    bound_proxy.read_hidden_state = AsyncMock(return_value=state)
    bound_proxy.write_hidden_state = AsyncMock()
    bound_proxy.project_status_label = AsyncMock()
    mock_github.pr = {
        "state": "open",
        "merged": False,
        "head": {"sha": "a" * 40},
        "user": {"id": 1, "login": "alice"},
    }
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[
        {"id": "perception", "target": "perception", "image": "registry/repo"},
        {"id": "driver-1", "category": "driver", "image": "registry/repo"},
    ])
    call_count = 0

    async def _status(runtime_id):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return {"status": "stopped", "running_image": ""}
        if call_count == 2:
            return {"status": "stopped", "running_image": ""}
        if call_count == 3:
            return {"status": "running", "running_image": components[0]["image_ref"]}
        return {"status": "starting", "running_image": ""}

    core.driver_status = AsyncMock(side_effect=_status)
    core.deploy_driver = AsyncMock(side_effect=lambda runtime_id, image_ref: {"ok": True})
    controller._core_for_node = AsyncMock(return_value=core)
    controller._upload_evidence = AsyncMock(return_value={
        "object_key": "deploy-approval/repo/pr1/head/evidence.tar.gz",
        "sha256": "f" * 64,
        "size": 123,
    })

    await controller.handle_approve_deploy("repo", 1, 6003, "multi-machine", "owner1", "1")

    final_state = bound_proxy.write_hidden_state.call_args.args[3]
    markdown = bound_proxy.write_hidden_state.call_args.args[2]
    assert "signed_url" not in json.dumps(final_state)
    assert "signed_url" not in markdown


def test_driver_paths_required_for_driver_machine(tmp_path):
    path = _write_machine_yaml(
        tmp_path,
        {
            "version": 1,
            "machines": {
                "driver-machine": {
                    "node_id": "node-1",
                    "node_host": "127.0.0.1",
                    "owners": ["owner1"],
                    "targets": ["driver"],
                    "platforms": ["linux/arm64"],
                }
            },
        },
    )
    with pytest.raises(MachineLoadError, match="driver_paths is required"):
        load_machines(path)


def test_driver_paths_reject_string_scalar(tmp_path):
    path = _write_machine_yaml(
        tmp_path,
        {
            "version": 1,
            "machines": {
                "driver-machine": {
                    "node_id": "node-1",
                    "node_host": "127.0.0.1",
                    "owners": ["owner1"],
                    "targets": ["driver"],
                    "platforms": ["linux/arm64"],
                    "driver_paths": "custom/driver",
                }
            },
        },
    )
    with pytest.raises(MachineLoadError, match="non-empty list"):
        load_machines(path)


@pytest.mark.parametrize(
    "driver_paths",
    [
        ["/abs/driver"],
        ["../driver"],
        ["driver\\path"],
        ["driver//path"],
        ["driver/../path"],
    ],
)
def test_driver_paths_reject_absolute_parent_backslash_and_empty_segments(tmp_path, driver_paths):
    path = _write_machine_yaml(
        tmp_path,
        {
            "version": 1,
            "machines": {
                "driver-machine": {
                    "node_id": "node-1",
                    "node_host": "127.0.0.1",
                    "owners": ["owner1"],
                    "targets": ["driver"],
                    "platforms": ["linux/arm64"],
                    "driver_paths": driver_paths,
                }
            },
        },
    )
    with pytest.raises(MachineLoadError):
        load_machines(path)


def test_driver_paths_are_trimmed_deduped_and_exact_case_preserved(tmp_path):
    path = _write_machine_yaml(
        tmp_path,
        {
            "version": 1,
            "machines": {
                "driver-machine": {
                    "node_id": "node-1",
                    "node_host": "127.0.0.1",
                    "owners": ["owner1"],
                    "targets": ["driver"],
                    "platforms": ["linux/arm64"],
                    "driver_paths": ["  unitree/G1  ", "unitree/G1", "Unitree/G1"],
                }
            },
        },
    )
    machines = load_machines(path)
    assert machines["driver-machine"].driver_paths == ["unitree/G1", "Unitree/G1"]


def test_driver_machine_policy_never_uses_substring_membership(controller):
    assert controller._get_component_ids_for_machine(
        "driver-machine",
        [_component(target="driver", driver_path="custom/driver-extra")],
    ) == []


def test_machine_node_host_ipv6_fails_closed(tmp_path):
    path = _write_machine_yaml(
        tmp_path,
        {
            "version": 1,
            "machines": {
                "test-machine": {
                    "node_id": "node-1",
                    "node_host": "::1",
                    "owners": ["owner1"],
                    "targets": ["perception"],
                    "platforms": ["linux/arm64"],
                }
            },
        },
    )
    with pytest.raises(MachineLoadError, match="IPv4"):
        load_machines(path)


def test_agent_core_client_ipv6_node_host_fails_closed(config):
    with pytest.raises(AgentCoreError, match="IPv4"):
        AgentCoreClient(
            config,
            base_url="http://[::1]:15678",
            node_host="::1",
        )
