"""Final recovery/outcome regressions for Deploy Approval."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from .. import comments as comments_mod
from ..agent_core_client import (
    AgentCoreClient,
    AgentCoreDeployOutcomeUncertain,
    AgentCoreError,
)
from ..config import Config, validate_config
from ..github_state_proxy import _validate_hidden_state
from ..models import BuildInfo, MachineInfo
from ..policy import Policy
from ..github_command_watcher import GitHubCommandWatcher
from ..router_webhook import webhook
from ..service import DeployController, DeployOutcomeUncertain
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
        "review_evidence": {"build_comment_id": 1, "build_comment_updated_at": "2026-09-18T00:00:00Z", "commit_prefix": "abc1234", "resolved_head_sha": "a" * 40, "test_comment_id": 2, "test_comment_updated_at": "2026-09-18T00:00:00Z", "code_review_comment_id": 3, "code_review_comment_updated_at": "2026-09-18T00:00:00Z", "review_author_id": "7950763"},
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
        target=target,
        driver_path=driver_path,
        variant=variant,
        success=success,
        image_tag=image_tag,
        deployable=True,
    )


def _controller():
    config = make_config()
    proxy = MagicMock()
    proxy.read_hidden_state = AsyncMock(return_value=_state())
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
    proxy.comment_identity = AsyncMock(return_value=("111", "alice"))
    proxy.find_trusted_lifecycle_comment = AsyncMock(return_value={"id": 42, "body": ""})
    proxy.get_pr = AsyncMock(
        return_value={
            "state": "open",
            "merged": False,
            "head": {"sha": "a" * 40},
            "user": {"id": 111, "login": "alice"},
        }
    )
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
    github.get_issue_comments = AsyncMock(return_value=[])
    async def _get_comment(repo, cid):
        if isinstance(cid, int) and not isinstance(cid, bool) and cid > 0:
            return {
                "id": cid,
                "body": "/approve_deploy machine=test-machine",
                "user": {"id": 111, "login": "owner1"},
            }
        return None

    proxy.get_comment = AsyncMock(side_effect=_get_comment)

    controller = DeployController(config, proxy, policy, github)
    return controller, proxy, policy, github, config


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
    cfg
    return AgentCoreClient(
        cfg,
        base_url="https://10.0.0.1:15678",
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
    assert result == {"running_image": "", "status": "stopped"}


@pytest.mark.asyncio
async def test_driver_status_invalid_status_type_fails_closed():
    """status field present but not a non-empty string -> AgentCoreError (fail closed)."""
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
    with pytest.raises(AgentCoreError, match="status must be a non-empty string"):
        await client.driver_status("driver")


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
    controller, proxy, policy, github, config = _controller()
    builds = [BuildInfo("perception", "", "5.11", True, "registry.example/repo:v1", True)]
    emdash = "\u2014"
    github.get_issue_comments = AsyncMock(return_value=[
        {
            "id": 5001,
            "user": {"id": "7950763", "login": "review-agent-bot"},
            "body": f"<!-- pr-review-agent -->\n## PR Review Agent {emdash} Build Result\n\nCommit: abcdef1\n\n| target | status | version | took |\n| perception (jetson-jp5.11) | :white_check_mark: | release.260918.abcdef1 | 10s |\n\n### Images\n\n**perception (jetson-jp5.11)**\n```\nregistry.example/repo:v1\n```\n",
            "created_at": "2026-09-03T09:00:00Z",
            "updated_at": "2026-09-03T10:00:00Z",
        },
        {
            "id": 5002,
            "user": {"id": "7950763", "login": "review-agent-bot"},
            "body": f"<!-- pr-review-agent -->\n## PR Review Agent {emdash} Code Review\n\nLGTM\n",
            "created_at": "2026-09-03T11:00:00Z",
            "updated_at": "2026-09-03T11:00:00Z",
        },
    ])
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
    proxy.read_hidden_state = AsyncMock(
        return_value={
            "version": 1,
            "head_sha": "a" * 40,
            "status": "deploy-ready",
            "review_evidence": {},
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
    github.resolve_commit_sha = AsyncMock(return_value="a" * 40)

    await controller.handle_request_deploy("4paradigm/phanthymotus", 1, 101)

    controller._build_component_snapshot.assert_awaited_once_with(
        "4paradigm/phanthymotus", 1, "a" * 40, builds
    )
    written_state = proxy.write_hidden_state.call_args.args[3]
    assert written_state["components"][0]["component_id"] == "comp-123"


@pytest.mark.asyncio
async def test_uncertain_recovery_rebuilds_fresh_component_snapshot():
    controller, proxy, policy, github, config = _controller()
    state = _state(
        review_evidence={"build_comment_id": 1, "build_comment_updated_at": "2026-09-18T00:00:00Z", "commit_prefix": "abc1234", "resolved_head_sha": "a" * 40, "test_comment_id": 2, "test_comment_updated_at": "2026-09-18T00:00:00Z", "code_review_comment_id": 3, "code_review_comment_updated_at": "2026-09-18T00:00:00Z", "review_author_id": "7950763"},
        components=[_component(component_id="comp-old", image_ref="registry.example/repo@sha256:" + "c" * 64)],
        deployments=[],
    )
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}})
    github.resolve_commit_sha = AsyncMock(return_value="a" * 40)
    from agents.deploy_approval.review_comment_parser import ReviewCommentEvidence, ReviewBuild
    fake_evidence = ReviewCommentEvidence(
        build_comment_id=1001,
        build_comment_updated_at="2026-09-18T03:55:54Z",
        commit_prefix="abc1234",
        test_comment_id=1002,
        test_comment_updated_at="2026-09-18T03:55:54Z",
        code_review_comment_id=1003,
        code_review_comment_updated_at="2026-09-18T03:56:00Z",
        code_review_text="Looks good.",
        builds=[ReviewBuild(target="perception", driver_path="test", variant="default", success=True, image_tag="registry.example/repo:v2", version="v2")],
        review_author_id="7950763",
    )
    emdash = "\u2014"
    github.get_issue_comments = AsyncMock(return_value=[
        {
            "id": 1001,
            "user": {"id": "7950763", "login": "review-agent-bot"},
            "body": f"<!-- pr-review-agent -->\n## PR Review Agent {emdash} Build Result\n\nCommit: abc1234\n\n| target | status | version | took |\n| perception | :white_check_mark: | v2 | 10s |\n\n### Images\n\n**perception**\n```\nregistry.example/repo:v2\n```\n",
            "created_at": "2026-09-18T03:50:00Z",
            "updated_at": "2026-09-18T03:55:54Z",
        },
        {
            "id": 1003,
            "user": {"id": "7950763", "login": "review-agent-bot"},
            "body": ("<!-- pr-review-agent -->\n## PR Review Agent " + emdash + " Code Review\n\nLooks good.\n").replace("\\n", "\n"),
            "created_at": "2026-09-18T03:56:00Z",
            "updated_at": "2026-09-18T03:56:00Z",
        },
    ])
    with patch('agents.deploy_approval.service.extract_review_evidence', return_value=fake_evidence):
        controller._build_component_snapshot = AsyncMock(
        return_value=[_component(component_id="comp-new", image_ref="registry.example/repo@sha256:" + "d" * 64)]
    )
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    result = await controller._refresh_uncertain_state("4paradigm/phanthymotus", 1, state)

    assert result == "deploy-requested"
    written_state = proxy.write_hidden_state.call_args.args[3]
    assert written_state["review_evidence"]["build_comment_id"] == 1001
    assert written_state["components"][0]["component_id"] == "comp-new"


@pytest.mark.asyncio
async def test_uncertain_recovery_new_job_never_keeps_old_components():
    controller, proxy, policy, github, config = _controller()
    state = _state(
        review_evidence={"build_comment_id": 1, "build_comment_updated_at": "2026-09-18T00:00:00Z", "commit_prefix": "abc1234", "resolved_head_sha": "a" * 40, "test_comment_id": 2, "test_comment_updated_at": "2026-09-18T00:00:00Z", "code_review_comment_id": 3, "code_review_comment_updated_at": "2026-09-18T00:00:00Z", "review_author_id": "7950763"},
        components=[_component(component_id="comp-old")],
        deployments=[],
    )
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}})
    github.resolve_commit_sha = AsyncMock(return_value="a" * 40)
    from agents.deploy_approval.review_comment_parser import ReviewCommentEvidence, ReviewBuild
    fake_evidence = ReviewCommentEvidence(
        build_comment_id=1001,
        build_comment_updated_at="2026-09-18T03:55:54Z",
        commit_prefix="abc1234",
        test_comment_id=1002,
        test_comment_updated_at="2026-09-18T03:55:54Z",
        code_review_comment_id=1003,
        code_review_comment_updated_at="2026-09-18T03:56:00Z",
        code_review_text="Looks good.",
        builds=[ReviewBuild(target="perception", driver_path="test", variant="default", success=True, image_tag="registry.example/repo:v2", version="v2")],
        review_author_id="7950763",
    )
    emdash = "\u2014"
    github.get_issue_comments = AsyncMock(return_value=[
        {
            "id": 1001,
            "user": {"id": "7950763", "login": "review-agent-bot"},
            "body": f"<!-- pr-review-agent -->\n## PR Review Agent {emdash} Build Result\n\nCommit: abc1234\n\n| target | status | version | took |\n| perception | :white_check_mark: | v2 | 10s |\n\n### Images\n\n**perception**\n```\nregistry.example/repo:v2\n```\n",
            "created_at": "2026-09-18T03:50:00Z",
            "updated_at": "2026-09-18T03:55:54Z",
        },
        {
            "id": 1003,
            "user": {"id": "7950763", "login": "review-agent-bot"},
            "body": ("<!-- pr-review-agent -->\n## PR Review Agent " + emdash + " Code Review\n\nLooks good.\n").replace("\\n", "\n"),
            "created_at": "2026-09-18T03:56:00Z",
            "updated_at": "2026-09-18T03:56:00Z",
        },
    ])
    with patch('agents.deploy_approval.service.extract_review_evidence', return_value=fake_evidence):
        controller._build_component_snapshot = AsyncMock(return_value=[_component(component_id="comp-new")])
        proxy.write_hidden_state = AsyncMock()
        proxy.project_status_label = AsyncMock()

        await controller._refresh_uncertain_state("4paradigm/phanthymotus", 1, state)

        written_state = proxy.write_hidden_state.call_args.args[3]
        assert [c["component_id"] for c in written_state["components"]] == ["comp-new"]


@pytest.mark.asyncio
async def test_uncertain_recovery_snapshot_change_resets_deployments():
    controller, proxy, policy, github, config = _controller()
    state = _state(
        review_evidence={"build_comment_id": 1, "build_comment_updated_at": "2026-09-18T00:00:00Z", "commit_prefix": "abc1234", "resolved_head_sha": "a" * 40, "test_comment_id": 2, "test_comment_updated_at": "2026-09-18T00:00:00Z", "code_review_comment_id": 3, "code_review_comment_updated_at": "2026-09-18T00:00:00Z", "review_author_id": "7950763"},
        components=[_component(component_id="comp-old")],
        deployments=[{"machine": "test-machine", "component_ids": ["comp-old"], "phase": "deployed"}],
    )
    state["command"]["phase"] = "completed"
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}})
    github.resolve_commit_sha = AsyncMock(return_value="a" * 40)
    from agents.deploy_approval.review_comment_parser import ReviewCommentEvidence, ReviewBuild
    fake_evidence = ReviewCommentEvidence(
        build_comment_id=1001,
        build_comment_updated_at="2026-09-18T03:55:54Z",
        commit_prefix="abc1234",
        test_comment_id=1002,
        test_comment_updated_at="2026-09-18T03:55:54Z",
        code_review_comment_id=1003,
        code_review_comment_updated_at="2026-09-18T03:56:00Z",
        code_review_text="Looks good.",
        builds=[ReviewBuild(target="perception", driver_path="test", variant="default", success=True, image_tag="registry.example/repo:v2", version="v2")],
        review_author_id="7950763",
    )
    emdash = "\u2014"
    github.get_issue_comments = AsyncMock(return_value=[
        {
            "id": 1001,
            "user": {"id": "7950763", "login": "review-agent-bot"},
            "body": f"<!-- pr-review-agent -->\n## PR Review Agent {emdash} Build Result\n\nCommit: abc1234\n\n| target | status | version | took |\n| perception | :white_check_mark: | v2 | 10s |\n\n### Images\n\n**perception**\n```\nregistry.example/repo:v2\n```\n",
            "created_at": "2026-09-18T03:50:00Z",
            "updated_at": "2026-09-18T03:55:54Z",
        },
        {
            "id": 1003,
            "user": {"id": "7950763", "login": "review-agent-bot"},
            "body": ("<!-- pr-review-agent -->\n## PR Review Agent " + emdash + " Code Review\n\nLooks good.\n").replace("\\n", "\n"),
            "created_at": "2026-09-18T03:56:00Z",
            "updated_at": "2026-09-18T03:56:00Z",
        },
    ])
    with patch('agents.deploy_approval.service.extract_review_evidence', return_value=fake_evidence):
        controller._build_component_snapshot = AsyncMock(
            return_value=[_component(component_id="comp-new", review_image_tag="registry.example/repo:v2")]
        )
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    await controller._refresh_uncertain_state("4paradigm/phanthymotus", 1, state)

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
    controller, proxy, policy, github, config = _controller()
    state = _state(
        review_evidence={"build_comment_id": 1001, "build_comment_updated_at": "2026-09-18T03:55:54Z", "commit_prefix": "abc1234", "resolved_head_sha": "a" * 40, "test_comment_id": 1002, "code_review_comment_id": 1003, "review_author_id": "7950763"},
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
    github.resolve_commit_sha = AsyncMock(return_value="a" * 40)
    emdash = "\u2014"
    github.get_issue_comments = AsyncMock(return_value=[
        {
            "id": 1001,
            "user": {"id": "7950763", "login": "review-agent-bot"},
            "body": ("<!-- pr-review-agent -->\n## PR Review Agent " + emdash + " Build Result\n\nCommit: abc1234\n\n| target | status | version | took |\n| perception | :white_check_mark: | v1 | 10s |\n| actucore | :white_check_mark: | v1 | 10s |\n\n### Images\n\n**perception**\n```\nregistry.example/repo:v1\n```\n\n**actucore**\n```\nregistry.example/repo:v1\n```\n").replace("\\n", "\n"),
            "created_at": "2026-09-18T03:50:00Z",
            "updated_at": "2026-09-18T03:55:54Z",
        },
        {
            "id": 1003,
            "user": {"id": "7950763", "login": "review-agent-bot"},
            "body": ("<!-- pr-review-agent -->\n## PR Review Agent " + emdash + " Code Review\n\nLooks good.\n").replace("\\n", "\n"),
            "created_at": "2026-09-18T03:56:00Z",
            "updated_at": "2026-09-18T03:56:00Z",
        },
    ])
    from agents.deploy_approval.review_comment_parser import ReviewCommentEvidence, ReviewBuild
    fake_evidence = ReviewCommentEvidence(
        build_comment_id=1001,
        build_comment_updated_at="2026-09-18T03:55:54Z",
        commit_prefix="abc1234",
        test_comment_id=1002,
        test_comment_updated_at="2026-09-18T03:55:54Z",
        code_review_comment_id=1003,
        code_review_comment_updated_at="2026-09-18T03:56:00Z",
        code_review_text="Looks good.",
        builds=[ReviewBuild(target="perception", driver_path="test", variant="default", success=True, image_tag="registry.example/repo:v1", version="v1"),
                ReviewBuild(target="actucore", driver_path="test", variant="default", success=True, image_tag="registry.example/repo:v1", version="v1")],
        review_author_id="7950763",
    )
    with patch('agents.deploy_approval.service.extract_review_evidence', return_value=fake_evidence):
        controller._build_component_snapshot = AsyncMock(return_value=fresh_components)
        proxy.write_hidden_state = AsyncMock()
        proxy.project_status_label = AsyncMock()

        await controller._refresh_uncertain_state("4paradigm/phanthymotus", 1, state)

        written_state = proxy.write_hidden_state.call_args.args[3]
        assert written_state["deployments"] == state["deployments"]
        # runtime_id preserved from prior deployed component
        assert written_state["deployments"] == state["deployments"]
        assert written_state["components"][0].get("runtime_id") is None
        assert "runtime_id" not in written_state["components"][1]


@pytest.mark.asyncio
async def test_uncertain_recovery_clears_runtime_id_for_ambiguous_component():
    controller, proxy, policy, github, config = _controller()
    state = _state(
        review_evidence={"build_comment_id": 1001, "build_comment_updated_at": "2026-09-18T03:55:54Z", "commit_prefix": "abc1234", "resolved_head_sha": "a" * 40, "test_comment_id": 1002, "code_review_comment_id": 1003, "review_author_id": "7950763"},
        components=[
            _component(component_id="comp-1", runtime_id="perception"),
            _component(component_id="comp-2", target="actucore", runtime_id="actucore"),
        ],
        deployments=[{"machine": "test-machine", "component_ids": ["comp-1"], "phase": "deployed"}],
    )
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}})
    github.resolve_commit_sha = AsyncMock(return_value="a" * 40)
    emdash = "\u2014"
    github.get_issue_comments = AsyncMock(return_value=[
        {
            "id": 1001,
            "user": {"id": "7950763", "login": "review-agent-bot"},
            "body": ("<!-- pr-review-agent -->\n## PR Review Agent " + emdash + " Build Result\n\nCommit: abc1234\n\n| target | status | version | took |\n| perception | :white_check_mark: | v1 | 10s |\n| actucore | :white_check_mark: | v1 | 10s |\n\n### Images\n\n**perception**\n```\nregistry.example/repo:v1\n```\n\n**actucore**\n```\nregistry.example/repo:v1\n```\n").replace("\\n", "\n"),
            "created_at": "2026-09-18T03:50:00Z",
            "updated_at": "2026-09-18T03:55:54Z",
        },
        {
            "id": 1003,
            "user": {"id": "7950763", "login": "review-agent-bot"},
            "body": ("<!-- pr-review-agent -->\n## PR Review Agent " + emdash + " Code Review\n\nLooks good.\n").replace("\\n", "\n"),
            "created_at": "2026-09-18T03:56:00Z",
            "updated_at": "2026-09-18T03:56:00Z",
        },
    ])
    from agents.deploy_approval.review_comment_parser import ReviewCommentEvidence, ReviewBuild
    fake_evidence = ReviewCommentEvidence(
        build_comment_id=1001,
        build_comment_updated_at="2026-09-18T03:55:54Z",
        commit_prefix="abc1234",
        test_comment_id=1002,
        test_comment_updated_at="2026-09-18T03:55:54Z",
        code_review_comment_id=1003,
        code_review_comment_updated_at="2026-09-18T03:56:00Z",
        code_review_text="Looks good.",
        builds=[ReviewBuild(target="perception", driver_path="test", variant="default", success=True, image_tag="registry.example/repo:v1", version="v1"),
                ReviewBuild(target="actucore", driver_path="test", variant="default", success=True, image_tag="registry.example/repo:v1", version="v1")],
        review_author_id="7950763",
    )
    with patch('agents.deploy_approval.service.extract_review_evidence', return_value=fake_evidence):
        controller._build_component_snapshot = AsyncMock(
        return_value=[
            _component(component_id="comp-1"),
            _component(component_id="comp-2", target="actucore"),
        ]
    )
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    await controller._refresh_uncertain_state("4paradigm/phanthymotus", 1, state)

    written_state = proxy.write_hidden_state.call_args.args[3]
    assert written_state["components"][0].get("runtime_id") is None
    assert "runtime_id" not in written_state["components"][1]


@pytest.mark.asyncio
async def test_uncertain_recovery_snapshot_rebuild_failure_stays_uncertain():
    controller, proxy, policy, github, config = _controller()
    state = _state(
        review_evidence={"build_comment_id": 1, "build_comment_updated_at": "2026-09-18T00:00:00Z", "commit_prefix": "abc1234", "resolved_head_sha": "a" * 40, "test_comment_id": 2, "test_comment_updated_at": "2026-09-18T00:00:00Z", "code_review_comment_id": 3, "code_review_comment_updated_at": "2026-09-18T00:00:00Z", "review_author_id": "7950763"},
        components=[_component()],
        deployments=[{"machine": "test-machine", "component_ids": ["comp-001"], "phase": "deployed"}],
    )
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}})
    github.resolve_commit_sha = AsyncMock(return_value="a" * 40)
    from agents.deploy_approval.review_comment_parser import ReviewCommentEvidence, ReviewBuild
    fake_evidence = ReviewCommentEvidence(
        build_comment_id=1001,
        build_comment_updated_at="2026-09-18T03:55:54Z",
        commit_prefix="abc1234",
        test_comment_id=1002,
        test_comment_updated_at="2026-09-18T03:55:54Z",
        code_review_comment_id=1003,
        code_review_comment_updated_at="2026-09-18T03:56:00Z",
        code_review_text="Looks good.",
        builds=[ReviewBuild(target="perception", driver_path="test", variant="default", success=True, image_tag="registry.example/repo:v2", version="v2")],
        review_author_id="7950763",
    )
    emdash = "\u2014"
    github.get_issue_comments = AsyncMock(return_value=[
        {
            "id": 1001,
            "user": {"id": "7950763", "login": "review-agent-bot"},
            "body": f"<!-- pr-review-agent -->\n## PR Review Agent {emdash} Build Result\n\nCommit: abc1234\n\n| target | status | version | took |\n| perception | :white_check_mark: | v2 | 10s |\n\n### Images\n\n**perception**\n```\nregistry.example/repo:v2\n```\n",
            "created_at": "2026-09-18T03:50:00Z",
            "updated_at": "2026-09-18T03:55:54Z",
        },
        {
            "id": 1003,
            "user": {"id": "7950763", "login": "review-agent-bot"},
            "body": ("<!-- pr-review-agent -->\n## PR Review Agent " + emdash + " Code Review\n\nLooks good.\n").replace("\\n", "\n"),
            "created_at": "2026-09-18T03:56:00Z",
            "updated_at": "2026-09-18T03:56:00Z",
        },
    ])
    with patch('agents.deploy_approval.service.extract_review_evidence', return_value=fake_evidence):
        controller._build_component_snapshot = AsyncMock(return_value=None)
        proxy.write_hidden_state = AsyncMock()
        proxy.project_status_label = AsyncMock()

        result = await controller._refresh_uncertain_state("4paradigm/phanthymotus", 1, state)

        assert result == "uncertain"
        written_state = proxy.write_hidden_state.call_args.args[3]
        assert written_state["review_evidence"].get("build_comment_id")
        assert written_state["components"] == [_component()]


@pytest.mark.asyncio
async def test_new_approve_from_uncertain_refreshes_before_final_pre_deploy_validation():
    controller, proxy, policy, github, config = _controller()
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
    controller._verify_deployed_runtime = AsyncMock(return_value=(True, {"component_id": "comp-001", "runtime_id": "test", "running_image": "x", "passed": False}))
    controller._run_automated_case = AsyncMock(return_value={})
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}, "user": {"id": 222, "login": "alice"}})

    await controller.handle_approve_deploy("repo", 1, 17, "test-machine", "owner1", "111")

    assert events[0] == "refresh"
    assert "list_drivers" in events
    assert events.index("refresh") < events.index("list_drivers")


@pytest.mark.asyncio
async def test_watcher_uncertain_without_new_approve_does_not_refresh_review():
    controller, proxy, policy, github, config = _controller()
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
    controller._core_for_node = AsyncMock(side_effect=AssertionError("unexpected Agent Core lookup"))
    controller._deploy_component = AsyncMock(side_effect=AssertionError("unexpected deploy"))
    controller._run_automated_case = AsyncMock(side_effect=AssertionError("unexpected case run"))
    controller.on_command = AsyncMock(return_value=True)

    watcher = GitHubCommandWatcher(config, proxy, controller)

    await watcher._process_pr("repo", 1)

    assert state["command"]["phase"] == "uncertain"
    assert controller.on_command.await_count == 0
    assert controller._core_for_node.await_count == 0
    assert controller._deploy_component.await_count == 0
    assert proxy.write_hidden_state.await_count == 0


@pytest.mark.asyncio
async def test_watcher_uncertain_new_approve_refreshes_review_before_final_pre_deploy_validation():
    controller, proxy, policy, github, config = _controller()
    state = _state()
    state["command"]["phase"] = "uncertain"
    state["last_processed_comment_id"] = 17

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

    emdash = "\u2014"

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
            {
                "id": 5001,
                "user": {"id": "7950763", "login": "review-agent-bot"},
                "body": f"<!-- pr-review-agent -->\n## PR Review Agent {emdash} Build Result\n\nCommit: abcdef1\n\n| target | status | version | took |\n| perception | :white_check_mark: | 5.11 | 10s |\n\n### Images\n\n**perception**\n```\nccr.ccs.tencentyun.com/repo:v1\n```\n",
                "created_at": "2026-09-03T09:00:00Z",
                "updated_at": "2026-09-03T10:00:00Z",
            },
            {
                "id": 5002,
                "user": {"id": "7950763", "login": "review-agent-bot"},
                "body": f"<!-- pr-review-agent -->\n## PR Review Agent {emdash} Code Review\n\nLGTM\n",
                "created_at": "2026-09-03T11:00:00Z",
                "updated_at": "2026-09-03T11:00:00Z",
            },
        ]


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
    _comment_lookup = {
        17: {
            "id": 17,
            "body": "/approve_deploy machine=test-machine",
            "user": {"id": 111, "login": "owner1"},
        },
        99: {
            "id": 99,
            "body": "/approve_deploy machine=test-machine",
            "user": {"id": 111, "login": "owner1"},
        },
    }
    def _get_comment(repo, cid):
        return _comment_lookup.get(cid, {"id": cid, "body": "normal comment", "user": {"id": 999}})
    proxy.get_comment = AsyncMock(side_effect=_get_comment)
    proxy.is_bot_comment = MagicMock(return_value=False)
    proxy.comment_identity = AsyncMock(return_value=("111", "owner1"))
    proxy.persist_cursor = AsyncMock()
    core = AsyncMock()
    core.list_drivers = AsyncMock(side_effect=_list_drivers)
    core.driver_status = AsyncMock(side_effect=_driver_status)
    controller._core_for_node = AsyncMock(return_value=core)
    controller._deploy_component = AsyncMock(side_effect=_deploy_component)
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
    assert "get_issue_comments" in events
    # review.list_jobs seam removed; evidence now from GitHub comments
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
        await client.deploy_driver("driver", "https://registry.example/repo:latest")
    assert not isinstance(excinfo.value, AgentCoreDeployOutcomeUncertain)


@pytest.mark.asyncio
async def test_uncertain_post_stops_later_components():
    """Canonical uncertain-post contract: A succeeds, B uncertain, C gets zero POSTs.

    Scenario with THREE components so the contract is fully observable:
    A = perception (succeeds), B = actucore (uncertain), C = driver (zero POSTs).

    Assertions:
    1. A POST exactly once
    2. B POST exactly once
    3. C POST zero times
    4. total deploy calls == 2
    5. successful deployment for A remains in state["deployments"]
    6. B is not marked successfully deployed
    7. C is not marked deployed
    8. state.status == "deploy-requested"
    9. state.command.phase == "uncertain"
    10. state.last_processed_comment_id == current approve comment ID
    11. no automatic replay
    12. no rollback behavior
    """
    controller, proxy, policy, github, config = _controller()
    real_comps = await controller._build_component_snapshot(
        "4paradigm/phanthymotus", 1, "a" * 40,
        [_build(), _build(target="actucore"), _build(target="driver", driver_path="custom/driver")],
    )
    assert real_comps is not None
    state = _state(
        status="deploy-requested",
        components=real_comps,
        deployments=[],
    )
    state["command"]["phase"] = "completed"
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.get_pr = AsyncMock(
        return_value={
            "state": "open",
            "merged": False,
            "head": {"sha": "a" * 40},
            "user": {"id": 222, "login": "alice"},
        }
    )
    core = AsyncMock()
    core.list_drivers = AsyncMock(
        return_value=[
            {"id": "perception", "target": "perception", "image": "registry.example/repo:v1"},
            {"id": "actucore", "target": "actucore", "image": "registry.example/repo:v1"},
            {"id": "driver", "category": "driver", "image": "registry.example/repo:v1"},
        ]
    )
    status_order = []

    async def _driver_status(driver_id):
        status_order.append(driver_id)
        return {"status": "running", "running_image": ""}

    core.driver_status = AsyncMock(side_effect=_driver_status)
    controller._core_for_node = AsyncMock(return_value=core)
    deploy_calls = {"perception": 0, "actucore": 0, "driver": 0}

    async def _deploy_component(_core, _node_id, _image_ref, runtime_id):
        deploy_calls[runtime_id] = deploy_calls.get(runtime_id, 0) + 1
        if runtime_id == "actucore":
            raise DeployOutcomeUncertain("network timeout")
        return {"result": {"code": 0}}

    controller._deploy_component = AsyncMock(side_effect=_deploy_component)
    controller._verify_deployed_runtime = AsyncMock(return_value=(True, {"component_id": "comp-001", "runtime_id": "test", "running_image": "x", "passed": False}))
    controller._run_automated_case = AsyncMock(return_value={})
    controller._fresh_review_evidence_matches_state = AsyncMock(return_value=True)
    proxy.get_issue_comments = AsyncMock(return_value=[])
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    await controller.handle_approve_deploy("4paradigm/phanthymotus", 1, 17, "test-machine", "owner1", "111")

    # 1-4: A once, B once, C zero, total 2
    assert deploy_calls.get("perception", 0) == 1, f"perception deployed {deploy_calls.get('perception', 0)} times"
    assert deploy_calls.get("actucore", 0) == 1, f"actucore deployed {deploy_calls.get('actucore', 0)} times"
    assert deploy_calls.get("driver", 0) == 0, f"driver deployed {deploy_calls.get('driver', 0)} times"
    total = sum(deploy_calls.values())
    assert total == 2, f"Expected 2 total deploy calls, got {total}"

    # 5-7: A deployed, B/C not
    written_state = proxy.write_hidden_state.call_args.args[3]
    deployed_cids = set()
    for dep in written_state.get("deployments", []):
        deployed_cids.update(dep.get("component_ids", []))
    assert real_comps[0]["component_id"] in deployed_cids, "Component A should be deployed"
    assert real_comps[1]["component_id"] not in deployed_cids, "Component B should not be deployed"

    # 8-10
    assert written_state["status"] == "deploy-requested"
    assert written_state["command"]["phase"] == "uncertain"
    assert written_state["last_processed_comment_id"] == 17

    # 11-12: no automatic replay (phase is uncertain, not executing), no rollback
    assert written_state["command"]["phase"] == "uncertain"
    # prior successful deployment preserved (no rollback)
    assert len(written_state["deployments"]) == 1
    assert written_state["deployments"][0]["component_ids"] == [real_comps[0]["component_id"]]



@pytest.mark.asyncio
async def test_uncertain_post_does_not_upload_failed_cos():
    controller, proxy, policy, github, config = _controller()
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
            {"id": "driver", "category": "driver", "image": "registry.example/repo:v1"},
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
    controller._run_automated_case = AsyncMock(return_value={})
    controller._upload_evidence = AsyncMock()
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    await controller.handle_approve_deploy("repo", 1, 17, "test-machine", "owner1", "111")

    controller._upload_evidence.assert_not_called()



def test_poll_disabled_webhook_enabled_fails_config():
    with pytest.raises(ValueError, match="requires polling"):
        validate_config(
            Config(
                github_repos=[
                    "4paradigm/phanthymotus",
                ],
                poll_enabled=False,
                webhook_enabled=True,
                github_webhook_secret="secret",
            )
        )


@pytest.mark.asyncio
async def test_webhook_remains_supplementary_zero_dispatch():
    controller, proxy, policy, github, config = _controller()
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
    controller, proxy, policy, github, config = _controller()
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
    controller, proxy, policy, github, config = _controller()
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
async def test_new_approve_deploys_only_remaining_components():
    """New approve processes REMAINING components only.

    Already successful component A receives ZERO new deploy POST.
    Remaining component B receives exactly ONE deploy POST.
    """
    import copy
    import hashlib

    controller, proxy, policy, github, config = _controller()
    REPO = "4paradigm/phanthymotus"
    events: list[str] = []
    write_log: list[tuple[str, dict]] = []

    FAKE_SHA = "a" * 64
    IMAGE_REF_A = f"registry.example/repo@sha256:{FAKE_SHA}"

    comp_a_id = hashlib.sha256(f"perception||5.11|{IMAGE_REF_A}".encode()).hexdigest()[:16]
    comp_b_id = hashlib.sha256(f"actucore||5.11|{IMAGE_REF_A}".encode()).hexdigest()[:16]

    current_state = _state(
        head_sha="a" * 40,
        status="deploy-requested",
        review_evidence={
            "build_comment_id": 5001,
            "build_comment_updated_at": "2026-09-18T03:55:54Z",
            "commit_prefix": "abc1234",
            "resolved_head_sha": "a" * 40,
            "test_comment_id": 5002,
            "test_comment_updated_at": "2026-09-18T03:55:54Z",
            "code_review_comment_id": 5003,
            "code_review_comment_updated_at": "2026-09-18T03:56:00Z",
            "review_author_id": "7950763",
        },
        components=[
            {
                "component_id": comp_a_id,
                "target": "perception",
                "driver_path": "",
                "variant": "5.11",
                "review_image_tag": "registry.example/repo:v1",
                "image_ref": IMAGE_REF_A,
                "resolved_platform": "linux/arm64",
                "runtime_id": "perception",
            },
            {
                "component_id": comp_b_id,
                "target": "actucore",
                "driver_path": "",
                "variant": "5.11",
                "review_image_tag": "registry.example/repo:v1",
                "image_ref": IMAGE_REF_A,
                "resolved_platform": "linux/arm64",
                "runtime_id": "actucore",
            },
        ],
        deployments=[
            {"machine": "test-machine", "component_ids": [comp_a_id], "phase": "deployed"}
        ],
        command={
            "comment_id": 17,
            "kind": "approve_deploy",
            "phase": "uncertain",
            "args": {"machine": "test-machine"},
        },
        last_processed_comment_id=17,
    )

    async def _read_hidden_state(*args, **kwargs):
        return copy.deepcopy(current_state)

    async def _write_hidden_state(*args, **kwargs):
        markdown = args[0] if args else kwargs.get("markdown", "")
        state = args[3] if len(args) > 3 else kwargs.get("state")
        if state is None:
            return
        written = copy.deepcopy(state)
        write_log.append((markdown, written))
        current_state.clear()
        current_state.update(written)

    proxy.read_hidden_state = AsyncMock(side_effect=_read_hidden_state)
    proxy.write_hidden_state = AsyncMock(side_effect=_write_hidden_state)
    proxy.project_status_label = AsyncMock()

    proxy.get_pr = AsyncMock(
        return_value={
            "state": "open",
            "merged": False,
            "head": {"sha": "a" * 40},
            "user": {"id": 333, "login": "pr-author"},
        }
    )

    actor_id = "222"
    async def _get_comment(repo, cid):
        return {
            "id": cid,
            "body": "/approve_deploy machine=test-machine",
            "user": {"id": int(actor_id), "login": "owner1"},
        }
    proxy.get_comment = AsyncMock(side_effect=_get_comment)
    proxy.comment_identity = AsyncMock(return_value=("222", "owner1"))
    proxy.post_issue_comment = AsyncMock(return_value={"id": 1})
    proxy.collaborator_permission = AsyncMock(return_value="admin")

    # Patch unrelated boundaries
    async def _refresh_uncertain_state(repo, pr_number, state):
        state["status"] = "deploy-requested"
        old_command = state.get("command", {})
        old_args = dict(old_command.get("args", {}) or {})
        state["command"] = {
            "comment_id": int(old_command.get("comment_id", 0) or 0),
            "kind": "approve_deploy",
            "phase": "completed",
            "args": old_args,
        }

        # Persist the refreshed state so subsequent production reads see phase=completed.
        current_state.clear()
        current_state.update(copy.deepcopy(state))

        return "deploy-requested"

    controller._refresh_uncertain_state = AsyncMock(side_effect=_refresh_uncertain_state)
    controller._fresh_review_evidence_matches_state = AsyncMock(return_value=True)

    # Mock _preflight for the REMAINING component (actucore) only
    controller._preflight_running_images = AsyncMock(return_value=[
        {
            "component": current_state["components"][1],
            "runtime_id": "actucore",
            "running_image": "",
            "runtime_repo": "registry.example/repo",
        },
    ])

    core = AsyncMock()
    deploy_calls: dict[str, int] = {"perception": 0, "actucore": 0}

    async def _deploy_driver(runtime_id, image):
        deploy_calls[runtime_id] = deploy_calls.get(runtime_id, 0) + 1
        events.append(f"deploy_driver:{runtime_id}")
        return {"code": 200, "data": {"status": "starting"}}
    core.deploy_driver = _deploy_driver
    core.list_drivers = AsyncMock(return_value=[
        {"id": "perception", "target": "perception", "image": "registry.example/repo:v1"},
        {"id": "actucore", "target": "actucore", "image": "registry.example/repo:v1"},
    ])
    controller._core_for_node = AsyncMock(return_value=core)
    controller._verify_deployed_runtime = AsyncMock(return_value=(True, {"component_id": "comp-001", "runtime_id": "test", "running_image": "x", "passed": False}))
    controller._run_automated_case = AsyncMock(return_value={})

    await controller.handle_approve_deploy(REPO, 1, 99, "test-machine", "owner1", actor_id)

    # Proofs:
    # A (perception) receives ZERO new deploy POST
    assert deploy_calls.get("perception", 0) == 0, (
        f"perception should NOT be redeployed, got {deploy_calls.get('perception', 0)}"
    )
    # B (actucore) receives exactly ONE deploy POST
    assert deploy_calls.get("actucore", 0) == 1, (
        f"actucore should be deployed once, got {deploy_calls.get('actucore', 0)}"
    )
    # A remains recorded in deployments
    final_state = write_log[-1][1] if write_log else current_state
    all_cids = []
    for dep in final_state.get("deployments", []):
        all_cids.extend(dep.get("component_ids", []))
    assert comp_a_id in all_cids, "Component A must remain in deployments"
    assert all_cids.count(comp_a_id) == 1
    assert all_cids.count(comp_b_id) == 1
    # Final state
    assert final_state["status"] == "testing"
    assert final_state["command"]["phase"] == "completed"
    _validate_hidden_state(final_state)


LEGACY_DIGEST = "registry.example/repo@sha256:" + "a" * 64
TAG_A = "bj-warehouse.tencentcloudcr.com/phanthy-motus/perception:release.260922.4707deb-jetson-jp5.11"
TAG_B = "bj-warehouse.tencentcloudcr.com/phanthy-motus/perception:release.260923.4707deb-jetson-jp5.11"


def _fake_config():
    from ..config import REVIEW_AGENT_GITHUB_LOGIN, REVIEW_AGENT_GITHUB_USER_ID
    from ..tests.conftest import make_config
    return make_config(
        review_comment_author_id=REVIEW_AGENT_GITHUB_USER_ID,
        review_comment_author_login=REVIEW_AGENT_GITHUB_LOGIN,
        agent_core_tokens={"m1": "test-token"},
    )


def _make_policy():
    policy = MagicMock()
    policy.get_machines.return_value = [
        MagicMock(
            alias="m1", node_host="127.0.0.1", node_id="n1",
            owners=["alice"],
            targets=["perception", "actucore"],
            variants=["5.11"],
            platforms=["linux/arm64"],
            driver_paths=[],
            node_host_public=False,
            is_production=True,
        )
    ]
    policy.get_machine_by_node_id.return_value = policy.get_machines.return_value[0]
    policy.check_machine_targets_component.return_value = None
    policy.check_variant_compatible.return_value = None
    policy.check_driver_path_compatible.return_value = None
    policy.get_machine_groups_for_components.return_value = []
    return policy


def _make_controller(fake_proxy, policy, fake_github):
    from ..config import REVIEW_AGENT_GITHUB_LOGIN, REVIEW_AGENT_GITHUB_USER_ID
    from ..service import DeployController
    config = _fake_config()
    config.review_comment_author_id = REVIEW_AGENT_GITHUB_USER_ID
    config.review_comment_author_login = REVIEW_AGENT_GITHUB_LOGIN
    config.agent_core_tokens = {"m1": "test-token"}
    # AsyncMock proxies return coroutines for every attribute; production
    # find_trusted_lifecycle_comment must resolve to None so the controller
    # falls through to its normal history scan, and is_bot_comment is a SYNC
    # method that must stay MagicMock-shaped to avoid un-awaited coroutines.
    fake_proxy.find_trusted_lifecycle_comment = AsyncMock(return_value=None)
    fake_proxy.is_bot_comment = MagicMock(return_value=False)
    controller = DeployController(config, fake_proxy, policy, fake_github)
    return controller


# ── Legacy digest migration regression tests (no Registry) ──────────


@pytest.mark.asyncio
async def test_legacy_digest_undeployed_component_migrates_to_tag_preserving_component_id(config, monkeypatch):
    """TEST 1: Old component with digest image_ref, no deployment, same semantic key
    -> migrate to tag, keep component_id. ZERO Registry calls."""
    from unittest.mock import AsyncMock, MagicMock
    from ..review_comment_parser import ReviewCommentEvidence

    fake_proxy = AsyncMock()
    fake_proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}})
    fake_proxy.comment_identity = AsyncMock(return_value=("test_author", "test_author"))
    fake_proxy.read_hidden_state = AsyncMock(return_value=None)

    fake_github = AsyncMock()
    fake_github.get_issue_comments = AsyncMock(return_value=[])
    fake_github.resolve_commit_sha = AsyncMock(return_value="a" * 40)

    policy = _make_policy()

    controller = _make_controller(fake_proxy, policy, fake_github)

    # Old state: undeployed, legacy digest, uncertain
    old_cid = "legacy-cid"
    old_state = {
        "version": 1, "head_sha": "a" * 40, "status": "deploy-requested",
        "review_evidence": {
            "build_comment_id": 1, "build_comment_updated_at": "2025-01-01T00:00:00Z",
            "commit_prefix": "a" * 7, "resolved_head_sha": "a" * 40,
            "test_comment_id": 2, "test_comment_updated_at": "2025-01-01T00:00:01Z",
            "code_review_comment_id": 3, "code_review_comment_updated_at": "2025-01-01T00:00:02Z",
            "review_author_id": "7950763",
        },
        "components": [{
            "component_id": old_cid, "target": "perception", "driver_path": "",
            "variant": "5.11", "review_image_tag": TAG_A,
            "image_ref": LEGACY_DIGEST, "resolved_platform": "linux/arm64",
        }],
        "deployments": [],
        "approve_attempts": [], "approve_attempts_total": 0,
        "approve_attempts_truncated": False, "case_results": {}, "test_result": "",
        "cos": {"object_key": "", "sha256": "", "size": 0},
        "command": {"comment_id": 17, "kind": "approve_deploy", "phase": "uncertain",
                    "args": {"machine": "m1"}},
        "last_processed_comment_id": 17,
    }

    # Set up comment with hidden state
    # Patch extract_review_evidence at the service module level to return valid evidence
    import agents.deploy_approval.service as svc_mod
    fake_evidence = ReviewCommentEvidence(
        head_sha="a" * 40, commit_prefix="a" * 7, review_author_id="7950763",
        build_comment_id=1, build_comment_updated_at="2025-01-01T00:00:00Z",
        test_comment_id=2, test_comment_updated_at="2025-01-01T00:00:01Z",
        code_review_comment_id=3, code_review_comment_updated_at="2025-01-01T00:00:02Z",
        builds=[MagicMock(target="perception", success=True, deployable=True,
                          image_tag=TAG_A, driver_path="", variant="5.11")],
    )
    monkeypatch.setattr(svc_mod, "extract_review_evidence", MagicMock(return_value=fake_evidence))

    # Directly call _refresh_uncertain_state
    import copy
    state_copy = copy.deepcopy(old_state)
    from ..github_state_proxy import _validate_hidden_state as _validate_hidden_state_fn
    _validate_hidden_state_fn(state_copy)
    result = await controller._refresh_uncertain_state("4paradigm/phanthymotus", 1, state_copy)

    assert result == "deploy-requested"

    # Verify written state
    write_call = fake_proxy.write_hidden_state.call_args
    assert write_call is not None, "write_hidden_state must have been called"
    written_state = write_call[0][3] if len(write_call[0]) > 3 else write_call[1].get("state")
    assert written_state is not None

    # component_id is on each component, not on state
    comp = written_state["components"][0]
    assert comp["component_id"] == old_cid, f"component_id should be {old_cid}, got {comp['component_id']}"
    assert comp["review_image_tag"] == TAG_A
    assert comp["image_ref"] == TAG_A
    assert comp["resolved_platform"] == "linux/arm64"
    assert "runtime_id" not in comp, "runtime_id must not be present for undeployed component"
    assert written_state["deployments"] == []

    # Verify ZERO registry calls (no registry mock was set up, so any call would fail)
    # If the code tried to call registry.resolve, it would raise AttributeError



@pytest.mark.asyncio
async def test_legacy_digest_deployed_component_preserves_deployment_and_historical_digest(config, monkeypatch):
    """TEST 2: Old deployed component with legacy digest preserves deployment and historical data."""
    from unittest.mock import AsyncMock, MagicMock

    fake_proxy = AsyncMock()
    fake_proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}})
    fake_proxy.comment_identity = AsyncMock(return_value=("test_author", "test_author"))
    fake_proxy.read_hidden_state = AsyncMock(return_value=None)

    fake_github = AsyncMock()
    fake_github.get_issue_comments = AsyncMock(return_value=[])
    fake_github.resolve_commit_sha = AsyncMock(return_value="a" * 40)

    policy = _make_policy()
    controller = _make_controller(fake_proxy, policy, fake_github)

    old_cid = "legacy-deployed-cid"
    old_state = {
        "version": 1, "head_sha": "a" * 40, "status": "deploy-requested",
        "review_evidence": {
            "build_comment_id": 1, "build_comment_updated_at": "2025-01-01T00:00:00Z",
            "commit_prefix": "a" * 7, "resolved_head_sha": "a" * 40,
            "test_comment_id": 2, "test_comment_updated_at": "2025-01-01T00:00:01Z",
            "code_review_comment_id": 3, "code_review_comment_updated_at": "2025-01-01T00:00:02Z",
            "review_author_id": "7950763",
        },
        "components": [{
            "component_id": old_cid, "target": "perception", "driver_path": "",
            "variant": "5.11", "review_image_tag": TAG_A,
            "image_ref": LEGACY_DIGEST, "resolved_platform": "linux/arm64",
            "runtime_id": "perception",
        }],
        "deployments": [{
            "machine": "m1", "component_ids": [old_cid], "phase": "deployed"
        }],
        "approve_attempts": [{"comment_id": 10, "actor": "alice", "machine": "m1",
                              "preflight": [], "outcome": "uncertain", "health": []}],
        "approve_attempts_total": 1,
        "approve_attempts_truncated": False,
        "case_results": {"legacy-deployed-cid": "pass"},
        "test_result": "pass",
        "cos": {"object_key": "evidence/key", "sha256": "b" * 64, "size": 1024},
        "command": {"comment_id": 17, "kind": "approve_deploy", "phase": "uncertain",
                    "args": {"machine": "m1"}},
        "last_processed_comment_id": 17,
    }

    # Patch extract_review_evidence at the service module level to return valid evidence
    import agents.deploy_approval.service as svc_mod
    from ..review_comment_parser import ReviewCommentEvidence
    fake_evidence = ReviewCommentEvidence(
        head_sha="a" * 40, commit_prefix="a" * 7, review_author_id="7950763",
        build_comment_id=1, build_comment_updated_at="2025-01-01T00:00:00Z",
        test_comment_id=2, test_comment_updated_at="2025-01-01T00:00:01Z",
        code_review_comment_id=3, code_review_comment_updated_at="2025-01-01T00:00:02Z",
        builds=[MagicMock(target="perception", success=True, deployable=True,
                          image_tag=TAG_A, driver_path="", variant="5.11")],
    )
    monkeypatch.setattr(svc_mod, "extract_review_evidence", MagicMock(return_value=fake_evidence))

    import copy
    state_copy = copy.deepcopy(old_state)
    from ..github_state_proxy import _validate_hidden_state as _validate_hidden_state_fn
    _validate_hidden_state_fn(state_copy)
    result = await controller._refresh_uncertain_state("4paradigm/phanthymotus", 1, state_copy)

    assert result == "deploy-requested"

    write_call = fake_proxy.write_hidden_state.call_args
    written_state = write_call[0][3] if len(write_call[0]) > 3 else write_call[1].get("state")

    comp = written_state["components"][0]
    assert comp["component_id"] == old_cid
    assert comp["review_image_tag"] == TAG_A
    assert comp["image_ref"] == LEGACY_DIGEST  # Historical digest preserved for deployed
    assert comp["runtime_id"] == "perception"

    assert written_state["deployments"] == [{"machine": "m1", "component_ids": [old_cid], "phase": "deployed"}]
    assert written_state["approve_attempts"] == old_state["approve_attempts"]
    assert written_state["approve_attempts_total"] == 1

    assert written_state["case_results"] == {"legacy-deployed-cid": "pass"}
    assert written_state["test_result"] == "pass"
    assert written_state["cos"] == {"object_key": "evidence/key", "sha256": "b" * 64, "size": 1024}


@pytest.mark.asyncio
async def test_legacy_deployed_component_missing_runtime_id_fails_closed(config, monkeypatch):
    """TEST: Deployed component without runtime_id must fail closed — not continue as migration."""
    from unittest.mock import AsyncMock

    fake_proxy = AsyncMock()
    fake_proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}})
    fake_proxy.comment_identity = AsyncMock(return_value=("test_author", "test_author"))
    fake_proxy.read_hidden_state = AsyncMock(return_value=None)

    fake_github = AsyncMock()
    fake_github.get_issue_comments = AsyncMock(return_value=[])
    fake_github.resolve_commit_sha = AsyncMock(return_value="a" * 40)

    policy = _make_policy()
    controller = _make_controller(fake_proxy, policy, fake_github)

    old_cid = "legacy-deployed-no-runtime"
    old_state = {
        "version": 1, "head_sha": "a" * 40, "status": "deploy-requested",
        "review_evidence": {
            "build_comment_id": 1, "build_comment_updated_at": "2025-01-01T00:00:00Z",
            "commit_prefix": "a" * 7, "resolved_head_sha": "a" * 40,
            "test_comment_id": 2, "test_comment_updated_at": "2025-01-01T00:00:01Z",
            "code_review_comment_id": 3, "code_review_comment_updated_at": "2025-01-01T00:00:02Z",
            "review_author_id": "7950763",
        },
        "components": [{
            "component_id": old_cid, "target": "perception", "driver_path": "",
            "variant": "5.11", "review_image_tag": TAG_A,
            "image_ref": LEGACY_DIGEST, "resolved_platform": "linux/arm64",
            "runtime_id": "",  # Missing runtime_id for deployed component!
        }],
        "deployments": [{
            "machine": "m1", "component_ids": [old_cid], "phase": "deployed"
        }],
        "approve_attempts": [], "approve_attempts_total": 0,
        "approve_attempts_truncated": False, "case_results": {}, "test_result": "",
        "cos": {"object_key": "", "sha256": "", "size": 0},
        "command": {"comment_id": 17, "kind": "approve_deploy", "phase": "uncertain",
                    "args": {"machine": "m1"}},
        "last_processed_comment_id": 17,
    }

    # Patch extract_review_evidence
    import agents.deploy_approval.service as svc_mod
    from ..review_comment_parser import ReviewCommentEvidence
    fake_evidence_rt = ReviewCommentEvidence(
        head_sha="a" * 40, commit_prefix="a" * 7, review_author_id="7950763",
        build_comment_id=1, build_comment_updated_at="2025-01-01T00:00:00Z",
        test_comment_id=2, test_comment_updated_at="2025-01-01T00:00:01Z",
        code_review_comment_id=3, code_review_comment_updated_at="2025-01-01T00:00:02Z",
        builds=[MagicMock(target="perception", success=True, deployable=True,
                          image_tag=TAG_A, driver_path="", variant="5.11")],
    )
    monkeypatch.setattr(svc_mod, "extract_review_evidence", MagicMock(return_value=fake_evidence_rt))

    import copy
    state_copy = copy.deepcopy(old_state)
    result = await controller._refresh_uncertain_state("4paradigm/phanthymotus", 1, state_copy)

    # Should reset to fresh snapshot (semantic_changed=True, evidence_changed=True)
    assert result == "deploy-requested"

    write_call = fake_proxy.write_hidden_state.call_args
    written_state = write_call[0][3] if len(write_call[0]) > 3 else write_call[1].get("state")

    # Because runtime_id was missing for deployed component, it triggers reset to fresh
    # Fresh components have a NEW component_id (from TAG_A), deployments should be cleared
    assert written_state["deployments"] == []
    # gate_note must NOT say "Previously confirmed deployments were preserved."
    write_call = fake_proxy.write_hidden_state.call_args
    markdown_arg = write_call[0][2] if len(write_call[0]) > 2 else ""
    assert "Previously confirmed deployments were preserved." not in markdown_arg
    # The component should have a fresh component_id (from TAG_A), not the old one
    comp = written_state["components"][0]
    # Fresh component_id comes from sha256(target|driver_path|variant|tag)
    import hashlib
    expected_cid = hashlib.sha256(f"perception||5.11|{TAG_A}".encode()).hexdigest()[:16]
    assert comp["component_id"] == expected_cid
    assert "runtime_id" not in comp, "runtime_id must not be present in fresh snapshot"



@pytest.mark.asyncio
async def test_real_review_tag_change_resets_snapshot(config, monkeypatch):
    """TEST 3: Real tag change -> semantic_changed=True, reset everything."""
    from unittest.mock import AsyncMock

    fake_proxy = AsyncMock()
    fake_proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}})
    fake_proxy.comment_identity = AsyncMock(return_value=("test_author", "test_author"))
    fake_proxy.read_hidden_state = AsyncMock(return_value=None)

    fake_github = AsyncMock()
    fake_github.get_issue_comments = AsyncMock(return_value=[])
    fake_github.resolve_commit_sha = AsyncMock(return_value="a" * 40)

    policy = _make_policy()
    controller = _make_controller(fake_proxy, policy, fake_github)

    old_cid_a = "component-tag-a"
    old_state = {
        "version": 1, "head_sha": "a" * 40, "status": "deploy-requested",
        "review_evidence": {
            "build_comment_id": 1, "build_comment_updated_at": "2025-01-01T00:00:00Z",
            "commit_prefix": "a" * 7, "resolved_head_sha": "a" * 40,
            "test_comment_id": 2, "test_comment_updated_at": "2025-01-01T00:00:01Z",
            "code_review_comment_id": 3, "code_review_comment_updated_at": "2025-01-01T00:00:02Z",
            "review_author_id": "7950763",
        },
        "components": [{
            "component_id": old_cid_a, "target": "perception", "driver_path": "",
            "variant": "5.11", "review_image_tag": TAG_A,
            "image_ref": TAG_A, "resolved_platform": "linux/arm64",
            "runtime_id": "perception",
        }],
        "deployments": [{"machine": "m1", "component_ids": [old_cid_a], "phase": "deployed"}],
        "approve_attempts": [{"comment_id": 10, "actor": "alice", "machine": "m1",
                              "preflight": [], "outcome": "uncertain", "health": []}],
        "approve_attempts_total": 1,
        "approve_attempts_truncated": False,
        "case_results": {"component-tag-a": "pass"},
        "test_result": "pass",
        "cos": {"object_key": "key", "sha256": "b" * 64, "size": 100},
        "command": {"comment_id": 17, "kind": "approve_deploy", "phase": "uncertain",
                    "args": {"machine": "m1"}},
        "last_processed_comment_id": 17,
    }

    # Patch extract_review_evidence with TAG_B (different from old TAG_A)
    import agents.deploy_approval.service as svc_mod
    from ..review_comment_parser import ReviewCommentEvidence
    fake_evidence_b = ReviewCommentEvidence(
        head_sha="a" * 40, commit_prefix="a" * 7, review_author_id="7950763",
        build_comment_id=1, build_comment_updated_at="2025-01-01T00:00:00Z",
        test_comment_id=2, test_comment_updated_at="2025-01-01T00:00:01Z",
        code_review_comment_id=3, code_review_comment_updated_at="2025-01-01T00:00:02Z",
        builds=[MagicMock(target="perception", success=True, deployable=True,
                          image_tag=TAG_B, driver_path="", variant="5.11")],
    )
    monkeypatch.setattr(svc_mod, "extract_review_evidence", MagicMock(return_value=fake_evidence_b))

    import copy
    state_copy = copy.deepcopy(old_state)
    result = await controller._refresh_uncertain_state("4paradigm/phanthymotus", 1, state_copy)

    assert result == "deploy-requested"

    write_call = fake_proxy.write_hidden_state.call_args
    written_state = write_call[0][3] if len(write_call[0]) > 3 else write_call[1].get("state")

    # semantic_changed=True because TAG_B != TAG_A
    assert written_state["deployments"] == []
    assert written_state["approve_attempts"] == []
    assert written_state["case_results"] == {}
    assert written_state["test_result"] == ""
    assert written_state["cos"] == {"object_key": "", "sha256": "", "size": 0}

    # New component_id from TAG_B
    import hashlib
    expected_cid = hashlib.sha256(f"perception||5.11|{TAG_B}".encode()).hexdigest()[:16]
    assert written_state["components"][0]["component_id"] == expected_cid
    assert written_state["components"][0]["review_image_tag"] == TAG_B
    assert written_state["components"][0]["image_ref"] == TAG_B



@pytest.mark.asyncio
async def test_removed_component_resets_snapshot(config, monkeypatch):
    """TEST 4: Removed component -> semantic_changed=True, reset everything."""
    from unittest.mock import AsyncMock

    fake_proxy = AsyncMock()
    fake_proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}})
    fake_proxy.comment_identity = AsyncMock(return_value=("test_author", "test_author"))
    fake_proxy.read_hidden_state = AsyncMock(return_value=None)

    fake_github = AsyncMock()
    fake_github.get_issue_comments = AsyncMock(return_value=[])
    fake_github.resolve_commit_sha = AsyncMock(return_value="a" * 40)

    policy = _make_policy()
    controller = _make_controller(fake_proxy, policy, fake_github)

    import hashlib
    cid_a = hashlib.sha256(f"perception||5.11|{TAG_A}".encode()).hexdigest()[:16]
    cid_b = hashlib.sha256(f"actucore||5.11|{TAG_A}".encode()).hexdigest()[:16]

    old_state = {
        "version": 1, "head_sha": "a" * 40, "status": "deploy-requested",
        "review_evidence": {
            "build_comment_id": 1, "build_comment_updated_at": "2025-01-01T00:00:00Z",
            "commit_prefix": "a" * 7, "resolved_head_sha": "a" * 40,
            "test_comment_id": 2, "test_comment_updated_at": "2025-01-01T00:00:01Z",
            "code_review_comment_id": 3, "code_review_comment_updated_at": "2025-01-01T00:00:02Z",
            "review_author_id": "7950763",
        },
        "components": [
            {"component_id": cid_a, "target": "perception", "driver_path": "",
             "variant": "5.11", "review_image_tag": TAG_A, "image_ref": TAG_A,
             "resolved_platform": "linux/arm64", "runtime_id": "perception"},
            {"component_id": cid_b, "target": "actucore", "driver_path": "",
             "variant": "5.11", "review_image_tag": TAG_A, "image_ref": TAG_A,
             "resolved_platform": "linux/arm64", "runtime_id": "actucore"},
        ],
        "deployments": [
            {"machine": "m1", "component_ids": [cid_a], "phase": "deployed"},
            {"machine": "m1", "component_ids": [cid_b], "phase": "deployed"},
        ],
        "approve_attempts": [], "approve_attempts_total": 0,
        "approve_attempts_truncated": False, "case_results": {}, "test_result": "",
        "cos": {"object_key": "", "sha256": "", "size": 0},
        "command": {"comment_id": 17, "kind": "approve_deploy", "phase": "uncertain",
                    "args": {"machine": "m1"}},
        "last_processed_comment_id": 17,
    }

    # Patch extract_review_evidence with only perception (B removed)
    import agents.deploy_approval.service as svc_mod
    from ..review_comment_parser import ReviewCommentEvidence
    fake_evidence_a = ReviewCommentEvidence(
        head_sha="a" * 40, commit_prefix="a" * 7, review_author_id="7950763",
        build_comment_id=1, build_comment_updated_at="2025-01-01T00:00:00Z",
        test_comment_id=2, test_comment_updated_at="2025-01-01T00:00:01Z",
        code_review_comment_id=3, code_review_comment_updated_at="2025-01-01T00:00:02Z",
        builds=[MagicMock(target="perception", success=True, deployable=True,
                          image_tag=TAG_A, driver_path="", variant="5.11")],
    )
    monkeypatch.setattr(svc_mod, "extract_review_evidence", MagicMock(return_value=fake_evidence_a))

    import copy
    state_copy = copy.deepcopy(old_state)
    result = await controller._refresh_uncertain_state("4paradigm/phanthymotus", 1, state_copy)

    assert result == "deploy-requested"

    write_call = fake_proxy.write_hidden_state.call_args
    written_state = write_call[0][3] if len(write_call[0]) > 3 else write_call[1].get("state")

    # semantic_changed=True because B was removed
    assert written_state["deployments"] == []
    assert written_state["approve_attempts"] == []
    assert written_state["case_results"] == {}
    assert written_state["test_result"] == ""
    assert written_state["cos"] == {"object_key": "", "sha256": "", "size": 0}
    # Only component A remains (fresh)
    assert len(written_state["components"]) == 1
    assert written_state["components"][0]["target"] == "perception"
    assert written_state["components"][0]["component_id"] == cid_a



@pytest.mark.asyncio
async def test_added_component_resets_snapshot(config, monkeypatch):
    """TEST 5: Added component -> semantic_changed=True, reset everything."""
    from unittest.mock import AsyncMock

    fake_proxy = AsyncMock()
    fake_proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}})
    fake_proxy.comment_identity = AsyncMock(return_value=("test_author", "test_author"))
    fake_proxy.read_hidden_state = AsyncMock(return_value=None)

    fake_github = AsyncMock()
    fake_github.get_issue_comments = AsyncMock(return_value=[])
    fake_github.resolve_commit_sha = AsyncMock(return_value="a" * 40)

    policy = _make_policy()
    controller = _make_controller(fake_proxy, policy, fake_github)

    import hashlib
    cid_a = hashlib.sha256(f"perception||5.11|{TAG_A}".encode()).hexdigest()[:16]

    old_state = {
        "version": 1, "head_sha": "a" * 40, "status": "deploy-requested",
        "review_evidence": {
            "build_comment_id": 1, "build_comment_updated_at": "2025-01-01T00:00:00Z",
            "commit_prefix": "a" * 7, "resolved_head_sha": "a" * 40,
            "test_comment_id": 2, "test_comment_updated_at": "2025-01-01T00:00:01Z",
            "code_review_comment_id": 3, "code_review_comment_updated_at": "2025-01-01T00:00:02Z",
            "review_author_id": "7950763",
        },
        "components": [
            {"component_id": cid_a, "target": "perception", "driver_path": "",
             "variant": "5.11", "review_image_tag": TAG_A, "image_ref": TAG_A,
             "resolved_platform": "linux/arm64", "runtime_id": "perception"},
        ],
        "deployments": [
            {"machine": "m1", "component_ids": [cid_a], "phase": "deployed"},
        ],
        "approve_attempts": [], "approve_attempts_total": 0,
        "approve_attempts_truncated": False, "case_results": {}, "test_result": "",
        "cos": {"object_key": "", "sha256": "", "size": 0},
        "command": {"comment_id": 17, "kind": "approve_deploy", "phase": "uncertain",
                    "args": {"machine": "m1"}},
        "last_processed_comment_id": 17,
    }

    # Patch extract_review_evidence with both perception and actucore (B added)
    import agents.deploy_approval.service as svc_mod
    from ..review_comment_parser import ReviewCommentEvidence
    fake_evidence_ab = ReviewCommentEvidence(
        head_sha="a" * 40, commit_prefix="a" * 7, review_author_id="7950763",
        build_comment_id=1, build_comment_updated_at="2025-01-01T00:00:00Z",
        test_comment_id=2, test_comment_updated_at="2025-01-01T00:00:01Z",
        code_review_comment_id=3, code_review_comment_updated_at="2025-01-01T00:00:02Z",
        builds=[
            MagicMock(target="perception", success=True, deployable=True,
                      image_tag=TAG_A, driver_path="", variant="5.11"),
            MagicMock(target="actucore", success=True, deployable=True,
                      image_tag=TAG_A, driver_path="", variant="5.11"),
        ],
    )
    monkeypatch.setattr(svc_mod, "extract_review_evidence", MagicMock(return_value=fake_evidence_ab))

    import copy
    state_copy = copy.deepcopy(old_state)
    result = await controller._refresh_uncertain_state("4paradigm/phanthymotus", 1, state_copy)

    assert result == "deploy-requested"

    write_call = fake_proxy.write_hidden_state.call_args
    written_state = write_call[0][3] if len(write_call[0]) > 3 else write_call[1].get("state")

    # semantic_changed=True because B was added
    assert written_state["deployments"] == []
    assert written_state["approve_attempts"] == []
    assert written_state["case_results"] == {}
    assert written_state["test_result"] == ""
    assert written_state["cos"] == {"object_key": "", "sha256": "", "size": 0}
    # Both A and B are fresh
    assert len(written_state["components"]) == 2



@pytest.mark.asyncio
async def test_duplicate_old_semantic_component_resets_snapshot(config, monkeypatch):
    """TEST: Old state with duplicate semantic components -> semantic_changed=True, reset."""
    import hashlib
    from unittest.mock import AsyncMock, MagicMock
    from ..review_comment_parser import ReviewCommentEvidence

    fake_proxy = AsyncMock()
    fake_proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}})
    fake_proxy.comment_identity = AsyncMock(return_value=("test_author", "test_author"))
    fake_proxy.read_hidden_state = AsyncMock(return_value=None)

    fake_github = AsyncMock()
    fake_github.get_issue_comments = AsyncMock(return_value=[])
    fake_github.resolve_commit_sha = AsyncMock(return_value="a" * 40)

    policy = _make_policy()
    controller = _make_controller(fake_proxy, policy, fake_github)

    cid_a = hashlib.sha256(f"perception||5.11|{TAG_A}".encode()).hexdigest()[:16]

    # Old state has TWO components with same semantic key (perception, TAG_A)
    old_state = {
        "version": 1, "head_sha": "a" * 40, "status": "deploy-requested",
        "review_evidence": {
            "build_comment_id": 1, "build_comment_updated_at": "2025-01-01T00:00:00Z",
            "commit_prefix": "a" * 7, "resolved_head_sha": "a" * 40,
            "test_comment_id": 2, "test_comment_updated_at": "2025-01-01T00:00:01Z",
            "code_review_comment_id": 3, "code_review_comment_updated_at": "2025-01-01T00:00:02Z",
            "review_author_id": "7950763",
        },
        "components": [
            {"component_id": cid_a, "target": "perception", "driver_path": "",
             "variant": "5.11", "review_image_tag": TAG_A, "image_ref": TAG_A,
             "resolved_platform": "linux/arm64"},
            {"component_id": cid_a + "-dup", "target": "perception", "driver_path": "",
             "variant": "5.11", "review_image_tag": TAG_A, "image_ref": TAG_A,
             "resolved_platform": "linux/arm64"},
        ],
        "deployments": [{"machine": "m1", "component_ids": [cid_a], "phase": "deployed"}],
        "approve_attempts": [], "approve_attempts_total": 0,
        "approve_attempts_truncated": False, "case_results": {}, "test_result": "",
        "cos": {"object_key": "", "sha256": "", "size": 0},
        "command": {"comment_id": 17, "kind": "approve_deploy", "phase": "uncertain",
                    "args": {"machine": "m1"}},
        "last_processed_comment_id": 17,
    }

    import agents.deploy_approval.service as svc_mod
    fake_evidence_a = ReviewCommentEvidence(
        head_sha="a" * 40, commit_prefix="a" * 7, review_author_id="7950763",
        build_comment_id=1, build_comment_updated_at="2025-01-01T00:00:00Z",
        test_comment_id=2, test_comment_updated_at="2025-01-01T00:00:01Z",
        code_review_comment_id=3, code_review_comment_updated_at="2025-01-01T00:00:02Z",
        builds=[MagicMock(target="perception", success=True, deployable=True,
                          image_tag=TAG_A, driver_path="", variant="5.11")],
    )
    monkeypatch.setattr(svc_mod, "extract_review_evidence", MagicMock(return_value=fake_evidence_a))

    import copy
    state_copy = copy.deepcopy(old_state)
    result = await controller._refresh_uncertain_state("4paradigm/phanthymotus", 1, state_copy)

    assert result == "deploy-requested"

    write_call = fake_proxy.write_hidden_state.call_args
    written_state = write_call[0][3] if len(write_call[0]) > 3 else write_call[1].get("state")

    # duplicate old semantic keys -> semantic_changed=True -> full reset
    assert written_state["deployments"] == []
    assert written_state["approve_attempts"] == []
    assert written_state["case_results"] == {}
    assert written_state["test_result"] == ""
    assert written_state["cos"] == {"object_key": "", "sha256": "", "size": 0}
    assert len(written_state["components"]) == 1
    assert written_state["components"][0]["target"] == "perception"

@pytest.mark.asyncio
async def test_duplicate_fresh_semantic_component_fails_closed(config, monkeypatch):
    """TEST 6: Fresh evidence with duplicate semantic components -> snapshot returns None."""
    from unittest.mock import AsyncMock, MagicMock

    fake_proxy = AsyncMock()
    fake_proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}})
    fake_proxy.comment_identity = AsyncMock(return_value=("test_author", "test_author"))
    fake_proxy.read_hidden_state = AsyncMock(return_value=None)

    fake_github = AsyncMock()
    fake_github.get_issue_comments = AsyncMock(return_value=[])
    fake_github.resolve_commit_sha = AsyncMock(return_value="a" * 40)

    policy = _make_policy()
    controller = _make_controller(fake_proxy, policy, fake_github)

    # Call the REAL _build_component_snapshot with two identical BuildInfo (Mock with deployable)
    build1 = MagicMock(target="perception", driver_path="", variant="5.11",
                       success=True, deployable=True, image_tag=TAG_A, version="v1")
    build2 = MagicMock(target="perception", driver_path="", variant="5.11",
                       success=True, deployable=True, image_tag=TAG_A, version="v1")

    snapshot = await controller._build_component_snapshot(
        "4paradigm/phanthymotus", 1, "a" * 40, [build1, build2]
    )
    assert snapshot is None, "duplicate semantic key must produce None snapshot"

    # Now also exercise via _refresh_uncertain_state with duplicate evidence builds
    old_state = {
        "version": 1, "head_sha": "a" * 40, "status": "deploy-requested",
        "review_evidence": {
            "build_comment_id": 1, "build_comment_updated_at": "2025-01-01T00:00:00Z",
            "commit_prefix": "a" * 7, "resolved_head_sha": "a" * 40,
            "test_comment_id": 2, "test_comment_updated_at": "2025-01-01T00:00:01Z",
            "code_review_comment_id": 3, "code_review_comment_updated_at": "2025-01-01T00:00:02Z",
            "review_author_id": "7950763",
        },
        "components": [], "deployments": [],
        "approve_attempts": [], "approve_attempts_total": 0,
        "approve_attempts_truncated": False, "case_results": {}, "test_result": "",
        "cos": {"object_key": "", "sha256": "", "size": 0},
        "command": {"comment_id": 17, "kind": "approve_deploy", "phase": "uncertain",
                    "args": {"machine": "m1"}},
        "last_processed_comment_id": 17,
    }

    import agents.deploy_approval.service as svc_mod
    from ..review_comment_parser import ReviewCommentEvidence
    fake_evidence_dup = ReviewCommentEvidence(
        head_sha="a" * 40, commit_prefix="a" * 7, review_author_id="7950763",
        build_comment_id=1, build_comment_updated_at="2025-01-01T00:00:00Z",
        test_comment_id=2, test_comment_updated_at="2025-01-01T00:00:01Z",
        code_review_comment_id=3, code_review_comment_updated_at="2025-01-01T00:00:02Z",
        builds=[
            MagicMock(target="perception", success=True, deployable=True,
                      image_tag=TAG_A, driver_path="", variant="5.11"),
            MagicMock(target="perception", success=True, deployable=True,
                      image_tag=TAG_A, driver_path="", variant="5.11"),
        ],
    )
    monkeypatch.setattr(svc_mod, "extract_review_evidence", MagicMock(return_value=fake_evidence_dup))

    import copy
    state_copy = copy.deepcopy(old_state)
    result = await controller._refresh_uncertain_state("4paradigm/phanthymotus", 1, state_copy)

    # duplicate semantic key -> _build_component_snapshot returns None -> uncertain
    assert result == "uncertain"
    assert old_state["deployments"] == []


@pytest.mark.asyncio
async def test_legacy_migration_zero_registry_http(config, monkeypatch):
    """TEST 7: Legacy migration makes ZERO Registry HTTP calls.

    Proves: legacy digest state -> recovery -> exact Review Agent tag ->
    ZERO Registry dependency.
    """
    from unittest.mock import AsyncMock

    fake_proxy = AsyncMock()
    fake_proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}})
    fake_proxy.comment_identity = AsyncMock(return_value=("test_author", "test_author"))
    fake_proxy.read_hidden_state = AsyncMock(return_value=None)

    fake_github = AsyncMock()
    fake_github.get_issue_comments = AsyncMock(return_value=[])
    fake_github.resolve_commit_sha = AsyncMock(return_value="a" * 40)

    policy = _make_policy()
    controller = _make_controller(fake_proxy, policy, fake_github)

    # CRITICAL: Controller must NOT have a registry attribute at all.
    assert not hasattr(controller, "registry")

    old_cid = "legacy-migration-cid"
    old_state = {
        "version": 1, "head_sha": "a" * 40, "status": "deploy-requested",
        "review_evidence": {
            "build_comment_id": 1, "build_comment_updated_at": "2025-01-01T00:00:00Z",
            "commit_prefix": "a" * 7, "resolved_head_sha": "a" * 40,
            "test_comment_id": 2, "test_comment_updated_at": "2025-01-01T00:00:01Z",
            "code_review_comment_id": 3, "code_review_comment_updated_at": "2025-01-01T00:00:02Z",
            "review_author_id": "7950763",
        },
        "components": [{
            "component_id": old_cid, "target": "perception", "driver_path": "",
            "variant": "5.11", "review_image_tag": TAG_A,
            "image_ref": LEGACY_DIGEST, "resolved_platform": "linux/arm64",
        }],
        "deployments": [], "approve_attempts": [], "approve_attempts_total": 0,
        "approve_attempts_truncated": False, "case_results": {}, "test_result": "",
        "cos": {"object_key": "", "sha256": "", "size": 0},
        "command": {"comment_id": 17, "kind": "approve_deploy", "phase": "uncertain",
                    "args": {"machine": "m1"}},
        "last_processed_comment_id": 17,
    }

    # Patch extract_review_evidence
    import agents.deploy_approval.service as svc_mod
    from ..review_comment_parser import ReviewCommentEvidence
    fake_evidence_zr = ReviewCommentEvidence(
        head_sha="a" * 40, commit_prefix="a" * 7, review_author_id="7950763",
        build_comment_id=1, build_comment_updated_at="2025-01-01T00:00:00Z",
        test_comment_id=2, test_comment_updated_at="2025-01-01T00:00:01Z",
        code_review_comment_id=3, code_review_comment_updated_at="2025-01-01T00:00:02Z",
        builds=[MagicMock(target="perception", success=True, deployable=True,
                          image_tag=TAG_A, driver_path="", variant="5.11")],
    )
    monkeypatch.setattr(svc_mod, "extract_review_evidence", MagicMock(return_value=fake_evidence_zr))

    import copy
    state_copy = copy.deepcopy(old_state)
    result = await controller._refresh_uncertain_state("4paradigm/phanthymotus", 1, state_copy)

    assert result == "deploy-requested"

    # Verify write_hidden_state was actually called
    fake_proxy.write_hidden_state.assert_awaited()

    # Parse the written state from the call
    written_state = fake_proxy.write_hidden_state.call_args.args[3]

    # Verify the migrated component preserves old component_id and gets exact Review Agent tag
    assert written_state["components"][0]["component_id"] == old_cid
    assert written_state["components"][0]["review_image_tag"] == TAG_A
    assert written_state["components"][0]["image_ref"] == TAG_A
    assert written_state["components"][0]["resolved_platform"] == "linux/arm64"

    # Verify all deployment/tracking state was reset
    assert written_state["deployments"] == []


# ── History archive regression tests ────────────────────────────────────────


def _lifecycle_visible(repo: str, pr_number: int, status: str = "deploy-requested") -> str:
    """Build a minimal NEW-format trusted lifecycle visible markdown."""
    from ..comments import BOT_MARKER, lifecycle_marker
    return "\n".join([
        BOT_MARKER,
        lifecycle_marker(repo, pr_number),
        "### Deploy Approval \u2014 Lifecycle",
        "",
        f"**Status:** `{status}`",
        "",
        "### Workflow",
        "",
        "- [x] review",
        "",
    ])


def _lifecycle_body(repo: str, pr_number: int, state: dict, visible: str) -> str:
    from ..github_state_proxy import _build_hidden_state_body
    return _build_hidden_state_body(visible, state)


@pytest.mark.asyncio
async def test_transient_deploying_visible_is_not_archived_as_legacy():
    """A trusted lifecycle whose visible part is the transient 'Deploying...' must
    NOT be treated as a legacy lifecycle: no archive comment, normal write."""
    controller, proxy, policy, github, config = _controller()
    state = _state()

    from ..comments import BOT_MARKER
    transient_visible = BOT_MARKER + "\nDeploying..."
    existing_body = _lifecycle_body("repo", 1, state, transient_visible)
    proxy.find_trusted_lifecycle_comment = AsyncMock(
        return_value={"id": 42, "body": existing_body}
    )
    proxy.get_issue_comments = AsyncMock(return_value=[{"id": 42, "body": existing_body}])
    proxy.write_hidden_state = AsyncMock()

    event = {"event": "Deploy started", "machine": "test-machine",
             "timestamp": comments_mod.beijing_now_str()}

    await controller._write_lifecycle_with_history(
        "repo", 1, state, _lifecycle_visible("repo", 1), event=event,
    )

    # NO legacy archive comment created
    proxy.post_issue_comment.assert_not_called()
    posted_bodies = [c.args[2] for c in proxy.post_issue_comment.call_args_list] if proxy.post_issue_comment.call_args_list else []
    assert all("Legacy lifecycle snapshot preserved" not in b for b in posted_bodies)

    # Normal lifecycle write happened with the new history event
    proxy.write_hidden_state.assert_awaited_once()
    written_visible = proxy.write_hidden_state.call_args.args[2]
    assert "Deploy started" in written_visible


@pytest.mark.asyncio
async def test_true_legacy_lifecycle_is_archived_once():
    """A true old-format Deploy Approval lifecycle is archived exactly once on the
    first meaningful event; a subsequent write must not duplicate the archive."""
    controller, proxy, policy, github, config = _controller()
    state = _state()

    from ..comments import BOT_MARKER
    legacy_visible = "\n".join([
        BOT_MARKER,
        "### Deploy Approval",
        "",
        "**Status:** `deploy-requested`",
        "",
        "Old-format lifecycle content.",
    ])
    legacy_body_with_state = _lifecycle_body("repo", 1, state, legacy_visible)

    # Emulate the real store: write_hidden_state UPDATES the trusted comment body,
    # so a second write reads the migrated new-format visible and must not re-archive.
    current_body = {"body": legacy_body_with_state}

    async def _find_trusted(_repo, _pr):
        return {"id": 42, "body": current_body["body"]}

    async def _write_hidden_state(_repo, _pr, visible, _state):
        from ..github_state_proxy import _build_hidden_state_body
        current_body["body"] = _build_hidden_state_body(visible, _state)
        return {"id": 42}

    proxy.find_trusted_lifecycle_comment = AsyncMock(side_effect=_find_trusted)
    proxy.get_issue_comments = AsyncMock(return_value=[{"id": 42, "body": legacy_body_with_state}])
    proxy.write_hidden_state = AsyncMock(side_effect=_write_hidden_state)
    proxy.post_issue_comment = AsyncMock(return_value={"id": 77})

    event = {"event": "First meaningful event", "machine": "test-machine",
             "timestamp": comments_mod.beijing_now_str()}

    await controller._write_lifecycle_with_history(
        "repo", 1, state, _lifecycle_visible("repo", 1), event=event,
    )

    # First call: ONE legacy archive created
    assert proxy.post_issue_comment.await_count == 1
    archive_body = proxy.post_issue_comment.call_args.args[2]
    assert "Legacy lifecycle snapshot preserved" in archive_body
    assert "History Archive Page 1" in archive_body
    # Hidden business state must not be lost: the archive preserves old visible
    assert "Old-format lifecycle content." in archive_body

    # Second write on the SAME legacy comment must not re-archive the same snapshot
    proxy.write_hidden_state.reset_mock()
    await controller._write_lifecycle_with_history(
        "repo", 1, state, _lifecycle_visible("repo", 1), event=event,
    )
    assert proxy.post_issue_comment.await_count == 1  # still just the one archive


@pytest.mark.asyncio
async def test_visible_history_rollover_preserves_oldest_events():
    """When the visible lifecycle approaches the 48 KiB budget, the preflight archive
    step (run before any unsafe deploy POST) moves oldest events into a History
    Archive page; no events are silently dropped and no #N autolink is produced."""
    repo, pr_number = "repo", 1
    controller, proxy, policy, github, config = _controller()
    state = _state()

    visible = _lifecycle_visible(repo, pr_number)
    posted_bodies: list[str] = []

    async def _post(_repo, _pr, body):
        posted_bodies.append(body)
        return {"id": 90}

    proxy.post_issue_comment = AsyncMock(side_effect=_post)

    # Build a large history: many oversized events so the block exceeds 48 KiB
    from ..github_state_proxy import _build_history_block, _count_visible_bytes
    events = [
        {"event": f"Bulk event {i} " + "x" * 900,
         "machine": "test-machine",
         "timestamp": f"2026-09-24 10:{i:02d}:00"}
        for i in reversed(range(60))
    ]
    history_block = _build_history_block(events)
    primed_visible = visible.rstrip() + "\n\n### History\n\n" + history_block + "\n"
    assert _count_visible_bytes(primed_visible) > 48 * 1024, "precondition: primed body must exceed budget"

    primed_body = _lifecycle_body(repo, pr_number, state, primed_visible)

    # Emulate the real store so the preflight update rewrites the same comment
    current_body = {"body": primed_body}

    async def _find_trusted(_repo, _pr):
        return {"id": 42, "body": current_body["body"]}

    async def _update_comment(_repo, comment_id, body):
        current_body["body"] = body
        return {"id": comment_id}

    proxy.find_trusted_lifecycle_comment = AsyncMock(side_effect=_find_trusted)
    proxy.get_issue_comments = AsyncMock(
        return_value=[{"id": 42, "body": current_body["body"]}]
    )
    proxy.update_comment = AsyncMock(side_effect=_update_comment)

    reserved_event = {"event": "Rollover trigger event", "machine": "test-machine",
                      "timestamp": comments_mod.beijing_now_str()}

    # Preflight runs before the unsafe deploy POST: rollover must happen here
    await controller._preflight_archive_for_event(
        repo, pr_number, visible, reserved_event=reserved_event,
    )

    # An archive comment was created for the oldest events
    assert proxy.post_issue_comment.await_count == 1
    archive_body = posted_bodies[0]
    assert "History Archive Page 1" in archive_body
    # Oldest events are preserved in the archive (no silent loss)
    assert "Bulk event 0" in archive_body

    # Main lifecycle bounded: rewritten visible stays within budget
    rewritten = current_body["body"]
    rewritten_visible = rewritten.split("<!-- deploy-approval-state:v1")[0]
    assert _count_visible_bytes(rewritten_visible) <= 48 * 1024
    # The new event is not silently lost: it stays reserved for the caller's write
    # and the shrunk main history retains the newest kept events
    assert "Bulk event 59" in rewritten_visible


# ── Visible history preservation regression tests ───────────────────────────

from ..github_state_proxy import (
    VISIBLE_HISTORY_END_MARKER,
    VISIBLE_HISTORY_START_MARKER,
    _build_history_block,
    _parse_visible_history,
)


def _visible_history_marker_counts(visible: str) -> tuple[int, int, int]:
    """Return (history_heading_count, start_marker_count, end_marker_count)."""
    return (
        visible.count("### History"),
        visible.count(VISIBLE_HISTORY_START_MARKER),
        visible.count(VISIBLE_HISTORY_END_MARKER),
    )


def _event_titles(visible: str) -> list[str]:
    _, events = _parse_visible_history(visible)
    return [str(e.get("event", "")) for e in events]


def _make_history_state(status: str = "succeeded", test_result: str = "pass") -> dict:
    st = _state()
    st["status"] = status
    st["test_result"] = test_result
    st["command"] = {
        "comment_id": 17, "kind": "record_test", "phase": "completed",
        "args": {"actor": "alice"},
    }
    st["last_processed_comment_id"] = 17
    return st


def _seed_lifecycle_with_history(proxy, repo: str, pr_number: int, state: dict):
    """Install store-emulating mocks so writes update the same comment body."""
    visible = _lifecycle_visible(repo, pr_number, status=state["status"])
    body_holder = {"body": _lifecycle_body(repo, pr_number, state, visible)}

    async def _find_trusted(_repo, _pr):
        return {"id": 42, "body": body_holder["body"]}

    async def _write_hidden_state(_repo, _pr, vis, _state):
        from ..github_state_proxy import _build_hidden_state_body
        body_holder["body"] = _build_hidden_state_body(vis, _state)
        return {"id": 42}

    proxy.find_trusted_lifecycle_comment = AsyncMock(side_effect=_find_trusted)
    proxy.write_hidden_state = AsyncMock(side_effect=_write_hidden_state)
    proxy.get_issue_comments = AsyncMock(return_value=[{"id": 42, "body": body_holder["body"]}])
    return body_holder


def _existing_history_events(count: int = 2) -> list[dict]:
    return [
        {"event": "Deployment requested", "machine": "test-machine", "ip": "127.0.0.1",
         "components": "perception", "result": "",
         "timestamp": "2026-09-30 10:00:00"},
        {"event": "Machine `test-machine` deployed", "machine": "test-machine",
         "ip": "127.0.0.1", "components": "perception", "result": "",
         "timestamp": "2026-09-30 10:05:00"},
    ][:count]


def _prime_history(body_holder: dict, repo: str, pr_number: int, state: dict):
    """Inject an existing visible History block into the stored lifecycle body."""
    from ..github_state_proxy import _build_hidden_state_body
    history_block = _build_history_block(_existing_history_events())
    body = body_holder["body"]
    visible, _, _ = body.partition("<!-- deploy-approval-state:v1")
    new_visible = visible.rstrip() + "\n\n### History\n\n" + history_block + "\n"
    body_holder["body"] = _build_hidden_state_body(new_visible, state)


@pytest.mark.asyncio
async def test_event_none_rewrite_preserves_visible_history():
    """event=None rewrite must carry over ALL existing visible history events,
    add no new event, and keep exactly one History section."""
    controller, proxy, _policy, _github, _config = _controller()
    state = _make_history_state()
    body_holder = _seed_lifecycle_with_history(proxy, "repo", 1, state)
    _prime_history(body_holder, "repo", 1, state)

    fresh_markdown = _lifecycle_visible("repo", 1, status="succeeded")

    await controller._write_lifecycle_with_history(
        "repo", 1, state, fresh_markdown, event=None,
    )

    written_visible = proxy.write_hidden_state.call_args.args[2]
    headings, starts, ends = _visible_history_marker_counts(written_visible)
    assert headings == 1
    assert starts == 1
    assert ends == 1
    titles = _event_titles(written_visible)
    assert "Deployment requested" in titles
    assert "Machine `test-machine` deployed" in titles
    # No new event was fabricated by the event=None rewrite
    assert len(titles) == 2


@pytest.mark.asyncio
async def test_terminal_cos_metadata_rebind_preserves_visible_history():
    """COS metadata rebind must update state.cos while keeping the terminal
    History (Test recorded) intact and emitting no new lifecycle event."""
    controller, proxy, _policy, _github, _config = _controller()
    state = _make_history_state()
    body_holder = _seed_lifecycle_with_history(proxy, "repo", 1, state)
    _prime_history(body_holder, "repo", 1, state)

    # Simulate the terminal record_test write: Test recorded event added
    terminal_md = comments_mod.succeeded_comment("repo", 1, "a" * 40)
    recorded_event = {
        "event": "Test recorded",
        "lifecycle": "`testing` → `succeeded`",
        "result": "pass",
        "timestamp": comments_mod.beijing_now_str(),
    }
    await controller._write_lifecycle_with_history(
        "repo", 1, state, terminal_md, event=recorded_event,
    )
    assert proxy.write_hidden_state.await_count == 1
    first_write = proxy.write_hidden_state.call_args.args[2]
    assert _event_titles(first_write).count("Test recorded") == 1

    proxy.write_hidden_state.reset_mock()
    fresh_state = _make_history_state()
    fresh_state["head_sha"] = "a" * 40

    async def _read_state(_repo, _pr):
        return dict(fresh_state)

    proxy.read_hidden_state = AsyncMock(side_effect=_read_state)

    rebind_md = comments_mod.succeeded_comment(
        "repo", 1, "a" * 40,
        cos_object_key="phanthymotus_pr/phanthymotus/2026-09/pr-1/evidence.log.gz",
        cos_bundle_sha256="ab" * 32,
        cos_bundle_size=1024,
    )
    rebound = await controller._rebind_terminal_cos_if_current(
        "repo", 1,
        expected_head="a" * 40,
        expected_terminal_status="succeeded",
        expected_comment_id=17,
        expected_command_kind="record_test",
        expected_test_result="pass",
        cos_metadata={"object_key": "phanthymotus_pr/phanthymotus/2026-09/pr-1/evidence.log.gz",
                      "sha256": "ab" * 32, "size": 1024},
        markdown=rebind_md,
    )
    assert rebound is True
    assert proxy.write_hidden_state.await_count == 1

    # state.cos updated correctly
    written_state = proxy.write_hidden_state.call_args.args[3]
    assert written_state["cos"]["object_key"] == \
        "phanthymotus_pr/phanthymotus/2026-09/pr-1/evidence.log.gz"
    assert written_state["cos"]["size"] == 1024

    # Terminal History intact; no new event; exactly one History section
    written_visible = proxy.write_hidden_state.call_args.args[2]
    headings, starts, ends = _visible_history_marker_counts(written_visible)
    assert (headings, starts, ends) == (1, 1, 1)
    titles = _event_titles(written_visible)
    assert titles.count("Test recorded") == 1
    assert len(titles) == 3  # 2 pre-existing + Test recorded, nothing new


@pytest.mark.asyncio
async def test_terminal_cos_presigned_url_rebind_preserves_visible_history():
    """Full record_test two-phase terminal flow: terminal write → COS metadata
    rebind → presigned URL rebind. Final visible keeps the COS download block,
    the full existing History, and exactly one Test recorded event."""
    controller, proxy, _policy, _github, _config = _controller()
    state = _make_history_state()
    body_holder = _seed_lifecycle_with_history(proxy, "repo", 1, state)
    _prime_history(body_holder, "repo", 1, state)

    object_key = "phanthymotus_pr/phanthymotus/2026-09/pr-1/evidence-" + "a" * 40 + ".log.gz"

    # Phase 0: terminal write with Test recorded event
    terminal_md = comments_mod.succeeded_comment("repo", 1, "a" * 40)
    recorded_event = {
        "event": "Test recorded",
        "lifecycle": "`testing` → `succeeded`",
        "result": "pass",
        "timestamp": comments_mod.beijing_now_str(),
    }
    await controller._write_lifecycle_with_history(
        "repo", 1, state, terminal_md, event=recorded_event,
    )

    proxy.write_hidden_state.reset_mock()
    fresh_state = _make_history_state()

    async def _read_state(_repo, _pr):
        return dict(fresh_state)

    proxy.read_hidden_state = AsyncMock(side_effect=_read_state)

    cos_metadata = {"object_key": object_key, "sha256": "cd" * 32, "size": 2048}

    # Phase 1: COS metadata rebind
    md_no_url = comments_mod.succeeded_comment(
        "repo", 1, "a" * 40,
        cos_object_key=object_key, cos_bundle_sha256="cd" * 32, cos_bundle_size=2048,
    )
    ok1 = await controller._rebind_terminal_cos_if_current(
        "repo", 1,
        expected_head="a" * 40, expected_terminal_status="succeeded",
        expected_comment_id=17, expected_command_kind="record_test",
        expected_test_result="pass", cos_metadata=cos_metadata, markdown=md_no_url,
    )
    assert ok1 is True

    # Phase 2: presigned URL rebind
    md_with_url = comments_mod.succeeded_comment(
        "repo", 1, "a" * 40,
        cos_object_key=object_key, cos_bundle_sha256="cd" * 32, cos_bundle_size=2048,
        cos_download_url="https://bucket.cos.ap-beijing.myqcloud.com/signed?token=x",
    )
    ok2 = await controller._rebind_terminal_cos_if_current(
        "repo", 1,
        expected_head="a" * 40, expected_terminal_status="succeeded",
        expected_comment_id=17, expected_command_kind="record_test",
        expected_test_result="pass", cos_metadata=cos_metadata, markdown=md_with_url,
    )
    assert ok2 is True
    assert proxy.write_hidden_state.await_count == 2

    final_visible = proxy.write_hidden_state.call_args.args[2]
    # COS evidence block present with correct key/sha/size rendering
    assert "Download COS evidence" in final_visible
    assert object_key in final_visible
    assert "@sha256:cdcdcdcdcdcd" in final_visible  # sha256[:12] rendered
    assert "2.0 KB" in final_visible

    # History fully preserved across both rebinds
    headings, starts, ends = _visible_history_marker_counts(final_visible)
    assert (headings, starts, ends) == (1, 1, 1)
    titles = _event_titles(final_visible)
    assert titles.count("Test recorded") == 1
    assert "Deployment requested" in titles
    assert "Machine `test-machine` deployed" in titles


@pytest.mark.asyncio
async def test_history_rewrite_does_not_duplicate_events():
    """Repeated event=None rewrites must be idempotent: event count never grows,
    every original event appears exactly once, markers stay unique."""
    controller, proxy, _policy, _github, _config = _controller()
    state = _make_history_state()
    body_holder = _seed_lifecycle_with_history(proxy, "repo", 1, state)
    _prime_history(body_holder, "repo", 1, state)

    fresh_markdown = _lifecycle_visible("repo", 1, status="succeeded")

    for _ in range(2):
        await controller._write_lifecycle_with_history(
            "repo", 1, state, fresh_markdown, event=None,
        )

    written_visible = proxy.write_hidden_state.call_args.args[2]
    headings, starts, ends = _visible_history_marker_counts(written_visible)
    assert (headings, starts, ends) == (1, 1, 1)
    titles = _event_titles(written_visible)
    assert len(titles) == 2
    for expected in ("Deployment requested", "Machine `test-machine` deployed"):
        assert titles.count(expected) == 1


@pytest.mark.asyncio
async def test_history_rewrite_preserves_archive_links():
    """event=None rewrite must keep the trusted archive comment linkage:
    the Archived history block and its History Archive Page link survive,
    without duplication, alongside the main visible History."""
    controller, proxy, _policy, _github, _config = _controller()
    state = _make_history_state()
    body_holder = _seed_lifecycle_with_history(proxy, "repo", 1, state)
    _prime_history(body_holder, "repo", 1, state)

    from ..comments import BOT_MARKER
    from ..github_state_proxy import _history_archive_marker
    archive_body = "\n".join([
        BOT_MARKER,
        _history_archive_marker("repo", 1, 1),
        "### History Archive Page 1",
        "",
        "Archived oldest history events.",
    ])
    proxy.get_issue_comments = AsyncMock(return_value=[
        {"id": 42, "body": body_holder["body"]},
        {"id": 77, "body": archive_body, "html_url":
            "https://github.com/repo/pull/1#issuecomment-77"},
    ])

    fresh_markdown = _lifecycle_visible("repo", 1, status="succeeded")

    await controller._write_lifecycle_with_history(
        "repo", 1, state, fresh_markdown, event=None,
    )

    written_visible = proxy.write_hidden_state.call_args.args[2]
    assert "### Archived history" in written_visible
    assert "History Archive Page 1" in written_visible
    assert written_visible.count("History Archive Page 1") == 1
    # Main history still intact
    headings, starts, ends = _visible_history_marker_counts(written_visible)
    assert (headings, starts, ends) == (1, 1, 1)
    assert len(_event_titles(written_visible)) == 2


@pytest.mark.asyncio
async def test_history_isolated_between_prs():
    """History events, archive links, and lifecycle markers must never leak
    across PRs or repos.

    Uses fully disjoint sentinel event titles with exact membership/equality
    assertions (no substring overlap possible):
      - repo#289   → EVENT_ALPHA_REPO_ONE_289
      - repo#290   → EVENT_BETA_REPO_ONE_290
      - repo2#289  → EVENT_GAMMA_REPO_TWO_289  (different repo, same PR number)
    Each lifecycle also gets its own trusted archive comment with a unique
    html_url; rewrites must keep only the matching archive link per lifecycle.
    """
    controller, proxy, _policy, _github, _config = _controller()

    EVENT_289 = "EVENT_ALPHA_REPO_ONE_289"
    EVENT_290 = "EVENT_BETA_REPO_ONE_290"
    EVENT_R2 = "EVENT_GAMMA_REPO_TWO_289"

    ARCHIVE_URL_289 = "https://example.invalid/archive/alpha-289"
    ARCHIVE_URL_290 = "https://example.invalid/archive/beta-290"
    ARCHIVE_URL_R2 = "https://example.invalid/archive/gamma-repo2-289"

    from ..comments import BOT_MARKER, lifecycle_marker
    from ..github_state_proxy import (
        _build_hidden_state_body,
        _history_archive_marker,
    )

    def _make_spec(repo: str, pr: int, event_title: str):
        """Seed a lifecycle primed with exactly one unique sentinel event."""
        state = _make_history_state()
        body_holder = _seed_lifecycle_with_history(proxy, repo, pr, state)
        body = body_holder["body"]
        visible, _, _ = body.partition("<!-- deploy-approval-state:v1")
        history_block = _build_history_block([
            {"event": event_title, "machine": f"m-{repo}-{pr}",
             "ip": "127.0.0.1", "components": "perception", "result": "",
             "timestamp": "2026-09-30 10:00:00"},
        ])
        new_visible = visible.rstrip() + "\n\n### History\n\n" + history_block + "\n"
        body_holder["body"] = _build_hidden_state_body(new_visible, state)
        return state, body_holder

    def _archive_body(repo: str, pr: int) -> str:
        return "\n".join([
            BOT_MARKER,
            _history_archive_marker(repo, pr, 1),
            "### History Archive Page 1",
            "",
            "Archived oldest history events.",
        ])

    state_289, holder_289 = _make_spec("repo", 289, EVENT_289)
    state_290, holder_290 = _make_spec("repo", 290, EVENT_290)
    state_r2, holder_r2 = _make_spec("repo2", 289, EVENT_R2)

    # Store emulation keyed by (repo, pr)
    bodies = {
        ("repo", 289): holder_289,
        ("repo", 290): holder_290,
        ("repo2", 289): holder_r2,
    }
    archive_urls = {
        ("repo", 289): ARCHIVE_URL_289,
        ("repo", 290): ARCHIVE_URL_290,
        ("repo2", 289): ARCHIVE_URL_R2,
    }

    async def _find_trusted(repo, pr):
        return {"id": 42, "body": bodies[(repo, pr)]["body"]}

    async def _write_hidden_state(repo, pr, vis, _state):
        bodies[(repo, pr)]["body"] = _build_hidden_state_body(vis, _state)
        return {"id": 42}

    async def _get_comments(repo, pr):
        # Only this repo/pr's lifecycle comment and its own archive comment.
        return [
            {"id": 42, "body": bodies[(repo, pr)]["body"]},
            {"id": 77, "body": _archive_body(repo, pr),
             "html_url": archive_urls[(repo, pr)]},
        ]

    proxy.find_trusted_lifecycle_comment = AsyncMock(side_effect=_find_trusted)
    proxy.write_hidden_state = AsyncMock(side_effect=_write_hidden_state)
    proxy.get_issue_comments = AsyncMock(side_effect=_get_comments)
    # Archive comments are trusted GitHub App comments (sync method).
    proxy.is_bot_comment = MagicMock(return_value=True)

    fresh_289 = _lifecycle_visible("repo", 289, status="succeeded")
    fresh_290 = _lifecycle_visible("repo", 290, status="succeeded")
    fresh_r2 = _lifecycle_visible("repo2", 289, status="succeeded")

    await controller._write_lifecycle_with_history(
        "repo", 289, state_289, fresh_289, event=None)
    await controller._write_lifecycle_with_history(
        "repo", 290, state_290, fresh_290, event=None)
    await controller._write_lifecycle_with_history(
        "repo2", 289, state_r2, fresh_r2, event=None)

    visible_289 = proxy.write_hidden_state.call_args_list[0].args[2]
    visible_290 = proxy.write_hidden_state.call_args_list[1].args[2]
    visible_r2 = proxy.write_hidden_state.call_args_list[2].args[2]

    # Exactly one History section per rewritten lifecycle.
    headings_289, starts_289, ends_289 = _visible_history_marker_counts(visible_289)
    headings_290, starts_290, ends_290 = _visible_history_marker_counts(visible_290)
    headings_r2, starts_r2, ends_r2 = _visible_history_marker_counts(visible_r2)
    assert (headings_289, starts_289, ends_289) == (1, 1, 1)
    assert (headings_290, starts_290, ends_290) == (1, 1, 1)
    assert (headings_r2, starts_r2, ends_r2) == (1, 1, 1)

    titles_289 = _event_titles(visible_289)
    titles_290 = _event_titles(visible_290)
    titles_r2 = _event_titles(visible_r2)

    # Exact event-title equality: each lifecycle carries exactly its own
    # sentinel event — no duplication, no fabrication, no cross-contamination.
    assert titles_289 == [EVENT_289]
    assert titles_290 == [EVENT_290]
    assert titles_r2 == [EVENT_R2]

    # Exact membership: sentinel events never appear in another lifecycle.
    assert EVENT_289 not in titles_290
    assert EVENT_289 not in titles_r2
    assert EVENT_290 not in titles_289
    assert EVENT_290 not in titles_r2
    assert EVENT_R2 not in titles_289
    assert EVENT_R2 not in titles_290

    # Archive link isolation: each visible keeps only its own archive URL.
    assert ARCHIVE_URL_289 in visible_289
    assert ARCHIVE_URL_290 not in visible_289
    assert ARCHIVE_URL_R2 not in visible_289
    assert ARCHIVE_URL_290 in visible_290
    assert ARCHIVE_URL_289 not in visible_290
    assert ARCHIVE_URL_R2 not in visible_290
    assert ARCHIVE_URL_R2 in visible_r2
    assert ARCHIVE_URL_289 not in visible_r2
    assert ARCHIVE_URL_290 not in visible_r2

    # "History Archive Page 1" link appears exactly once per lifecycle.
    assert visible_289.count("History Archive Page 1") == 1
    assert visible_290.count("History Archive Page 1") == 1
    assert visible_r2.count("History Archive Page 1") == 1

    # Lifecycle markers stay bound to their own repo/pr.
    assert lifecycle_marker("repo", 289) in visible_289
    assert lifecycle_marker("repo", 290) not in visible_289
    assert lifecycle_marker("repo2", 289) not in visible_289
    assert lifecycle_marker("repo", 290) in visible_290
    assert lifecycle_marker("repo", 289) not in visible_290
    assert lifecycle_marker("repo2", 289) not in visible_290
    assert lifecycle_marker("repo2", 289) in visible_r2
    assert lifecycle_marker("repo", 289) not in visible_r2
    assert lifecycle_marker("repo", 290) not in visible_r2
