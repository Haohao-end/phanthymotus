"""Final Deploy Approval contract tests."""

from __future__ import annotations

import builtins
import inspect
import json
import sys
import types
from types import SimpleNamespace

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from ..case_runner import CaseRunner
from ..config import Config
from ..cos_client import CosClient
from ..github_state_proxy import GitHubStateProxy
from ..models import ALL_STATUSES, MachineInfo
from ..policy import Policy
from ..review_client import ReviewJobInfo
from ..router_webhook import webhook
from ..service import DeployController
from .conftest import make_config


@pytest.fixture
def config():
    return make_config()


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
        "review_image_tag": "registry/repo:v1",
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
        "status": "testing",
        "review_job_id": "job-1",
        "components": [_component()],
        "deployments": [{"machine": "test-machine", "component_ids": ["comp-001"], "phase": "deployed"}],
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


def _fake_webhook_request(config, proxy, controller, payload, signature):
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


def _fake_cos_sdk(*, signed_url="https://cos.example/signed", put_error=None):
    calls = {"put": [], "signed": []}
    module = types.ModuleType("qcloud_cos")

    class CosConfig:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class CosS3Client:
        def __init__(self, cfg):
            self.cfg = cfg

        def put_object(self, **kwargs):
            calls["put"].append(kwargs)
            if put_error is not None:
                raise put_error

        def get_presigned_url(self, **kwargs):
            calls["signed"].append(kwargs)
            return signed_url

    module.CosConfig = CosConfig
    module.CosS3Client = CosS3Client
    return module, calls


def _deployment(image_ref="registry/repo@sha256:" + "a" * 64, driver_id="perception"):
    return {
        "component_id": "comp-001",
        "target": "perception",
        "variant": "5.11",
        "driver_path": "",
        "node_id": "node-1",
        "node_host": "127.0.0.1",
        "image_ref": image_ref,
        "machine_alias": "test-machine",
        "_core": AsyncMock(),
        "_driver_id": driver_id,
    }


@pytest.mark.asyncio
async def test_proxy_get_comment_passthrough_exists(proxy, mock_github):
    mock_github.get_comment.return_value = {"id": 77, "body": "hi"}

    comment = await proxy.get_comment("repo", 77)

    assert comment["id"] == 77
    mock_github.get_comment.assert_called_once_with("repo", 77)


@pytest.mark.asyncio
async def test_webhook_re_reads_comment_through_proxy(config, proxy, controller, mock_github):
    payload = {
        "action": "created",
        "repository": {"full_name": "4paradigm/phanthymotus"},
        "issue": {"number": 1, "pull_request": {}},
        "comment": {"id": 99},
    }
    request = _fake_webhook_request(config, proxy, controller, payload, "sha256=" + "0" * 64)

    with patch("agents.deploy_approval.router_webhook._verify_signature_impl", return_value=True):
        mock_github.get_comment.return_value = {"id": 99, "body": "/request_deploy"}
        result = await webhook(request)

    mock_github.get_comment.assert_called_once_with("4paradigm/phanthymotus", 99)
    assert result["status"] == "deferred"


@pytest.mark.asyncio
async def test_webhook_recognized_command_returns_deferred(config, proxy, controller, mock_github):
    payload = {
        "action": "created",
        "repository": {"full_name": "4paradigm/phanthymotus"},
        "issue": {"number": 1, "pull_request": {}},
        "comment": {"id": 99},
    }
    request = _fake_webhook_request(config, proxy, controller, payload, "sha256=" + "0" * 64)

    with patch("agents.deploy_approval.router_webhook._verify_signature_impl", return_value=True):
        mock_github.get_comment.return_value = {"id": 99, "body": "/request_deploy"}
        result = await webhook(request)

    assert result == {"status": "deferred", "reason": "processed by GitHubCommandWatcher"}


@pytest.mark.asyncio
async def test_webhook_command_has_zero_controller_dispatch(config, proxy, controller, mock_github):
    payload = {
        "action": "created",
        "repository": {"full_name": "4paradigm/phanthymotus"},
        "issue": {"number": 1, "pull_request": {}},
        "comment": {"id": 99},
    }
    request = _fake_webhook_request(config, proxy, controller, payload, "sha256=" + "0" * 64)
    controller.handle_request_deploy = AsyncMock()
    controller.handle_approve_deploy = AsyncMock()
    controller.handle_record_test = AsyncMock()

    with patch("agents.deploy_approval.router_webhook._verify_signature_impl", return_value=True):
        mock_github.get_comment.return_value = {"id": 99, "body": "/request_deploy"}
        await webhook(request)

    controller.handle_request_deploy.assert_not_called()
    controller.handle_approve_deploy.assert_not_called()
    controller.handle_record_test.assert_not_called()


@pytest.mark.asyncio
async def test_webhook_command_has_zero_hidden_state_write(config, proxy, controller, mock_github):
    payload = {
        "action": "created",
        "repository": {"full_name": "4paradigm/phanthymotus"},
        "issue": {"number": 1, "pull_request": {}},
        "comment": {"id": 99},
    }
    request = _fake_webhook_request(config, proxy, controller, payload, "sha256=" + "0" * 64)
    proxy.write_hidden_state = AsyncMock()

    with patch("agents.deploy_approval.router_webhook._verify_signature_impl", return_value=True):
        mock_github.get_comment.return_value = {"id": 99, "body": "/request_deploy"}
        await webhook(request)

    proxy.write_hidden_state.assert_not_called()


@pytest.mark.asyncio
async def test_case_receives_actual_agent_core_client(controller):
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[
        {"id": "perception", "target": "perception", "mcp_url": "http://mcp/runtime-1"}
    ])
    controller._core_for_node = AsyncMock(return_value=core)
    captured = {}

    runner = MagicMock()
    runner.select_case.return_value = "perception-health-check"

    async def _capture(case_id, deployment):
        captured["case_id"] = case_id
        captured["deployment"] = deployment
        return {"passed": True, "case_id": case_id, "logs": [], "error": ""}

    runner.run_case = AsyncMock(side_effect=_capture)
    controller._get_case_runner = MagicMock(return_value=runner)

    result = await controller._run_automated_case(
        "repo",
        1,
        "a" * 40,
        [_component()],
        [{"machine": "test-machine", "component_ids": ["comp-001"], "phase": "deployed"}],
    )

    assert result == {"comp-001": "pass"}
    assert captured["deployment"]["_core"] is core


@pytest.mark.asyncio
async def test_case_receives_actual_runtime_identifier(controller):
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[
        {"id": "perception", "target": "perception", "mcp_url": "http://mcp/runtime-1"}
    ])
    controller._core_for_node = AsyncMock(return_value=core)
    captured = {}

    runner = MagicMock()
    runner.select_case.return_value = "perception-health-check"

    async def _capture(case_id, deployment):
        captured.update(deployment)
        return {"passed": True, "case_id": case_id, "logs": [], "error": ""}

    runner.run_case = AsyncMock(side_effect=_capture)
    controller._get_case_runner = MagicMock(return_value=runner)

    await controller._run_automated_case(
        "repo",
        1,
        "a" * 40,
        [_component()],
        [{"machine": "test-machine", "component_ids": ["comp-001"], "phase": "deployed"}],
    )

    assert captured["_driver_id"] == "perception"


@pytest.mark.asyncio
async def test_case_uses_exact_component_image_ref(controller):
    image_ref = "registry/repo@sha256:" + "b" * 64
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[
        {"id": "perception", "target": "perception", "mcp_url": "http://mcp/runtime-1"}
    ])
    controller._core_for_node = AsyncMock(return_value=core)
    captured = {}

    runner = MagicMock()
    runner.select_case.return_value = "perception-health-check"

    async def _capture(case_id, deployment):
        captured.update(deployment)
        return {"passed": True, "case_id": case_id, "logs": [], "error": ""}

    runner.run_case = AsyncMock(side_effect=_capture)
    controller._get_case_runner = MagicMock(return_value=runner)

    await controller._run_automated_case(
        "repo",
        1,
        "a" * 40,
        [_component(image_ref=image_ref)],
        [{"machine": "test-machine", "component_ids": ["comp-001"], "phase": "deployed"}],
    )

    assert captured["image_ref"] == image_ref


@pytest.mark.asyncio
async def test_case_missing_runtime_identifier_fails(controller):
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[{"target": "perception", "mcp_url": "http://mcp/runtime-1"}])
    controller._core_for_node = AsyncMock(return_value=core)
    runner = MagicMock()
    runner.select_case.return_value = "perception-health-check"
    runner.run_case = AsyncMock()
    controller._get_case_runner = MagicMock(return_value=runner)

    result = await controller._run_automated_case(
        "repo",
        1,
        "a" * 40,
        [_component(runtime_id="")],
        [{"machine": "test-machine", "component_ids": ["comp-001"], "phase": "deployed"}],
    )

    assert result == {"comp-001": "fail"}
    runner.run_case.assert_not_called()


@pytest.mark.asyncio
async def test_case_missing_machine_mapping_fails(controller):
    core = AsyncMock()
    controller._core_for_node = AsyncMock(return_value=core)
    runner = MagicMock()
    runner.select_case.return_value = "perception-health-check"
    runner.run_case = AsyncMock()
    controller._get_case_runner = MagicMock(return_value=runner)

    result = await controller._run_automated_case(
        "repo",
        1,
        "a" * 40,
        [_component()],
        [{"machine": "missing-machine", "component_ids": ["comp-001"], "phase": "deployed"}],
    )

    assert result == {"comp-001": "fail"}


def _case_runner(config):
    return CaseRunner(config)


@pytest.mark.asyncio
async def test_case_uses_real_agent_core_response_field(config):
    runner = _case_runner(config)
    image_ref = "registry/repo@sha256:" + "a" * 64
    core = AsyncMock()
    core.driver_status = AsyncMock(return_value={"status": "running", "running_image": image_ref})
    core.list_drivers = AsyncMock(return_value=[
        {"id": "perception", "target": "perception", "mcp_url": "http://mcp/runtime-1"}
    ])
    core.list_mcp = AsyncMock(return_value=[{"id": "perception", "url": "http://mcp/runtime-1"}])
    core.mcp_ping = AsyncMock(return_value={"online": True, "tools": []})

    result = await runner.run_case(
        "perception-health-check",
        {
            "component_id": "comp-001",
            "target": "perception",
            "variant": "5.11",
            "driver_path": "",
            "node_id": "node-1",
            "node_host": "127.0.0.1",
            "image_ref": image_ref,
            "machine_alias": "test-machine",
            "_core": core,
            "_driver_id": "perception",
        },
    )

    assert result["passed"] is True
    core.driver_status.assert_called_once_with("perception")


@pytest.mark.asyncio
async def test_case_exact_immutable_image_must_match_runtime(config):
    runner = _case_runner(config)
    image_ref = "registry/repo@sha256:" + "a" * 64
    core = AsyncMock()
    core.driver_status = AsyncMock(return_value={"status": "running", "running_image": image_ref})
    core.list_drivers = AsyncMock(return_value=[
        {"id": "perception", "target": "perception", "mcp_url": "http://mcp/runtime-1"}
    ])
    core.list_mcp = AsyncMock(return_value=[{"id": "perception", "url": "http://mcp/runtime-1"}])
    core.mcp_ping = AsyncMock(return_value={"online": True, "tools": []})

    result = await runner.run_case(
        "perception-health-check",
        {
            "component_id": "comp-001",
            "target": "perception",
            "variant": "5.11",
            "driver_path": "",
            "node_id": "node-1",
            "node_host": "127.0.0.1",
            "image_ref": image_ref,
            "machine_alias": "test-machine",
            "_core": core,
            "_driver_id": "perception",
        },
    )

    assert result["passed"] is True


@pytest.mark.asyncio
async def test_case_empty_runtime_image_fails(config):
    runner = _case_runner(config)
    image_ref = "registry/repo@sha256:" + "a" * 64
    core = AsyncMock()
    core.driver_status = AsyncMock(side_effect=[{"status": "running", "running_image": ""}])
    core.list_drivers = AsyncMock(return_value=[
        {"id": "perception", "target": "perception", "mcp_url": "http://mcp/runtime-1"}
    ])
    core.list_mcp = AsyncMock(return_value=[{"id": "perception", "url": "http://mcp/runtime-1"}])
    core.mcp_ping = AsyncMock(return_value={"online": True, "tools": []})

    result = await runner.run_case(
        "perception-health-check",
        {
            "component_id": "comp-001",
            "target": "perception",
            "variant": "5.11",
            "driver_path": "",
            "node_id": "node-1",
            "node_host": "127.0.0.1",
            "image_ref": image_ref,
            "machine_alias": "test-machine",
            "_core": core,
            "_driver_id": "perception",
        },
    )

    assert result["passed"] is False
    assert "Running image is empty" in result["error"]


@pytest.mark.asyncio
async def test_case_wrong_runtime_image_fails(config):
    runner = _case_runner(config)
    image_ref = "registry/repo@sha256:" + "a" * 64
    core = AsyncMock()
    core.driver_status = AsyncMock(return_value={"status": "running", "running_image": "registry/repo@sha256:" + "b" * 64})
    core.list_drivers = AsyncMock(return_value=[
        {"id": "perception", "target": "perception", "mcp_url": "http://mcp/runtime-1"}
    ])
    core.list_mcp = AsyncMock(return_value=[{"id": "perception", "url": "http://mcp/runtime-1"}])
    core.mcp_ping = AsyncMock(return_value={"online": True, "tools": []})

    result = await runner.run_case(
        "perception-health-check",
        {
            "component_id": "comp-001",
            "target": "perception",
            "variant": "5.11",
            "driver_path": "",
            "node_id": "node-1",
            "node_host": "127.0.0.1",
            "image_ref": image_ref,
            "machine_alias": "test-machine",
            "_core": core,
            "_driver_id": "perception",
        },
    )

    assert result["passed"] is False
    assert "Running image mismatch" in result["error"]


@pytest.mark.asyncio
async def test_case_mcp_lookup_uses_real_agent_core_contract(config):
    runner = _case_runner(config)
    image_ref = "registry/repo@sha256:" + "a" * 64
    core = AsyncMock()
    core.driver_status = AsyncMock(return_value={"status": "running", "running_image": image_ref})
    core.list_drivers = AsyncMock(return_value=[
        {"id": "perception", "target": "perception", "mcp_url": "http://mcp/runtime-1"}
    ])
    core.list_mcp = AsyncMock(return_value=[{"id": "perception", "url": "http://mcp/runtime-1"}])
    core.mcp_ping = AsyncMock(return_value={"online": True, "tools": []})

    result = await runner.run_case(
        "perception-health-check",
        {
            "component_id": "comp-001",
            "target": "perception",
            "variant": "5.11",
            "driver_path": "",
            "node_id": "node-1",
            "node_host": "127.0.0.1",
            "image_ref": image_ref,
            "machine_alias": "test-machine",
            "_core": core,
            "_driver_id": "perception",
        },
    )

    assert result["passed"] is True
    core.list_drivers.assert_called_once()
    core.list_mcp.assert_called_once()
    core.mcp_ping.assert_called_once_with("perception")


def test_cos_production_path_calls_real_sdk_put_object(config):
    config.cos_region = "ap-shanghai"
    config.cos_bucket = "bucket-1"
    config.cos_secret_id = "sid"
    config.cos_secret_key = "skey"
    sdk, calls = _fake_cos_sdk()
    client = CosClient(config)

    with patch.dict(sys.modules, {"qcloud_cos": sdk}):
        import asyncio

        assert asyncio.run(client.upload_evidence_archive("key", b"payload")) is True

    assert calls["put"]
    assert calls["put"][0]["Bucket"] == "bucket-1"


def test_cos_production_path_upload_failure_returns_false(config):
    config.cos_region = "ap-shanghai"
    config.cos_bucket = "bucket-1"
    config.cos_secret_id = "sid"
    config.cos_secret_key = "skey"
    sdk, _ = _fake_cos_sdk(put_error=RuntimeError("boom"))
    client = CosClient(config)

    with patch.dict(sys.modules, {"qcloud_cos": sdk}):
        import asyncio

        assert asyncio.run(client.upload_evidence_archive("key", b"payload")) is False


def test_cos_production_path_missing_sdk_fails_closed(config):
    config.cos_region = "ap-shanghai"
    config.cos_bucket = "bucket-1"
    config.cos_secret_id = "sid"
    config.cos_secret_key = "skey"
    client = CosClient(config)

    orig_import = builtins.__import__

    def _missing_sdk(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "qcloud_cos":
            raise ImportError("missing qcloud_cos")
        return orig_import(name, globals, locals, fromlist, level)

    with patch("builtins.__import__", side_effect=_missing_sdk):
        import asyncio

        assert asyncio.run(client.upload_evidence_archive("key", b"payload")) is False


def test_cos_signed_url_calls_real_sdk(config):
    config.cos_region = "ap-shanghai"
    config.cos_bucket = "bucket-1"
    config.cos_secret_id = "sid"
    config.cos_secret_key = "skey"
    sdk, calls = _fake_cos_sdk(signed_url="https://cos.example/signed")
    client = CosClient(config)

    with patch.dict(sys.modules, {"qcloud_cos": sdk}):
        import asyncio

        assert asyncio.run(client.generate_signed_url("key")) == "https://cos.example/signed"

    assert calls["signed"]
    assert calls["signed"][0]["Key"] == "key"


def test_cos_production_source_contains_no_placeholder_signed_url():
    source = inspect.getsource(CosClient)
    assert "placeholder" not in source


@pytest.mark.asyncio
async def test_cos_metadata_written_only_after_real_upload_success(controller, proxy, mock_github):
    state = _state()
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
    mock_github.get_pr.return_value = {"state": "open", "merged": False, "head": {"sha": "a" * 40}}
    mock_github.collaborator_permission = AsyncMock(return_value="admin")
    controller._upload_evidence = AsyncMock(return_value={"object_key": "key", "sha256": "b" * 64, "size": 12})
    controller.cos.generate_signed_url = AsyncMock(return_value="https://signed")

    await controller.handle_record_test("repo", 1, 101, "pass", "", "owner1", "")

    written_state = proxy.write_hidden_state.call_args_list[-1].args[3]
    assert written_state["cos"]["object_key"] == "key"
    assert written_state["cos"]["sha256"] == "b" * 64

    proxy.write_hidden_state.reset_mock()
    proxy.read_hidden_state = AsyncMock(return_value=_state())
    controller._upload_evidence = AsyncMock(return_value={"object_key": "", "sha256": "", "size": 0})
    await controller.handle_record_test("repo", 1, 102, "pass", "", "owner1", "")

    written_state = proxy.write_hidden_state.call_args_list[-1].args[3]
    assert written_state["cos"]["object_key"] == ""


def _deploy_requested_state(components=None, deployments=None, **overrides):
    component_list = list(components or [_component()])
    state = _state(
        status="deploy-requested",
        review_job_id="job-1",
        components=component_list,
        deployments=list(deployments or []),
        command={"comment_id": 0, "kind": "", "phase": "completed", "args": {}},
    )
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
async def test_review_lookup_does_not_pass_pr_number(controller, proxy, mock_github):
    mock_github.get_comment.return_value = {"id": 100, "user": {"id": 111, "login": "alice"}, "body": "/request_deploy"}
    mock_github.get_pr.return_value = {
        "state": "open",
        "merged": False,
        "head": {"sha": "a" * 40},
        "user": {"id": 111, "login": "alice"},
    }
    proxy.read_hidden_state = AsyncMock(return_value=_state(status="deploy-ready", review_job_id="", components=[]))
    controller.review.list_jobs = AsyncMock(return_value=[
        _review_job("job-1", "a" * 40, [
        {"target": "perception", "driver_path": "", "variant": "5.11", "success": True, "image_tag": "registry.example/repo:tag"},
        ], completed_at="2026-09-01T10:00:00Z"),
    ])
    controller.registry.resolve.return_value = SimpleNamespace(image_ref="registry/repo@sha256:" + "b" * 64, platform="linux/arm64")
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    await controller.handle_request_deploy("repo", 1, 100)

    assert controller.review.list_jobs.call_args.kwargs == {"repo": "repo", "status": "review_done", "limit": 100, "offset": 0}
    assert "pr_number" not in controller.review.list_jobs.call_args.kwargs


@pytest.mark.asyncio
async def test_review_lookup_exact_repo_pr_full_head_latest(controller, proxy, mock_github):
    head_sha = "a" * 40
    mock_github.get_comment.return_value = {"id": 101, "user": {"id": 111, "login": "alice"}, "body": "/request_deploy"}
    mock_github.get_pr.return_value = {
        "state": "open",
        "merged": False,
        "head": {"sha": head_sha},
        "user": {"id": 111, "login": "alice"},
    }
    proxy.read_hidden_state = AsyncMock(return_value=_state(status="deploy-ready", review_job_id="job-new", head_sha=head_sha, components=[]))
    job_new = _review_job("job-new", head_sha, [
        {"target": "perception", "driver_path": "", "variant": "5.11", "success": True, "image_tag": "registry.example/repo:tag-new"},
    ], completed_at="2026-09-01T11:00:00Z")
    controller.review.list_jobs = AsyncMock(return_value=[
        _review_job("job-old", head_sha, [
            {"target": "perception", "driver_path": "", "variant": "5.11", "success": True, "image_tag": "registry.example/repo:tag-old"},
        ], completed_at="2026-09-01T10:00:00Z"),
        job_new,
        _review_job("job-other", "b" * 40, [
            {"target": "perception", "driver_path": "", "variant": "5.11", "success": True, "image_tag": "registry.example/repo:tag-other"},
        ], completed_at="2026-09-01T12:00:00Z"),
    ])
    controller.review.get_job = AsyncMock(return_value=job_new)
    controller.registry.resolve.side_effect = [
        SimpleNamespace(image_ref="registry/repo@sha256:" + "c" * 64, platform="linux/arm64"),
    ]
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    await controller.handle_request_deploy("repo", 1, 101)

    written_state = proxy.write_hidden_state.call_args.args[3]
    assert written_state["review_job_id"] == "job-new"


@pytest.mark.asyncio
async def test_clean_gate_ignores_runtime_status_when_image_empty(controller, proxy, mock_github):
    state = _deploy_requested_state()
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
    mock_github.get_pr.return_value = {"state": "open", "merged": False, "head": {"sha": "a" * 40}}
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[{"id": "perception", "target": "perception", "image": "registry/repo@sha256:" + "a" * 64, "variant": "5.11"}])
    core.driver_status = AsyncMock(side_effect=[{"status": "busy", "running_image": ""}, {"status": "running", "running_image": "registry/repo@sha256:" + "a" * 64}])
    core.deploy_driver = AsyncMock()
    controller._core_for_node = AsyncMock(return_value=core)
    controller._run_automated_case = AsyncMock(return_value={})

    await controller.handle_approve_deploy("repo", 1, 201, "test-machine", "owner1", "1")

    core.deploy_driver.assert_called_once()
    assert proxy.write_hidden_state.call_args.args[3]["status"] == "testing"


@pytest.mark.asyncio
async def test_clean_gate_blocks_occupied_image_even_if_status_looks_clean(controller, proxy, mock_github):
    state = _deploy_requested_state()
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
    mock_github.get_pr.return_value = {"state": "open", "merged": False, "head": {"sha": "a" * 40}}
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[{"id": "perception", "target": "perception", "image": "registry/repo@sha256:" + "a" * 64, "variant": "5.11"}])
    core.driver_status = AsyncMock(return_value={"status": "stopped", "running_image": "old@sha256:" + "b" * 64})
    core.deploy_driver = AsyncMock()
    controller._core_for_node = AsyncMock(return_value=core)

    await controller.handle_approve_deploy("repo", 1, 202, "test-machine", "owner1", "1")

    core.deploy_driver.assert_not_called()
    written_state = proxy.write_hidden_state.call_args.args[3]
    assert written_state["status"] == "deploy-requested"
    assert written_state["command"]["phase"] == "completed"
    assert written_state["last_processed_comment_id"] == 202
    assert "running_image" in proxy.write_hidden_state.call_args.args[2]


@pytest.mark.asyncio
async def test_clean_gate_preflights_all_components_before_any_deploy(controller, proxy, mock_github):
    controller.policy.machines["test-machine"].variants = ["5.11", "6.1"]
    components = [
        _component(component_id="comp-001"),
        _component(component_id="comp-002", variant="alt-variant"),
    ]
    state = _deploy_requested_state(components=components)
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
    mock_github.get_pr.return_value = {"state": "open", "merged": False, "head": {"sha": "a" * 40}}
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[
        {"id": "perception", "target": "perception", "variant": "5.11"},
        {"id": "runtime-2", "target": "perception", "variant": "alt-variant"},
    ])
    # Only comp-001 (variant=5.11) is compatible. comp-002 (alt-variant) is filtered out.
    # Sequential: preflight(i) -> deploy -> health(xN) -> pass
    image_ref = "registry/repo@sha256:" + "a" * 64
    core.driver_status = AsyncMock(side_effect=[
        {"status": "busy", "running_image": ""},  # preflight
        {"status": "running", "running_image": image_ref},  # health pass
    ])
    core.deploy_driver = AsyncMock(return_value={"ok": True})
    controller._core_for_node = AsyncMock(return_value=core)
    controller._run_automated_case = AsyncMock(return_value={})

    await controller.handle_approve_deploy("repo", 1, 203, "test-machine", "owner1", "1")

    # Preflight (1) + health poll (1) = 2 calls
    core.deploy_driver.assert_called_once()


@pytest.mark.asyncio
async def test_new_approve_rechecks_running_image_until_empty(controller, proxy, mock_github):
    state1 = _deploy_requested_state()
    state2 = _deploy_requested_state()
    proxy.read_hidden_state = AsyncMock(side_effect=[state1, state2])
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
    mock_github.get_pr.return_value = {"state": "open", "merged": False, "head": {"sha": "a" * 40}}
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[{"id": "perception", "target": "perception", "image": "registry/repo@sha256:" + "a" * 64, "variant": "5.11"}])
    core.driver_status = AsyncMock(side_effect=[
        {"status": "busy", "running_image": "occupied@sha256:" + "b" * 64},
        {"status": "busy", "running_image": ""},
    ])
    core.deploy_driver = AsyncMock()
    controller._core_for_node = AsyncMock(return_value=core)
    controller._run_automated_case = AsyncMock(return_value={})

    await controller.handle_approve_deploy("repo", 1, 204, "test-machine", "owner1", "1")
    await controller.handle_approve_deploy("repo", 1, 205, "test-machine", "owner1", "1")

    core.deploy_driver.assert_called_once()


@pytest.mark.asyncio
async def test_clean_gate_writes_executing_before_first_deploy_post(controller, proxy, mock_github):
    state = _deploy_requested_state()
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.project_status_label = AsyncMock()
    mock_github.get_pr.return_value = {"state": "open", "merged": False, "head": {"sha": "a" * 40}}
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[{"id": "perception", "target": "perception", "image": "registry/repo@sha256:" + "a" * 64, "variant": "5.11"}])
    core.driver_status = AsyncMock(side_effect=[{"status": "busy", "running_image": ""}, {"status": "running", "running_image": "registry/repo@sha256:" + "c" * 64}])
    events: list[str] = []

    async def _write_hidden_state(*args, **kwargs):
        events.append(("write", args[3]["command"]["phase"]))
        return {"id": 1}

    async def _deploy_driver(*args, **kwargs):
        events.append("deploy")
        return {"ok": True}

    core.deploy_driver = AsyncMock(side_effect=_deploy_driver)
    controller._core_for_node = AsyncMock(return_value=core)
    controller._run_automated_case = AsyncMock(return_value={})
    proxy.write_hidden_state = AsyncMock(side_effect=_write_hidden_state)

    await controller.handle_approve_deploy("repo", 1, 206, "test-machine", "owner1", "1")

    assert events[:2] == [("write", "executing"), "deploy"]


@pytest.mark.asyncio
async def test_occupied_gate_advances_new_comment_cursor(controller, proxy, mock_github):
    state = _deploy_requested_state()
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
    mock_github.get_pr.return_value = {"state": "open", "merged": False, "head": {"sha": "a" * 40}}
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[{"id": "perception", "target": "perception", "image": "registry/repo@sha256:" + "a" * 64, "variant": "5.11"}])
    core.driver_status = AsyncMock(return_value={"status": "stopped", "running_image": "occupied@sha256:" + "b" * 64})
    core.deploy_driver = AsyncMock()
    controller._core_for_node = AsyncMock(return_value=core)

    await controller.handle_approve_deploy("repo", 1, 207, "test-machine", "owner1", "1")

    written_state = proxy.write_hidden_state.call_args.args[3]
    assert written_state["command"]["comment_id"] == 207
    assert written_state["last_processed_comment_id"] == 207


@pytest.mark.asyncio
async def test_restart_executing_advances_cursor_to_command_comment(controller, proxy):
    state = _deploy_requested_state(command={"comment_id": 17, "kind": "approve_deploy", "phase": "executing", "args": {"machine": "test-machine"}})
    state["last_processed_comment_id"] = 3
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
    proxy.get_pr = AsyncMock(return_value={"state": "open", "merged": False, "head": {"sha": "a" * 40}, "user": {"id": 1, "login": "alice"}})

    await controller.reconcile_pr("repo", 1)

    written_state = proxy.write_hidden_state.call_args.args[3]
    assert written_state["command"]["phase"] == "uncertain"
    assert written_state["last_processed_comment_id"] >= 17


@pytest.mark.asyncio
async def test_restart_old_approve_comment_never_replayed(controller, proxy, config, mock_github):
    state_before = _deploy_requested_state(command={"comment_id": 100, "kind": "approve_deploy", "phase": "executing", "args": {"machine": "test-machine"}})
    state_after = _deploy_requested_state(command={"comment_id": 100, "kind": "approve_deploy", "phase": "uncertain", "args": {"machine": "test-machine"}})
    state_after["last_processed_comment_id"] = 100
    proxy.read_hidden_state = AsyncMock(side_effect=[state_before, state_after, state_after])
    mock_github.get_pr.return_value = {"state": "open", "merged": False, "head": {"sha": "a" * 40}}
    controller.review.list_jobs = AsyncMock(return_value=[])
    proxy.get_issue_comments = AsyncMock(return_value=[
        {"id": 100, "body": "/approve_deploy machine=test-machine", "user": {"id": 1, "login": "owner1"}},
        {"id": 101, "body": "/approve_deploy machine=test-machine", "user": {"id": 1, "login": "owner1"}},
    ])
    proxy.is_bot_comment = MagicMock(return_value=False)
    controller.on_command = AsyncMock(return_value=True)

    from ..github_command_watcher import GitHubCommandWatcher

    watcher = GitHubCommandWatcher(config, proxy, controller)

    await watcher._process_pr("repo", 1)

    assert controller.on_command.call_count == 1
    assert controller.on_command.call_args.args[3] == 101


@pytest.mark.asyncio
async def test_uncertain_same_head_relooks_up_review_job(controller, proxy, mock_github):
    state = _deploy_requested_state(command={"comment_id": 50, "kind": "approve_deploy", "phase": "uncertain", "args": {"machine": "test-machine"}})
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
    mock_github.get_pr.return_value = {"state": "open", "merged": False, "head": {"sha": "a" * 40}}
    controller.review.list_jobs = AsyncMock(return_value=[
        _review_job("job-2", "a" * 40, [
            {"target": "perception", "driver_path": "", "variant": "5.11", "success": True, "image_tag": "registry.example/repo:tag"},
        ], completed_at="2026-09-01T11:00:00Z"),
    ])
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[{"id": "perception", "target": "perception", "image": "registry/repo@sha256:" + "a" * 64, "variant": "5.11"}])
    core.driver_status = AsyncMock(side_effect=[{"status": "busy", "running_image": ""}, {"status": "running", "running_image": "registry/repo@sha256:" + "a" * 64}])
    core.deploy_driver = AsyncMock()
    controller._core_for_node = AsyncMock(return_value=core)
    controller._run_automated_case = AsyncMock(return_value={})

    await controller.handle_approve_deploy("repo", 1, 51, "test-machine", "owner1", "1")

    controller.review.list_jobs.assert_awaited_once_with(repo="repo", status="review_done", limit=100, offset=0)
    assert proxy.write_hidden_state.called


@pytest.mark.asyncio
async def test_uncertain_head_drift_requires_new_review(controller, proxy, mock_github):
    state = _deploy_requested_state(head_sha="a" * 40, command={"comment_id": 51, "kind": "approve_deploy", "phase": "uncertain", "args": {"machine": "test-machine"}})
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
    mock_github.get_pr.return_value = {"state": "open", "merged": False, "head": {"sha": "b" * 40}}

    await controller.handle_approve_deploy("repo", 1, 51, "test-machine", "owner1", "1")

    written_state = proxy.write_hidden_state.call_args.args[3]
    assert written_state["status"] == "review-required"
    proxy.project_status_label.assert_called_with("repo", 1, "review-required")


@pytest.mark.asyncio
async def test_uncertain_missing_exact_review_job_requires_new_review(controller, proxy, mock_github):
    state = _deploy_requested_state(command={"comment_id": 52, "kind": "approve_deploy", "phase": "uncertain", "args": {"machine": "test-machine"}})
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
    mock_github.get_pr.return_value = {"state": "open", "merged": False, "head": {"sha": "a" * 40}}
    controller.review.list_jobs = AsyncMock(return_value=[])

    await controller.handle_approve_deploy("repo", 1, 52, "test-machine", "owner1", "1")

    written_state = proxy.write_hidden_state.call_args.args[3]
    assert written_state["status"] == "review-required"
    assert written_state["last_processed_comment_id"] == 52


def test_top_level_statuses_are_exactly_seven():
    assert set(ALL_STATUSES) == {
        "review-required",
        "reviewing",
        "deploy-ready",
        "deploy-requested",
        "testing",
        "succeeded",
        "failed",
    }


@pytest.mark.asyncio
async def test_record_test_fail_uses_failed(controller, proxy, mock_github):
    state = _state(status="testing", deployments=[{"machine": "test-machine", "component_ids": ["comp-001"], "phase": "deployed"}])
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
    mock_github.get_pr.return_value = {"state": "open", "merged": False, "head": {"sha": "a" * 40}}
    mock_github.collaborator_permission = AsyncMock(return_value="admin")
    controller._upload_evidence = AsyncMock(return_value={"object_key": "", "sha256": "", "size": 0})
    controller.cos.generate_signed_url = AsyncMock(return_value="")

    await controller.handle_record_test("repo", 1, 301, "fail", "", "owner1", "")

    written_state = proxy.write_hidden_state.call_args.args[3]
    assert written_state["status"] == "failed"
    proxy.project_status_label.assert_any_call("repo", 1, "failed")


@pytest.mark.asyncio
async def test_partial_machine_approval_stays_deploy_requested(controller, proxy, mock_github):
    components = [
        _component(component_id="comp-perception", target="perception", variant="5.11"),
        _component(component_id="comp-driver", target="driver", variant="", driver_path="custom/driver", image_ref="registry/repo@sha256:" + "c" * 64, resolved_platform="linux/arm64"),
    ]
    state = _deploy_requested_state(components=components)
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
    mock_github.get_pr.return_value = {"state": "open", "merged": False, "head": {"sha": "a" * 40}}
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[
        {"id": "perception", "target": "perception", "variant": "5.11"},
    ])
    core.driver_status = AsyncMock(side_effect=[{"status": "busy", "running_image": ""}, {"status": "running", "running_image": "registry/repo@sha256:" + "a" * 64}])
    core.deploy_driver = AsyncMock()
    controller._core_for_node = AsyncMock(return_value=core)

    await controller.handle_approve_deploy("repo", 1, 401, "test-machine", "owner1", "1")

    assert proxy.write_hidden_state.call_args.args[3]["status"] == "deploy-requested"


@pytest.mark.asyncio
async def test_all_machine_groups_deployed_enters_testing(controller, proxy, mock_github):
    components = [
        _component(component_id="comp-perception", target="perception", variant="5.11"),
        _component(component_id="comp-driver", target="driver", variant="", driver_path="custom/driver", image_ref="registry/repo@sha256:" + "c" * 64, resolved_platform="linux/arm64"),
    ]
    state = _deploy_requested_state(
        components=components,
        deployments=[{"machine": "test-machine", "component_ids": ["comp-perception"], "phase": "deployed"}],
    )
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
    mock_github.get_pr.return_value = {"state": "open", "merged": False, "head": {"sha": "a" * 40}}
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[
        {"id": "perception", "target": "perception", "image": "registry/repo"},
        {"id": "driver-123", "category": "driver", "image": "registry/repo@sha256:" + "c" * 64},
    ])
    core.driver_status = AsyncMock(side_effect=[
        {"status": "busy", "running_image": ""},
        {"status": "running", "running_image": "registry/repo@sha256:" + "c" * 64},
        {"status": "running", "running_image": "registry/repo@sha256:" + "c" * 64},
        {"status": "running", "running_image": "registry/repo@sha256:" + "c" * 64},
    ])
    core.deploy_driver = AsyncMock()
    controller._core_for_node = AsyncMock(return_value=core)
    controller._run_automated_case = AsyncMock(return_value={"comp-driver": "pass"})

    await controller.handle_approve_deploy("repo", 1, 402, "driver-machine", "driver-owner", "2")

    assert proxy.write_hidden_state.call_args.args[3]["status"] == "testing"


@pytest.mark.asyncio
async def test_case_fail_does_not_block_overall_manual_pass(controller, proxy, mock_github):
    state = _state(status="testing", deployments=[{"machine": "test-machine", "component_ids": ["comp-001"], "phase": "deployed"}], case_results={"comp-001": "fail"})
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
    mock_github.get_pr.return_value = {"state": "open", "merged": False, "head": {"sha": "a" * 40}}
    mock_github.collaborator_permission = AsyncMock(return_value="admin")
    controller._upload_evidence = AsyncMock(return_value={"object_key": "", "sha256": "", "size": 0})
    controller.cos.generate_signed_url = AsyncMock(return_value="")

    await controller.handle_record_test("repo", 1, 501, "pass", "", "owner1", "")

    assert proxy.write_hidden_state.call_args.args[3]["status"] == "succeeded"


@pytest.mark.asyncio
async def test_case_not_run_before_all_components_deployed(controller, proxy, mock_github):
    components = [
        _component(component_id="comp-perception", target="perception", variant="test-variant"),
        _component(component_id="comp-driver", target="driver", variant="driver-variant", driver_path="custom/driver", image_ref="registry/repo@sha256:" + "c" * 64, resolved_platform="linux/arm64"),
    ]
    state = _deploy_requested_state(components=components)
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
    mock_github.get_pr.return_value = {"state": "open", "merged": False, "head": {"sha": "a" * 40}}
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[
        {"id": "perception", "target": "perception", "variant": "5.11"},
    ])
    core.driver_status = AsyncMock(side_effect=[{"status": "busy", "running_image": ""}, {"status": "running", "running_image": "registry/repo@sha256:" + "a" * 64}])
    core.deploy_driver = AsyncMock()
    controller._core_for_node = AsyncMock(return_value=core)
    controller._run_automated_case = AsyncMock()

    await controller.handle_approve_deploy("repo", 1, 601, "test-machine", "owner1", "1")

    controller._run_automated_case.assert_not_called()


@pytest.mark.asyncio
async def test_case_pass_does_not_auto_succeed(controller, proxy, mock_github):
    state = _deploy_requested_state()
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
    mock_github.get_pr.return_value = {"state": "open", "merged": False, "head": {"sha": "a" * 40}}
    core = AsyncMock()
    core.list_drivers = AsyncMock(return_value=[{"id": "perception", "target": "perception", "image": "registry/repo@sha256:" + "a" * 64, "variant": "5.11"}])
    core.driver_status = AsyncMock(side_effect=[{"status": "busy", "running_image": ""}, {"status": "running", "running_image": "registry/repo@sha256:" + "a" * 64}])
    core.deploy_driver = AsyncMock()
    controller._core_for_node = AsyncMock(return_value=core)
    controller._run_automated_case = AsyncMock(return_value={"comp-001": "pass"})

    await controller.handle_approve_deploy("repo", 1, 602, "test-machine", "owner1", "1")

    assert proxy.write_hidden_state.call_args.args[3]["status"] == "testing"
