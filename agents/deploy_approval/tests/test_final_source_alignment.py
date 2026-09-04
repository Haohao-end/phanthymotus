"""Focused regressions for the final source-alignment contract."""

from __future__ import annotations

import asyncio
import hashlib
import json
import inspect
import os
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from ..agent_core_client import AgentCoreClient, AgentCoreError
from ..case_runner import CaseRunner
from ..config import Config
from ..models import MachineInfo
from ..policy import Policy
from ..registry_client import RegistryClient, RegistryError, ResolvedImage
from ..review_client import ReviewJobInfo
from ..service import DeployController
from .conftest import make_config


def _text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def _request_state() -> dict:
    return {
        "version": 1,
        "head_sha": "a" * 40,
        "status": "deploy-ready",
        "review_job_id": "job-1",
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


def _review_job(repo: str = "repo", pr_number: int = 1, head_sha: str = "a" * 40) -> ReviewJobInfo:
    return ReviewJobInfo(
        {
            "id": "job-1",
            "repo": repo,
            "pr_number": pr_number,
            "head_sha": head_sha,
            "status": "review_done",
            "review_text": "review complete",
            "options": {"build_only": False},
            "completed_at": "2026-09-01T12:00:00Z",
            "build_results": [
                {
                    "idx": 0,
                    "target": "perception",
                    "driver_path": "",
                    "variant": "5.11",
                    "success": True,
                    "image_tag": "registry.example/repo:v1",
                }
            ],
        }
    )


def _controller():
    config = make_config()
    proxy = MagicMock()
    proxy.read_hidden_state = AsyncMock(return_value=_request_state())
    proxy.comment_identity = AsyncMock(return_value=("1", "alice"))
    proxy.get_pr = AsyncMock(
        return_value={
            "state": "open",
            "merged": False,
            "head": {"sha": "a" * 40},
            "user": {"id": 1, "login": "alice"},
        }
    )
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()
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
    review = MagicMock()
    review.list_jobs = AsyncMock()
    review.get_job = AsyncMock()
    registry = MagicMock()
    registry.resolve = AsyncMock()
    controller = DeployController(config, proxy, policy, github, review, registry)
    return controller, proxy, review, registry


def _case_runner(config: Config | None = None) -> CaseRunner:
    return CaseRunner(config or make_config())


def _review_manifest_bytes() -> tuple[bytes, str, bytes, str]:
    cfg_body = b'{"os":"linux","architecture":"arm64"}'
    cfg_digest = "sha256:" + hashlib.sha256(cfg_body).hexdigest()
    manifest_body = json.dumps(
        {"schemaVersion": 2, "config": {"digest": cfg_digest, "size": len(cfg_body)}},
        separators=(",", ":"),
    ).encode("utf-8")
    manifest_digest = "sha256:" + hashlib.sha256(manifest_body).hexdigest()
    return cfg_body, cfg_digest, manifest_body, manifest_digest


def test_driver_status_requires_running_image_but_ignores_status_field():
    cfg = make_config(allow_private_http=True)
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json={
                "code": 200,
                "data": {
                    "status": "running",
                    "running_image": "registry.example/repo@sha256:" + "a" * 64,
                },
            },
            request=request,
        )
    )
    client = AgentCoreClient(
        cfg,
        base_url="http://10.0.0.1:15678",
        node_host="10.0.0.1",
        http=httpx.AsyncClient(transport=transport),
    )
    result = asyncio.run(client.driver_status("driver"))
    assert result == {"running_image": "registry.example/repo@sha256:" + "a" * 64}


def test_driver_status_missing_running_image_fails_closed():
    cfg = make_config(allow_private_http=True)
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json={"code": 200, "data": {"status": "running"}},
            request=request,
        )
    )
    client = AgentCoreClient(
        cfg,
        base_url="http://10.0.0.1:15678",
        node_host="10.0.0.1",
        http=httpx.AsyncClient(transport=transport),
    )
    with pytest.raises(AgentCoreError):
        asyncio.run(client.driver_status("driver"))


@pytest.mark.asyncio
async def test_postdeploy_health_ignores_machine_status_when_image_matches():
    controller, _, _, _ = _controller()
    image_ref = "registry.example/repo@sha256:" + "a" * 64
    core = AsyncMock()
    core.driver_status = AsyncMock(
        return_value={"status": "stopped", "running_image": image_ref}
    )

    result = await controller._wait_for_deploy_health(
        core,
        "perception",
        image_ref,
        "perception/comp-001",
    )

    assert result == {"passed": True, "running_image": image_ref}


@pytest.mark.asyncio
async def test_postdeploy_health_uses_exact_running_image_only():
    controller, _, _, _ = _controller()
    image_ref = "registry.example/repo@sha256:" + "a" * 64
    core = AsyncMock()
    core.driver_status = AsyncMock(
        return_value={
            "status": "running",
            "running_image": "registry.example/repo@sha256:" + "b" * 64,
        }
    )

    result = await controller._wait_for_deploy_health(
        core,
        "perception",
        image_ref,
        "perception/comp-001",
    )

    assert result["passed"] is False
    assert result["running_image"] == "registry.example/repo@sha256:" + "b" * 64
    assert "status" not in result


@pytest.mark.asyncio
async def test_case_runner_ignores_machine_status_when_image_matches():
    runner = _case_runner()
    image_ref = "registry.example/repo@sha256:" + "a" * 64
    core = AsyncMock()
    core.driver_status = AsyncMock(
        return_value={"status": "stopped", "running_image": image_ref}
    )
    core.list_drivers = AsyncMock(
        return_value=[{"id": "perception", "target": "perception", "mcp_url": "http://mcp/runtime-1"}]
    )
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
async def test_case_runner_image_mismatch_fails_regardless_of_status():
    runner = _case_runner()
    image_ref = "registry.example/repo@sha256:" + "a" * 64
    core = AsyncMock()
    core.driver_status = AsyncMock(
        return_value={"status": "running", "running_image": "registry.example/repo@sha256:" + "b" * 64}
    )
    core.list_drivers = AsyncMock(
        return_value=[{"id": "perception", "target": "perception", "mcp_url": "http://mcp/runtime-1"}]
    )
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
async def test_request_deploy_sources_job_build_target_image_from_review_agent():
    controller, proxy, review, registry = _controller()
    review_job = _review_job()
    review.list_jobs = AsyncMock(return_value=[review_job])
    review.get_job = AsyncMock(return_value=review_job)
    registry.resolve = AsyncMock(
        return_value=SimpleNamespace(
            image_ref="registry.example/repo@sha256:" + "b" * 64,
            platform="linux/arm64",
        )
    )
    proxy.read_hidden_state = AsyncMock(return_value=_request_state())

    await controller.handle_request_deploy("repo", 1, 101)

    registry.resolve.assert_awaited_once_with(
        "registry.example/repo:v1",
        platform="",
        allowed_prefixes=["registry.example/repo"],
    )
    hidden_state = proxy.write_hidden_state.call_args.args[3]
    component = hidden_state["components"][0]
    assert component["review_image_tag"] == "registry.example/repo:v1"
    assert component["image_ref"] == "registry.example/repo@sha256:" + "b" * 64
    assert component["resolved_platform"] == "linux/arm64"


@pytest.mark.asyncio
async def test_registry_resolves_exact_review_agent_image_tag_only():
    cfg = make_config(allow_private_http=True)
    cfg.registry_auth_host_allowlist = []
    cfg.github_token = "tok"
    cfg.poll_enabled = False
    cfg.webhook_enabled = True
    cfg.github_webhook_secret = "secret"
    cfg.review_agent_base_url = "http://host.docker.internal:25000"

    cfg_body, cfg_digest, manifest_body, manifest_digest = _review_manifest_bytes()
    requested_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_paths.append(request.url.path)
        if request.url.path == "/v2/repo/manifests/v1":
            return httpx.Response(
                200,
                headers={"Docker-Content-Digest": manifest_digest},
                content=manifest_body,
                request=request,
            )
        if request.url.path == f"/v2/repo/blobs/{cfg_digest}":
            return httpx.Response(200, content=cfg_body, request=request)
        raise AssertionError(f"unexpected path {request.url.path}")

    client = RegistryClient(cfg, http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    resolved = await client.resolve(
        "registry.example/repo:v1",
        allowed_prefixes=["registry.example/repo"],
        platform="linux/arm64",
    )

    assert resolved.digest == manifest_digest
    assert requested_paths[0] == "/v2/repo/manifests/v1"


@pytest.mark.asyncio
async def test_registry_cannot_substitute_review_image_repository():
    cfg = make_config(allow_private_http=True)
    client = RegistryClient(cfg, http=httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(404, request=request))))
    client.resolve_tag = AsyncMock(
        return_value=ResolvedImage(
            family="registry.example/other",
            tag="v1",
            digest="sha256:" + "c" * 64,
            platform="linux/arm64",
            size=1,
        )
    )

    with pytest.raises(RegistryError):
        await client.resolve(
            "registry.example/repo:v1",
            allowed_prefixes=["registry.example/repo"],
            platform="linux/arm64",
        )


@pytest.mark.asyncio
async def test_request_deploy_does_not_use_agent_core_for_build_facts():
    controller, proxy, review, registry = _controller()
    review_job = _review_job()
    review.list_jobs = AsyncMock(return_value=[review_job])
    review.get_job = AsyncMock(return_value=review_job)
    registry.resolve = AsyncMock(
        return_value=SimpleNamespace(
            image_ref="registry.example/repo@sha256:" + "b" * 64,
            platform="linux/arm64",
        )
    )
    controller._core_for_node = AsyncMock()

    await controller.handle_request_deploy("repo", 1, 101)

    controller._core_for_node.assert_not_called()


@pytest.mark.asyncio
async def test_component_snapshot_preserves_review_image_tag_provenance():
    controller, proxy, review, registry = _controller()
    review_job = _review_job()
    review.list_jobs = AsyncMock(return_value=[review_job])
    review.get_job = AsyncMock(return_value=review_job)
    registry.resolve = AsyncMock(
        return_value=SimpleNamespace(
            image_ref="registry.example/repo@sha256:" + "b" * 64,
            platform="linux/arm64",
        )
    )

    await controller.handle_request_deploy("repo", 1, 101)

    component = proxy.write_hidden_state.call_args.args[3]["components"][0]
    assert component == {
        "component_id": component["component_id"],
        "target": "perception",
        "driver_path": "",
        "variant": "5.11",
        "review_image_tag": "registry.example/repo:v1",
        "image_ref": "registry.example/repo@sha256:" + "b" * 64,
        "resolved_platform": "linux/arm64",
    }


def test_runtime_env_names_are_upstream_existing_only():
    files = {
        path: _text(path)
        for path in (
            "agents/deploy_approval/config.py",
            "agents/deploy_approval/server.py",
            "agents/deploy_approval/agent_core_client.py",
            "deploy/deploy-approval/deploy.sh",
            "deploy/deploy-approval/docker-compose.yml",
        )
    }
    forbidden = (
        "DA_DEPLOY_ENV",
        "DA_REVIEW_ENV",
        "DA_AGENT_CORE_ENV",
        "DA_ENV_FILE",
        "GITHUB_COMMAND_POLL_INTERVAL_SECONDS",
        "AGENT_CORE_TOKEN",
        "API_TOKEN",
        "MACHINE_OWNERS_FILE",
        "MACHINE_OWNERS_HOST_FILE",
        "REVIEW_AGENT_BASE_URL",
        "ALLOW_PRIVATE_HTTP",
        "HTTP_ALLOWED_CIDRS",
        "HTTP_CONNECT_TIMEOUT",
        "HTTP_READ_TIMEOUT",
        "HTTP_TOTAL_TIMEOUT",
        "HEALTH_POLL_INTERVAL_SECONDS",
        "HEALTH_TIMEOUT_SECONDS",
        "COS_REGION",
        "COS_BUCKET",
        "COS_SECRET_ID",
        "COS_SECRET_KEY",
        "COS_SESSION_TOKEN",
        "COS_PREFIX",
        "COS_SIGNED_URL_TTL_SECONDS",
        "REGISTRY_USER_ENV",
        "REGISTRY_PASSWORD_ENV",
        "REGISTRY_AUTH_HOST_ALLOWLIST",
    )
    for name in forbidden:
        env_read = re.compile(rf'os\.getenv\(\s*[\"\']{re.escape(name)}[\"\']')
        shell_read = re.compile(rf"\${{{re.escape(name)}}}")
        compose_env = re.compile(rf"^\s*{re.escape(name)}:\s*\"", re.MULTILINE)
        assert not any(
            env_read.search(text)
            or shell_read.search(text)
            or compose_env.search(text)
            for text in files.values()
        ), name
    all_text = "\n".join(files.values())
    for name in (
        "GITHUB_TOKEN",
        "GITHUB_REPOS",
        "POLL_ENABLED",
        "POLL_INTERVAL_SECONDS",
        "WEBHOOK_ENABLED",
        "GITHUB_WEBHOOK_SECRET",
        "REGISTRY",
        "REGISTRY_USER",
        "REGISTRY_PASSWORD",
        "ACCESS_TOKEN",
    ):
        assert name in all_text


def test_poll_reuses_poll_interval_seconds():
    text = _text("agents/deploy_approval/github_command_watcher.py")
    assert "self.config.poll_interval_seconds" in text
    assert "GITHUB_COMMAND_POLL_INTERVAL_SECONDS" not in text


def test_no_da_environment_names():
    text = "\n".join(
        _text(path)
        for path in (
            "agents/deploy_approval/config.py",
            "agents/deploy_approval/server.py",
            "deploy/deploy-approval/deploy.sh",
            "deploy/deploy-approval/docker-compose.yml",
        )
    )
    assert "DA_" not in text


def test_no_custom_agent_core_token_env():
    text = "\n".join(
        _text(path)
        for path in (
            "agents/deploy_approval/config.py",
            "agents/deploy_approval/agent_core_client.py",
            "agents/deploy_approval/service.py",
            "deploy/deploy-approval/deploy.sh",
        )
    )
    assert "AGENT_CORE_TOKEN" not in text
    assert "os.getenv(\"ACCESS_TOKEN\"" in _text("agents/deploy_approval/agent_core_client.py")


def test_no_deploy_approval_api_token_runtime_state():
    text = "\n".join(
        _text(path)
        for path in (
            "agents/deploy_approval/config.py",
            "agents/deploy_approval/server.py",
            "deploy/deploy-approval/deploy.sh",
            "deploy/deploy-approval/docker-compose.yml",
        )
    )
    assert "API_TOKEN" not in text
    assert "config.api_token" not in _text("agents/deploy_approval/server.py")


def test_machine_and_cos_config_are_fixed_read_only_files():
    config = Config()
    assert config.machine_owners_file == "/run/deploy-approval/machines.yaml"
    assert config.secrets_file == "/run/deploy-approval/secrets.yaml"

    deploy_sh = _text("deploy/deploy-approval/deploy.sh")
    compose = _text("deploy/deploy-approval/docker-compose.yml")
    assert "./machines.yaml" in deploy_sh
    assert "./secrets.yaml" in deploy_sh
    assert "./machines.yaml:/run/deploy-approval/machines.yaml:ro" in compose
    assert "./secrets.yaml:/run/deploy-approval/secrets.yaml:ro" in compose


def test_deploy_script_has_no_stateful_purge():
    deploy_sh = _text("deploy/deploy-approval/deploy.sh")
    assert "PURGE-DEPLOY-DATA" not in deploy_sh
    assert "down -v" not in deploy_sh


def test_dockerfile_has_no_deploy_approval_data_state_dir():
    dockerfile = _text("agents/deploy_approval/Dockerfile")
    assert "/data" not in dockerfile


def test_source_of_truth_contract_is_explicit():
    docs = "\n".join(
        _text(path)
        for path in (
            "DEPLOY_APPROVAL_AGENT.md",
            "docs/deploy-approval-github-driven-architecture.md",
        )
    )
    assert "GitHub hidden lifecycle JSON" in docs
    assert "Review Agent API is the sole source of job/build/target/image candidate facts" in docs
    assert "Registry only verifies/resolves that exact Review Agent image tag" in docs
    assert "Agent Core only supplies runtime identity, current `running_image`, and MCP evidence" in docs


def test_single_replica_restart_safe_contract_is_documented():
    text = "\n".join(
        _text(path)
        for path in (
            "deploy/deploy-approval/docker-compose.yml",
            "docs/deploy-approval-github-driven-architecture.md",
        )
    )
    lowered = text.lower()
    assert "single-replica" in lowered or "single replica" in lowered
    assert "single-writer" in lowered or "single writer" in lowered
    assert "replicas >1" in text or "multiple concurrent Deploy Controller replicas are unsupported" in text


def test_architecture_doc_explicitly_documents_single_replica_single_writer():
    docs = "\n".join(
        _text(path)
        for path in (
            "DEPLOY_APPROVAL_AGENT.md",
            "docs/deploy-approval-github-driven-architecture.md",
        )
    )
    lowered = docs.lower()
    assert "restart-safe stateless" in lowered
    assert "single-replica / single-writer" in lowered
    assert "githubcommandwatcher" in lowered
    assert "serially processes mutating commands" in lowered


def test_architecture_doc_rejects_multi_replica_claim():
    docs = _text("docs/deploy-approval-github-driven-architecture.md")
    lowered = docs.lower()
    assert "multiple concurrent deploy controller replicas are unsupported" in lowered
    assert "no cas/distributed lock" in lowered
    assert "replicas >1" in lowered


def test_docs_use_poll_interval_seconds_not_hardcoded_60_second_polling():
    docs = "\n".join(
        _text(path)
        for path in (
            "DEPLOY_APPROVAL_AGENT.md",
            "docs/deploy-approval-github-driven-architecture.md",
            "agents/deploy_approval/github_command_watcher.py",
        )
    )
    assert "POLL_INTERVAL_SECONDS" in docs
    assert "30 seconds" in docs
    assert "60-second polling" not in docs
    assert "every 60 seconds" not in docs


def test_deploy_script_is_executable():
    mode = Path("deploy/deploy-approval/deploy.sh").stat().st_mode
    assert os.access("deploy/deploy-approval/deploy.sh", os.X_OK)
    assert mode & 0o111


def test_config_has_no_api_token_field():
    assert "api_token" not in Config.__dataclass_fields__


def test_config_has_no_legacy_github_command_poll_interval_field():
    assert "github_command_poll_interval_seconds" not in Config.__dataclass_fields__


def test_agent_core_client_has_no_token_env_parameter():
    sig = inspect.signature(AgentCoreClient.__init__)
    params = sig.parameters
    assert "token_env" not in params
    assert not any(
        p.kind is inspect.Parameter.VAR_KEYWORD
        for p in sig.parameters.values()
    )


def test_agent_core_client_rejects_unknown_constructor_kwargs():
    with pytest.raises(TypeError):
        AgentCoreClient(
            Config(),
            base_url="https://example.invalid:15678",
            typo_option="must-fail",
        )


def test_dead_registry_env_selector_fields_removed_when_unused():
    assert "registry_user_env" not in Config.__dataclass_fields__
    assert "registry_password_env" not in Config.__dataclass_fields__


def test_sparse_review_env_does_not_emit_empty_optional_overrides():
    deploy_sh = _text("deploy/deploy-approval/deploy.sh")
    assert "dotenv_has_key" in deploy_sh
    assert "if [ -n \"$value\" ]" in deploy_sh
    assert "printf 'GITHUB_REPOS=%s\\n'" not in deploy_sh
    assert "printf 'POLL_ENABLED=%s\\n'" not in deploy_sh


def test_poll_defaults_to_30_when_upstream_poll_interval_is_absent():
    compose = _text("deploy/deploy-approval/docker-compose.yml")
    assert 'POLL_INTERVAL_SECONDS: "${POLL_INTERVAL_SECONDS:-30}"' in compose
    assert 'POLL_ENABLED: "${POLL_ENABLED:-true}"' in compose


def test_optional_webhook_env_absence_keeps_default_false():
    compose = _text("deploy/deploy-approval/docker-compose.yml")
    assert 'WEBHOOK_ENABLED: "${WEBHOOK_ENABLED:-false}"' in compose


def test_machine_policy_symlink_rejected():
    deploy_sh = _text("deploy/deploy-approval/deploy.sh")
    lowered = deploy_sh.lower()
    assert '! -L "$MACHINES_FILE"' in deploy_sh
    assert "machine policy file must be a regular file" in lowered


def test_machine_policy_duplicate_node_id_rejected():
    deploy_sh = _text("deploy/deploy-approval/deploy.sh")
    assert "duplicate node_id" in deploy_sh


def test_machine_policy_empty_owner_rejected():
    deploy_sh = _text("deploy/deploy-approval/deploy.sh")
    assert "owners list" in deploy_sh
    assert "invalid owner entry" in deploy_sh


def test_secrets_symlink_rejected():
    deploy_sh = _text("deploy/deploy-approval/deploy.sh")
    assert '! -L "$SECRETS_FILE"' in deploy_sh
    assert "COS secrets file must be a regular file" in deploy_sh


def test_secrets_requires_version_one():
    deploy_sh = _text("deploy/deploy-approval/deploy.sh")
    assert "secrets file must be version 1" in deploy_sh


def test_secrets_rejects_non_string_secret_fields():
    deploy_sh = _text("deploy/deploy-approval/deploy.sh")
    assert "must be a string" in deploy_sh


def test_secrets_rejects_bool_ttl():
    deploy_sh = _text("deploy/deploy-approval/deploy.sh")
    assert "isinstance(ttl, bool)" in deploy_sh
    assert "must be 1..604800" in deploy_sh
