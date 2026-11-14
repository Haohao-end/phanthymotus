"""Focused regressions for the final source-alignment contract."""

from __future__ import annotations

import inspect
import os
import re
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ..agent_core_client import AgentCoreClient
from .. import comments as comments_mod
from ..config import Config
from ..models import MachineInfo
from ..policy import Policy
# registry_client removed: Deploy Approval no longer accesses Registry
from ..service import DeployController
from ..github_state_proxy import GitHubStateProxy


def _text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def _request_state() -> dict:
    return {
        "version": 1,
        "head_sha": "a" * 40,
        "status": "deploy-ready",
        "review_evidence": {"build_comment_id": 1, "build_comment_updated_at": "2026-09-18T00:00:00Z", "commit_prefix": "abc1234", "resolved_head_sha": "a" * 40, "test_comment_id": 2, "test_comment_updated_at": "2026-09-18T00:00:00Z", "code_review_comment_id": 3, "code_review_comment_updated_at": "2026-09-18T00:00:00Z", "review_author_id": "7950763"},
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

        "COS_PREFIX",
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
        "GITHUB_APP_ID",
        "GITHUB_INSTALLATION_ID",
        "GITHUB_APP_PRIVATE_KEY_FILE",
        "GITHUB_REPOS",
        "POLL_ENABLED",
        "POLL_INTERVAL_SECONDS",
        "WEBHOOK_ENABLED",
        "GITHUB_WEBHOOK_SECRET",
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
    assert "os.getenv(\"ACCESS_TOKEN\")" not in _text("agents/deploy_approval/agent_core_client.py")


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
    # Configuration directory must come from DEPLOY_APPROVAL_CONFIG_DIR env var,
    # NOT be hardcoded to any server path.
    assert "DEPLOY_APPROVAL_CONFIG_DIR" in deploy_sh
    assert 'PERSISTENT_DIR="${DEPLOY_APPROVAL_CONFIG_DIR:' in deploy_sh
    assert "/var/lib/deploy-approval" not in deploy_sh
    assert "/var/lib/deploy-approval/policy-candidates" in compose
    assert "/var/lib/deploy-approval/machines.yaml" not in compose
    assert "/var/lib/deploy-approval/secrets.yaml" not in compose
    assert 'source: "${DEPLOY_APPROVAL_CONFIG_DIR:?config directory required}/machines.yaml"' in compose
    assert 'source: "${DEPLOY_APPROVAL_CONFIG_DIR:?config directory required}/secrets.yaml"' in compose
    assert "DEPLOY_APPROVAL_CONFIG_DIR" in compose
    # Long-form volumes: check key elements are present in the YAML text
    assert 'target: /run/deploy-approval/machines.yaml' in compose
    assert 'target: /run/deploy-approval/secrets.yaml' in compose
    assert 'read_only: true' in compose


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
    assert "GitHub PR comments are the source of Review Agent Build/Test/Code Review evidence" in docs
    assert "Deploy Approval performs zero Registry HTTP" in docs
    assert "Agent Core receives the exact tag" in docs


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
            base_url="https://192.0.2.1:15678",
            node_host="192.0.2.1",
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




def test_architecture_markdown_includes_machine_owner():
    """DEPLOY_APPROVAL_AGENT.md Architecture must include Machine Owner."""
    md = Path("DEPLOY_APPROVAL_AGENT.md").read_text(encoding="utf-8")
    assert "Machine Owner" in md
    # Registry and GitHub State Proxy must not be top-level actors
    # They may appear in lower sections but not as architecture actors
    arch_section = md.split("## Architecture")[1].split("```")[1] if "## Architecture" in md else ""
    if arch_section:
        assert "GitHub State Proxy" not in arch_section



# ═══════════════════════════════════════════════════════════════════════
# MIGRATED from test_v8_contract.py
# ═══════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_phanthymotus_core_only_is_not_deployable(controller, proxy, mock_github):
    mock_github.get_comment.return_value = {"user": {"id": 111, "login": "alice"}, "body": "/request_deploy"}
    mock_github.get_pr.return_value = {"state": "open", "merged": False, "head": {"sha": "a" * 40}, "user": {"id": 111, "login": "alice"}}
    from ..review_comment_parser import ReviewBuild, ReviewCommentEvidence
    mock_evidence = ReviewCommentEvidence(
        head_sha="a" * 40,
        commit_prefix="abcdef1",
        review_author_id="7950763",
        review_author_login="review-bot",
        builds=[
            ReviewBuild(
                target="CORE", driver_path="", variant="",
                success=True, image_tag="registry.example/repo:tag-core",
            )
        ],
        build_comment_id=1001,
        build_comment_updated_at="2026-09-18T03:55:54Z",
        code_review_comment_id=1003,
        code_review_created_at="2026-09-18T03:57:00Z",
        code_review_text="Review completed.",
    )
    with patch('agents.deploy_approval.service.extract_review_evidence', return_value=mock_evidence):
        proxy.post_issue_comment = AsyncMock()
        proxy.write_hidden_state = AsyncMock()
        proxy.project_status_label = AsyncMock()

        await controller.handle_request_deploy("Haohao-end/phanthymotus", 1, 99)

    proxy.write_hidden_state.assert_not_called()
    proxy.post_issue_comment.assert_called()


@pytest.mark.asyncio
async def test_phanthymotus_core_plus_perception_deploys_only_perception(controller, proxy, mock_github):
    mock_github.get_comment.return_value = {"user": {"id": 111, "login": "alice"}, "body": "/request_deploy"}
    mock_github.get_pr.return_value = {"state": "open", "merged": False, "head": {"sha": "a" * 40}, "user": {"id": 111, "login": "alice"}}
    from ..review_comment_parser import ReviewBuild, ReviewCommentEvidence
    mock_evidence = ReviewCommentEvidence(
        head_sha="a" * 40,
        commit_prefix="abcdef1",
        review_author_id="7950763",
        review_author_login="review-bot",
        builds=[
            ReviewBuild(target="CORE", driver_path="", variant="", success=True, image_tag="registry.example/repo:tag-core"),
            ReviewBuild(target="perception", driver_path="", variant="5.11", success=True, image_tag="registry.example/repo:tag-perception"),
        ],
        build_comment_id=1001,
        build_comment_updated_at="2026-09-18T03:55:54Z",
        test_comment_id=1002,
        test_comment_updated_at="2026-09-18T03:55:54Z",
        code_review_comment_id=1003,
        code_review_comment_updated_at="2026-09-18T03:57:00Z",
        code_review_text="Review completed.",
    )
    proxy.read_hidden_state = AsyncMock(return_value={
        "version": 1,
        "head_sha": "a" * 40,
        "status": "deploy-ready",
        "review_evidence": {"build_comment_id": 1, "build_comment_updated_at": "2026-09-18T00:00:00Z", "commit_prefix": "abc1234", "resolved_head_sha": "a" * 40, "test_comment_id": 2, "test_comment_updated_at": "2026-09-18T00:00:00Z", "code_review_comment_id": 3, "code_review_comment_updated_at": "2026-09-18T00:00:00Z", "review_author_id": "7950763"},
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
    })
    with patch('agents.deploy_approval.service.extract_review_evidence', return_value=mock_evidence):
        proxy.write_hidden_state = AsyncMock()
        proxy.project_status_label = AsyncMock()
        mock_github.resolve_commit_sha.return_value = "a" * 40

        await controller.handle_request_deploy("Haohao-end/phanthymotus", 1, 100)

    written_state = proxy.write_hidden_state.call_args.args[3]
    assert [c["target"] for c in written_state["components"]] == ["perception"]
    assert written_state["review_evidence"].get("build_comment_id") == 1001





# ══════════════════════════════════════════════════════════════════════════════
# MIGRATED from test_v10_contract.py
# ══════════════════════════════════════════════════════════════════════════════

# ── Fixtures and helpers for runtime resolution tests (migrated) ──


@pytest.fixture
def mock_github():
    github = MagicMock()
    github.get_pr = AsyncMock()
    github.get_comment = AsyncMock()
    github.get_issue_comments = AsyncMock()
    github.resolve_commit_sha = AsyncMock()
    github.collaborator_permission = AsyncMock()
    github.comment_identity = AsyncMock()
    github.post_issue_comment = AsyncMock()
    github.update_comment = AsyncMock()
    github.get_issue_labels = AsyncMock()
    github.list_open_prs = AsyncMock()
    github.get_repo = AsyncMock()
    return github


@pytest.fixture
def proxy(config, mock_github):
    return GitHubStateProxy(config, mock_github, github_app_id="12345")


@pytest.fixture
def policy(config):
    p = Policy(config)
    p.machines = {
        "perception-machine": MachineInfo(
            alias="perception-machine",
            node_id="node-1",
            owners=["owner1"],
            node_host="10.0.0.1",
            targets=["perception", "actucore"],
            platforms=["linux/arm64"],
            variants=["5.11", "6.1"],
        ),
        "driver-machine": MachineInfo(
            alias="driver-machine",
            node_id="node-2",
            owners=["owner1"],
            node_host="10.0.0.2",
            targets=["driver"],
            platforms=["linux/arm64"],
            variants=["5.11"],
            driver_paths=["unitree/g1"],
        ),
        "multi-machine": MachineInfo(
            alias="multi-machine",
            node_id="node-3",
            owners=["owner1"],
            node_host="10.0.0.3",
            targets=["perception", "actucore", "driver"],
            platforms=["linux/arm64"],
            variants=["5.11", ""],
            driver_paths=["custom/driver"],
        ),
    }
    return p


@pytest.fixture
def controller(config, proxy, policy, mock_github):
    return DeployController(config, proxy, policy, mock_github)


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
        "review_evidence": {"build_comment_id": 1, "build_comment_updated_at": "2026-09-18T00:00:00Z", "commit_prefix": "abc1234", "resolved_head_sha": "a" * 40, "test_comment_id": 2, "test_comment_updated_at": "2026-09-18T00:00:00Z", "code_review_comment_id": 3, "code_review_comment_updated_at": "2026-09-18T00:00:00Z", "review_author_id": "7950763"},
        "components": [_component()],
        "deployments": [{"machine": "perception-machine", "component_ids": ["comp-001"], "phase": "deployed"}],
        "case_results": {},
        "test_result": "",
        "cos": {"object_key": "", "sha256": "", "size": 0},
        "command": {"comment_id": 0, "kind": "", "phase": "completed", "args": {}},
        "last_processed_comment_id": 0,
    }
    state.update(overrides)
    return state


class TestRuntimeResolution:
    """Exact runtime id resolution, no fallback, no fuzzy."""

    def test_service_runtime_requires_exact_perception_id(self, controller):
        """Perception runtime id must be EXACT 'perception'."""
        drivers = [
            {"id": "perception", "target": "perception", "image": "registry/perception:v1"},
        ]
        result = controller._resolve_component_runtime(
            drivers, {"target": "perception", "image_ref": "registry/perception@sha256:" + "a" * 64}
        )
        assert result is not None
        assert result["runtime_id"] == "perception"

        # No "perception" in drivers
        drivers2 = [{"id": "runtime-1", "target": "perception", "image": "registry/perception:v1"}]
        result2 = controller._resolve_component_runtime(
            drivers2, {"target": "perception", "image_ref": "registry/perception@sha256:" + "a" * 64}
        )
        assert result2 is None

    def test_service_runtime_requires_exact_actucore_id(self, controller):
        """ActuCore runtime id must be EXACT 'actucore'."""
        drivers = [
            {"id": "actucore", "target": "actucore", "image": "registry/actucore:v1"},
        ]
        result = controller._resolve_component_runtime(
            drivers, {"target": "actucore", "image_ref": "registry/actucore@sha256:" + "a" * 64}
        )
        assert result is not None
        assert result["runtime_id"] == "actucore"

        drivers2 = [{"id": "runtime-2", "target": "actucore", "image": "registry/actucore:v1"}]
        result2 = controller._resolve_component_runtime(
            drivers2, {"target": "actucore", "image_ref": "registry/actucore@sha256:" + "a" * 64}
        )
        assert result2 is None

    def test_driver_runtime_missing_repository_metadata_fails_closed(self, controller):
        """Driver resolver must fail closed when Agent Core entry has no image repository metadata."""
        drivers = [
            {"id": "unitree-g1", "category": "driver", "image": ""},
        ]
        result = controller._resolve_component_runtime(
            drivers,
            {
                "target": "driver",
                "image_ref": "registry/unitree/g1@sha256:" + "a" * 64,
            },
        )
        assert result is None

    def test_driver_runtime_never_falls_back_to_driver_path(self, controller):
        """Driver resolution must never use driver_path as runtime id."""
        drivers = [
            {"id": "unitree-g1", "category": "driver",
             "image": "registry/unitree/g1:v1"},
        ]
        result = controller._resolve_component_runtime(
            drivers,
            {
                "target": "driver",
                "driver_path": "unitree/g1",
                "image_ref": "registry/unitree/g1@sha256:" + "a" * 64,
            },
        )
        assert result is not None
        assert result["runtime_id"] == "unitree-g1"
        # driver_path was never used as a fallback for id

    def test_driver_runtime_never_falls_back_to_single_driver(self, controller):
        """When there is exactly one driver in the catalog, but no image match, fail closed."""
        drivers = [
            {"id": "only-driver", "category": "driver",
             "image": "registry/other:v1"},
        ]
        result = controller._resolve_component_runtime(
            drivers,
            {
                "target": "driver",
                "image_ref": "registry/unitree/g1@sha256:" + "a" * 64,
            },
        )
        assert result is None

    def test_unknown_review_service_variant_fails_closed(self):
        """A non-empty variant that is not 5.11 or 6.1 must fail closed."""
        from ..service import _normalize_variant, DeployControllerError
        with pytest.raises(DeployControllerError, match="unsupported variant"):
            _normalize_variant("unknown-variant")



class TestCaseContract:
    """Case must use pinned runtime_id from deploy, not re-resolve."""

    @pytest.mark.asyncio
    async def test_case_uses_pinned_runtime_id_from_deploy(self, controller):
        """The automated case must use the deploy-pinned runtime_id, not re-list drivers."""
        core = AsyncMock()
        core.list_drivers = AsyncMock(return_value=[
            {"id": "perception", "target": "perception", "mcp_url": "http://mcp/runtime-1"},
        ])
        controller._core_for_node = AsyncMock(return_value=core)
        captured = {}

        runner = MagicMock()
        runner.select_case.return_value = "perception-health-check"

        async def _capture(case_id, deployment):
            captured["runtime_id"] = deployment.get("runtime_id", "")
            return {"passed": True, "case_id": case_id, "logs": [], "error": ""}

        runner.run_case = AsyncMock(side_effect=_capture)
        controller._get_case_runner = MagicMock(return_value=runner)

        result = await controller._run_automated_case(
            "repo",
            1,
            "a" * 40,
            [_component(runtime_id="perception")],
            [{"machine": "perception-machine", "component_ids": ["comp-001"], "phase": "deployed"}],
        )
        assert result == {"comp-001": "pass"}
        assert captured["runtime_id"] == "perception"

    @pytest.mark.asyncio
    async def test_case_does_not_reresolve_runtime_to_different_driver(self, controller):
        """The case must not re-resolve the runtime by calling list_drivers again."""
        core = AsyncMock()
        core.list_drivers = AsyncMock(return_value=[
            {"id": "different-driver", "target": "perception", "mcp_url": "http://mcp/runtime-1"},
        ])
        controller._core_for_node = AsyncMock(return_value=core)
        captured = {}

        runner = MagicMock()
        runner.select_case.return_value = "perception-health-check"

        async def _capture(case_id, deployment):
            captured["runtime_id"] = deployment.get("runtime_id", "")
            captured["_driver_id"] = deployment.get("_driver_id", "")
            return {"passed": True, "case_id": case_id, "logs": [], "error": ""}

        runner.run_case = AsyncMock(side_effect=_capture)
        controller._get_case_runner = MagicMock(return_value=runner)

        # The component has runtime_id="perception" pinned from deploy
        result = await controller._run_automated_case(
            "repo",
            1,
            "a" * 40,
            [_component(runtime_id="perception")],
            [{"machine": "perception-machine", "component_ids": ["comp-001"], "phase": "deployed"}],
        )
        assert result == {"comp-001": "pass"}
        # The case used the pinned runtime_id, not the different one from list_drivers
        assert captured["runtime_id"] == "perception"
        assert captured["_driver_id"] == "perception"
        # list_drivers may have been called but the result was not used for resolution
        # (the pinned runtime_id from deploy takes precedence)


def test_no_registry_legacy_terms_in_production_files():
    """Regression: production files must not contain registry-era legacy terms."""
    files = {
        "config.py": _text("agents/deploy_approval/config.py"),
        "agent_md": _text("DEPLOY_APPROVAL_AGENT.md"),
        "arch_md": _text("docs/deploy-approval-github-driven-architecture.md"),
    }
    all_text = "\n".join(files.values())

    forbidden = [
        "GitHub/poll/webhook/registry keys",
        "Review Agent / Registry / Agent Core",
        "fresh GitHub PR comments + Registry resolution",
        "Registry remains an internal fresh-fact implementation detail",
        "resolved to an immutable `repository@sha256:digest`",
        "| `REGISTRY` |",
        "| `REGISTRY_USER` |",
        "| `REGISTRY_PASSWORD` |",
        "GitHub State Proxy 和 Registry 作为独立 Actor",
    ]
    for term in forbidden:
        assert term not in all_text, f"Found forbidden term: {term!r}"

    # Must contain the correct zero-registry claims
    assert "Deploy Approval performs zero Registry HTTP" in all_text
    assert "Agent Core receives the exact tag" in all_text
    assert "owns all Registry authentication, pull, and deploy" in all_text


def _summary_next_action(markdown: str) -> str:
    heading = "### Next action"
    start = markdown.index(heading) + len(heading)
    next_heading = re.search(r"(?m)^### ", markdown[start:])
    end = start + next_heading.start() if next_heading else len(markdown)
    return markdown[start:end].strip()


def _summary_headings(markdown: str) -> list[str]:
    return re.findall(r"(?m)^### (.+)$", markdown)


def test_summary_only_next_action_changes_for_lifecycle_states():
    from ..models import BuildInfo

    repo = "example/phanthymotus"
    head = "a" * 40
    component = {
        "component_id": "component-1",
        "target": "driver",
        "driver_path": "example/driver",
        "variant": "5.11",
        "image_ref": "registry.example/driver@sha256:" + "b" * 64,
    }
    machine = {
        "alias": "fixture-machine",
        "ip": "10.100.129.168",
        "primary_ip": "10.100.129.168",
        "node_host": "10.100.129.168",
        "node_id": "node-fixture-machine",
        "repo_authorized": True,
        "identity_confirmed": True,
        "approval_available": True,
        "ip_command_safe": True,
        "command_selector": "10.100.129.168",
        "component_ids": [component["component_id"]],
    }
    ready = comments_mod.deploy_ready(
        repo, 473, head,
        [BuildInfo(
            target="driver", driver_path=component["driver_path"],
            variant="5.11", success=True, image_tag=component["image_ref"],
            deployable=True, component_id=component["component_id"],
        )],
        review_evidence={
            "build_comment_id": 1,
            "code_review_comment_id": 2,
            "resolved_head_sha": head,
        },
        machine_groups=[machine],
        components=[component],
    )
    deploying = comments_mod.deploy_requested(
        repo, 473, head, [component], [machine],
        deployments=[{
            "machine": machine["alias"], "ip": machine["ip"],
            "component_ids": [component["component_id"]], "phase": "deploying",
        }],
        display_status="deploying",
    )
    testing = comments_mod.testing(repo, 473, head)
    summaries = {
        "review-required": comments_mod.review_required(repo, 473, head),
        "deploy-ready": ready,
        "deploying": deploying,
        "testing": testing,
    }
    expected_headings = {
        "review-required": [
            "Deploy Approval — Lifecycle", "Workflow", "Next action", "Current Deployment",
        ],
        "deploy-ready": [
            "Deploy Approval — Lifecycle", "Workflow", "Next action", "构建结果",
        ],
        "deploying": [
            "Deploy Approval — Lifecycle", "Workflow", "Next action", "部署进度",
        ],
        "testing": ["Deploy Approval — Lifecycle", "Workflow", "Next action"],
    }
    expected_workflow_steps = [
        "1. Request Review",
        "2. Review Agent completed",
        "3. Request deployment",
        "4. Machine Owner approval(s)",
        "5. All required components deployed",
        "6. Machine Owner uploads evidence",
        "7. Record validation result",
        "8. Deployment accepted",
    ]
    for status, markdown in summaries.items():
        assert _summary_headings(markdown) == expected_headings[status]
        assert markdown.count("### Next action") == 1
        action = _summary_next_action(markdown)
        assert "**Machine Owner**" not in action
        assert "**Developer**" not in action
        workflow = re.search(
            r"(?ms)^### Workflow\n\n(.*?)(?=^### )", markdown,
        )
        assert workflow is not None
        assert workflow.group(1).strip() == comments_mod._workflow_lines(status)
        workflow_steps = [
            re.sub(r"^- \[[ x]\] ", "", line).split(" ← ", 1)[0]
            for line in workflow.group(1).strip().splitlines()
        ]
        assert workflow_steps == expected_workflow_steps

    assert "**Status:** `review-required`" in summaries["review-required"]
    assert f"**Bound HEAD:** `{head[:7]}`" in summaries["review-required"]
    assert "**Repository:** `example/phanthymotus`" in summaries["review-required"]
    assert "**Status:** `deploy-ready`" in ready
    assert f"**Bound HEAD:** `{head[:7]}`" in ready
    assert "**Status:** <code>deploying</code>" in deploying
    assert f"**Bound HEAD:** <code>{head[:7]}</code>" in deploying
    assert "**Repository:** <code>example/phanthymotus</code>" in deploying
    assert "等待当前 HEAD 的 Review 和镜像构建结果" in _summary_next_action(
        summaries["review-required"],
    )
    assert "当前 HEAD 的 Review 和镜像构建均已完成，可以部署" in _summary_next_action(ready)
    deploying_action = _summary_next_action(deploying)
    assert machine["alias"] in deploying_action
    assert machine["ip"] in deploying_action
    assert component["image_ref"] in deploying_action
    assert "当前部署尚未完成" in deploying_action
    assert "等待部署结果" in deploying_action
    assert "testing" not in deploying_action.casefold()
    testing_action = _summary_next_action(testing)
    assert "部署已经完成，现在可以开始测试" in testing_action
    assert "`/request_acceptance`" in testing_action
    # The testing builder has no Bound HEAD field in HEAD; retain that layout.
    assert "**Bound HEAD:**" not in testing


def test_summary_workflow_evidence_deployments_and_history_remain_unchanged():
    target = "registry.example/driver@sha256:" + "a" * 64
    current = "registry.example/driver@sha256:" + "b" * 64
    machine = "fixture-machine"
    ip = "10.100.129.168"
    markdown = "\n".join([
        "<!-- deploy-approval-agent -->",
        "### Deploy Approval — Lifecycle",
        "",
        "**Status:** `deploy-ready`",
        "**Bound HEAD:** `abcdef0`",
        "**Repository:** `example/phanthymotus`",
        "",
        "### Workflow",
        "",
        "- [x] 1. Request Review",
        "- [ ] 2. Review Agent completed ← **Next**",
        "",
        "### Next action",
        "",
        "Existing next action text.",
        "",
        "### Current Deployment",
        "",
        "| Machine | IP | Image |",
        "|---|---|---|",
        f"| {machine} | {ip} | {current} |",
        "<!-- evidence-projection:start -->",
        "### Test Evidence",
        "Existing test evidence projection.",
        "<!-- evidence-projection:end -->",
        "<!-- deploy-approval-visible-history:start -->",
        "### History",
        "Existing historical round and event.",
        "<!-- deploy-approval-visible-history:end -->",
    ])
    bounds = comments_mod._next_action_body_bounds(markdown)
    assert bounds is not None
    body_start, body_end = bounds
    prefix, suffix = markdown[:body_start], markdown[body_end:]

    updated = comments_mod.update_runtime_image_checks(
        markdown,
        [{
            "machine": machine,
            "component_id": "component-1",
            "status": "mismatch",
            "primary_ip": ip,
            "node_host": ip,
            "command_selector": ip,
            "approval_available": True,
            "component_compatible": True,
            "identity_confirmed": True,
            "repository_authorized": True,
            "target_image": target,
            "observed_image": current,
        }],
        [{
            "component_id": "component-1", "target": "driver",
            "driver_path": "example/driver", "image_ref": target,
        }],
        lifecycle_status="deploy-ready",
        machine_groups=[{
            "alias": machine, "primary_ip": ip, "node_host": ip,
            "approval_available": True, "component_compatible": True,
            "identity_confirmed": True, "repository_authorized": True,
        }],
        machine_inventory=[{"alias": machine, "primary_ip": ip}],
    )

    assert updated != markdown
    assert updated.startswith(prefix)
    assert updated.endswith(suffix)
    action = _summary_next_action(updated)
    assert target in action
    assert current in action
    assert f"/approve_deploy machine={ip}" in action
    assert "### Workflow\n\n- [x] 1. Request Review" in updated
    assert f"| {machine} | {ip} | {current} |" in updated
    assert "Existing test evidence projection." in updated
    assert "Existing historical round and event." in updated


def test_deploy_ready_lists_exact_machine_commands_without_placeholder():
    from ..models import BuildInfo

    repo = "example/phanthymotus"
    head = "c" * 40
    image = "registry.example/driver@sha256:" + "d" * 64
    component = {
        "component_id": "component-1", "target": "driver",
        "driver_path": "example/driver", "variant": "5.11",
        "image_ref": image,
    }
    build = BuildInfo(
        target="driver", driver_path="example/driver", variant="5.11",
        success=True, image_tag=image, deployable=True,
        component_id="component-1",
    )
    review = {
        "build_comment_id": 1, "code_review_comment_id": 2,
        "resolved_head_sha": head,
    }

    def machine(alias: str, ip: str) -> dict:
        return {
            "alias": alias, "ip": ip, "primary_ip": ip, "node_host": ip,
            "node_id": f"node-{alias}", "repo_authorized": True,
            "identity_confirmed": True, "approval_available": True,
            "ip_command_safe": True, "command_selector": ip,
            "component_ids": [component["component_id"]],
        }

    single = comments_mod.deploy_ready(
        repo, 473, head, [build], review_evidence=review,
        machine_groups=[machine("machine-one", "10.100.129.168")],
        components=[component],
    )
    assert "machine-one" in single
    assert "10.100.129.168" in single
    assert "driver example/driver" in single
    assert "`/approve_deploy machine=10.100.129.168`" in single
    assert "`/approve_deploy`" in single
    assert "`/request_deploy` 是可选操作" in single
    assert "machine=<alias-or-ip>" not in single
    assert "machine=..." not in single

    multiple = comments_mod.deploy_ready(
        repo, 473, head, [build], review_evidence=review,
        machine_groups=[
            machine("machine-one", "10.100.129.168"),
            machine("machine-two", "10.100.129.169"),
        ],
        components=[component],
    )
    assert "`/approve_deploy machine=10.100.129.168`" in multiple
    assert "`/approve_deploy machine=10.100.129.169`" in multiple
    assert "有多台兼容机器，请先选择目标机器" in multiple
    assert "`/approve_deploy`" not in _summary_next_action(multiple)
    assert "machine=<alias-or-ip>" not in multiple
    assert "machine=..." not in multiple


def test_testing_next_action_exposes_upload_url_and_actual_reviewers():
    repo = "example/phanthymotus"
    head = "e" * 40
    upload_url = (
        "https://evidence.example.com/evidence/example/phanthymotus/pulls/473"
        "?cap=fixture-capability"
    )
    testing = comments_mod.testing(
        repo, 473, head, evidence_url=upload_url,
    )
    testing_action = _summary_next_action(testing)
    assert "部署已经完成，现在可以开始测试" in testing_action
    assert f"[上传测试证据](<{upload_url}>)" in testing_action
    assert "审批人检查真实开发效果" in testing_action
    assert "是否通过验收、是否可以合并" in testing_action
    assert "`/request_acceptance`" in testing_action

    reviewers = ["reviewer-one", "reviewer-two"]
    pending = comments_mod.testing(
        repo, 473, head,
        acceptance_pending=True,
        acceptance_reviewers=reviewers,
        evidence_url=upload_url,
    )
    pending_action = _summary_next_action(pending)
    for reviewer in reviewers:
        assert f"@{reviewer}" in pending_action
    assert "负责检查和记录" in pending_action
    assert "`/record_test result=pass`" in pending_action
    assert "`/record_test result=fail`" in pending_action
    assert f"[补充上传测试证据](<{upload_url}>)" in pending_action
    assert "test_reviewers.yaml" not in pending_action
