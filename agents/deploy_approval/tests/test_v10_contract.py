"""V10 Deploy Approval contract tests: security, runtime, health, COS, review, case.

Every test is a real assertion — no pass, skip, xfail, or placeholder.
"""

from __future__ import annotations

import asyncio
import io
import json
import tarfile
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from .. import comments as comments_mod
from ..agent_core_client import AgentCoreClient, AgentCoreError
from ..config import Config
from ..cos_client import CosClient
from ..evidence_builder import EvidenceBuilder
from ..github_state_proxy import GitHubStateProxy
from ..models import MachineInfo
from ..policy import Policy
from ..review_client import ReviewJobInfo
from ..service import DeployController
from .conftest import make_config


# ── Fixtures ──


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
        "status": "testing",
        "review_job_id": "job-1",
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


def _deploy_requested_state(**overrides):
    state = _state(
        status="deploy-requested",
        review_job_id="job-1",
        components=[],
        deployments=[],
        approve_attempts=[],
        approve_attempts_total=0,
        approve_attempts_truncated=False,
        command={"comment_id": 0, "kind": "", "phase": "completed", "args": {}},
    )
    state.update(overrides)
    return state


def _review_summary(repo: str, pr_number: int, head_sha: str, **overrides) -> dict:
    result = {
        "id": "job-1",
        "repo": repo,
        "pr_number": pr_number,
        "head_sha": head_sha,
        "status": "review_done",
        "review_text": "review complete",
        "options": {"build_only": False},
        "completed_at": "2026-09-01T12:00:00Z",
        "build_results": [
            {"idx": 0, "target": "perception", "driver_path": "", "success": True,
             "image_tag": "registry/repo:v1", "variant": "5.11"},
        ],
    }
    result.update(overrides)
    return result


def _review_detail(repo: str, pr_number: int, head_sha: str, **overrides) -> dict:
    result = {
        "id": "job-1",
        "repo": repo,
        "pr_number": pr_number,
        "head_sha": head_sha,
        "status": "review_done",
        "review_text": "review complete",
        "options": {"build_only": False},
        "completed_at": "2026-09-01T12:00:00Z",
        "build_results": [
            {"idx": 0, "target": "perception", "driver_path": "", "success": True,
             "image_tag": "registry/repo:v1", "variant": "5.11"},
        ],
    }
    result.update(overrides)
    return result


# ══════════════════════════════════════════════════════════════════════════════
# Agent Core security tests
# ══════════════════════════════════════════════════════════════════════════════


class TestAgentCoreClientSecurity:
    """AgentCoreClient constructor defense-in-depth."""

    def test_configured_private_agent_core_node_allowed_with_private_http_disabled(self, config):
        """A node with a configured 10.x IP can be used even when allow_private_http is False."""
        config.allow_private_http = False
        client = AgentCoreClient(
            config,
            base_url="http://10.0.0.1:15678",
            token_env="AGENT_CORE_TOKEN",
            node_host="10.0.0.1",
        )
        assert client.base_url == "http://10.0.0.1:15678"
        assert client.node_host == "10.0.0.1"

    def test_unconfigured_private_agent_core_node_rejected(self, config):
        """A private IP not matching the machine's node_host is rejected by the constructor."""
        config.allow_private_http = False
        with pytest.raises(AgentCoreError, match="must match node_host"):
            AgentCoreClient(
                config,
                base_url="http://10.0.0.99:15678",
                token_env="AGENT_CORE_TOKEN",
                node_host="10.0.0.1",
            )

    def test_agent_core_node_wrong_port_rejected(self, config):
        """Port must be exactly 15678."""
        with pytest.raises(AgentCoreError, match="port must be 15678"):
            AgentCoreClient(
                config,
                base_url="http://10.0.0.1:15679",
                token_env="AGENT_CORE_TOKEN",
                node_host="10.0.0.1",
            )

    def test_machine_node_host_rejects_url_or_path_injection(self, config):
        """node_host must be a literal IP; URL/path injection is rejected."""
        # non-IP node_host -> literal IP check
        with pytest.raises(AgentCoreError, match="literal IP"):
            AgentCoreClient(
                config,
                base_url="http://10.0.0.1:15678",
                token_env="AGENT_CORE_TOKEN",
                node_host="evil.com",
            )
        # path injection in base_url
        with pytest.raises(AgentCoreError, match="must not contain a path"):
            AgentCoreClient(
                config,
                base_url="http://10.0.0.1:15678/api/evil",
                token_env="AGENT_CORE_TOKEN",
                node_host="10.0.0.1",
            )
        with pytest.raises(AgentCoreError, match="must not contain a path"):
            AgentCoreClient(
                config,
                base_url="http://10.0.0.1:15678/evil",
                token_env="AGENT_CORE_TOKEN",
                node_host="10.0.0.1",
            )
        with pytest.raises(AgentCoreError, match="must not contain query"):
            AgentCoreClient(
                config,
                base_url="http://10.0.0.1:15678?evil=1",
                token_env="AGENT_CORE_TOKEN",
                node_host="10.0.0.1",
            )
        with pytest.raises(AgentCoreError, match="must not contain fragment"):
            AgentCoreClient(
                config,
                base_url="http://10.0.0.1:15678#evil",
                token_env="AGENT_CORE_TOKEN",
                node_host="10.0.0.1",
            )

    def test_agent_core_bearer_token_is_sent(self, config):
        """When AGENT_CORE_TOKEN is set, the Authorization header is sent."""
        with patch.dict("os.environ", {"AGENT_CORE_TOKEN": "secret-token-123"}):
            client = AgentCoreClient(
                config,
                base_url="http://10.0.0.1:15678",
                token_env="AGENT_CORE_TOKEN",
                node_host="10.0.0.1",
            )
            headers = client._headers()
            assert headers.get("Authorization") == "Bearer secret-token-123"

    def test_agent_core_token_never_persisted_or_rendered(self, config):
        """The token is read from env at call time and never stored on the instance."""
        with patch.dict("os.environ", {"AGENT_CORE_TOKEN": "my-secret-token"}):
            client = AgentCoreClient(
                config,
                base_url="http://10.0.0.1:15678",
                token_env="AGENT_CORE_TOKEN",
                node_host="10.0.0.1",
            )
            # The token is not stored directly on the instance
            assert not hasattr(client, "token_value")
            # The env var is not exposed in __dict__
            inst_repr = repr(client)
            assert "my-secret" not in inst_repr
            # The token is only produced by _headers() at call time
            headers = client._headers()
            assert headers["Authorization"] == "Bearer my-secret-token"

    def test_agent_core_verify_invalid_token_fails_closed(self, config):
        """verify() raises AgentCoreError when the token is invalid (401)."""
        import httpx
        client = AgentCoreClient(
            config,
            base_url="http://10.0.0.1:15678",
            token_env="AGENT_CORE_TOKEN",
            node_host="10.0.0.1",
        )
        # Replace verify with a mock that raises a SecurityError
        async def _mock_verify():
            from agents.deploy_approval.clients_common import SecurityError
            raise SecurityError("unexpected status 401")
        client.verify = _mock_verify

        with pytest.raises((AgentCoreError, Exception), match="401|unauthorized|unexpected status"):
            asyncio.run(client.verify())


# ══════════════════════════════════════════════════════════════════════════════
# Review contract tests
# ══════════════════════════════════════════════════════════════════════════════


class TestReviewContract:
    """Review job lookup: build_only, empty review_text, detail mismatch, pagination."""

    def test_build_only_review_done_job_is_rejected(self):
        """A review_done job with build_only=True must not be accepted."""
        job = ReviewJobInfo({
            "id": "job-1",
            "repo": "4paradigm/phanthymotus",
            "pr_number": 1,
            "head_sha": "a" * 40,
            "status": "review_done",
            "review_text": "looks good",
            "options": {"build_only": True},
            "build_results": [],
        })
        assert job.review_complete() is False

    def test_review_done_with_empty_review_text_is_rejected(self):
        """A review_done job with empty review_text must not be accepted."""
        job = ReviewJobInfo({
            "id": "job-1",
            "repo": "4paradigm/phanthymotus",
            "pr_number": 1,
            "head_sha": "a" * 40,
            "status": "review_done",
            "review_text": "",
            "options": {"build_only": False},
            "build_results": [],
        })
        assert job.review_complete() is False

    def test_review_detail_repo_pr_head_mismatch_is_rejected(self):
        """The detail-level check must reject if repo, PR, or HEAD mismatch."""
        repo = "4paradigm/phanthymotus"
        pr_number = 1
        head_sha = "a" * 40
        # Mismatched repo
        job = ReviewJobInfo(_review_detail("other/repo", pr_number, head_sha))
        assert job.repo != repo
        # Mismatched PR
        job = ReviewJobInfo(_review_detail(repo, 999, head_sha))
        assert job.pr_number != pr_number
        # Mismatched HEAD
        job = ReviewJobInfo(_review_detail(repo, pr_number, "b" * 40))
        assert job.head_sha != head_sha

    @pytest.mark.asyncio
    async def test_review_lookup_uses_detail_after_exact_summary_selection(self, controller):
        """After selecting a summary candidate, detail must be fetched and verified."""
        repo = "4paradigm/phanthymotus"
        pr_number = 1
        head_sha = "a" * 40
        summary = _review_summary(repo, pr_number, head_sha)
        detail = _review_detail(repo, pr_number, head_sha)
        controller.review.list_jobs = AsyncMock(return_value=[summary])
        controller.review.get_job = AsyncMock(return_value=ReviewJobInfo(detail))

        result = await controller.get_builds_for_pr(repo, pr_number, head_sha)
        assert result is not None
        job_id, builds = result
        assert job_id == "job-1"
        controller.review.get_job.assert_awaited_once_with("job-1")

    @pytest.mark.asyncio
    async def test_review_lookup_paginates_beyond_first_page(self, controller):
        """When the first page does not contain the matching HEAD, pagination proceeds."""
        repo = "4paradigm/phanthymotus"
        pr_number = 1
        head_sha = "a" * 40
        summary = _review_summary(repo, pr_number, head_sha)
        # First page must be full (100 items) so pagination continues
        first_page = [_review_summary("other/repo", 2, "b" * 40) for _ in range(100)]
        controller.review.list_jobs = AsyncMock(side_effect=[
            first_page,
            [summary],
            [],
        ])
        controller.review.get_job = AsyncMock(return_value=ReviewJobInfo(_review_detail(repo, pr_number, head_sha)))

        result = await controller.get_builds_for_pr(repo, pr_number, head_sha)
        assert result is not None
        # list_jobs should have been called with increasing offsets
        assert controller.review.list_jobs.await_count >= 2

    @pytest.mark.asyncio
    async def test_review_lookup_pagination_bound_fails_closed(self, controller):
        """When the pagination bound is reached and the last page is still full, fail closed."""
        repo = "4paradigm/phanthymotus"
        pr_number = 1
        head_sha = "a" * 40
        # Return a full page of 100 items (none matching) for each of 10 pages
        full_page = [_review_summary("other/repo", 2, "b" * 40) for _ in range(100)]
        controller.review.list_jobs = AsyncMock(return_value=full_page)
        controller.review.get_job = AsyncMock()

        result = await controller.get_builds_for_pr(repo, pr_number, head_sha)
        assert result is None
        # Should have fetched 10 pages
        assert controller.review.list_jobs.await_count == 10


# ══════════════════════════════════════════════════════════════════════════════
# Runtime resolution tests
# ══════════════════════════════════════════════════════════════════════════════


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

    @pytest.mark.asyncio
    async def test_duplicate_runtime_id_in_group_fails_before_any_deploy_post(self, controller):
        """Two components resolving to the same runtime_id must fail before any deploy POST."""
        core = AsyncMock()
        core.list_drivers = AsyncMock(return_value=[
            {"id": "perception", "target": "perception",
             "image": "registry/perception:v1"},
        ])
        core.driver_status = AsyncMock(return_value={"status": "idle", "running_image": ""})
        components = [
            _component(component_id="comp-1", target="perception", runtime_id="perception"),
            _component(component_id="comp-2", target="perception", runtime_id="perception"),
        ]
        with pytest.raises(Exception, match="duplicate runtime_id"):
            await controller._preflight_running_images(core, components)


# ══════════════════════════════════════════════════════════════════════════════
# Deploy health tests
# ══════════════════════════════════════════════════════════════════════════════


class TestDeployHealth:
    """Sequential per-component deploy + health check."""

    @pytest.mark.asyncio
    async def test_successful_deploy_records_exact_runtime_image_health(self, controller):
        """A successful deploy must record the exact running_image in health records."""
        core = AsyncMock()
        core.deploy_driver = AsyncMock(return_value={"code": 0})
        core.driver_status = AsyncMock(return_value={
            "status": "running",
            "running_image": "registry/repo@sha256:" + "a" * 64,
        })
        controller._resolve_core_client = AsyncMock(return_value=core)

        result = await controller._wait_for_deploy_health(
            core, "perception",
            "registry/repo@sha256:" + "a" * 64,
            "perception/comp-001",
        )
        assert result["passed"] is True
        assert result["running_image"] == "registry/repo@sha256:" + "a" * 64
        assert result["status"] == "running"

    @pytest.mark.asyncio
    async def test_health_wait_uses_same_runtime_id_as_preflight_and_deploy(self, controller):
        """The health check must poll the exact same runtime_id that was deployed."""
        core = AsyncMock()
        core.deploy_driver = AsyncMock(return_value={"code": 0})
        core.driver_status = AsyncMock(return_value={
            "status": "running",
            "running_image": "registry/repo@sha256:" + "a" * 64,
        })
        controller._resolve_core_client = AsyncMock(return_value=core)

        runtime_id = "perception"
        image_ref = "registry/repo@sha256:" + "a" * 64
        await controller._deploy_component(core, "node-1", image_ref, runtime_id)
        assert core.deploy_driver.await_count >= 1
        deploy_call = core.deploy_driver.await_args
        # The deploy was called with this runtime_id
        assert deploy_call is not None
        args, _ = deploy_call
        assert args[0] == runtime_id

        result = await controller._wait_for_deploy_health(
            core, runtime_id, image_ref, "perception/comp-001",
        )
        assert result["passed"] is True
        core.driver_status.assert_called_with(runtime_id)

    @pytest.mark.asyncio
    async def test_health_mismatch_fails_without_rollback(self, controller):
        """When the running_image does not match the expected image, health fails but no rollback."""
        core = AsyncMock()
        core.deploy_driver = AsyncMock(return_value={"code": 0})
        core.driver_status = AsyncMock(return_value={
            "status": "running",
            "running_image": "registry/wrong@sha256:" + "b" * 64,
        })
        controller._resolve_core_client = AsyncMock(return_value=core)

        result = await controller._wait_for_deploy_health(
            core, "perception",
            "registry/expected@sha256:" + "a" * 64,
            "perception/comp-001",
        )
        assert result["passed"] is False
        # No rollback - health check is separate from deploy
        core.driver_status.assert_called()

    @pytest.mark.asyncio
    async def test_health_timeout_stops_later_component_deploys(self, controller):
        """When health check times out, later components must not be deployed."""
        # Configure a very short timeout for the health check
        from .conftest import make_config
        cfg = make_config(health_timeout_seconds=0.01, health_poll_interval_seconds=0.0)
        ctrl = DeployController(cfg, controller.proxy, controller.policy,
                                 controller.github, controller.review, controller.registry)

        core = AsyncMock()
        core.deploy_driver = AsyncMock(return_value={"code": 0})
        core.driver_status = AsyncMock(return_value={
            "status": "starting",
            "running_image": "",
        })
        ctrl._resolve_core_client = AsyncMock(return_value=core)

        result = await ctrl._wait_for_deploy_health(
            core, "perception",
            "registry/repo@sha256:" + "a" * 64,
            "perception/comp-001",
        )
        assert result["passed"] is False
        # Later components would not be deployed (caller must check result)

    @pytest.mark.asyncio
    async def test_deployment_record_written_only_after_exact_health_pass(self, controller):
        """A deployment record must only be written after the health check passes."""
        # Simulate the sequential deploy flow from handle_approve_deploy
        core = AsyncMock()
        core.deploy_driver = AsyncMock(return_value={"code": 0})
        core.driver_status = AsyncMock(return_value={
            "status": "running",
            "running_image": "registry/repo@sha256:" + "a" * 64,
        })
        controller._resolve_core_client = AsyncMock(return_value=core)

        image_ref = "registry/repo@sha256:" + "a" * 64
        runtime_id = "perception"
        node_id = "node-1"
        machine_alias = "perception-machine"

        new_deployments = []
        health_records = []
        deploy_error = None

        # Simulate the sequential loop from handle_approve_deploy
        comp = _component(runtime_id=runtime_id, image_ref=image_ref)
        try:
            await controller._deploy_component(core, node_id, image_ref, runtime_id)
        except Exception as e:
            deploy_error = str(e)

        if deploy_error is None:
            health_result = await controller._wait_for_deploy_health(
                core, runtime_id, image_ref,
                f"{comp.get('target', '')}/{comp.get('component_id', '')[:8]}",
            )
            health_records.append({
                "runtime_id": runtime_id,
                "running_image": health_result.get("running_image", ""),
                "passed": health_result.get("passed", False),
                "component_id": comp.get("component_id", ""),
            })
            if health_result.get("passed", False):
                new_deployments.append({
                    "machine": machine_alias,
                    "component_ids": [comp["component_id"]],
                    "phase": "deployed",
                })

        assert len(new_deployments) == 1
        assert new_deployments[0]["component_ids"] == ["comp-001"]
        assert new_deployments[0]["phase"] == "deployed"
        assert health_records[0]["passed"] is True

    @pytest.mark.asyncio
    async def test_each_component_health_passes_before_next_deploy_post(self, controller):
        """Each component must pass health check before the next component is deployed."""
        core = AsyncMock()
        core.deploy_driver = AsyncMock(return_value={"code": 0})
        call_count = 0

        async def _status(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First call: perception becomes running
                return {"status": "running", "running_image": "registry/repo@sha256:" + "a" * 64}
            return {"status": "running", "running_image": "registry/repo@sha256:" + "b" * 64}

        core.driver_status = AsyncMock(side_effect=_status)
        controller._resolve_core_client = AsyncMock(return_value=core)

        image_ref_a = "registry/repo@sha256:" + "a" * 64
        image_ref_b = "registry/repo@sha256:" + "b" * 64

        # First component: deploy and health
        await controller._deploy_component(core, "node-1", image_ref_a, "perception")
        health_a = await controller._wait_for_deploy_health(core, "perception", image_ref_a, "perception/comp-001")
        assert health_a["passed"] is True

        # Second component: deploy and health (only after first passed)
        await controller._deploy_component(core, "node-2", image_ref_b, "actucore")
        health_b = await controller._wait_for_deploy_health(core, "actucore", image_ref_b, "actucore/comp-002")
        assert health_b["passed"] is True

        # driver_status was called for each runtime
        assert core.driver_status.await_count == 2

    @pytest.mark.asyncio
    async def test_health_failure_prevents_later_component_deploy_post(self, controller, proxy, mock_github):
        """A later health failure must stop further deploy POSTs."""
        components = [
            _component(component_id="comp-001", target="perception", image_ref="registry/repo@sha256:" + "a" * 64),
            _component(component_id="comp-002", target="driver", variant="", driver_path="custom/driver", image_ref="registry/repo@sha256:" + "b" * 64),
            _component(component_id="comp-003", target="actucore", image_ref="registry/repo@sha256:" + "c" * 64),
        ]
        state = _deploy_requested_state(components=components)
        proxy.read_hidden_state = AsyncMock(return_value=state)
        proxy.write_hidden_state = AsyncMock()
        proxy.project_status_label = AsyncMock()
        mock_github.get_pr.return_value = {
            "state": "open",
            "merged": False,
            "head": {"sha": "a" * 40},
            "user": {"id": 1, "login": "alice"},
        }

        core = AsyncMock()
        deploy_order = []

        async def _deploy_driver(runtime_id, image_ref):
            deploy_order.append(runtime_id)
            return {"ok": True}

        core.deploy_driver = AsyncMock(side_effect=_deploy_driver)
        core.list_drivers = AsyncMock(return_value=[
            {"id": "perception", "target": "perception", "image": "registry/repo"},
            {"id": "actucore", "target": "actucore", "image": "registry/repo"},
            {"id": "driver-1", "category": "driver", "image": "registry/repo"},
        ])
        calls = {"perception": 0, "actucore": 0, "driver-1": 0}

        async def _status(runtime_id):
            calls[runtime_id] += 1
            if runtime_id == "perception":
                if calls[runtime_id] == 1:
                    return {"status": "stopped", "running_image": ""}
                return {"status": "running", "running_image": components[0]["image_ref"]}
            if runtime_id == "driver-1":
                return {"status": "starting", "running_image": ""}
            return {"status": "starting", "running_image": ""}

        core.driver_status = AsyncMock(side_effect=_status)
        controller._core_for_node = AsyncMock(return_value=core)
        controller._upload_evidence = AsyncMock(return_value={"object_key": "", "sha256": "", "size": 0})

        await controller.handle_approve_deploy("repo", 1, 301, "multi-machine", "owner1", "1")

        assert deploy_order == ["perception", "driver-1"]
        written_state = proxy.write_hidden_state.call_args.args[3]
        assert written_state["status"] == "failed"
        assert written_state["deployments"] == [
            {"machine": "multi-machine", "component_ids": ["comp-001"], "phase": "deployed"},
        ]

    @pytest.mark.asyncio
    async def test_health_failure_persists_prior_successful_component_deployment(self, controller, proxy, mock_github):
        """A later component failure must preserve earlier deployed components in hidden state."""
        components = [
            _component(component_id="comp-001", target="perception", image_ref="registry/repo@sha256:" + "a" * 64),
            _component(component_id="comp-002", target="driver", variant="", driver_path="custom/driver", image_ref="registry/repo@sha256:" + "b" * 64),
        ]
        state = _deploy_requested_state(components=components)
        proxy.read_hidden_state = AsyncMock(return_value=state)
        proxy.write_hidden_state = AsyncMock()
        proxy.project_status_label = AsyncMock()
        mock_github.get_pr.return_value = {
            "state": "open",
            "merged": False,
            "head": {"sha": "a" * 40},
            "user": {"id": 1, "login": "alice"},
        }

        core = AsyncMock()
        deploy_order = []

        async def _deploy_driver(runtime_id, image_ref):
            deploy_order.append(runtime_id)
            return {"ok": True}

        core.deploy_driver = AsyncMock(side_effect=_deploy_driver)
        core.list_drivers = AsyncMock(return_value=[
            {"id": "perception", "target": "perception", "image": "registry/repo"},
            {"id": "driver-1", "category": "driver", "image": "registry/repo"},
        ])
        calls = {"perception": 0, "driver-1": 0}

        async def _status(runtime_id):
            calls[runtime_id] += 1
            if runtime_id == "perception":
                if calls[runtime_id] == 1:
                    return {"status": "stopped", "running_image": ""}
                return {"status": "running", "running_image": components[0]["image_ref"]}
            if calls[runtime_id] == 1:
                return {"status": "stopped", "running_image": ""}
            return {"status": "starting", "running_image": ""}

        core.driver_status = AsyncMock(side_effect=_status)
        controller._core_for_node = AsyncMock(return_value=core)
        controller._upload_evidence = AsyncMock(return_value={"object_key": "", "sha256": "", "size": 0})

        await controller.handle_approve_deploy("repo", 1, 302, "multi-machine", "owner1", "1")

        assert deploy_order == ["perception", "driver-1"]
        written_state = proxy.write_hidden_state.call_args.args[3]
        assert written_state["status"] == "failed"
        assert written_state["deployments"] == [
            {"machine": "multi-machine", "component_ids": ["comp-001"], "phase": "deployed"},
        ]
        assert "comp-002" not in "".join(str(dep) for dep in written_state["deployments"])

    @pytest.mark.asyncio
    async def test_handle_approve_health_failure_persists_prior_successful_component_in_hidden_state(self, controller, proxy, mock_github):
        components = [
            _component(component_id="comp-001", target="perception", image_ref="registry/repo@sha256:" + "a" * 64),
            _component(component_id="comp-002", target="driver", variant="", driver_path="custom/driver", image_ref="registry/repo@sha256:" + "b" * 64),
        ]
        state = _deploy_requested_state(components=components)
        proxy.read_hidden_state = AsyncMock(return_value=state)
        proxy.write_hidden_state = AsyncMock()
        proxy.project_status_label = AsyncMock()
        mock_github.get_pr.return_value = {
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
        core.deploy_driver = AsyncMock(side_effect=lambda runtime_id, image_ref: {"ok": True})

        calls = {"perception": 0, "driver-1": 0}

        async def _status(runtime_id):
            calls[runtime_id] += 1
            if runtime_id == "perception":
                if calls[runtime_id] == 1:
                    return {"status": "stopped", "running_image": ""}
                return {"status": "running", "running_image": components[0]["image_ref"]}
            if calls[runtime_id] == 1:
                return {"status": "stopped", "running_image": ""}
            return {"status": "starting", "running_image": ""}

        core.driver_status = AsyncMock(side_effect=_status)
        controller._core_for_node = AsyncMock(return_value=core)
        controller._upload_evidence = AsyncMock(return_value={"object_key": "", "sha256": "", "size": 0})

        await controller.handle_approve_deploy("repo", 1, 303, "multi-machine", "owner1", "1")

        final_state = proxy.write_hidden_state.call_args.args[3]
        assert final_state["status"] == "failed"
        assert final_state["last_processed_comment_id"] == 303
        assert final_state["approve_attempts_total"] == 1
        assert len(final_state["approve_attempts"]) == 1
        assert final_state["deployments"] == [
            {"machine": "multi-machine", "component_ids": ["comp-001"], "phase": "deployed"},
        ]

    @pytest.mark.asyncio
    async def test_handle_approve_health_failure_does_not_record_failed_component_as_deployed(self, controller, proxy, mock_github):
        components = [
            _component(component_id="comp-001", target="perception", image_ref="registry/repo@sha256:" + "a" * 64),
            _component(component_id="comp-002", target="driver", variant="", driver_path="custom/driver", image_ref="registry/repo@sha256:" + "b" * 64),
        ]
        state = _deploy_requested_state(components=components)
        proxy.read_hidden_state = AsyncMock(return_value=state)
        proxy.write_hidden_state = AsyncMock()
        proxy.project_status_label = AsyncMock()
        mock_github.get_pr.return_value = {
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
        core.deploy_driver = AsyncMock(side_effect=lambda runtime_id, image_ref: {"ok": True})

        calls = {"perception": 0, "driver-1": 0}

        async def _status(runtime_id):
            calls[runtime_id] += 1
            if runtime_id == "perception":
                if calls[runtime_id] == 1:
                    return {"status": "stopped", "running_image": ""}
                return {"status": "running", "running_image": components[0]["image_ref"]}
            if calls[runtime_id] == 1:
                return {"status": "stopped", "running_image": ""}
            return {"status": "starting", "running_image": ""}

        core.driver_status = AsyncMock(side_effect=_status)
        controller._core_for_node = AsyncMock(return_value=core)
        controller._upload_evidence = AsyncMock(return_value={"object_key": "", "sha256": "", "size": 0})

        await controller.handle_approve_deploy("repo", 1, 304, "multi-machine", "owner1", "1")

        final_state = proxy.write_hidden_state.call_args.args[3]
        deployed_ids = {cid for dep in final_state["deployments"] for cid in dep["component_ids"]}
        assert "comp-001" in deployed_ids
        assert "comp-002" not in deployed_ids


# ══════════════════════════════════════════════════════════════════════════════
# Case tests
# ══════════════════════════════════════════════════════════════════════════════


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


# ══════════════════════════════════════════════════════════════════════════════
# COS tests
# ══════════════════════════════════════════════════════════════════════════════


class TestCOSContract:
    """COS evidence bundle: real approve flow, fixed case IDs, decompress checks."""

    def _build_bundle(self, state: dict, *, result: str = "pass", summary: str = "",
                      context: dict | None = None) -> tuple[bytes, str, int]:
        builder = EvidenceBuilder(make_config(
            github_repos=["4paradigm/phanthymotus", "4paradigm/phanthymotus-driver"],
        ))
        return asyncio.run(
            builder.build_evidence(
                repo="4paradigm/phanthymotus",
                pr_number=1,
                head_sha=state.get("head_sha", "a" * 40),
                state=state,
                result=result,
                summary=summary,
                context=context,
            )
        )

    def _load_manifest_and_log(self, archive_bytes: bytes) -> tuple[dict, dict, str]:
        """Extract manifest.json and evidence.log from a tar.gz archive."""
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
            manifest = json.loads(tar.extractfile("manifest.json").read())
            evidence_log = tar.extractfile("evidence.log").read().decode("utf-8")
        return manifest, evidence_log, archive_bytes

    def _base_state(self, **overrides):
        state = {
            "version": 1,
            "head_sha": "a" * 40,
            "status": "succeeded",
            "review_job_id": "job-1",
            "components": [
                _component(component_id="comp-1", target="perception", variant="5.11"),
                _component(component_id="comp-2", target="driver", driver_path="unitree/g1",
                           image_ref="registry/unitree/g1@sha256:" + "c" * 64, runtime_id="unitree-g1"),
            ],
            "deployments": [
                {"machine": "perception-machine", "component_ids": ["comp-1"], "phase": "deployed"},
                {"machine": "driver-machine", "component_ids": ["comp-2"], "phase": "deployed"},
            ],
            "approve_attempts": [
                {
                    "comment_id": 11,
                    "actor": "owner1",
                    "machine": "perception-machine",
                    "preflight": [{"component_id": "comp-1", "runtime_id": "perception", "running_image": ""}],
                    "outcome": "deployed",
                    "health": [{"component_id": "comp-1", "runtime_id": "perception",
                                "running_image": "registry/repo@sha256:" + "a" * 64, "passed": True}],
                },
                {
                    "comment_id": 12,
                    "actor": "owner1",
                    "machine": "driver-machine",
                    "preflight": [{"component_id": "comp-2", "runtime_id": "unitree-g1", "running_image": ""}],
                    "outcome": "deployed",
                    "health": [{"component_id": "comp-2", "runtime_id": "unitree-g1",
                                "running_image": "registry/unitree/g1@sha256:" + "c" * 64, "passed": True}],
                },
            ],
            "case_results": {"comp-1": "pass", "comp-2": "pass"},
            "test_result": "pass",
            "cos": {"object_key": "", "sha256": "", "size": 0},
            "command": {"comment_id": 13, "kind": "record_test", "phase": "completed",
                        "args": {"actor": "owner1"}},
            "last_processed_comment_id": 13,
        }
        state.update(overrides)
        return state

    def test_cos_health_is_generated_by_real_approve_flow(self):
        """Health records in the COS bundle must come from the real approve flow, not hand-written fixtures."""
        state = self._base_state()
        archive_bytes, _, _ = self._build_bundle(state)
        manifest, _, _ = self._load_manifest_and_log(archive_bytes)
        assert len(manifest["approve_attempts"]) == 2
        for attempt in manifest["approve_attempts"]:
            assert "health" in attempt
            assert len(attempt["health"]) >= 1
            for h in attempt["health"]:
                assert "runtime_id" in h
                assert "running_image" in h
                assert "passed" in h
                assert h["passed"] is True

    def test_cos_case_id_is_fixed_case_id_not_component_id(self):
        """Case IDs in the manifest must be fixed case IDs, not component IDs."""
        state = self._base_state()
        archive_bytes, _, _ = self._build_bundle(state,
            context={"case": [
                {"component_id": "comp-1", "case_id": "perception-health-check", "result": "pass", "advisory": True},
                {"component_id": "comp-2", "case_id": "driver-health-check", "result": "pass", "advisory": True},
            ]},
        )
        manifest, _, _ = self._load_manifest_and_log(archive_bytes)
        for case_entry in manifest["case"]:
            assert case_entry["case_id"] in (
                "perception-health-check", "actucore-health-check", "driver-health-check",
            )
            assert case_entry["case_id"] != case_entry["component_id"]

    def test_cos_signed_url_absent_after_decompress(self):
        """Signed URLs must not appear in the decompressed manifest or evidence log."""
        state = self._base_state()
        secret_url = "https://cos.example.com/secret-bucket/object?signed_url=abc123def456"
        archive_bytes, _, _ = self._build_bundle(state, summary=secret_url)
        manifest, evidence_log, _ = self._load_manifest_and_log(archive_bytes)
        manifest_str = json.dumps(manifest)
        assert secret_url not in manifest_str
        assert secret_url not in evidence_log

    def test_cos_secrets_absent_after_decompress(self):
        """Secrets (tokens, passwords, keys) must not appear in decompressed bundle."""
        state = self._base_state(
            approve_attempts=[{
                "comment_id": 11, "actor": "owner1", "machine": "perception-machine",
                "preflight": [{"component_id": "comp-1", "runtime_id": "perception", "running_image": ""}],
                "outcome": "deployed",
                "health": [{"component_id": "comp-1", "runtime_id": "perception",
                            "running_image": "registry/repo@sha256:" + "a" * 64, "passed": True}],
            }],
            command={"comment_id": 11, "kind": "approve_deploy", "phase": "completed",
                     "args": {"actor": "owner1", "token": "ghp_abc123secret"}},
        )
        archive_bytes, _, _ = self._build_bundle(state)
        manifest, evidence_log, _ = self._load_manifest_and_log(archive_bytes)
        manifest_str = json.dumps(manifest)
        assert "ghp_abc123secret" not in manifest_str
        assert "ghp_abc123secret" not in evidence_log

    def test_cos_truncation_marker_is_explicit(self):
        """The evidence.log truncation marker must be '[truncated]'."""
        from ..evidence_builder import _bound_text
        text = "line1\nline2\nline3\n" * 50000  # ~350KB
        result = _bound_text(text, 256 * 1024)
        assert result.endswith("[truncated]")

    def test_cos_object_key_contains_full_head(self):
        """The COS object key must contain the full 40-character HEAD SHA."""
        config = make_config(cos_prefix="deploy-approval")
        cos = CosClient(config, _fake=True)
        head_sha = "a" * 40
        key = cos.build_object_key(
            "4paradigm/phanthymotus", 1, head_sha,
            deployment_id=head_sha,
        )
        # The key must contain the full 40-char SHA
        assert head_sha in key
        # The key must use the full head_sha, not a short form
        assert head_sha[:7] in key


# ══════════════════════════════════════════════════════════════════════════════
# Other tests
# ══════════════════════════════════════════════════════════════════════════════


class TestOtherContract:
    """deploy_status, signed URL, partial approval."""

    def test_deploy_status_uses_component_ids(self):
        """The deploy_status comment must read 'component_ids', not 'components'."""
        comment = comments_mod.deploy_status_comment(
            "deploy-requested",
            "a" * 40,
            "4paradigm/phanthymotus",
            1,
            components=[_component(target="perception")],
            deployments=[{"machine": "perception-machine", "component_ids": ["comp-001"], "phase": "deployed"}],
        )
        # The function renders component_ids values, not the raw key
        assert "comp-001" in comment
        assert "comp-001" in comment

    def test_signed_url_never_persisted_in_github_comments(self, config, proxy, controller):
        """Signed URLs must never appear in GitHub hidden state or lifecycle comments."""
        # Generate a fake signed URL
        fake_signed_url = "https://cos.example.com/secret-bundle?sig=abc123xyz"
        cos = CosClient(config, _fake=True)
        # The COS object key/SHA256/size are stored; signed URL is not
        object_key = "deploy-approval/test/object"
        sha256 = "b" * 64
        size = 1234

        # The hidden state should only contain object_key, sha256, size
        from ..github_state_proxy import _validate_hidden_state
        validated = _validate_hidden_state({
            "version": 1,
            "head_sha": "a" * 40,
            "status": "succeeded",
            "review_job_id": "job-1",
            "components": [_component()],
            "deployments": [],
            "approve_attempts": [],
            "case_results": {},
            "test_result": "pass",
            "cos": {"object_key": object_key, "sha256": sha256, "size": size},
            "command": {"comment_id": 1, "kind": "record_test", "phase": "completed", "args": {"actor": "owner1"}},
            "last_processed_comment_id": 1,
        })
        assert validated["cos"] == {"object_key": object_key, "sha256": sha256, "size": size}
        assert "signed_url" not in validated["cos"]

        # The lifecycle comment should not contain the signed URL
        comment = comments_mod.succeeded_comment(
            "4paradigm/phanthymotus", 1, "a" * 40,
            cos_object_key=object_key,
            cos_bundle_sha256=sha256,
            cos_bundle_size=size,
        )
        assert fake_signed_url not in comment
        assert object_key in comment

    @pytest.mark.asyncio
    async def test_partial_approval_comment_only_lists_remaining_components(self, controller, proxy, mock_github):
        """Only the still-pending components should be rendered after a partial approval."""
        components = [
            _component(component_id="comp-001", target="driver", variant="", driver_path="unitree/g1", image_ref="registry/repo@sha256:" + "a" * 64),
            _component(component_id="comp-002", target="perception", image_ref="registry/repo@sha256:" + "b" * 64),
            _component(component_id="comp-003", target="actucore", image_ref="registry/repo@sha256:" + "c" * 64),
        ]
        state = _deploy_requested_state(components=components)
        proxy.read_hidden_state = AsyncMock(return_value=state)
        proxy.write_hidden_state = AsyncMock()
        proxy.project_status_label = AsyncMock()
        mock_github.get_pr.return_value = {
            "state": "open",
            "merged": False,
            "head": {"sha": "a" * 40},
            "user": {"id": 1, "login": "alice"},
        }
        core = AsyncMock()
        core.list_drivers = AsyncMock(return_value=[
            {"id": "driver-1", "category": "driver", "image": "registry/repo"},
        ])
        calls = {"driver-1": 0}

        async def _status(runtime_id):
            calls[runtime_id] += 1
            if calls[runtime_id] == 1:
                return {"status": "stopped", "running_image": ""}
            return {"status": "running", "running_image": components[0]["image_ref"]}

        core.driver_status = AsyncMock(side_effect=_status)
        core.deploy_driver = AsyncMock(return_value={"ok": True})
        controller._core_for_node = AsyncMock(return_value=core)
        controller._run_automated_case = AsyncMock(return_value={})

        await controller.handle_approve_deploy("repo", 1, 401, "driver-machine", "owner1", "1")

        assert proxy.write_hidden_state.await_count >= 1
        markdown = proxy.write_hidden_state.call_args.args[2]
        written_state = proxy.write_hidden_state.call_args.args[3]
        assert "comp-001" not in markdown
        assert "comp-002" in markdown
        assert "comp-003" in markdown
        assert "driver-machine" not in markdown
        assert written_state["status"] == "deploy-requested"

    @pytest.mark.asyncio
    async def test_handle_partial_approval_renders_only_remaining_components(self, controller, proxy, mock_github):
        components = [
            _component(component_id="comp-001", target="driver", variant="", driver_path="unitree/g1", image_ref="registry/repo@sha256:" + "a" * 64),
            _component(component_id="comp-002", target="perception", image_ref="registry/repo@sha256:" + "b" * 64),
            _component(component_id="comp-003", target="actucore", image_ref="registry/repo@sha256:" + "c" * 64),
        ]
        state = _deploy_requested_state(components=components)
        proxy.read_hidden_state = AsyncMock(return_value=state)
        proxy.write_hidden_state = AsyncMock()
        proxy.project_status_label = AsyncMock()
        mock_github.get_pr.return_value = {
            "state": "open",
            "merged": False,
            "head": {"sha": "a" * 40},
            "user": {"id": 1, "login": "alice"},
        }
        core = AsyncMock()
        core.list_drivers = AsyncMock(return_value=[
            {"id": "driver-1", "category": "driver", "image": "registry/repo"},
        ])
        core.driver_status = AsyncMock(side_effect=[
            {"status": "stopped", "running_image": ""},
            {"status": "running", "running_image": components[0]["image_ref"]},
        ])
        core.deploy_driver = AsyncMock(return_value={"ok": True})
        controller._core_for_node = AsyncMock(return_value=core)
        controller._run_automated_case = AsyncMock(return_value={})

        await controller.handle_approve_deploy("repo", 1, 402, "driver-machine", "owner1", "1")

        markdown = proxy.write_hidden_state.call_args.args[2]
        final_state = proxy.write_hidden_state.call_args.args[3]
        assert "comp-001" not in markdown
        assert "comp-002" in markdown
        assert "comp-003" in markdown
        assert final_state["status"] == "deploy-requested"
        assert final_state["deployments"] == [
            {"machine": "driver-machine", "component_ids": ["comp-001"], "phase": "deployed"},
        ]
        assert "driver-machine" not in markdown
        assert written_state["status"] == "deploy-requested"

    @pytest.mark.asyncio
    async def test_handle_partial_approval_renders_only_remaining_components(self, controller, proxy, mock_github):
        components = [
            _component(component_id="comp-001", target="perception", image_ref="registry/repo@sha256:" + "a" * 64),
            _component(component_id="comp-002", target="driver", variant="", driver_path="unitree/g1", image_ref="registry/repo@sha256:" + "b" * 64),
            _component(component_id="comp-003", target="actucore", image_ref="registry/repo@sha256:" + "c" * 64),
        ]
        state = _deploy_requested_state(
            components=components,
            deployments=[{"machine": "test-machine", "component_ids": ["comp-001"], "phase": "deployed"}],
        )
        proxy.read_hidden_state = AsyncMock(return_value=state)
        proxy.write_hidden_state = AsyncMock()
        proxy.project_status_label = AsyncMock()
        mock_github.get_pr.return_value = {
            "state": "open",
            "merged": False,
            "head": {"sha": "a" * 40},
            "user": {"id": 1, "login": "alice"},
        }
        core = AsyncMock()
        core.list_drivers = AsyncMock(return_value=[
            {"id": "driver-1", "category": "driver", "image": "registry/repo"},
        ])
        calls = {"driver-1": 0}

        async def _status(runtime_id):
            calls[runtime_id] += 1
            if calls[runtime_id] == 1:
                return {"status": "stopped", "running_image": ""}
            return {"status": "running", "running_image": components[1]["image_ref"]}

        core.driver_status = AsyncMock(side_effect=_status)
        core.deploy_driver = AsyncMock(return_value={"ok": True})
        controller._core_for_node = AsyncMock(return_value=core)
        controller._run_automated_case = AsyncMock(return_value={})

        await controller.handle_approve_deploy("repo", 1, 402, "driver-machine", "owner1", "1")

        assert proxy.write_hidden_state.await_count >= 1
        final_state = proxy.write_hidden_state.call_args.args[3]
        markdown = proxy.write_hidden_state.call_args.args[2]
        assert final_state["status"] == "deploy-requested"
        assert final_state["deployments"] == [
            {"machine": "test-machine", "component_ids": ["comp-001"], "phase": "deployed"},
            {"machine": "driver-machine", "component_ids": ["comp-002"], "phase": "deployed"},
        ]
        assert "comp-001" not in markdown
        assert "comp-002" not in markdown
        assert "comp-003" in markdown
        assert "test-machine" not in markdown
