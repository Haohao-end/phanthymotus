"""V8 real-contract alignment tests."""

from __future__ import annotations

import asyncio
import io
import json
import tarfile
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from .. import comments as comments_mod
from ..config import Config
from ..evidence_builder import EvidenceBuilder
from ..github_state_proxy import _validate_hidden_state
from ..models import MachineInfo
from ..policy import Policy, load_machines
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
    client.get_issue_comments = AsyncMock(return_value=[])
    client.post_issue_comment = AsyncMock(return_value={"id": 42})
    client.update_comment = AsyncMock()
    client.get_pr = AsyncMock()
    client.collaborator_permission = AsyncMock(return_value="admin")
    client.get_issue_labels = AsyncMock(return_value=[])
    client.set_issue_labels = AsyncMock()
    client.list_open_prs = AsyncMock(return_value=[])
    return client


@pytest.fixture
def proxy(config, mock_github):
    from ..github_state_proxy import GitHubStateProxy

    return GitHubStateProxy(config, mock_github, bot_user_id="12345", bot_login="test-bot")


@pytest.fixture
def policy(config):
    p = Policy(config)
    p.machines = {
        "perception-machine": MachineInfo(
            alias="perception-machine",
            node_id="node-perception",
            owners=["owner1"],
            node_host="127.0.0.1",
            targets=["perception", "actucore"],
            platforms=["linux/arm64"],
            variants=["5.11", "6.1"],
        ),
        "driver-machine": MachineInfo(
            alias="driver-machine",
            node_id="node-driver",
            owners=["driver-owner"],
            node_host="127.0.0.2",
            targets=["driver"],
            platforms=["linux/arm64"],
            driver_paths=["unitree/g1", "agibot/AimDK_X2", "newvendor/alpha-beta"],
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
    c = DeployController(config, proxy, policy, mock_github, review, registry)
    c._run_automated_case = AsyncMock(return_value={})
    return c


def _component(
    component_id: str,
    target: str,
    *,
    variant: str = "",
    driver_path: str = "",
    image_ref: str = "registry.example/repo@sha256:" + "a" * 64,
    resolved_platform: str = "linux/arm64",
) -> dict:
    return {
        "component_id": component_id,
        "target": target,
        "driver_path": driver_path,
        "variant": variant,
        "review_image_tag": "registry/repo:v1",
        "image_ref": image_ref,
        "resolved_platform": resolved_platform,
    }


def _review_job(repo: str, pr_number: int, head_sha: str, builds: list[dict], *, completed_at: str) -> ReviewJobInfo:
    return ReviewJobInfo({
        "id": f"job-{repo.split('/')[-1]}-{pr_number}",
        "repo": repo,
        "pr_number": pr_number,
        "head_sha": head_sha,
        "status": "review_done",
        "review_text": "review complete",
        "options": {"build_only": False},
        "build_results": builds,
        "completed_at": completed_at,
    })


def _open_pr(head_sha: str = "a" * 40, *, user_id: int = 111, login: str = "alice") -> dict:
    return {
        "state": "open",
        "merged": False,
        "head": {"sha": head_sha},
        "user": {"id": user_id, "login": login},
    }


def _fake_request(config, proxy, controller, payload, signature="sha256=" + "0" * 64):
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


def _build_bundle(state: dict, *, result: str = "pass", summary: str = ""):
    builder = EvidenceBuilder(make_config(github_repos=["4paradigm/phanthymotus", "4paradigm/phanthymotus-driver"]))
    return asyncio.run(
        builder.build_evidence(
            repo="4paradigm/phanthymotus",
            pr_number=1,
            head_sha=state.get("head_sha", "a" * 40),
            state=state,
            result=result,
            summary=summary,
        )
    )


def _base_state(**overrides):
    state = {
        "version": 1,
        "head_sha": "a" * 40,
        "status": "deploy-requested",
        "review_job_id": "job-1",
        "components": [_component("comp-1", "perception", variant="5.11")],
        "deployments": [],
        "approve_attempts": [],
        "case_results": {},
        "test_result": "",
        "cos": {"object_key": "", "sha256": "", "size": 0},
        "command": {"comment_id": 1, "kind": "approve_deploy", "phase": "completed", "args": {"machine": "perception-machine", "actor": "owner1"}},
        "last_processed_comment_id": 1,
    }
    state.update(overrides)
    return state


def _load_manifest_and_log(archive_bytes: bytes):
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
        names = tar.getnames()
        manifest = json.loads(tar.extractfile("manifest.json").read().decode("utf-8"))
        evidence_log = tar.extractfile("evidence.log").read().decode("utf-8")
    return names, manifest, evidence_log


def test_default_supported_repos_include_both_real_repositories():
    cfg = Config(github_token="tok")
    assert cfg.github_repos == ["4paradigm/phanthymotus", "4paradigm/phanthymotus-driver"]


@pytest.mark.asyncio
async def test_unknown_repository_fails_closed(config, proxy, controller):
    config.webhook_enabled = True
    config.github_webhook_secret = "secret"
    payload = {
        "action": "created",
        "repository": {"full_name": "evil/repo"},
        "issue": {"number": 1, "pull_request": {}},
        "comment": {"id": 99},
    }
    request = _fake_request(config, proxy, controller, payload)

    with patch("agents.deploy_approval.router_webhook._verify_signature_impl", return_value=True):
        with pytest.raises(Exception) as exc:
            await webhook(request)

    assert getattr(exc.value, "status_code", None) == 404


@pytest.mark.asyncio
async def test_same_pr_number_across_repositories_never_cross_binds_review_job(controller):
    head_a = "a" * 40
    head_b = "b" * 40
    job_a_obj = _review_job(
        "4paradigm/phanthymotus",
        17,
        head_a,
        [{"target": "perception", "driver_path": "", "variant": "5.11", "success": True, "image_tag": "registry.example/repo:tag-a"}],
        completed_at="2026-09-01T10:00:00Z",
    )
    job_b_obj = _review_job(
        "4paradigm/phanthymotus-driver",
        17,
        head_b,
        [{"target": "driver", "driver_path": "unitree/g1", "variant": "", "success": True, "image_tag": "registry.example/driver:tag-b"}],
        completed_at="2026-09-01T11:00:00Z",
    )
    controller.review.list_jobs = AsyncMock(return_value=[
        job_a_obj,
        job_b_obj,
    ])
    controller.review.get_job = AsyncMock(side_effect=lambda jid: {
        "job-phanthymotus-17": job_a_obj,
        "job-phanthymotus-driver-17": job_b_obj,
    }.get(jid))

    job_a, _ = await controller.get_builds_for_pr("4paradigm/phanthymotus", 17, head_a)
    job_b, _ = await controller.get_builds_for_pr("4paradigm/phanthymotus-driver", 17, head_b)

    assert job_a == "job-phanthymotus-17"
    assert job_b == "job-phanthymotus-driver-17"


@pytest.mark.asyncio
async def test_phanthymotus_core_only_is_not_deployable(controller, proxy, mock_github):
    mock_github.get_comment.return_value = {"user": {"id": 111, "login": "alice"}, "body": "/request_deploy"}
    mock_github.get_pr.return_value = _open_pr()
    review_job = _review_job(
        "4paradigm/phanthymotus",
        1,
        "a" * 40,
        [{"target": "CORE", "driver_path": "", "variant": "", "success": True, "image_tag": "registry.example/repo:tag-core"}],
        completed_at="2026-09-01T10:00:00Z",
    )
    controller.review.list_jobs = AsyncMock(return_value=[review_job])
    controller.review.get_job = AsyncMock(return_value=review_job)
    proxy.post_issue_comment = AsyncMock()
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    await controller.handle_request_deploy("4paradigm/phanthymotus", 1, 99)

    proxy.write_hidden_state.assert_not_called()
    proxy.post_issue_comment.assert_called()


@pytest.mark.asyncio
async def test_phanthymotus_core_plus_perception_deploys_only_perception(controller, proxy, mock_github):
    mock_github.get_comment.return_value = {"user": {"id": 111, "login": "alice"}, "body": "/request_deploy"}
    mock_github.get_pr.return_value = _open_pr()
    review_job = _review_job(
        "4paradigm/phanthymotus",
        1,
        "a" * 40,
        [
            {"target": "CORE", "driver_path": "", "variant": "", "success": True, "image_tag": "registry.example/repo:tag-core"},
            {"target": "perception", "driver_path": "", "variant": "5.11", "success": True, "image_tag": "registry.example/repo:tag-perception"},
        ],
        completed_at="2026-09-01T10:00:00Z",
    )
    proxy.read_hidden_state = AsyncMock(return_value={
        "version": 1,
        "head_sha": "a" * 40,
        "status": "deploy-ready",
        "review_job_id": "job-phanthymotus-1",
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
    controller.review.list_jobs = AsyncMock(return_value=[review_job])
    controller.review.get_job = AsyncMock(return_value=review_job)
    controller.registry.resolve.return_value = SimpleNamespace(
        image_ref="registry.example/perception@sha256:" + "b" * 64,
        platform="linux/arm64",
    )
    proxy.write_hidden_state = AsyncMock()
    proxy.project_status_label = AsyncMock()

    await controller.handle_request_deploy("4paradigm/phanthymotus", 1, 100)

    written_state = proxy.write_hidden_state.call_args.args[3]
    assert [c["target"] for c in written_state["components"]] == ["perception"]
    assert written_state["review_job_id"] == "job-phanthymotus-1"


def test_phanthymotus_actucore_runtime_id_is_exact(controller):
    component = _component("comp-1", "actucore", variant="6.1", image_ref="registry.example/actucore@sha256:" + "c" * 64)
    runtime = controller._resolve_component_runtime(
        [
            {"id": "actucore", "category": "actucore", "image": "registry.example/actucore:latest"},
        ],
        component,
    )
    assert runtime["runtime_id"] == "actucore"


def _write_machines(tmp_path: Path, body: str) -> str:
    path = tmp_path / "machines.yaml"
    path.write_text(textwrap.dedent(body))
    return str(path)


def test_perception_review_variant_511_matches_canonical_machine_variant(tmp_path):
    machines = load_machines(_write_machines(tmp_path, """
        version: 1
        machines:
          m1:
            node_id: node-1
            node_host: 127.0.0.1
            owners: [owner1]
            targets: [perception]
            platforms: [linux/arm64]
            variants: [jetson-jp5.11]
    """))
    assert machines["m1"].variants == ["5.11"]


def test_perception_review_variant_61_matches_canonical_machine_variant(tmp_path):
    machines = load_machines(_write_machines(tmp_path, """
        version: 1
        machines:
          m1:
            node_id: node-1
            node_host: 127.0.0.1
            owners: [owner1]
            targets: [perception]
            platforms: [linux/arm64]
            variants: [jetson-jp6.1]
    """))
    assert machines["m1"].variants == ["6.1"]


def test_legacy_jetson_variant_is_normalized_once_or_rejected_explicitly(tmp_path):
    machines = load_machines(_write_machines(tmp_path, """
        version: 1
        machines:
          m1:
            node_id: node-1
            node_host: 127.0.0.1
            owners: [owner1]
            targets: [perception]
            platforms: [linux/arm64]
            variants: [jetson-jp5.11, jetson-jp5.11]
    """))
    assert machines["m1"].variants == ["5.11"]


def test_driver_path_is_used_for_machine_policy_not_runtime_id_derivation(controller):
    component = _component(
        "comp-driver",
        "driver",
        driver_path="agibot/AimDK_X2",
        image_ref="registry.example/agibot/x2@sha256:" + "d" * 64,
    )
    accepted = controller._get_component_ids_for_machine("driver-machine", [component])
    runtime = controller._resolve_component_runtime(
        [
            {"id": "agibot-x2", "category": "driver", "image": "registry.example/agibot/x2:latest"},
        ],
        component,
    )
    assert accepted == ["comp-driver"]
    assert runtime["runtime_id"] == "agibot-x2"


def test_driver_runtime_resolves_by_exact_agent_core_image_repository(controller):
    component = _component(
        "comp-driver",
        "driver",
        driver_path="unitree/g1",
        image_ref="registry.example/unitree/g1@sha256:" + "d" * 64,
    )
    runtime = controller._resolve_component_runtime(
        [
            {"id": "unitree-g1", "category": "driver", "image": "registry.example/unitree/g1:latest"},
        ],
        component,
    )
    assert runtime["runtime_id"] == "unitree-g1"


def test_driver_runtime_unitree_g1_real_shape(controller):
    component = _component(
        "comp-driver",
        "driver",
        driver_path="unitree/g1",
        image_ref="registry.example/unitree/g1@sha256:" + "e" * 64,
    )
    runtime = controller._resolve_component_runtime(
        [
            {"id": "unitree-g1", "category": "driver", "image": "registry.example/unitree/g1:release"},
        ],
        component,
    )
    assert runtime["runtime_id"] == "unitree-g1"


def test_driver_runtime_agibot_aimdk_x2_real_shape(controller):
    component = _component(
        "comp-driver",
        "driver",
        driver_path="agibot/AimDK_X2",
        image_ref="registry.example/agibot/x2@sha256:" + "f" * 64,
    )
    runtime = controller._resolve_component_runtime(
        [
            {"id": "agibot-x2", "category": "driver", "image": "registry.example/agibot/x2:latest"},
        ],
        component,
    )
    assert runtime["runtime_id"] == "agibot-x2"
    assert runtime["runtime_id"] != "agibot-AimDK_X2"


def test_driver_runtime_missing_exact_image_repository_fails_closed(controller):
    component = _component(
        "comp-driver",
        "driver",
        driver_path="unitree/g1",
        image_ref="registry.example/unitree/g1@sha256:" + "1" * 64,
    )
    runtime = controller._resolve_component_runtime(
        [
            {"id": "unitree-g1", "category": "driver", "image": "registry.example/unitree/g2:latest"},
        ],
        component,
    )
    assert runtime is None


def test_driver_runtime_ambiguous_image_repository_fails_closed(controller):
    component = _component(
        "comp-driver",
        "driver",
        driver_path="unitree/g1",
        image_ref="registry.example/unitree/g1@sha256:" + "2" * 64,
    )
    runtime = controller._resolve_component_runtime(
        [
            {"id": "unitree-g1-a", "category": "driver", "image": "registry.example/unitree/g1:latest"},
            {"id": "unitree-g1-b", "category": "driver", "image": "registry.example/unitree/g1:release"},
        ],
        component,
    )
    assert runtime is None


def test_driver_runtime_does_not_use_substring_or_fuzzy_match(controller):
    component = _component(
        "comp-driver",
        "driver",
        driver_path="unitree/g1",
        image_ref="registry.example/unitree/g1@sha256:" + "3" * 64,
    )
    runtime = controller._resolve_component_runtime(
        [
            {"id": "unitree-g1-extra", "category": "driver", "image": "registry.example/unitree/g1-extra:latest"},
        ],
        component,
    )
    assert runtime is None


def test_new_driver_vendor_requires_no_hardcoded_vendor_branch(controller):
    component = _component(
        "comp-driver",
        "driver",
        driver_path="newvendor/alpha-beta",
        image_ref="registry.example/newvendor/alpha-beta@sha256:" + "4" * 64,
    )
    runtime = controller._resolve_component_runtime(
        [
            {"id": "newvendor-alpha-beta", "category": "driver", "image": "registry.example/newvendor/alpha-beta:release"},
        ],
        component,
    )
    assert runtime["runtime_id"] == "newvendor-alpha-beta"


def test_cos_bundle_default_members_are_exactly_manifest_and_evidence_log():
    state = _base_state()
    archive_bytes, _, _ = _build_bundle(state)
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
        assert tar.getnames() == ["manifest.json", "evidence.log"]


def test_cos_manifest_contains_minimal_developer_owner_evidence():
    state = _base_state(
        approve_attempts=[{
            "comment_id": 9,
            "actor": "owner1",
            "machine": "perception-machine",
            "preflight": [{"component_id": "comp-1", "runtime_id": "perception", "running_image": ""}],
            "outcome": "deployed",
            "health": [{"component_id": "comp-1", "runtime_id": "perception", "running_image": "registry.example/perception@sha256:" + "a" * 64, "passed": True}],
        }],
        case_results={"comp-1": "pass"},
    )
    _, manifest, _ = _load_manifest_and_log(_build_bundle(state)[0])
    assert set(manifest.keys()) == {
        "schema_version",
        "source",
        "components",
        "approve_attempts",
        "approve_attempts_total",
        "approve_attempts_truncated",
        "case",
        "final",
    }
    assert "node_host" not in json.dumps(manifest)
    assert manifest["source"]["repo"] == "4paradigm/phanthymotus"


def test_cos_manifest_records_blocked_occupied_new_approve_attempt():
    state = _base_state(
        approve_attempts=[{
            "comment_id": 10,
            "actor": "owner1",
            "machine": "driver-machine",
            "preflight": [{"component_id": "comp-1", "runtime_id": "unitree-g1", "running_image": "registry.example/unitree/g1@sha256:" + "b" * 64}],
            "outcome": "blocked_occupied",
            "health": [],
        }],
    )
    _, manifest, _ = _load_manifest_and_log(_build_bundle(state)[0])
    attempt = manifest["approve_attempts"][0]
    assert attempt["outcome"] == "blocked_occupied"
    assert attempt["preflight"][0]["runtime_id"] == "unitree-g1"
    assert attempt["preflight"][0]["running_image"].endswith("b" * 12)


def test_cos_manifest_records_exact_runtime_and_immutable_health():
    state = _base_state(
        components=[_component("comp-1", "driver", driver_path="unitree/g1", image_ref="registry.example/unitree/g1@sha256:" + "c" * 64)],
        approve_attempts=[{
            "comment_id": 11,
            "actor": "owner1",
            "machine": "driver-machine",
            "preflight": [{"component_id": "comp-1", "runtime_id": "unitree-g1", "running_image": ""}],
            "outcome": "deployed",
            "health": [{"component_id": "comp-1", "runtime_id": "unitree-g1", "running_image": "registry.example/unitree/g1@sha256:" + "c" * 64, "passed": True}],
        }],
    )
    _, manifest, _ = _load_manifest_and_log(_build_bundle(state)[0])
    assert manifest["components"][0]["image_ref"].endswith("@sha256:" + "c" * 64)
    assert manifest["approve_attempts"][0]["health"][0]["runtime_id"] == "unitree-g1"
    assert manifest["approve_attempts"][0]["health"][0]["passed"] is True


def test_cos_case_result_is_advisory():
    state = _base_state(case_results={"comp-1": "pass"})
    _, manifest, _ = _load_manifest_and_log(_build_bundle(state)[0])
    assert manifest["case"][0]["advisory"] is True


def test_cos_evidence_log_is_bounded_to_256k():
    state = _base_state(
        approve_attempts=[{
            "comment_id": 12,
            "actor": "owner1",
            "machine": "driver-machine",
            "preflight": [{"component_id": "comp-1", "runtime_id": "unitree-g1", "running_image": "x" * (512 * 1024)}],
            "outcome": "blocked_occupied",
            "health": [],
        }],
    )
    archive_bytes, _, _ = _build_bundle(state)
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
        log_size = tar.getmember("evidence.log").size
        assert log_size <= 256 * 1024


def test_cos_bundle_redacts_secrets_and_signed_url():
    state = _base_state(
        approve_attempts=[{
            "comment_id": 13,
            "actor": "owner1",
            "machine": "driver-machine",
            "preflight": [{"component_id": "comp-1", "runtime_id": "unitree-g1", "running_image": ""}],
            "outcome": "deployed",
            "health": [],
        }],
    )
    archive_bytes, _, _ = _build_bundle(state, summary="https://signed.example/secret")
    assert b"https://signed.example/secret" not in archive_bytes


def test_cos_manifest_excludes_node_host_by_default():
    state = _base_state()
    _, manifest, _ = _load_manifest_and_log(_build_bundle(state)[0])
    assert "node_host" not in json.dumps(manifest)


def test_cos_hidden_state_persists_only_object_key_sha256_size():
    state = {
        "version": 1,
        "head_sha": "a" * 40,
        "status": "succeeded",
        "review_job_id": "job-1",
        "components": [_component("comp-1", "perception", variant="5.11")],
        "deployments": [],
        "approve_attempts": [],
        "case_results": {},
        "test_result": "pass",
        "cos": {"object_key": "deploy-approval/x", "sha256": "b" * 64, "size": 1},
        "command": {"comment_id": 1, "kind": "record_test", "phase": "completed", "args": {"actor": "owner1"}},
        "last_processed_comment_id": 1,
    }
    assert _validate_hidden_state(state)["cos"] == {"object_key": "deploy-approval/x", "sha256": "b" * 64, "size": 1}


def test_deploy_requested_comment_is_compact_and_actionable():
    comment = comments_mod.deploy_requested(
        "4paradigm/phanthymotus",
        1,
        "a" * 40,
        [{"target": "perception", "driver_path": "", "variant": "5.11"}],
        [{"alias": "perception-machine", "component_ids": ["comp-1"]}],
    )
    assert "**Status:** `deploy-requested`" in comment
    assert "`/approve_deploy machine=<alias>`" in comment
    assert "node_host" not in comment
    assert "hidden JSON" not in comment
    assert len(comment) < 4000


def test_occupied_comment_has_zero_deploy_and_one_new_approve_action():
    comment = comments_mod.approve_deploy_occupied_comment(
        "4paradigm/phanthymotus",
        1,
        "a" * 40,
        "driver-machine",
        [{"target": "driver", "runtime_id": "unitree-g1", "component_id": "comp-1"}],
        {"comp-1": "registry.example/unitree/g1@sha256:" + "b" * 64},
    )
    assert "ZERO deployment was performed." in comment
    assert "/approve_deploy machine=driver-machine" in comment
    assert "running_image" in comment


def test_testing_comment_has_case_advisory_and_record_test_action():
    comment = comments_mod.testing(
        "4paradigm/phanthymotus",
        1,
        "a" * 40,
        case_result="comp-1=pass",
    )
    assert "Fixed Case results are advisory only." in comment
    assert "`/record_test result=pass|fail [summary=\"...\"]`" in comment


def test_terminal_comment_has_compact_evidence_link_without_internal_state_dump():
    comment = comments_mod.succeeded_comment(
        "4paradigm/phanthymotus",
        1,
        "a" * 40,
        cos_object_key="deploy-approval/x",
        cos_bundle_sha256="b" * 64,
        cos_bundle_size=123,
    )
    assert "signed.example" not in comment
    assert "hidden JSON" not in comment
    assert "node_host" not in comment
