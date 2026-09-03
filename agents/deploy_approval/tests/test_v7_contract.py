"""V7 Deploy Approval contract tests."""



from __future__ import annotations



from types import SimpleNamespace



import pytest

from unittest.mock import AsyncMock, MagicMock



from ..github_command_watcher import GitHubCommandWatcher

from ..github_state_proxy import GitHubStateProxy

from ..models import ALL_STATUSES

from ..policy import Policy

from ..review_client import ReviewJobInfo

from ..service import DeployController

from ..models import MachineInfo

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

    client.list_open_prs = AsyncMock(return_value=[])

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

            node_host="127.0.0.1",

            targets=["perception"],

            platforms=["linux/arm64"],

            variants=["5.11"],

        ),

        "driver-machine": MachineInfo(

            alias="driver-machine",

            node_id="node-2",

            owners=["owner1"],

            node_host="127.0.0.2",

            targets=["driver"],

            platforms=["linux/arm64"],

            variants=[""],

            driver_paths=["custom/driver"],

        ),

        "multi-machine": MachineInfo(

            alias="multi-machine",

            node_id="node-3",

            owners=["owner1"],

            node_host="127.0.0.3",

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

    c = DeployController(config, proxy, policy, mock_github, review, registry)

    c._run_automated_case = AsyncMock(return_value={})

    return c





def _component(component_id: str, target: str, *, variant: str = "5.11",

               driver_path: str = "", image_digest: str = "a" * 64,

               runtime_id: str = "") -> dict:

    runtime_id_val = runtime_id or target

    return {

        "component_id": component_id,

        "target": target,

        "driver_path": driver_path,

        "variant": variant,
        "review_image_tag": "registry/repo:v1",
        "image_ref": "registry/repo@sha256:" + image_digest,

        "resolved_platform": "linux/arm64",

        "runtime_id": runtime_id_val,

    }





def _state(**overrides):

    state = {

        "version": 1,

        "head_sha": "a" * 40,

        "status": "deploy-requested",

        "review_job_id": "job-1",

        "components": [_component("comp-1", "perception")],

        "deployments": [],

        "case_results": {},

        "test_result": "",

        "cos": {"object_key": "", "sha256": "", "size": 0},

        "command": {

            "comment_id": 10,

            "kind": "approve_deploy",

            "phase": "completed",

            "args": {"machine": "multi-machine"},

        },

        "last_processed_comment_id": 10,

    }

    state.update(overrides)

    return state





def _review_job(job_id: str, repo: str, pr_number: int, head_sha: str, *, completed_at: str):

    raw = {

        "id": job_id,

        "repo": repo,

        "pr_number": pr_number,

        "head_sha": head_sha,

        "status": "review_done",

        "review_text": "review complete",

        "options": {"build_only": False},

        "build_results": [

            {

                "idx": 0,

                "target": "perception",

                "driver_path": "",

                "variant": "5.11",

                "success": True,

                "image_tag": "registry/repo:v1",

            }

        ],

        "completed_at": completed_at,

    }

    return ReviewJobInfo(raw)





def _open_pr(head_sha: str = "a" * 40):

    return {

        "state": "open",

        "merged": False,

        "head": {"sha": head_sha},

        "user": {"id": 111, "login": "alice"},

    }





@pytest.mark.asyncio

async def test_review_lookup_does_not_pass_pr_number(controller):

    controller.review.list_jobs = AsyncMock(return_value=[])

    result = await controller.get_builds_for_pr("repo", 7, "a" * 40)

    assert result is None

    controller.review.list_jobs.assert_awaited_once_with(

        repo="repo", status="review_done",

        limit=100, offset=0,

    )





@pytest.mark.asyncio

async def test_review_lookup_exact_repo_pr_full_head_latest(controller):

    head = "a" * 40

    job_latest = _review_job("job-latest", "repo", 7, head, completed_at="2026-09-01T11:00:00Z")

    controller.review.list_jobs = AsyncMock(return_value=[

        _review_job("job-old", "repo", 7, head, completed_at="2026-09-01T10:00:00Z"),

        job_latest,

        _review_job("job-other-repo", "other", 7, head, completed_at="2026-09-01T12:00:00Z"),

        _review_job("job-other-pr", "repo", 8, head, completed_at="2026-09-01T12:00:00Z"),

    ])

    controller.review.get_job = AsyncMock(return_value=job_latest)



    job_id, builds = await controller.get_builds_for_pr("repo", 7, head)



    assert job_id == "job-latest"

    assert [b.target for b in builds] == ["perception"]





@pytest.mark.asyncio

async def test_clean_gate_ignores_runtime_status_when_image_empty(controller, proxy, mock_github):

    state = _state(components=[_component("comp-1", "perception")])

    proxy.read_hidden_state = AsyncMock(return_value=state)

    proxy.write_hidden_state = AsyncMock()

    proxy.project_status_label = AsyncMock()

    mock_github.get_pr.return_value = _open_pr()

    controller._core_for_node = AsyncMock()

    core = AsyncMock()

    core.list_drivers = AsyncMock(return_value=[{"id": "perception", "target": "perception", "image": "registry/repo@sha256:" + "a" * 64}])

    core.driver_status = AsyncMock(side_effect=[{"status": "busy", "running_image": ""}, {"status": "running", "running_image": "registry/repo@sha256:" + "a" * 64}])

    controller._core_for_node.return_value = core

    controller._deploy_component = AsyncMock(return_value={"result": "ok"})

    controller._run_automated_case = AsyncMock(return_value={})



    await controller.handle_approve_deploy("repo", 7, 99, "perception-machine", "owner1", "1")



    controller._deploy_component.assert_awaited_once()





@pytest.mark.asyncio

async def test_clean_gate_blocks_occupied_image_even_if_status_looks_clean(controller, proxy, mock_github):

    state = _state(components=[_component("comp-1", "perception")])

    proxy.read_hidden_state = AsyncMock(return_value=state)

    proxy.write_hidden_state = AsyncMock()

    proxy.project_status_label = AsyncMock()

    mock_github.get_pr.return_value = _open_pr()

    controller._core_for_node = AsyncMock()

    core = AsyncMock()

    core.list_drivers = AsyncMock(return_value=[{"id": "perception", "target": "perception", "image": "registry/repo@sha256:" + "a" * 64}])

    core.driver_status = AsyncMock(return_value={

        "status": "stopped",

        "running_image": "registry/repo@sha256:" + "b" * 64,

    })

    controller._core_for_node.return_value = core

    controller._deploy_component = AsyncMock()

    controller._run_automated_case = AsyncMock(return_value={})



    await controller.handle_approve_deploy("repo", 7, 99, "perception-machine", "owner1", "1")



    controller._deploy_component.assert_not_called()

    written_state = proxy.write_hidden_state.call_args.args[3]

    assert written_state["status"] == "deploy-requested"

    assert written_state["command"]["phase"] == "completed"





@pytest.mark.asyncio

async def test_clean_gate_preflights_all_components_before_any_deploy(controller, proxy, mock_github):

    state = _state(

        components=[

            _component("comp-1", "perception", variant="5.11"),

            _component("comp-2", "driver", variant="6.1", driver_path="custom/driver"),

        ],

    )

    proxy.read_hidden_state = AsyncMock(return_value=state)

    proxy.write_hidden_state = AsyncMock()

    proxy.project_status_label = AsyncMock()

    mock_github.get_pr.return_value = _open_pr()

    controller._core_for_node = AsyncMock()

    core = AsyncMock()

    core.list_drivers = AsyncMock(return_value=[

        {"id": "perception", "target": "perception", "variant": "5.11"},

        {"id": "actucore", "target": "actucore", "variant": "5.11"},

    ])

    seen_status_calls = 0



    async def _driver_status(driver_id: str):

        nonlocal seen_status_calls

        seen_status_calls += 1

        return {"status": "busy", "running_image": ""}



    core.driver_status = AsyncMock(side_effect=_driver_status)

    controller._core_for_node.return_value = core



    async def _deploy_component(*args, **kwargs):

        # Sequential flow: preflight for this component completed before deploy
        assert seen_status_calls >= 1

        return {"result": "ok"}



    controller._deploy_component = AsyncMock(side_effect=_deploy_component)

    controller._run_automated_case = AsyncMock(return_value={})



    await controller.handle_approve_deploy("repo", 7, 99, "perception-machine", "owner1", "1")



    assert seen_status_calls >= 2

    controller._deploy_component.assert_awaited()





@pytest.mark.asyncio

async def test_new_approve_rechecks_running_image_until_empty(controller, proxy, mock_github):

    state = _state(components=[_component("comp-1", "perception")])

    proxy.read_hidden_state = AsyncMock(return_value=state)

    proxy.write_hidden_state = AsyncMock()

    proxy.project_status_label = AsyncMock()

    mock_github.get_pr.return_value = _open_pr()

    controller._core_for_node = AsyncMock()

    core = AsyncMock()

    core.list_drivers = AsyncMock(return_value=[{"id": "perception", "target": "perception", "image": "registry/repo@sha256:" + "a" * 64}])

    core.driver_status = AsyncMock(side_effect=[

        {"status": "busy", "running_image": "registry/repo@sha256:" + "b" * 64},

        {"status": "busy", "running_image": ""},

    ])

    controller._core_for_node.return_value = core

    controller._deploy_component = AsyncMock(return_value={"result": "ok"})

    controller._run_automated_case = AsyncMock(return_value={})



    await controller.handle_approve_deploy("repo", 7, 99, "perception-machine", "owner1", "1")

    await controller.handle_approve_deploy("repo", 7, 100, "perception-machine", "owner1", "1")



    controller._deploy_component.assert_awaited_once()





@pytest.mark.asyncio

async def test_clean_gate_writes_executing_before_first_deploy_post(controller, proxy, mock_github):

    state = _state(components=[_component("comp-1", "perception")])

    proxy.read_hidden_state = AsyncMock(return_value=state)

    phases = []



    async def _write_hidden_state(repo, pr_number, markdown, hidden_state):

        phases.append(hidden_state["command"]["phase"])

        return {"id": 42}



    proxy.write_hidden_state = AsyncMock(side_effect=_write_hidden_state)

    proxy.project_status_label = AsyncMock()

    mock_github.get_pr.return_value = _open_pr()

    controller._core_for_node = AsyncMock()

    core = AsyncMock()

    core.list_drivers = AsyncMock(return_value=[{"id": "perception", "target": "perception", "image": "registry/repo@sha256:" + "a" * 64}])

    core.driver_status = AsyncMock(side_effect=[{"status": "running", "running_image": ""}, {"status": "running", "running_image": "registry/repo@sha256:" + "a" * 64}])

    controller._core_for_node.return_value = core



    async def _deploy_component(*args, **kwargs):

        assert phases and phases[0] == "executing"

        return {"result": "ok"}



    controller._deploy_component = AsyncMock(side_effect=_deploy_component)

    controller._run_automated_case = AsyncMock(return_value={})



    await controller.handle_approve_deploy("repo", 7, 99, "perception-machine", "owner1", "1")



    assert phases[0] == "executing"





@pytest.mark.asyncio

async def test_occupied_gate_advances_new_comment_cursor(controller, proxy, mock_github):

    state = _state(components=[_component("comp-1", "perception")])

    proxy.read_hidden_state = AsyncMock(return_value=state)

    proxy.write_hidden_state = AsyncMock()

    proxy.project_status_label = AsyncMock()

    mock_github.get_pr.return_value = _open_pr()

    controller._core_for_node = AsyncMock()

    core = AsyncMock()

    core.list_drivers = AsyncMock(return_value=[{"id": "perception", "target": "perception", "image": "registry/repo@sha256:" + "a" * 64}])

    core.driver_status = AsyncMock(return_value={

        "status": "stopped",

        "running_image": "registry/repo@sha256:" + "b" * 64,

    })

    controller._core_for_node.return_value = core

    controller._deploy_component = AsyncMock()

    controller._run_automated_case = AsyncMock(return_value={})



    await controller.handle_approve_deploy("repo", 7, 99, "perception-machine", "owner1", "1")



    written_state = proxy.write_hidden_state.call_args.args[3]

    assert written_state["command"]["comment_id"] == 99

    assert written_state["last_processed_comment_id"] == 99

    assert written_state["status"] == "deploy-requested"





@pytest.mark.asyncio

async def test_restart_executing_advances_cursor_to_command_comment(controller, proxy, mock_github):

    state = _state(

        status="deploy-requested",

        command={

            "comment_id": 42,

            "kind": "approve_deploy",

            "phase": "executing",

            "args": {"machine": "multi-machine"},

        },

        last_processed_comment_id=10,

    )

    proxy.read_hidden_state = AsyncMock(return_value=state)

    proxy.write_hidden_state = AsyncMock()

    proxy.project_status_label = AsyncMock()

    mock_github.get_pr.return_value = _open_pr()

    controller.review.list_jobs = AsyncMock(return_value=[])


    await controller.reconcile_pr("repo", 7)



    written_state = proxy.write_hidden_state.call_args.args[3]

    assert written_state["command"]["phase"] == "uncertain"

    assert written_state["last_processed_comment_id"] == 42





@pytest.mark.asyncio

async def test_restart_old_approve_comment_never_replayed(controller, proxy, mock_github):

    executing_state = _state(

        command={

            "comment_id": 42,

            "kind": "approve_deploy",

            "phase": "executing",

            "args": {"machine": "multi-machine"},

        },

        last_processed_comment_id=10,

    )

    uncertain_state = _state(

        status="review-required",

        command={

            "comment_id": 42,

            "kind": "approve_deploy",

            "phase": "completed",

            "args": {"machine": "multi-machine"},

        },

        last_processed_comment_id=42,

        components=[],

        deployments=[],

        review_job_id="",

    )

    proxy.read_hidden_state = AsyncMock(side_effect=[executing_state, uncertain_state])
    mock_github.get_pr.return_value = {"state": "open", "merged": False, "head": {"sha": "a" * 40}}

    proxy.get_issue_comments = AsyncMock(return_value=[

        {"id": 42, "body": "/approve_deploy machine=multi-machine", "user": {"id": 111, "login": "alice"}},

    ])

    proxy.write_hidden_state = AsyncMock()

    proxy.persist_cursor = AsyncMock()

    proxy.is_bot_comment = lambda comment: False

    controller.on_command = AsyncMock()



    watcher = GitHubCommandWatcher(config, proxy, controller)

    await watcher._process_pr("repo", 7)



    controller.on_command.assert_not_called()





@pytest.mark.asyncio

async def test_uncertain_same_head_relooks_up_review_job(controller, proxy, mock_github):

    state = _state(

        command={

            "comment_id": 42,

            "kind": "approve_deploy",

            "phase": "uncertain",

            "args": {"machine": "multi-machine"},

        },

        last_processed_comment_id=42,

    )

    proxy.read_hidden_state = AsyncMock(return_value=state)

    proxy.write_hidden_state = AsyncMock()

    proxy.project_status_label = AsyncMock()

    mock_github.get_pr.return_value = _open_pr()

    review_job = _review_job("job-2", "repo", 7, "a" * 40, completed_at="2026-09-01T12:00:00Z")
    controller.review.list_jobs = AsyncMock(return_value=[review_job])
    controller.review.get_job = AsyncMock(return_value=review_job)

    core = AsyncMock()

    core.list_drivers = AsyncMock(return_value=[

        {"id": "perception", "target": "perception", "variant": "5.11"}

    ])

    core.driver_status = AsyncMock(side_effect=[{"status": "busy", "running_image": ""}, {"status": "running", "running_image": "registry/repo@sha256:" + "a" * 64}])

    core.deploy_driver = AsyncMock()

    controller._core_for_node = AsyncMock(return_value=core)

    controller._run_automated_case = AsyncMock(return_value={})



    await controller.handle_approve_deploy("repo", 7, 43, "perception-machine", "owner1", "111")



    controller.review.list_jobs.assert_awaited_once_with(repo="repo", status="review_done", limit=100, offset=0)

    written_state = proxy.write_hidden_state.call_args.args[3]

    assert written_state["status"] in {"deploy-requested", "testing"}





@pytest.mark.asyncio

async def test_uncertain_head_drift_requires_new_review(controller, proxy, mock_github):

    state = _state(

        command={

            "comment_id": 42,

            "kind": "approve_deploy",

            "phase": "uncertain",

            "args": {"machine": "multi-machine"},

        },

        last_processed_comment_id=42,

    )

    proxy.read_hidden_state = AsyncMock(return_value=state)

    proxy.write_hidden_state = AsyncMock()

    proxy.project_status_label = AsyncMock()

    mock_github.get_pr.return_value = _open_pr(head_sha="b" * 40)

    controller.review.list_jobs = AsyncMock()



    await controller.handle_approve_deploy("repo", 7, 43, "multi-machine", "owner1", "111")



    controller.review.list_jobs.assert_not_called()

    written_state = proxy.write_hidden_state.call_args.args[3]

    assert written_state["status"] == "review-required"





@pytest.mark.asyncio

async def test_uncertain_missing_exact_review_job_requires_new_review(controller, proxy, mock_github):

    state = _state(

        command={

            "comment_id": 42,

            "kind": "approve_deploy",

            "phase": "uncertain",

            "args": {"machine": "multi-machine"},

        },

        last_processed_comment_id=42,

    )

    proxy.read_hidden_state = AsyncMock(return_value=state)

    proxy.write_hidden_state = AsyncMock()

    proxy.project_status_label = AsyncMock()

    mock_github.get_pr.return_value = _open_pr()

    controller.review.list_jobs = AsyncMock(return_value=[
        _review_job("job-wrong", "repo", 7, "b" * 40, completed_at="2026-09-01T12:00:00Z"),

    ])



    await controller.handle_approve_deploy("repo", 7, 43, "multi-machine", "owner1", "111")



    written_state = proxy.write_hidden_state.call_args.args[3]

    assert written_state["status"] == "review-required"





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

    state = _state(status="testing")

    state["deployments"] = [{"machine": "perception-machine", "component_ids": ["comp-1"], "phase": "deployed"}]

    state["components"] = [_component("comp-1", "perception")]

    proxy.read_hidden_state = AsyncMock(return_value=state)

    proxy.write_hidden_state = AsyncMock()

    proxy.project_status_label = AsyncMock()

    proxy.collaborator_permission = AsyncMock(return_value="admin")

    mock_github.get_pr.return_value = _open_pr()

    controller._upload_evidence = AsyncMock(return_value={"object_key": "", "sha256": "", "size": 0})

    controller.cos.generate_signed_url = AsyncMock(return_value="")



    await controller.handle_record_test("repo", 7, 101, "fail", "summary", "owner1", "")



    written_state = proxy.write_hidden_state.call_args.args[3]

    assert written_state["status"] == "failed"

    assert written_state["test_result"] == "fail"





@pytest.mark.asyncio

async def test_partial_machine_approval_stays_deploy_requested(controller, proxy, mock_github):

    state = _state(

        components=[

            _component("comp-1", "perception"),

            _component("comp-2", "driver", variant="6.1", driver_path="custom/driver"),

        ],

        deployments=[],

    )

    proxy.read_hidden_state = AsyncMock(return_value=state)

    proxy.write_hidden_state = AsyncMock()

    proxy.project_status_label = AsyncMock()

    mock_github.get_pr.return_value = _open_pr()

    controller._core_for_node = AsyncMock()

    core = AsyncMock()

    core.list_drivers = AsyncMock(return_value=[{"id": "perception", "target": "perception", "image": "registry/repo@sha256:" + "a" * 64, "variant": "5.11"}])

    core.driver_status = AsyncMock(side_effect=[{"status": "running", "running_image": ""}, {"status": "running", "running_image": "registry/repo@sha256:" + "a" * 64}])

    controller._core_for_node.return_value = core

    controller._deploy_component = AsyncMock(return_value={"result": "ok"})

    controller._run_automated_case = AsyncMock(return_value={})



    await controller.handle_approve_deploy("repo", 7, 99, "perception-machine", "owner1", "1")



    written_state = proxy.write_hidden_state.call_args.args[3]

    assert written_state["status"] == "deploy-requested"

    controller._run_automated_case.assert_not_called()





@pytest.mark.asyncio

async def test_all_machine_groups_deployed_enters_testing(controller, proxy, mock_github):

    state = _state(

        components=[

            _component("comp-1", "perception"),

            _component("comp-2", "driver", variant="6.1", driver_path="custom/driver"),

        ],

        deployments=[{"machine": "perception-machine", "component_ids": ["comp-1"], "phase": "deployed"}],

    )

    proxy.read_hidden_state = AsyncMock(return_value=state)

    proxy.write_hidden_state = AsyncMock()

    proxy.project_status_label = AsyncMock()

    mock_github.get_pr.return_value = _open_pr()

    controller._core_for_node = AsyncMock()

    core = AsyncMock()

    core.list_drivers = AsyncMock(return_value=[{"id": "unitree-g1", "category": "driver", "target": "driver", "image": "registry/repo@sha256:" + "a" * 64, "variant": "6.1"}])

    core.driver_status = AsyncMock(side_effect=[{"status": "running", "running_image": ""}, {"status": "running", "running_image": "registry/repo@sha256:" + "a" * 64}])

    controller._core_for_node.return_value = core

    controller._deploy_component = AsyncMock(return_value={"result": "ok"})

    controller._run_automated_case = AsyncMock(return_value={})



    await controller.handle_approve_deploy("repo", 7, 100, "driver-machine", "owner1", "1")



    written_state = proxy.write_hidden_state.call_args.args[3]

    assert written_state["status"] == "testing"





@pytest.mark.asyncio

async def test_case_fail_does_not_block_overall_manual_pass(controller, proxy, mock_github):

    state = _state(

        components=[_component("comp-1", "perception")],

        deployments=[],

    )

    proxy.read_hidden_state = AsyncMock(return_value=state)

    proxy.write_hidden_state = AsyncMock()

    proxy.project_status_label = AsyncMock()

    mock_github.get_pr.return_value = _open_pr()

    controller._core_for_node = AsyncMock()

    core = AsyncMock()

    core.list_drivers = AsyncMock(return_value=[{"id": "perception", "target": "perception", "image": "registry/repo@sha256:" + "a" * 64}])

    core.driver_status = AsyncMock(side_effect=[{"status": "running", "running_image": ""}, {"status": "running", "running_image": "registry/repo@sha256:" + "a" * 64}])

    controller._core_for_node.return_value = core

    controller._deploy_component = AsyncMock(return_value={"result": "ok"})

    controller._run_automated_case = AsyncMock(return_value={"comp-1": "fail"})

    controller._upload_evidence = AsyncMock(return_value={"object_key": "", "sha256": "", "size": 0})

    controller.cos.generate_signed_url = AsyncMock(return_value="")

    proxy.collaborator_permission = AsyncMock(return_value="admin")



    await controller.handle_approve_deploy("repo", 7, 99, "perception-machine", "owner1", "1")

    assert state["status"] == "testing"



    proxy.read_hidden_state = AsyncMock(return_value=state)

    await controller.handle_record_test("repo", 7, 101, "pass", "summary", "owner1", "")



    written_state = proxy.write_hidden_state.call_args.args[3]

    assert written_state["status"] == "succeeded"





@pytest.mark.asyncio

async def test_case_not_run_before_all_components_deployed(controller, proxy, mock_github):

    state = _state(

        components=[

            _component("comp-1", "perception"),

            _component("comp-2", "driver", variant="6.1", driver_path="custom/driver"),

        ],

        deployments=[],

    )

    proxy.read_hidden_state = AsyncMock(return_value=state)

    proxy.write_hidden_state = AsyncMock()

    proxy.project_status_label = AsyncMock()

    mock_github.get_pr.return_value = _open_pr()

    controller._core_for_node = AsyncMock()

    core = AsyncMock()

    core.list_drivers = AsyncMock(return_value=[{"id": "perception", "target": "perception", "image": "registry/repo@sha256:" + "a" * 64}])

    core.driver_status = AsyncMock(side_effect=[{"status": "running", "running_image": ""}, {"status": "running", "running_image": "registry/repo@sha256:" + "a" * 64}])

    controller._core_for_node.return_value = core

    controller._deploy_component = AsyncMock(return_value={"result": "ok"})

    controller._run_automated_case = AsyncMock(return_value={})



    await controller.handle_approve_deploy("repo", 7, 99, "perception-machine", "owner1", "1")



    controller._run_automated_case.assert_not_called()

    written_state = proxy.write_hidden_state.call_args.args[3]

    assert written_state["status"] == "deploy-requested"





@pytest.mark.asyncio

async def test_case_pass_does_not_auto_succeed(controller, proxy, mock_github):

    state = _state(

        components=[_component("comp-1", "perception")],

        deployments=[],

    )

    proxy.read_hidden_state = AsyncMock(return_value=state)

    proxy.write_hidden_state = AsyncMock()

    proxy.project_status_label = AsyncMock()

    mock_github.get_pr.return_value = _open_pr()

    controller._core_for_node = AsyncMock()

    core = AsyncMock()

    core.list_drivers = AsyncMock(return_value=[{"id": "perception", "target": "perception", "image": "registry/repo@sha256:" + "a" * 64}])

    core.driver_status = AsyncMock(side_effect=[{"status": "running", "running_image": ""}, {"status": "running", "running_image": "registry/repo@sha256:" + "a" * 64}])

    controller._core_for_node.return_value = core

    controller._deploy_component = AsyncMock(return_value={"result": "ok"})

    controller._run_automated_case = AsyncMock(return_value={"comp-1": "pass"})



    await controller.handle_approve_deploy("repo", 7, 99, "perception-machine", "owner1", "1")



    written_state = proxy.write_hidden_state.call_args.args[3]

    assert written_state["status"] == "testing"
