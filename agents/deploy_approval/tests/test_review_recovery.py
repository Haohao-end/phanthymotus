"""Focused offline regressions for frozen deploy-requested Review recovery.

All GitHub, archive, COS, and Agent Core boundaries in this module are fakes.
These tests are added for the independent acceptance run and are not executed
as part of the source-only repair task.
"""
from __future__ import annotations

import copy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from .. import review_comment_parser as review_parser
from ..evidence_models import make_round_id
from ..github_state_proxy import (
    _build_hidden_state_body,
    _build_history_block,
)
from ..image_ref import get_deploy_platform
from ..models import BuildInfo
from ..review_comment_parser import ReviewBuild, ReviewCommentEvidence, ReviewJobAnchor
from ..service import DeployController
from .conftest import make_config


REPO = "test-owner/phanthymotus"
PR = 347
HEAD = "a" * 40
PREFIX = HEAD[:12]
REVIEW_ID = "7950763"
REVIEW_LOGIN = "review-agent-bot"
OWNER = {"id": 1, "login": "alice", "type": "User"}
REVIEW_AGENT = {"id": int(REVIEW_ID), "login": REVIEW_LOGIN, "type": "Bot"}
OTHER_USER = {"id": 2, "login": "mallory", "type": "User"}
OLD_BUILD_ID = 200
OLD_TEST_ID = 205
OLD_CODE_ID = 210
OLD_REQUEST_ID = 220
REVIEW_REQUEST_ID = 230
NEW_BUILD_ID = 240
NEW_TEST_ID = 250
NEW_CODE_ID = 260
IMAGE = "registry.example/phanthymotus/perception:v2"


def _comment(comment_id, body, created_at, updated_at=None, user=None,
             *, repo=REPO, pr_number=PR, api="https://api.github.com"):
    return {
        "id": comment_id,
        "body": body,
        "created_at": created_at,
        "updated_at": updated_at or created_at,
        "url": f"{api}/repos/{repo}/issues/comments/{comment_id}",
        "issue_url": f"{api}/repos/{repo}/issues/{pr_number}",
        "user": copy.deepcopy(user or REVIEW_AGENT),
    }


def _build_body(label="new"):
    return (
        f"{review_parser.PR_REVIEW_MARKER}\n"
        f"## PR Review Agent\nCommit: {PREFIX}\n"
        f"{review_parser.BUILD_HEADING}\n"
        f"| Target | Status | Version | Took |\n"
        f"| perception (jetson-jp5.11) | success | `v2` | 1m |\n"
        f"<!-- {label} build body -->"
    )


def _state(**overrides):
    components = [{
        "component_id": "old-component",
        "target": "perception",
        "driver_path": "",
        "variant": "5.11",
        "review_image_tag": "registry.example/phanthymotus/perception:v1",
        "image_ref": "registry.example/phanthymotus/perception:v1",
        "resolved_platform": get_deploy_platform(),
    }]
    state = {
        "version": 1,
        "head_sha": HEAD,
        "status": "deploy-requested",
        "round_id": make_round_id(HEAD, OLD_REQUEST_ID),
        "round_started_at": "2026-11-03T03:16:01Z",
        "review_evidence": {
            "build_comment_id": OLD_BUILD_ID,
            "build_comment_updated_at": "2026-11-03T03:15:21Z",
            "commit_prefix": PREFIX,
            "resolved_head_sha": HEAD,
            "test_comment_id": OLD_TEST_ID,
            "test_comment_updated_at": "2026-11-03T03:15:40Z",
            "code_review_comment_id": OLD_CODE_ID,
            "code_review_comment_updated_at": "2026-11-03T03:15:50Z",
            "review_author_id": REVIEW_ID,
            "test_passed": 4,
            "test_failed": 0,
            "test_skipped": False,
        },
        "components": components,
        "deployments": [],
        "approve_attempts": [],
        "approve_attempts_total": 0,
        "approve_attempts_truncated": False,
        "deployment_logs": {},
        "case_results": {},
        "test_result": "",
        "cos": {"object_key": "", "sha256": "", "size": 0},
        "command": {
            "comment_id": OLD_REQUEST_ID,
            "kind": "request_deploy",
            "phase": "completed",
            "args": {},
        },
        "last_processed_comment_id": OLD_REQUEST_ID,
        "round_archive": None,
    }
    state.update(overrides)
    return state


class FakeProxy:
    def __init__(self, comments, pr):
        self.comments = {item["id"]: copy.deepcopy(item) for item in comments}
        self.pr = copy.deepcopy(pr)
        self.issue_comment_reads = 0
        self.hidden_state_reads = 0
        self.pr_reads = 0
        self.comment_reads = 0
        self.read_hook = None

    async def get_issue_comments(self, repo, pr_number):
        self.issue_comment_reads += 1
        if self.read_hook is not None:
            self.read_hook(self.issue_comment_reads, self.comments)
        return copy.deepcopy(list(self.comments.values()))

    async def get_comment(self, repo, comment_id):
        self.comment_reads += 1
        return copy.deepcopy(self.comments.get(comment_id, {}))

    async def get_pr(self, repo, pr_number):
        self.pr_reads += 1
        return copy.deepcopy(self.pr)

    async def read_hidden_state(self, repo, pr_number):
        self.hidden_state_reads += 1
        return None

    async def read_evidence_records(self, repo, pr_number):
        return []

    async def collaborator_permission(self, repo, login):
        return "admin"

    def is_bot_comment(self, comment):
        return comment.get("user", {}).get("type") == "Bot"


def _harness(monkeypatch):
    config = make_config(
        github_repos=[REPO], active_repos=[REPO],
        review_comment_author_id=REVIEW_ID,
        review_comment_author_login=REVIEW_LOGIN,
    )
    old_build = _comment(
        OLD_BUILD_ID, _build_body("old"), "2026-11-03T03:14:57Z",
        "2026-11-03T03:15:21Z",
    )
    old_test = _comment(
        OLD_TEST_ID,
        f"{review_parser.PR_REVIEW_MARKER}\n{review_parser.TEST_HEADING}\n| test | pass |",
        "2026-11-03T03:15:40Z",
    )
    old_code = _comment(
        OLD_CODE_ID,
        f"{review_parser.PR_REVIEW_MARKER}\n{review_parser.CODE_REVIEW_HEADING}\nNo findings.",
        "2026-11-03T03:15:50Z",
    )
    old_request = _comment(
        OLD_REQUEST_ID, "/request_deploy", "2026-11-03T03:16:01Z", user=OWNER,
    )
    review_request = _comment(
        REVIEW_REQUEST_ID,
        "/request_bot_review force realman/rm75_6f_v",
        "2026-11-03T03:35:00Z", user=OWNER,
    )
    new_build = _comment(
        NEW_BUILD_ID, _build_body(), "2026-11-03T03:35:44Z",
        "2026-11-03T03:36:03Z",
    )
    new_test = _comment(
        NEW_TEST_ID,
        f"{review_parser.PR_REVIEW_MARKER}\n{review_parser.TEST_HEADING}\n| test | pass |",
        "2026-11-03T03:36:10Z",
    )
    new_code = _comment(
        NEW_CODE_ID,
        f"{review_parser.PR_REVIEW_MARKER}\n{review_parser.CODE_REVIEW_HEADING}\nNo findings.",
        "2026-11-03T03:36:20Z",
    )
    comments = [old_build, old_test, old_code, old_request,
                review_request, new_build, new_test, new_code]
    pr = {
        "number": PR,
        "state": "open",
        "merged": False,
        "draft": False,
        "head": {"sha": HEAD},
        "base": {"repo": {"full_name": REPO}},
        "user": copy.deepcopy(OWNER),
        "updated_at": "2026-11-03T03:36:20Z",
    }
    proxy = FakeProxy(comments, pr)
    github = SimpleNamespace(resolve_commit_sha=AsyncMock(return_value=HEAD))
    controller = DeployController(config, proxy, SimpleNamespace(), github)
    component = {
        "component_id": "new-component",
        "target": "perception",
        "driver_path": "",
        "variant": "5.11",
        "review_image_tag": IMAGE,
        "image_ref": IMAGE,
        "resolved_platform": get_deploy_platform(),
    }
    evidence = ReviewCommentEvidence(
        head_sha=HEAD,
        commit_prefix=PREFIX,
        review_author_id=REVIEW_ID,
        review_author_login=REVIEW_LOGIN,
        builds=[ReviewBuild(
            target="perception", variant="5.11", success=True,
            version="v2", image_tag=IMAGE, image_ref=IMAGE,
        )],
        build_comment_id=NEW_BUILD_ID,
        build_comment_created_at="2026-11-03T03:35:44Z",
        build_comment_updated_at="2026-11-03T03:36:03Z",
        test_comment_id=NEW_TEST_ID,
        test_comment_created_at="2026-11-03T03:36:10Z",
        test_comment_updated_at="2026-11-03T03:36:10Z",
        test_passed=4,
        test_failed=0,
        test_skipped=False,
        code_review_comment_id=NEW_CODE_ID,
        code_review_created_at="2026-11-03T03:36:20Z",
        code_review_comment_updated_at="2026-11-03T03:36:20Z",
        code_review_text="No findings.",
        test_status="VALID",
        run_binding_valid=True,
        request_comment=copy.deepcopy(review_request),
        code_review_binding="DIRECT_SHA",
    )
    controller._extract_trusted_review_evidence = (
        lambda _comments, head_sha="": copy.deepcopy(evidence)
    )
    controller._review_build_infos = lambda _repo, _evidence: [BuildInfo(
        target="perception", driver_path="", variant="5.11",
        success=True, image_tag=IMAGE, deployable=True,
    )]
    controller._build_component_snapshot = AsyncMock(return_value=[copy.deepcopy(component)])
    holder = SimpleNamespace(latest_state="build-succeeded")

    def fake_extract_latest(comments_arg, trusted_id, trusted_login=""):
        anchors = [item for item in comments_arg
                   if isinstance(item, dict)
                   and item.get("id") in {OLD_BUILD_ID, NEW_BUILD_ID}]
        if not anchors:
            return None
        item = max(anchors, key=lambda value: (value["created_at"], value["id"]))
        state = (holder.latest_state if item["id"] == NEW_BUILD_ID
                 else "build-succeeded")
        return ReviewJobAnchor(
            comment_id=item["id"], commit_prefix=PREFIX,
            created_at=item["created_at"], updated_at=item["updated_at"],
            state=state, body=item["body"],
        )

    monkeypatch.setattr(review_parser, "extract_latest_review_job_anchor", fake_extract_latest)
    return SimpleNamespace(
        config=config, controller=controller, proxy=proxy, github=github,
        state=_state(), comments=comments, evidence=evidence,
        component=component, holder=holder, old_request=old_request,
        review_request=review_request,
    )


@pytest.mark.asyncio
async def test_r01_mutable_build_progress_comment_can_recover(monkeypatch):
    h = _harness(monkeypatch)
    status, candidate = await h.controller._review_recovery_candidate(
        REPO, PR, h.state, HEAD, final_recheck=False,
    )
    assert status == "ready"
    assert candidate["snapshot"]["build_comment_id"] == NEW_BUILD_ID
    assert candidate["snapshot"]["build_comment_updated_at"] == "2026-11-03T03:36:03Z"
    assert candidate["fingerprint"]["comments"][NEW_BUILD_ID]["created_at"] == "2026-11-03T03:35:44Z"
    assert candidate["fingerprint"]["comments"][NEW_BUILD_ID]["updated_at"] == "2026-11-03T03:36:03Z"


@pytest.mark.asyncio
async def test_r02_old_build_update_must_match_frozen_evidence(monkeypatch):
    h = _harness(monkeypatch)
    h.proxy.comments[OLD_BUILD_ID]["updated_at"] = "2026-11-03T03:15:22Z"
    status, candidate = await h.controller._review_recovery_candidate(
        REPO, PR, h.state, HEAD, final_recheck=False,
    )
    assert status == "review_run_identity_mismatch"
    assert candidate is None


@pytest.mark.asyncio
@pytest.mark.parametrize("comment_id", [NEW_BUILD_ID, REVIEW_REQUEST_ID, NEW_TEST_ID, NEW_CODE_ID])
async def test_r03_to_r06_final_comment_snapshot_changes_fail_closed(monkeypatch, comment_id):
    h = _harness(monkeypatch)

    def edit_during_reread(read_number, comments):
        if read_number == 2:
            comments[comment_id]["body"] += " edited during final check"
            comments[comment_id]["updated_at"] = "2026-11-03T03:40:00Z"

    h.proxy.read_hook = edit_during_reread
    status, candidate = await h.controller._review_recovery_candidate(
        REPO, PR, h.state, HEAD, final_recheck=True,
    )
    assert status == "review_comment_changed_during_check"
    assert candidate is None


@pytest.mark.asyncio
@pytest.mark.parametrize("latest_state", ["reviewing", "terminal"])
async def test_r07_r08_latest_build_running_or_failed_blocks(monkeypatch, latest_state):
    h = _harness(monkeypatch)
    h.holder.latest_state = latest_state
    status, candidate = await h.controller._review_recovery_candidate(
        REPO, PR, h.state, HEAD, final_recheck=False,
    )
    assert status == ("latest_review_still_running" if latest_state == "reviewing"
                      else "latest_review_failed")
    assert candidate is None


@pytest.mark.asyncio
async def test_r09_and_r28_untrusted_newer_review_never_falls_back(monkeypatch):
    h = _harness(monkeypatch)
    rogue = _comment(
        270,
        f"{review_parser.PR_REVIEW_MARKER}\n## PR Review Agent\nCommit: {PREFIX}\n"
        f"{review_parser.BUILD_HEADING}\nmalicious output",
        "2026-11-03T03:37:00Z", user=OTHER_USER,
    )
    h.proxy.comments[rogue["id"]] = rogue
    status, candidate = await h.controller._review_recovery_candidate(
        REPO, PR, h.state, HEAD, final_recheck=False,
    )
    assert status == "untrusted_newer_review_run"
    assert candidate is None
    assert h.proxy.hidden_state_reads == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("change, expected", [
    ("head", "head_changed"),
    ("closed", "pr_identity_or_status_mismatch"),
    ("draft", "pr_identity_or_status_mismatch"),
    ("repo", "pr_identity_or_status_mismatch"),
])
async def test_r10_pr_and_head_identity_changes_block(monkeypatch, change, expected):
    h = _harness(monkeypatch)
    if change == "head":
        h.proxy.pr["head"]["sha"] = "b" * 40
    elif change == "closed":
        h.proxy.pr["state"] = "closed"
    elif change == "draft":
        h.proxy.pr["draft"] = True
    else:
        h.proxy.pr["base"]["repo"]["full_name"] = "test-owner/phanthymotus-driver"
    status, candidate = await h.controller._review_recovery_candidate(
        REPO, PR, h.state, HEAD, final_recheck=False,
    )
    assert status == expected
    assert candidate is None


@pytest.mark.asyncio
async def test_r11_original_request_identity_must_be_authorized(monkeypatch):
    h = _harness(monkeypatch)
    h.proxy.comments[OLD_REQUEST_ID]["user"] = copy.deepcopy(OTHER_USER)
    status, candidate = await h.controller._review_recovery_candidate(
        REPO, PR, h.state, HEAD, final_recheck=False,
    )
    assert status == "original_request_identity_unverifiable"
    assert candidate is None


@pytest.mark.parametrize("override", [
    {"approve_attempts": [{"comment_id": 221}], "approve_attempts_total": 1},
    {"deployments": [{"phase": "deployed", "machine": "m1"}]},
    {"command": {"comment_id": 221, "kind": "approve_deploy",
                  "phase": "uncertain", "args": {"machine": "m1"}}},
    {"deployment_logs": {"m1": {"status": "pending"}}},
])
def test_r12_to_r15_deployment_activity_is_not_recoverable(override):
    controller = DeployController(
        make_config(), SimpleNamespace(), SimpleNamespace(), SimpleNamespace(),
    )
    assert not controller._review_recovery_state_is_eligible(
        _state(**override), HEAD,
    )


@pytest.mark.asyncio
async def test_r16_archive_error_does_not_advance_lifecycle(monkeypatch):
    h = _harness(monkeypatch)
    old = _state()
    next_state = copy.deepcopy(old)
    next_state["status"] = "deploy-ready"
    next_state["round_id"] = make_round_id(HEAD, NEW_BUILD_ID)
    visible = (
        "<!-- deploy-approval-agent -->\n# Deploy Approval\n\n"
        + _build_history_block([{"event": "old", "timestamp": "2026-11-03T00:00:00Z"}])
    )
    lifecycle_comment = {
        "id": 900,
        "body": _build_hidden_state_body(visible, old),
    }
    h.proxy.find_trusted_lifecycle_comment = AsyncMock(return_value=lifecycle_comment)
    h.proxy.read_hidden_state = AsyncMock(return_value=copy.deepcopy(old))
    h.proxy.get_pr = AsyncMock(return_value=copy.deepcopy(h.proxy.pr))
    h.proxy.get_issue_comments = AsyncMock(return_value=[])
    h.proxy.write_hidden_state = AsyncMock()
    h.controller._render_evidence_projection = AsyncMock(side_effect=lambda _r, _p, _s, text: text)
    h.controller._archive_round_unlocked = AsyncMock(side_effect=RuntimeError("archive unavailable"))
    with pytest.raises(RuntimeError, match="archive unavailable"):
        await h.controller._write_lifecycle_with_history(
            REPO, PR, next_state, "# Deploy Approval\n\n### Status: deploy-ready",
            event={"event": "recovered"}, expected_lifecycle_state=old,
            archive_reason="New trusted Review Run invalidated frozen deployment request",
        )
    h.proxy.write_hidden_state.assert_not_awaited()
    assert next_state["round_archive"] is None
    assert old["status"] == "deploy-requested"


@pytest.mark.asyncio
async def test_r17_lifecycle_cas_failure_does_not_overwrite_new_state(monkeypatch):
    h = _harness(monkeypatch)
    old = _state()
    competing = copy.deepcopy(old)
    competing["last_processed_comment_id"] += 1
    next_state = copy.deepcopy(old)
    next_state["status"] = "deploy-ready"
    next_state["round_id"] = make_round_id(HEAD, NEW_BUILD_ID)
    visible = "<!-- deploy-approval-agent -->\n# Deploy Approval"
    comment = {"id": 901, "body": _build_hidden_state_body(visible, old)}
    h.proxy.find_trusted_lifecycle_comment = AsyncMock(return_value=comment)
    h.proxy.read_hidden_state = AsyncMock(return_value=competing)
    h.proxy.write_hidden_state = AsyncMock()
    result = await h.controller._write_lifecycle_with_history(
        REPO, PR, next_state, "# Deploy Approval", expected_lifecycle_state=old,
    )
    assert not result
    h.proxy.write_hidden_state.assert_not_awaited()


@pytest.mark.asyncio
async def test_r18_review_change_after_archive_fails_final_guard(monkeypatch):
    h = _harness(monkeypatch)
    archive_reasons = []

    async def fake_writer(_repo, _pr, _state, _markdown, *, write_guard,
                          archive_reason=None, **_kwargs):
        archive_reasons.append(archive_reason)
        h.proxy.comments[NEW_BUILD_ID]["body"] += " changed after archive"
        h.proxy.comments[NEW_BUILD_ID]["updated_at"] = "2026-11-03T03:45:00Z"
        return await write_guard()

    h.controller._write_lifecycle_with_history = fake_writer
    result = await h.controller._recover_deploy_requested_review(
        REPO, PR, h.state, HEAD,
    )
    assert result == h.state
    assert archive_reasons == [
        "New trusted Review Run invalidated frozen deployment request",
    ]
    assert h.proxy.issue_comment_reads == 2


@pytest.mark.asyncio
async def test_r19_repeat_reconcile_archives_once_and_r20_restart_is_idempotent(monkeypatch):
    h = _harness(monkeypatch)
    prior_archive = {
        "round_id": make_round_id(HEAD, 100),
        "sha256": "c" * 64,
    }
    h.state["round_archive"] = prior_archive
    stored_state = copy.deepcopy(h.state)
    visible = (
        "<!-- deploy-approval-agent -->\n# Deploy Approval\n\n"
        + _build_history_block([{
            "event": "existing lifecycle event",
            "timestamp": "2026-11-03T00:00:00Z",
        }])
        + "\n\n### Workflow\n"
    )
    lifecycle_comment = {
        "id": 903,
        "body": _build_hidden_state_body(visible, stored_state),
    }
    archive = {"round_id": stored_state["round_id"], "sha256": "b" * 64}
    archive_calls = []
    writes = []

    async def archive_once(_repo, _pr, old_state, reason):
        archive_calls.append((copy.deepcopy(old_state), reason))
        return copy.deepcopy(archive)

    async def write_state(_repo, _pr, rendered, next_state, **_kwargs):
        nonlocal stored_state
        writes.append(copy.deepcopy(next_state))
        stored_state = copy.deepcopy(next_state)
        lifecycle_comment["body"] = _build_hidden_state_body(rendered, stored_state)
        return {"id": lifecycle_comment["id"], "body": lifecycle_comment["body"]}

    h.proxy.find_trusted_lifecycle_comment = AsyncMock(
        side_effect=lambda *_args: copy.deepcopy(lifecycle_comment),
    )
    h.proxy.read_hidden_state = AsyncMock(
        side_effect=lambda *_args: copy.deepcopy(stored_state),
    )
    h.proxy.get_pr = AsyncMock(return_value=copy.deepcopy(h.proxy.pr))
    h.proxy.write_hidden_state = AsyncMock(side_effect=write_state)
    h.controller._archive_round_unlocked = AsyncMock(side_effect=archive_once)
    recovered = await h.controller._recover_deploy_requested_review(
        REPO, PR, h.state, HEAD,
    )
    assert recovered["status"] == "deploy-ready"
    assert recovered["round_id"] == make_round_id(HEAD, NEW_BUILD_ID)
    assert recovered["round_id"] != make_round_id(HEAD, OLD_REQUEST_ID)
    assert recovered["last_processed_comment_id"] == NEW_CODE_ID
    assert recovered["command"]["comment_id"] == NEW_CODE_ID
    assert len(archive_calls) == 1
    assert archive_calls[0][0]["round_id"] == make_round_id(HEAD, OLD_REQUEST_ID)
    assert archive_calls[0][0]["round_archive"] == prior_archive
    assert archive_calls[0][1] == "New trusted Review Run invalidated frozen deployment request"
    assert len(writes) == 1
    assert stored_state["round_archive"] == archive

    restarted = DeployController(
        h.config, h.proxy, SimpleNamespace(), h.github,
    )
    assert not restarted._review_recovery_state_is_eligible(stored_state, HEAD)
    assert await restarted._recover_deploy_requested_review(
        REPO, PR, stored_state, HEAD,
    ) == stored_state
    assert len(archive_calls) == 1
    assert len(writes) == 1


@pytest.mark.asyncio
async def test_r21_other_pr_comments_cannot_supply_review_evidence(monkeypatch):
    h = _harness(monkeypatch)
    # Model Driver PR #454's frozen request alongside leaked evidence from
    # Driver PR #472. The API fixture deliberately returns both PR comment sets.
    driver_repo = "test-owner/phanthymotus-driver"
    h.proxy.pr.update({
        "number": 454,
        "base": {"repo": {"full_name": driver_repo}},
    })
    for comment_id in (OLD_BUILD_ID, OLD_TEST_ID, OLD_CODE_ID, OLD_REQUEST_ID):
        h.proxy.comments[comment_id]["url"] = (
            f"https://api.github.com/repos/{driver_repo}/issues/comments/{comment_id}"
        )
        h.proxy.comments[comment_id]["issue_url"] = (
            f"https://api.github.com/repos/{driver_repo}/issues/454"
        )
    for comment_id in (REVIEW_REQUEST_ID, NEW_BUILD_ID, NEW_TEST_ID, NEW_CODE_ID):
        h.proxy.comments[comment_id]["url"] = (
            f"https://api.github.com/repos/{driver_repo}/issues/comments/{comment_id}"
        )
        h.proxy.comments[comment_id]["issue_url"] = (
            f"https://api.github.com/repos/{driver_repo}/issues/472"
        )
    status, candidate = await h.controller._review_recovery_candidate(
        driver_repo, 454, h.state, HEAD,
        final_recheck=False,
    )
    assert status == "review_comment_identity_mismatch"
    assert candidate is None


@pytest.mark.asyncio
async def test_r22_r23_recovery_has_no_agent_core_or_cos_side_effects(monkeypatch):
    h = _harness(monkeypatch)
    h.controller._core_for_node = AsyncMock()
    h.controller._deploy_component = AsyncMock()
    h.controller._upload_evidence = AsyncMock()

    async def writer(_repo, _pr, _state, _markdown, *, write_guard, **_kwargs):
        return await write_guard()

    h.controller._write_lifecycle_with_history = writer
    result = await h.controller._recover_deploy_requested_review(
        REPO, PR, h.state, HEAD,
    )
    assert result["status"] == "deploy-ready"
    h.controller._core_for_node.assert_not_awaited()
    h.controller._deploy_component.assert_not_awaited()
    h.controller._upload_evidence.assert_not_awaited()


@pytest.mark.asyncio
async def test_r24_existing_history_survives_guarded_round_replacement(monkeypatch):
    h = _harness(monkeypatch)
    old = _state()
    next_state = copy.deepcopy(old)
    next_state["status"] = "deploy-ready"
    next_state["round_id"] = make_round_id(HEAD, NEW_BUILD_ID)
    history = _build_history_block([{
        "event": "previous deployment history",
        "timestamp": "2026-11-03T01:00:00Z",
    }])
    visible = "<!-- deploy-approval-agent -->\n# Deploy Approval\n\n" + history
    lifecycle_comment = {
        "id": 902,
        "body": _build_hidden_state_body(visible, old),
    }
    archive = {"round_id": old["round_id"], "sha256": "a" * 64}
    writes = []
    h.proxy.find_trusted_lifecycle_comment = AsyncMock(return_value=lifecycle_comment)
    h.proxy.read_hidden_state = AsyncMock(return_value=copy.deepcopy(old))
    h.proxy.get_pr = AsyncMock(return_value=copy.deepcopy(h.proxy.pr))
    h.proxy.get_issue_comments = AsyncMock(return_value=[])
    async def write_state(_repo, _pr, rendered, state, **_kwargs):
        writes.append((rendered, copy.deepcopy(state)))
        return {"id": lifecycle_comment["id"], "body": "updated"}
    h.proxy.write_hidden_state = AsyncMock(side_effect=write_state)
    h.controller._archive_round_unlocked = AsyncMock(return_value=archive)
    h.controller._render_evidence_projection = AsyncMock(side_effect=lambda _r, _p, _s, text: text)
    result = await h.controller._write_lifecycle_with_history(
        REPO, PR, next_state, "# Deploy Approval\n\n### Status: deploy-ready",
        event={"event": "New trusted Review Run invalidated frozen deployment request",
               "timestamp": "2026-11-03T03:50:00Z"},
        expected_lifecycle_state=old,
        write_guard=AsyncMock(return_value=True),
        archive_reason="New trusted Review Run invalidated frozen deployment request",
    )
    assert result
    assert len(writes) == 1
    assert "previous deployment history" in writes[0][0]
    assert "New trusted Review Run invalidated frozen deployment request" in writes[0][0]
    assert writes[0][1]["round_archive"] == archive


@pytest.mark.asyncio
async def test_r25_new_request_uses_latest_ready_review_snapshot(monkeypatch):
    h = _harness(monkeypatch)
    snapshot = h.controller._review_evidence_snapshot(h.evidence, HEAD)
    ready = _state(
        status="deploy-ready",
        round_id=make_round_id(HEAD, NEW_BUILD_ID),
        review_evidence=snapshot,
        components=[copy.deepcopy(h.component)],
        last_processed_comment_id=NEW_CODE_ID,
        command={"comment_id": NEW_CODE_ID, "kind": "", "phase": "completed", "args": {}},
    )
    h.proxy.get_pr = AsyncMock(return_value=copy.deepcopy(h.proxy.pr))
    h.proxy.read_hidden_state = AsyncMock(return_value=ready)
    h.proxy.comment_identity = AsyncMock(return_value=("1", "alice"))
    h.proxy.project_status_label = AsyncMock()
    h.controller._post_error = AsyncMock()
    h.github.get_issue_comments = AsyncMock(return_value=list(h.proxy.comments.values()))
    h.controller._review_evidence_from_comments = AsyncMock(return_value=copy.deepcopy(h.evidence))
    h.controller._resolve_review_evidence_for_head = AsyncMock(return_value=HEAD)
    h.controller._get_machine_groups_for_components = lambda _components, _repo: []
    captured = []
    async def write(_repo, _pr, state, _markdown, **kwargs):
        captured.append((copy.deepcopy(state), kwargs))
        return True
    h.controller._write_lifecycle_with_history = write
    result = await h.controller.handle_request_deploy(REPO, PR, 300)
    assert result
    assert len(captured) == 1
    requested, kwargs = captured[0]
    assert requested["status"] == "deploy-requested"
    assert requested["review_evidence"]["build_comment_id"] == NEW_BUILD_ID
    assert requested["round_id"] == make_round_id(HEAD, 300)
    assert kwargs["archive_reason"] == "New deployment request"
    h.controller._post_error.assert_not_awaited()


@pytest.mark.asyncio
async def test_r26_old_request_comment_is_not_replayed(monkeypatch):
    h = _harness(monkeypatch)
    ready = _state(
        status="deploy-ready",
        round_id=make_round_id(HEAD, NEW_BUILD_ID),
        last_processed_comment_id=NEW_CODE_ID,
        command={"comment_id": NEW_CODE_ID, "kind": "", "phase": "completed", "args": {}},
    )
    h.proxy.get_pr = AsyncMock(return_value=copy.deepcopy(h.proxy.pr))
    h.proxy.read_hidden_state = AsyncMock(return_value=ready)
    h.proxy.comment_identity = AsyncMock(return_value=("1", "alice"))
    h.controller._write_lifecycle_with_history = AsyncMock()
    result = await h.controller.handle_request_deploy(REPO, PR, OLD_REQUEST_ID)
    assert result
    h.controller._write_lifecycle_with_history.assert_not_awaited()
    assert h.proxy.issue_comment_reads == 0


@pytest.mark.asyncio
async def test_r27_component_matrix_is_rebuilt_not_inherited(monkeypatch):
    h = _harness(monkeypatch)
    h.evidence.builds[0].image_tag = "registry.example/phanthymotus/perception:v3"
    h.evidence.builds[0].image_ref = h.evidence.builds[0].image_tag
    h.controller._review_build_infos = lambda _repo, evidence: [BuildInfo(
        target="perception", driver_path="", variant="5.11",
        success=True, image_tag=evidence.builds[0].image_tag, deployable=True,
    )]
    changed = copy.deepcopy(h.component)
    changed.update({
        "component_id": "new-matrix-component",
        "review_image_tag": "registry.example/phanthymotus/perception:v3",
        "image_ref": "registry.example/phanthymotus/perception:v3",
    })
    h.controller._build_component_snapshot = AsyncMock(return_value=[changed])
    status, candidate = await h.controller._review_recovery_candidate(
        REPO, PR, h.state, HEAD, final_recheck=False,
    )
    assert status == "ready"
    assert candidate["components"] == [changed]
    assert candidate["components"] != h.state["components"]


def test_build_anchor_allows_edit_but_immutable_results_do_not():
    controller = DeployController(
        make_config(review_comment_author_id=REVIEW_ID,
                    review_comment_author_login=REVIEW_LOGIN),
        SimpleNamespace(), SimpleNamespace(), SimpleNamespace(),
    )
    edited_build = _comment(
        NEW_BUILD_ID, _build_body(), "2026-11-03T03:35:44Z",
        "2026-11-03T03:36:03Z",
    )
    immutable_code = _comment(
        NEW_CODE_ID, "code review", "2026-11-03T03:36:20Z",
    )
    assert controller._review_recovery_comment_is_scoped(
        REPO, PR, NEW_BUILD_ID, edited_build, REVIEW_ID, REVIEW_LOGIN,
        allow_edited=True,
    )
    assert not controller._review_recovery_comment_is_scoped(
        REPO, PR, NEW_BUILD_ID, edited_build, REVIEW_ID, REVIEW_LOGIN,
    )
    assert controller._review_recovery_comment_is_scoped(
        REPO, PR, NEW_CODE_ID, immutable_code, REVIEW_ID, REVIEW_LOGIN,
    )


@pytest.mark.asyncio
async def test_api_reads_no_new_review_and_success_path_are_bounded(monkeypatch):
    idle = _harness(monkeypatch)
    idle.proxy.comments = {
        comment_id: comment for comment_id, comment in idle.proxy.comments.items()
        if comment_id <= OLD_REQUEST_ID
    }
    idle.controller._write_lifecycle_with_history = AsyncMock()
    unchanged = await idle.controller._recover_deploy_requested_review(
        REPO, PR, idle.state, HEAD,
    )
    assert unchanged == idle.state
    idle.controller._write_lifecycle_with_history.assert_not_awaited()
    assert idle.proxy.issue_comment_reads == 1
    assert idle.proxy.hidden_state_reads == 0
    assert idle.proxy.pr_reads == 0
    assert idle.proxy.comment_reads == 0
    idle.github.resolve_commit_sha.assert_not_awaited()

    active = _harness(monkeypatch)
    async def writer(_repo, _pr, _state, _markdown, *, write_guard, **_kwargs):
        return await write_guard()
    active.controller._write_lifecycle_with_history = writer
    recovered = await active.controller._recover_deploy_requested_review(
        REPO, PR, active.state, HEAD,
    )
    assert recovered["status"] == "deploy-ready"
    # One discovery snapshot plus one final snapshot and its post-await reread.
    assert active.proxy.issue_comment_reads == 3
    # The once-only deploy-ready notice checks the newly persisted lifecycle
    # snapshot before posting; the recovery candidate itself reuses its inputs.
    assert active.proxy.hidden_state_reads == 1
    assert active.proxy.pr_reads == 7
    assert active.proxy.comment_reads == 4
    assert active.github.resolve_commit_sha.await_count == 2
