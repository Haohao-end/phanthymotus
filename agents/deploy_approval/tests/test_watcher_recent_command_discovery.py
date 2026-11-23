"""Regression tests for V2122 watcher recent-command discovery.

Real incident: PR #569 HEAD d20a0762aa235e6c3031938ed27ee354ebd09e90.
R02 (comment 7036786426) was processed and became the hidden-state cursor.
R03 (comment 7037147040, ``/request_deploy force=true``) was never discovered,
queued, or dispatched because repo-wide ``list_open_prs`` timed out and the
recent-comment filter silently dropped the command.

These tests use the real comment IDs, timestamps, and issue_url shape and pin
the required behavior: a valid deployment intent must always be observable and
then either queued (baseline complete) or explicitly rejected (pre-baseline).
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from .. import commands as commands_mod
from ..config import Config, DEFAULT_GITHUB_REPOS
from ..github_command_watcher import GitHubCommandWatcher

REPO = "4paradigm/phanthymotus"
PR = 569
HEAD = "d20a0762aa235e6c3031938ed27ee354ebd09e90"
R02_ID = 7036786426
R03_ID = 7037147040
R03_CREATED = "2026-11-20T10:25:13Z"
R02_CREATED = "2026-11-20T09:20:00Z"
R03_BODY = "/request_deploy force=true"
CUTOFF = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)


def _config(**overrides) -> Config:
    cfg = Config(
        github_repos=list(DEFAULT_GITHUB_REPOS),
        github_api_url="https://api.github.com",
        poll_enabled=True,
        poll_interval_seconds=30,
        webhook_enabled=False,
        review_comment_author_id="7950763",
        review_comment_author_login="kentcyq",
        machine_owners_file="/dev/null",
    )
    for key, value in overrides.items():
        setattr(cfg, key, value)
    cfg.active_repos = list(overrides.get("github_repos", cfg.github_repos))
    cfg.auth_valid = True
    return cfg


def _r03_comment(**overrides) -> dict:
    comment = {
        "id": R03_ID,
        "body": R03_BODY,
        "created_at": R03_CREATED,
        "updated_at": R03_CREATED,
        "issue_url": f"https://api.github.com/repos/{REPO}/issues/{PR}",
        "user": {"id": 4242, "login": "dev-actor", "type": "User"},
    }
    comment.update(overrides)
    return comment


def _watcher(config, *, github=None, proxy=None, controller=None):
    proxy = proxy or MagicMock()
    if not isinstance(proxy.is_bot_comment, MagicMock) or (
            proxy.is_bot_comment.return_value is not False):
        proxy.is_bot_comment = MagicMock(return_value=False)
    controller = controller or MagicMock()
    watcher = GitHubCommandWatcher(
        config, proxy, controller, github=github,
    )
    # The real cutoff is published by mark_repos_pending_baseline at startup.
    watcher._repo_baseline_cutoff_utc[REPO] = CUTOFF
    return watcher


# ---------------------------------------------------------------------------
# 1-3: Command intent must be recognized even when parse_command fails.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("body", [
    "/request_deploy force=true",
    "/request_deploy machine=10.110.8.244",
    "/request_deploy 123",
    "/request_depoly",
])
def test_deploy_command_intent_recognized_for_r03_and_variants(body):
    parsed = commands_mod.parse_command(body)
    # Each of these is an intent-bearing command, not a prose comment.
    assert parsed.is_command or commands_mod.detect_deployment_command_intent(body)
    assert commands_mod.detect_deployment_command_intent(body) == "request_deploy"


def test_unknown_argument_is_not_silently_filtered():
    parsed = commands_mod.parse_command(R03_BODY)
    assert parsed.kind == "unknown"
    assert parsed.error.startswith("unknown_argument")
    assert parsed.is_command is True
    assert parsed.intent == "request_deploy"


@pytest.mark.asyncio
async def test_r03_enters_recent_discovery_and_priority_queue():
    config = _config()
    github = MagicMock()
    github.list_recent_issue_comments = AsyncMock(return_value=[_r03_comment()])
    watcher = _watcher(config, github=github)

    queued = await watcher._discover_recent_command_prs([REPO])

    assert queued is True
    assert (REPO, PR) in watcher._priority_pr_set
    assert (REPO, PR) in watcher._priority_pr_queue
    assert (REPO, PR, R03_ID) in watcher._recent_command_records
    stats = watcher.recent_discovery_stats
    assert stats["recent_comments_received"] == 1
    assert stats["eligible_commands"] == 1
    assert stats["newly_discovered_prs"] == 1
    assert stats["priority_queued"] >= 1
    assert stats["baseline_cutoff_filtered"] == 0


# ---------------------------------------------------------------------------
# 4-5: Authorization baseline semantics.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pre_baseline_command_never_executes_but_is_not_dropped():
    config = _config()
    github = MagicMock()
    pre_baseline = _r03_comment(created_at="2026-11-20T09:30:00Z",
                                updated_at="2026-11-20T09:30:00Z")
    github.list_recent_issue_comments = AsyncMock(return_value=[pre_baseline])
    controller = MagicMock()
    controller.on_command = AsyncMock(return_value=True)
    watcher = _watcher(config, github=github, controller=controller)

    await watcher._discover_recent_command_prs([REPO])

    key = (REPO, PR, R03_ID)
    # Not executed, no dispatch, but observed + queued for a rejection notice.
    assert controller.on_command.await_count == 0
    assert key in watcher._recent_command_records
    assert key in watcher._pending_baseline_notices
    assert watcher._recent_command_records[key]["failure_reason"] == (
        "baseline_cutoff_filtered"
    )
    stats = watcher.recent_discovery_stats
    assert stats["baseline_cutoff_filtered"] == 1
    assert stats["eligible_commands"] == 0


@pytest.mark.asyncio
async def test_post_baseline_command_is_queued_in_comment_id_order():
    config = _config()
    later = _r03_comment()
    earlier = _r03_comment(
        id=7037000000,
        body="/request_deploy",
        created_at="2026-11-20T10:10:00Z",
        updated_at="2026-11-20T10:10:00Z",
    )
    github = MagicMock()
    github.list_recent_issue_comments = AsyncMock(return_value=[later, earlier])
    watcher = _watcher(config, github=github)

    await watcher._discover_recent_command_prs([REPO])

    # Both commands are eligible and the PR is queued exactly once.
    assert watcher.recent_discovery_stats["eligible_commands"] == 2
    assert list(watcher._priority_pr_queue) == [(REPO, PR)]
    # The newest eligible comment is the one tracked as the PR's queue hint.
    assert (REPO, PR, R03_ID) in watcher._recent_command_records


@pytest.mark.asyncio
async def test_missing_authorization_cutoff_holds_command_without_executing():
    config = _config()
    github = MagicMock()
    github.list_recent_issue_comments = AsyncMock(return_value=[_r03_comment()])
    controller = MagicMock()
    controller.on_command = AsyncMock(return_value=True)
    proxy = MagicMock()
    proxy.is_bot_comment = MagicMock(return_value=False)
    watcher = GitHubCommandWatcher(config, proxy, controller, github=github)
    # No cutoff published yet (auth baseline still in progress).
    watcher._repo_baseline_cutoff_utc.pop(REPO, None)

    await watcher._discover_recent_command_prs([REPO])

    assert controller.on_command.await_count == 0
    assert (REPO, PR) not in watcher._priority_pr_set
    stats = watcher.recent_discovery_stats
    assert stats["baseline_cutoff_unavailable"] == 1
    assert stats["eligible_commands"] == 0


# ---------------------------------------------------------------------------
# 6-7: Recent discovery is independent of list_open_prs, retry keeps state.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_open_prs_timeout_does_not_block_recent_command():
    import asyncio

    config = _config()
    github = MagicMock()
    github.list_recent_issue_comments = AsyncMock(return_value=[_r03_comment()])
    proxy = MagicMock()
    proxy.get_pr = AsyncMock(return_value={
        "number": PR, "state": "open", "merged": False, "draft": False,
        "head": {"sha": HEAD},
        "base": {"repo": {"full_name": REPO}},
    })

    async def timed_out_open_prs(_repo):
        raise asyncio.TimeoutError

    proxy.get_open_prs = AsyncMock(side_effect=timed_out_open_prs)
    proxy.read_hidden_state = AsyncMock(return_value={
        "head_sha": HEAD, "status": "deploy-ready",
        "last_processed_comment_id": R02_ID,
    })
    controller = MagicMock()
    controller.reconcile_pr = AsyncMock()
    controller.on_command = AsyncMock(return_value=True)
    controller.policy = None
    controller.github = None
    watcher = _watcher(config, github=github, proxy=proxy, controller=controller)
    watcher._baseline_progress[REPO] = {PR}
    watcher._validated_current_summary_cos_links = AsyncMock(return_value=set())
    # Discovery runs first (its own task in production) and must succeed even
    # though the ordinary open-PR listing then times out.
    await watcher._discover_recent_command_prs([REPO])
    assert (REPO, PR) in watcher._priority_pr_set

    # A full cycle still records the timeout but must not drop the queued hint.
    await watcher._poll_once()
    assert proxy.get_open_prs.await_count >= 1
    assert (REPO, PR) in watcher._priority_pr_set or (REPO, PR) in [
        item for item in watcher._priority_pr_queue
    ]
    assert any("read_timeout" in reason for reason in watcher._last_scan_failure_reasons)


@pytest.mark.asyncio
async def test_github_proxy_error_keeps_retry_state_and_cursor():
    from ..github_state_proxy import GitHubStateProxyError

    config = _config()
    github = MagicMock()
    github.list_recent_issue_comments = AsyncMock(return_value=[_r03_comment()])
    proxy = MagicMock()
    proxy.get_pr = AsyncMock(side_effect=GitHubStateProxyError("boom"))
    proxy.get_open_prs = AsyncMock(return_value=[])
    proxy.persist_cursor = AsyncMock()
    proxy.ensure_visible_evidence_archive_comments = AsyncMock()
    proxy.retire_legacy_evidence_link_replies = AsyncMock()
    controller = MagicMock()
    controller.project_evidence = AsyncMock()
    controller.on_command = AsyncMock(return_value=True)
    watcher = _watcher(config, github=github, proxy=proxy, controller=controller)
    # Run the initial baseline once so the recent command can be dispatched.
    watcher._baseline_progress[REPO] = {PR}
    watcher._validated_current_summary_cos_links = AsyncMock(return_value=set())
    watcher._process_pr = AsyncMock(side_effect=GitHubStateProxyError("proxy down"))

    await watcher._discover_recent_command_prs([REPO])
    assert (REPO, PR) in watcher._priority_pr_set

    await watcher._poll_once()

    key = (REPO, PR, R03_ID)
    record = watcher._recent_command_records[key]
    # Failure is recorded as retryable — never "handled".
    assert record["status"] == "retry"
    assert record["failure_reason"] == "GitHubStateProxyError"
    assert (REPO, PR) in watcher._priority_pr_set or (REPO, PR) in [
        item for item in watcher._priority_pr_queue
    ]
    assert controller.on_command.await_count == 0
    # The cursor was never advanced: no hidden-state write happened at all.
    proxy.persist_cursor.assert_not_awaited()


@pytest.mark.asyncio
async def test_retry_does_not_repost_bot_comment():
    config = _config()
    pre_baseline = _r03_comment(created_at="2026-11-20T09:30:00Z",
                                updated_at="2026-11-20T09:30:00Z")
    github = MagicMock()
    github.list_recent_issue_comments = AsyncMock(return_value=[pre_baseline])
    proxy = MagicMock()
    proxy.get_pr = AsyncMock(return_value={
        "number": PR, "state": "open", "merged": False, "draft": False,
        "head": {"sha": HEAD},
        "base": {"repo": {"full_name": REPO}},
    })
    proxy.read_hidden_state = AsyncMock(return_value={
        "head_sha": HEAD, "status": "deploy-ready",
        "last_processed_comment_id": R02_ID,
    })
    proxy.consume_comment_cursor = AsyncMock()
    proxy.persist_cursor = AsyncMock(return_value={
        "head_sha": HEAD, "last_processed_comment_id": R03_ID,
    })
    controller = MagicMock()
    controller._post_command_reply = AsyncMock(return_value=True)
    watcher = _watcher(config, github=github, proxy=proxy, controller=controller)
    watcher._pending_baseline_repos.add(REPO)
    watcher._baseline_progress[REPO] = set()
    watcher._baseline_pr = AsyncMock(return_value=True)

    await watcher._discover_recent_command_prs([REPO])
    await watcher._poll_once()
    first_replies = controller._post_command_reply.await_count
    assert first_replies == 1
    # The rejection notice is explicitly not an error reply and does not
    # dispatch the command.
    controller.on_command = None
    assert (REPO, PR, R03_ID) not in watcher._pending_baseline_notices

    # Re-discovery observes the same handled comment; no second notice.
    await watcher._discover_recent_command_prs([REPO])
    await watcher._flush_pending_baseline_notices(REPO, PR)
    assert controller._post_command_reply.await_count == first_replies
    assert (REPO, PR, R03_ID) not in watcher._pending_baseline_notices


@pytest.mark.asyncio
async def test_incomplete_baseline_never_executes_command():
    config = _config()
    github = MagicMock()
    github.list_recent_issue_comments = AsyncMock(return_value=[_r03_comment()])
    proxy = MagicMock()
    proxy.is_bot_comment = MagicMock(return_value=False)
    proxy.get_pr = AsyncMock(return_value={
        "number": PR, "state": "open", "merged": False, "draft": False,
        "head": {"sha": HEAD},
        "base": {"repo": {"full_name": REPO}},
    })
    proxy.get_open_prs = AsyncMock(return_value=[])
    controller = MagicMock()
    controller.on_command = AsyncMock(return_value=True)
    controller.project_evidence = AsyncMock()
    watcher = _watcher(config, github=github, proxy=proxy, controller=controller)
    watcher._baseline_pr = AsyncMock(return_value=False)
    watcher._validated_current_summary_cos_links = AsyncMock(return_value=set())

    await watcher._discover_recent_command_prs([REPO])
    await watcher._poll_once()

    # Baseline did not complete, so the command stays pending on the queue.
    controller.on_command.assert_not_awaited()
    assert (REPO, PR) in watcher._priority_pr_set
    record = watcher._recent_command_records[(REPO, PR, R03_ID)]
    assert record["status"] == "retry"
    assert record["failure_reason"] == "baseline_incomplete"
    assert watcher._priority_pr_retry_after.get((REPO, PR), 0.0) > 0.0


@pytest.mark.asyncio
async def test_unknown_argument_dispatches_rejection_notice_not_command():
    """parse_command -> unknown intent must reach error handling, not on_command."""
    config = _config()
    state = {
        "head_sha": HEAD, "status": "deploy-ready",
        "last_processed_comment_id": R02_ID,
    }
    comment = _r03_comment()
    proxy = MagicMock()
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.get_pr = AsyncMock(return_value={
        "number": PR, "state": "open", "merged": False, "draft": False,
        "head": {"sha": HEAD},
        "base": {"repo": {"full_name": REPO}},
    })
    proxy.get_issue_comments = AsyncMock(return_value=[comment])
    proxy.get_comment = AsyncMock(return_value=comment)
    proxy.is_bot_comment = MagicMock(return_value=False)
    proxy.comment_identity = AsyncMock(return_value=("4242", "dev-actor"))

    async def persist(_repo, _pr, comment_id):
        state["last_processed_comment_id"] = comment_id
        return state

    proxy.persist_cursor = AsyncMock(side_effect=persist)
    controller = MagicMock()
    controller.reconcile_pr = AsyncMock()
    controller.policy = None
    controller.github = None
    controller.on_command = AsyncMock(return_value=True)
    controller._post_command_reply = AsyncMock(return_value=True)
    controller.begin_command_reply_tracking = MagicMock()
    controller.take_command_reply_delivery = MagicMock(return_value=None)
    watcher = GitHubCommandWatcher(config, proxy, controller)
    watcher._repo_baseline_cutoff_utc[REPO] = CUTOFF

    await watcher._process_pr(REPO, PR)

    controller.on_command.assert_not_awaited()
    controller._post_command_reply.assert_awaited_once()
    assert state["last_processed_comment_id"] == R03_ID


# ---------------------------------------------------------------------------
# 8-9: New commands are not starved; per-PR ordering is comment_id ascending.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_new_command_not_starved_by_older_recent_hints():
    config = _config()
    other_pr = 540
    old_comment = _r03_comment(
        id=7035000000, issue_url=f"https://api.github.com/repos/{REPO}/issues/{other_pr}",
        created_at="2026-11-20T10:05:00Z", updated_at="2026-11-20T10:05:00Z",
    )
    github = MagicMock()
    github.list_recent_issue_comments = AsyncMock(
        return_value=[_r03_comment(), old_comment],
    )
    watcher = _watcher(config, github=github)

    await watcher._discover_recent_command_prs([REPO])

    queue = list(watcher._priority_pr_queue)
    assert queue[0] == (REPO, PR)   # newest comment first
    assert queue[1] == (REPO, other_pr)


@pytest.mark.asyncio
async def test_same_pr_commands_processed_in_comment_id_order():
    config = _config()
    first = _r03_comment(
        id=7037100000, body="/request_deploy",
        created_at="2026-11-20T10:20:00Z", updated_at="2026-11-20T10:20:00Z",
    )
    second = _r03_comment()  # id 7037147040, later created_at
    proxy = MagicMock()
    proxy.get_pr = AsyncMock(return_value={
        "number": PR, "state": "open", "merged": False, "draft": False,
        "head": {"sha": HEAD},
        "base": {"repo": {"full_name": REPO}},
    })
    state = {"head_sha": HEAD, "status": "deploy-ready",
             "last_processed_comment_id": R02_ID}
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.get_issue_comments = AsyncMock(return_value=[second, first])
    proxy.get_comment = AsyncMock(side_effect=lambda _repo, cid: (
        second if cid == second["id"] else first
    ))
    proxy.is_bot_comment = MagicMock(return_value=False)
    proxy.comment_identity = AsyncMock(return_value=("4242", "dev-actor"))

    async def consume(_repo, _pr, comment_id):
        state["last_processed_comment_id"] = comment_id
        return True

    proxy.persist_cursor = AsyncMock(side_effect=consume)
    dispatched = []
    controller = MagicMock()
    controller.reconcile_pr = AsyncMock()
    controller.policy = None
    controller.github = None
    controller.on_command = AsyncMock(
        side_effect=lambda cmd, _repo, _pr, cid: dispatched.append(cid) or True,
    )
    controller.begin_command_reply_tracking = MagicMock()
    controller.take_command_reply_delivery = MagicMock(return_value=True)
    watcher = GitHubCommandWatcher(config, proxy, controller)
    watcher._repo_baseline_cutoff_utc[REPO] = CUTOFF

    await watcher._process_pr(REPO, PR, yield_for_priority=True)

    # Only the first (lowest comment_id) command dispatches this cycle; the
    # later one must wait for a subsequent cycle, never jump ahead.
    assert dispatched == [7037100000]
    assert state["last_processed_comment_id"] == 7037100000


@pytest.mark.asyncio
async def test_pre_baseline_rejection_precedes_later_dispatch():
    """The visible rejection for an older command must not follow a newer one."""
    config = _config()
    pre_baseline = _r03_comment(
        id=7036900000, body="/request_deploy",
        created_at="2026-11-20T09:40:00Z", updated_at="2026-11-20T09:40:00Z",
    )
    post_baseline = _r03_comment(body="/request_deploy")  # R03, 10:25:13Z, after CUTOFF
    state = {"head_sha": HEAD, "status": "deploy-ready",
             "last_processed_comment_id": R02_ID}
    proxy = MagicMock()
    proxy.read_hidden_state = AsyncMock(return_value=state)
    proxy.get_pr = AsyncMock(return_value={
        "number": PR, "state": "open", "merged": False, "draft": False,
        "head": {"sha": HEAD},
        "base": {"repo": {"full_name": REPO}},
    })
    proxy.get_issue_comments = AsyncMock(return_value=[pre_baseline, post_baseline])
    proxy.get_comment = AsyncMock(side_effect=lambda _repo, cid: (
        pre_baseline if cid == pre_baseline["id"] else post_baseline
    ))
    proxy.is_bot_comment = MagicMock(return_value=False)
    proxy.comment_identity = AsyncMock(return_value=("4242", "dev-actor"))
    proxy.persist_cursor = AsyncMock(side_effect=lambda _r, _p, cid: (
        state.update(last_processed_comment_id=cid) or state
    ))

    order = []
    controller = MagicMock()
    controller.reconcile_pr = AsyncMock()
    controller.policy = None
    controller.github = None
    controller.begin_command_reply_tracking = MagicMock()
    controller.take_command_reply_delivery = MagicMock(return_value=True)
    controller.on_command = AsyncMock(
        side_effect=lambda cmd, _repo, _pr, cid: order.append(("dispatch", cid)) or True,
    )

    async def post_reply(_repo, _pr, cid, _msg, *, topic, error):
        order.append((topic, cid))
        return True

    controller._post_command_reply = AsyncMock(side_effect=post_reply)
    watcher = GitHubCommandWatcher(config, proxy, controller)
    watcher._repo_baseline_cutoff_utc[REPO] = CUTOFF
    watcher._baseline_progress[REPO] = {PR}
    watcher._pending_baseline_notices[(REPO, PR, pre_baseline["id"])] = None
    watcher._observe_recent_command(
        REPO, PR, pre_baseline,
        datetime(2026, 11, 20, 9, 40, 0, tzinfo=timezone.utc),
    )

    # Cycle 1: the older pre-baseline command is consumed as history (one
    # business action per PR cycle) and its rejection is delivered.
    await watcher._process_scheduled_pr(REPO, PR)
    # Cycle 2: the post-baseline command may now dispatch, never earlier.
    await watcher._process_scheduled_pr(REPO, PR)

    assert order, "expected at least one user-visible action"
    assert order[0] == ("baseline-rejected", pre_baseline["id"])
    assert order.index(("baseline-rejected", pre_baseline["id"])) < order.index(
        ("dispatch", post_baseline["id"]),
    )
    assert sum(1 for entry in order
               if entry == ("dispatch", post_baseline["id"])) == 1


@pytest.mark.asyncio
async def test_pre_baseline_rejection_is_delivered_only_once():
    config = _config()
    proxy = MagicMock()
    proxy.get_pr = AsyncMock(return_value={
        "number": PR, "state": "open", "merged": False, "draft": False,
        "head": {"sha": HEAD},
        "base": {"repo": {"full_name": REPO}},
    })
    controller = MagicMock()
    controller._post_command_reply = AsyncMock(return_value=True)
    watcher = _watcher(config, proxy=proxy, controller=controller)
    comment = _r03_comment(created_at="2026-11-20T09:30:00Z",
                           updated_at="2026-11-20T09:30:00Z")
    key = (REPO, PR, comment["id"])
    watcher._observe_recent_command(
        REPO, PR, comment, datetime(2026, 11, 20, 9, 30, 0, tzinfo=timezone.utc),
    )
    watcher._pending_baseline_notices[key] = None

    assert await watcher._flush_pending_baseline_notices(REPO, PR) is True
    assert await watcher._flush_pending_baseline_notices(REPO, PR) is True

    controller._post_command_reply.assert_awaited_once()
    assert key not in watcher._pending_baseline_notices
    assert watcher.recent_discovery_stats["baseline_rejection_notices"] == 1


# ---------------------------------------------------------------------------
# 6: PR #581 regression: Human command must not be swallowed by subsequent bot notice.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pr581_human_command_not_swallowed_by_subsequent_bot_notice():
    """Simulate PR 581 timeline:
    1. PR 581 on 4paradigm/phanthymotus-driver, HEAD 1f8a8cf69e69287054748d54aacb1b3b218f3b0a
    2. R01: comment 7080880956 (/request_deploy 123) at 2026-11-22T14:53:18Z
    3. Bot subsequently posts ordinary deploy-ready reminder: comment 7080883326 at 2026-11-22T14:53:29Z
    4. Fixed authorization cutoff: 2026-11-22T14:50:00Z (older than R01)

    Assertions:
    - Cycle 1: Baseline establishes without consuming R01 (cursor remains 0).
    - Cycle 2: R01 receives extra_parameter error reply, cursor advances to 7080880956.
    - Assert business status unchanged ('deploy-ready').
    - Assert no deployment occurred (on_command not called).
    - Cycle 3: Bot notice consumed without dispatch, cursor advances to 7080883326.
    - Restart: New watcher instance with persisted state does not re-reply or deploy.
    - Subsequent valid command (/request_deploy) executes normally.
    """
    repo = "4paradigm/phanthymotus-driver"
    pr = 581
    head = "1f8a8cf69e69287054748d54aacb1b3b218f3b0a"
    cutoff = datetime(2026, 11, 22, 14, 50, 0, tzinfo=timezone.utc)

    r01_id = 7080880956
    r01_comment = {
        "id": r01_id,
        "body": "/request_deploy 123",
        "created_at": "2026-11-22T14:53:18Z",
        "updated_at": "2026-11-22T14:53:18Z",
        "issue_url": f"https://api.github.com/repos/{repo}/issues/{pr}",
        "user": {"id": 1234, "login": "alice", "type": "User"},
    }
    bot_id = 7080883326
    bot_comment = {
        "id": bot_id,
        "body": "PR status: deploy-ready\nUse /request_deploy",
        "created_at": "2026-11-22T14:53:29Z",
        "updated_at": "2026-11-22T14:53:29Z",
        "issue_url": f"https://api.github.com/repos/{repo}/issues/{pr}",
        "user": {"id": 9999, "login": "deploy-bot", "type": "Bot"},
    }

    # Verify R01 command parse result has extra_parameter error
    parsed_r01 = commands_mod.parse_command(r01_comment["body"])
    assert parsed_r01.is_command is True
    assert parsed_r01.error == "extra_parameter"
    assert parsed_r01.intent == "request_deploy"

    config = Config(
        github_repos=[repo],
        github_api_url="https://api.github.com",
        poll_enabled=True,
        poll_interval_seconds=30,
        webhook_enabled=False,
        machine_owners_file="/dev/null",
    )
    config.active_repos = [repo]
    config.auth_valid = True

    state = None
    pr_comments = [r01_comment]

    proxy = MagicMock()
    async def mock_read_hidden_state(r, p):
        return state
    async def mock_persist_cursor(r, p, cid):
        nonlocal state
        if state is None:
            state = {
                "head_sha": head,
                "status": "deploy-ready",
                "last_processed_comment_id": cid,
                "command": {"comment_id": 0, "kind": "", "phase": "completed", "args": {}},
            }
        else:
            state["last_processed_comment_id"] = max(state.get("last_processed_comment_id", 0), cid)
        return state
    async def mock_get_pr(r, p):
        return {
            "number": pr, "state": "open", "merged": False, "draft": False,
            "head": {"sha": head}, "base": {"repo": {"full_name": repo}},
        }
    async def mock_get_issue_comments(r, p):
        return list(pr_comments)
    async def mock_get_comment(r, cid):
        for c in pr_comments:
            if c["id"] == cid:
                return c
        return None
    async def mock_comment_identity(r, cid):
        for c in pr_comments:
            if c["id"] == cid:
                return str(c["user"]["id"]), c["user"]["login"]
        return "", ""

    proxy.read_hidden_state = AsyncMock(side_effect=mock_read_hidden_state)
    proxy.persist_cursor = AsyncMock(side_effect=mock_persist_cursor)
    proxy.get_pr = AsyncMock(side_effect=mock_get_pr)
    proxy.get_issue_comments = AsyncMock(side_effect=mock_get_issue_comments)
    proxy.get_comment = AsyncMock(side_effect=mock_get_comment)
    proxy.comment_identity = AsyncMock(side_effect=mock_comment_identity)
    proxy.is_bot_comment = MagicMock(side_effect=lambda c: c.get("user", {}).get("login") == "deploy-bot")

    controller = MagicMock()
    async def mock_reconcile(r, p):
        nonlocal state
        if bot_comment not in pr_comments:
            pr_comments.append(bot_comment)
        if state is None:
            state = {
                "head_sha": head,
                "status": "deploy-ready",
                "last_processed_comment_id": 0,
                "command": {"comment_id": 0, "kind": "", "phase": "completed", "args": {}},
            }
    controller.reconcile_pr = AsyncMock(side_effect=mock_reconcile)
    controller.on_command = AsyncMock(return_value=True)
    replies = []
    async def mock_post_reply(r, p, cid, msg, topic="", error=False):
        replies.append((cid, topic, error))
        return True
    controller._post_command_reply = AsyncMock(side_effect=mock_post_reply)
    controller.begin_command_reply_tracking = MagicMock()
    controller.take_command_reply_delivery = MagicMock(return_value=None)

    watcher = GitHubCommandWatcher(config, proxy, controller)
    watcher._repo_baseline_cutoff_utc[repo] = cutoff

    # Cycle 1: Baseline pass establishes cutoff boundary; R01 and Bot notice are after cutoff
    # Cursor remains 0, no dispatch, no reply
    await watcher._process_scheduled_pr(repo, pr)
    assert state is not None
    assert state["last_processed_comment_id"] == 0
    assert replies == []
    controller.on_command.assert_not_called()

    # Cycle 2: Normal processing evaluates R01 first (ordered by comment ID)
    # R01 receives extra_parameter error reply, cursor advances to r01_id
    await watcher._process_scheduled_pr(repo, pr)
    assert len(replies) == 1
    assert replies[0] == (r01_id, "command-error-request_deploy", True)
    assert state["status"] == "deploy-ready"
    assert state["command"]["kind"] == ""
    assert state["last_processed_comment_id"] == r01_id
    controller.on_command.assert_not_called()

    # Cycle 3: Bot notice consumed without dispatch, cursor advances past bot_id
    await watcher._process_scheduled_pr(repo, pr)
    assert len(replies) == 1
    assert state["status"] == "deploy-ready"
    assert state["last_processed_comment_id"] == bot_id
    controller.on_command.assert_not_called()

    # Restart simulation: new watcher instance with persisted state from storage
    restart_cutoff = datetime(2026, 11, 22, 15, 0, 0, tzinfo=timezone.utc)
    watcher_restart = GitHubCommandWatcher(config, proxy, controller)
    watcher_restart._repo_baseline_cutoff_utc[repo] = restart_cutoff
    controller._post_command_reply.reset_mock()
    controller.on_command.reset_mock()

    # Cycle 4 (after restart): ensure no duplicate reply and no deployment
    await watcher_restart._process_scheduled_pr(repo, pr)
    controller._post_command_reply.assert_not_called()
    controller.on_command.assert_not_called()
    assert state["status"] == "deploy-ready"
    assert state["last_processed_comment_id"] == bot_id

    # New valid command: /request_deploy
    valid_id = 7080885000
    valid_comment = {
        "id": valid_id,
        "body": "/request_deploy",
        "created_at": "2026-11-22T15:05:00Z",
        "updated_at": "2026-11-22T15:05:00Z",
        "issue_url": f"https://api.github.com/repos/{repo}/issues/{pr}",
        "user": {"id": 1234, "login": "alice", "type": "User"},
    }
    pr_comments.append(valid_comment)

    # Cycle 5: process valid command
    await watcher_restart._process_scheduled_pr(repo, pr)
    controller.on_command.assert_awaited_once()
    call_args = controller.on_command.call_args[0]
    cmd = call_args[0]
    assert cmd.kind == "request_deploy"
    assert cmd.is_command is True
    assert call_args[1] == repo
    assert call_args[2] == pr
    assert call_args[3] == valid_id
    assert state["last_processed_comment_id"] == valid_id


@pytest.mark.asyncio
async def test_pr581_temporary_api_failure_recovers_without_skipping_error_reply():
    """Verify that if posting error reply fails transiently, cursor does NOT advance,
    and on next cycle it retries and succeeds before advancing cursor."""
    repo = "4paradigm/phanthymotus-driver"
    pr = 581
    head = "1f8a8cf69e69287054748d54aacb1b3b218f3b0a"
    cutoff = datetime(2026, 11, 22, 14, 50, 0, tzinfo=timezone.utc)

    r01_id = 7080880956
    r01_comment = {
        "id": r01_id,
        "body": "/request_deploy 123",
        "created_at": "2026-11-22T14:53:18Z",
        "updated_at": "2026-11-22T14:53:18Z",
        "issue_url": f"https://api.github.com/repos/{repo}/issues/{pr}",
        "user": {"id": 1234, "login": "alice", "type": "User"},
    }

    config = Config(
        github_repos=[repo],
        github_api_url="https://api.github.com",
        poll_enabled=True,
        poll_interval_seconds=30,
        webhook_enabled=False,
        machine_owners_file="/dev/null",
    )
    config.active_repos = [repo]
    config.auth_valid = True

    state = {
        "head_sha": head,
        "status": "deploy-ready",
        "last_processed_comment_id": 0,
        "command": {"comment_id": 0, "kind": "", "phase": "completed", "args": {}},
    }
    pr_comments = [r01_comment]

    proxy = MagicMock()
    proxy.read_hidden_state = AsyncMock(side_effect=lambda r, p: state)
    async def mock_persist(r, p, cid):
        state["last_processed_comment_id"] = cid
        return state
    proxy.persist_cursor = AsyncMock(side_effect=mock_persist)
    proxy.get_pr = AsyncMock(return_value={
        "number": pr, "state": "open", "merged": False, "draft": False,
        "head": {"sha": head}, "base": {"repo": {"full_name": repo}},
    })
    proxy.get_issue_comments = AsyncMock(side_effect=lambda r, p: list(pr_comments))
    proxy.get_comment = AsyncMock(side_effect=lambda r, cid: r01_comment if cid == r01_id else None)
    proxy.comment_identity = AsyncMock(return_value=("1234", "alice"))
    proxy.is_bot_comment = MagicMock(return_value=False)

    controller = MagicMock()
    controller.reconcile_pr = AsyncMock()
    controller.on_command = AsyncMock(return_value=True)

    # First attempt: _post_command_reply fails (returns False)
    controller._post_command_reply = AsyncMock(return_value=False)

    watcher = GitHubCommandWatcher(config, proxy, controller)
    watcher._repo_baseline_cutoff_utc[repo] = cutoff
    watcher._baseline_progress[repo] = {pr}  # Already baselined

    # Cycle 1: Error reply fails -> cursor must NOT advance
    await watcher._process_scheduled_pr(repo, pr)
    controller._post_command_reply.assert_awaited_once()
    assert state["last_processed_comment_id"] == 0
    controller.on_command.assert_not_called()

    # Second attempt: _post_command_reply succeeds (returns True)
    controller._post_command_reply = AsyncMock(return_value=True)

    # Cycle 2: Error reply succeeds -> cursor safely advances to r01_id
    await watcher._process_scheduled_pr(repo, pr)
    controller._post_command_reply.assert_awaited_once()
    assert state["last_processed_comment_id"] == r01_id
    controller.on_command.assert_not_called()
