"""GitHub command watcher — polls PR comments using `POLL_INTERVAL_SECONDS`.

This is the ONLY active poller for Deploy Approval. It polls configured
repositories/open PRs, reads comments, identifies commands newer than the
hidden-state cursor, and dispatches them one at a time to the Deploy Controller.

No SQLite, no Redis, no local cursor file, no comment lease, no DB persistence.
Single serial worker — no asyncio.gather for mutating PR work.

Safety rules:
- Never write stale local hidden state over Controller output.
- Cursor-only mutation must fresh-read hidden state from GitHub and preserve
  exact visible markdown.
- After dispatching one valid command, stop processing that PR for this cycle.
- Next cycle starts with fresh GitHub state.
- Transient command failure -> no cursor advance and no later command processing
  in same PR cycle.
"""

from __future__ import annotations

import asyncio
import json
import time
import logging
import re
from collections import deque
from datetime import datetime, timezone
from urllib.parse import urlparse

from . import commands as commands_mod
from .config import Config, DEFAULT_GITHUB_REPOS, resolve_authorized_repos
from .github_client import (
    GitHubClient, GitHubError, GitHubRateLimitError, GitHubTransientError,
)
from .github_state_proxy import HIDDEN_STATE_MARKER, GitHubStateProxy, GitHubStateProxyError
from .review_comment_parser import (
    BUILD_HEADING, CODE_REVIEW_HEADING, PR_REVIEW_MARKER,
)

logger = logging.getLogger(__name__)
PR_RECONCILE_CACHE_SECONDS = 120.0
MACHINE_PROJECTION_REFRESH_SECONDS = 300.0
OPEN_PR_LIST_REFRESH_SECONDS = 30.0
OPEN_PR_SNAPSHOT_MAX_AGE_SECONDS = 120.0
OPEN_PR_LIST_QUERY_TIMEOUT_SECONDS = 300.0
OPEN_PR_LIST_FAILURE_MAX_BACKOFF_SECONDS = 300.0
PRIORITY_BASELINE_RETRY_BASE_SECONDS = 30.0
PRIORITY_BASELINE_RETRY_MAX_SECONDS = 300.0
# Ready-evidence reconcile pacing. Every item is one repo/PR hint, so the
# queue is bounded per PR and never scans the whole repository.
EVIDENCE_SYNC_RETRY_BASE_SECONDS = 30.0
EVIDENCE_SYNC_RETRY_MAX_SECONDS = 300.0
EVIDENCE_SYNC_QUEUE_MAX = 128
EVIDENCE_SYNC_STARTUP_SEED_PER_REPO = 32
# Bounded bookkeeping for recent-command notices, so a long-running watcher
# never grows these sets without limit.
RECENT_COMMAND_NOTICE_MAX = 1024
CANONICAL_STATUS_LABELS = frozenset({
    "status: review-required",
    "status: reviewing",
    "status: deploy-ready",
    "status: deploy-requested",
    "status: deploying",
    "status: testing",
    "status: acceptance-required",
    "status: succeeded",
    "status: failed",
})
ACTIVE_PROJECTION_STATUS_LABELS = frozenset({
    "status: reviewing",
    "status: deploy-ready",
    "status: deploy-requested",
    "status: deploying",
    "status: testing",
    "status: acceptance-required",
})


class DeployCommandError(Exception):
    """Raised when a command cannot be processed."""


def _github_failure_reason(exc: Exception) -> str:
    if isinstance(exc, GitHubRateLimitError):
        return "github_rate_limited"
    if isinstance(exc, GitHubTransientError):
        return "github_transient_or_timeout"
    if isinstance(exc, GitHubError) and exc.status_code is not None:
        return f"github_http_{exc.status_code}"
    return type(exc).__name__


_REJECTION_CODES = {
    "unknown_argument": "unknown_argument",
    "extra_parameter": "extra_parameter",
    "missing_machine_value": "invalid_parameter",
    "invalid_ip_format": "invalid_parameter",
    "missing_parameter": "missing_parameter",
    "invalid_parameter": "invalid_parameter",
    "duplicate_argument": "duplicate_argument",
    "invalid_arguments": "invalid_arguments",
    "parameter_error": "parameter_error",
    "command_not_found": "command_not_found",
    "unknown_command": "command_not_found",
    "machine_not_found": "machine_not_found",
    "machine_selector_not_found": "machine_not_found",
    "unknown_machine": "machine_not_found",
    "machine_not_unique": "machine_not_unique",
    "machine_ambiguous": "machine_not_unique",
    "ambiguous_machine": "machine_not_unique",
    "ambiguous_ip": "machine_not_unique",
    "permission_denied": "permission_denied",
    "machine_not_authorized": "permission_denied",
    "machine_unauthorized": "permission_denied",
    "unauthorized_machine": "permission_denied",
    "machine_permission_denied": "permission_denied",
    "machine_access_denied": "permission_denied",
    "machine_authorization_failed": "permission_denied",
    "owner_not_authorized": "permission_denied",
    "machine_owner_required": "permission_denied",
    "machine_owner_not_authorized": "permission_denied",
    "actor_not_machine_owner": "permission_denied",
    "machine_incompatible": "machine_incompatible",
    "incompatible_machine": "machine_incompatible",
    "component_incompatible": "machine_incompatible",
    "target_unsupported": "machine_incompatible",
    "platform_mismatch": "machine_incompatible",
    "head_changed": "head_changed",
    "stale_head": "head_changed",
    "round_changed": "head_changed",
    "pr_closed": "pr_closed",
    "pr_not_open": "pr_closed",
    "pr_merged": "pr_merged",
    "merged_pr": "pr_merged",
    "pr_draft": "pr_draft",
    "pr_is_draft": "pr_draft",
    "draft_pr": "pr_draft",
    "state_not_allowed": "state_not_allowed",
    "current_state_not_allowed": "state_not_allowed",
    "lifecycle_state_not_allowed": "state_not_allowed",
    "invalid_lifecycle_state": "state_not_allowed",
    "command_not_allowed_in_state": "state_not_allowed",
    "repository_policy_unavailable": "repository_policy_unavailable",
    "repo_policy_unavailable": "repository_policy_unavailable",
    "policy_unavailable": "repository_policy_unavailable",
    "repository_policy_missing": "repository_policy_unavailable",
    "repository_policy_not_configured": "repository_policy_unavailable",
    "repo_policy_missing": "repository_policy_unavailable",
    "machines_yaml_unavailable": "repository_policy_unavailable",
    "machine_policy_unavailable": "repository_policy_unavailable",
}

def _stable_error_code(value: str) -> str:
    """Normalize a stable code while retaining its stable suffix for display."""
    if not isinstance(value, str):
        return ""
    code = value.strip().split(":", 1)[0].strip().casefold().replace("-", "_")
    return code


def _exception_code(exc: Exception | None) -> str:
    if exc is None:
        return ""
    for name in ("code", "error_code", "stable_code"):
        value = getattr(exc, name, None)
        if isinstance(value, str) and value.strip():
            return value.strip()
    raw = str(exc).strip()
    code = _stable_error_code(raw)
    return raw if code in _REJECTION_CODES else ""


def _command_kind(cmd) -> str:
    """Public command name for a parsed/queued command (never empty)."""
    kind = getattr(cmd, "kind", "") or ""
    if kind and kind != "unknown":
        return kind
    return getattr(cmd, "intent", "") or "unknown"


def _needs_initial_comment_baseline(state: dict | None) -> bool:
    """Determine if a PR needs an initial comment baseline cycle.

    Returns True when:
    1. state is None (never observed)
    2. state exists but is the "empty reconcile" state:
       last_processed_comment_id == 0
       command.comment_id == 0
       command.kind == ""
       command.phase == "completed"
       command.args == {}

    This allows recovery when baseline persistence failed silently.
    """
    if state is None:
        return True
    if not isinstance(state, dict):
        return False
    if state.get("last_processed_comment_id") != 0:
        return False
    cmd = state.get("command")
    if not isinstance(cmd, dict):
        return False
    if cmd.get("comment_id") != 0:
        return False
    if cmd.get("kind") != "":
        return False
    if cmd.get("phase") != "completed":
        return False
    if cmd.get("args") != {}:
        return False
    return True


def _top_level_command(text: str, name: str) -> str:
    """Return a recognized top-level special command line, if present."""
    expected = "/" + name
    for line in commands_mod._iter_top_level_command_lines(text or ""):
        if line.split(None, 1)[0].lower() == expected:
            return line
    return ""


class GitHubCommandWatcher:
    """Polls PR comments using `POLL_INTERVAL_SECONDS` and dispatches commands.

    Exactly one serial command worker. Processes comments in ascending order.
    """

    def __init__(
        self,
        config: Config,
        proxy: GitHubStateProxy,
        controller: object,
        github: GitHubClient | None = None,
        github_auth: object | None = None,
    ):
        self.config = config
        self.proxy = proxy
        self.controller = controller
        self._github = github
        self._github_auth = github_auth
        self._auth_refresh_interval = 120  # seconds
        self._last_auth_refresh = -1.0  # never refreshed
        self._auth_refresh_in_progress = False
        self._monotonic = time.monotonic  # deterministic clock source
        self._task: asyncio.Task | None = None
        self._recent_discovery_task: asyncio.Task | None = None
        self._open_pr_listing_scheduler_task: asyncio.Task | None = None
        self._running = False
        # Repos newly (re)activated by an auth refresh.  Each is baselined
        # (cursor = max observed comment id, no dispatch) before normal
        # command processing resumes, so preexisting comments never execute
        # as fresh approvals.
        self._pending_baseline_repos: set[str] = set()
        # Fixed UTC boundary for each active authorization generation. A slow
        # baseline must not move the boundary forward and absorb new commands.
        self._repo_baseline_cutoff_utc: dict[str, datetime] = {}
        # Ready-for-review webhook times are transient scheduling boundaries;
        # successful baselining consumes them without adding persistent state.
        self._ready_for_review_at: dict[tuple[str, int], datetime] = {}
        # Per-repo set of PRs already baselined in the current
        # pending-generation. Prevents rebaselining PRs that
        # already succeeded this generation.
        self._baseline_progress: dict[str, set[int]] = {}
        # Bounded polling cursors: repository order rotates each cycle, while
        # each repository resumes its ordinary scan position in PR-number order.
        self._repo_poll_cursor = 0
        self._pr_scan_cursor: dict[str, int] = {}
        self._recent_pr_cursor: dict[str, int] = {}
        self._active_pr_cursor: dict[str, int] = {}
        self._draft_pr_cursor: dict[str, int] = {}
        self._normal_pr_lane_cursor: dict[str, int] = {}
        self._draft_label_attempts: dict[tuple[str, int], int] = {}
        self._draft_label_retry_after: dict[tuple[str, int], float] = {}
        self._ordinary_pr_scan_retries: dict[tuple[str, int], dict] = {}
        # Scheduling hints only. Selected PRs still pass through fresh
        # authorization, HEAD, cursor, and compare-and-swap checks.
        self._pr_reconcile_cache: dict[tuple[str, int], dict] = {}
        self._last_ordinary_pr_skips = 0
        self._priority_pr_queue: deque[tuple[str, int]] = deque()
        self._priority_pr_set: set[tuple[str, int]] = set()
        self._priority_source_repo_cursor: dict[str, int] = {}
        self._priority_pr_enqueued_at: dict[tuple[str, int], float] = {}
        self._priority_pr_sources: dict[tuple[str, int], str] = {}
        self._priority_generation = 0
        self._priority_baseline_failures: dict[tuple[str, int], int] = {}
        self._priority_pr_retry_after: dict[tuple[str, int], float] = {}
        self._priority_baseline_external_bypassed: set[tuple[str, int]] = set()
        self._new_pr_initialization_attempts: dict[tuple[str, int], int] = {}
        self._new_pr_initialization_retry_after: dict[tuple[str, int], float] = {}
        self._new_pr_initialization_snapshot: dict[tuple[str, int], tuple] = {}
        self._machine_projection_versions: dict[str, object] = {}
        self._machine_refresh_pending: dict[str, dict] = {}
        self._machine_refresh_pr_versions: dict[tuple[str, int], object] = {}
        self._machine_refresh_last_results: dict[tuple[str, int], dict] = {}
        self._machine_refresh_failures: dict[tuple[str, int], int] = {}
        self._machine_refresh_retry_after: dict[tuple[str, int], float] = {}
        self._machine_version_api_missing_repos: set[str] = set()
        # Initialized in start() under the running event loop (Python 3.9 safe).
        self._wakeup = None
        self._last_successful_cycle = None
        self._last_completed_scan_at = None
        self._last_scan_duration = None
        self._last_scan_failure_reasons: list[str] = []
        self._last_scan_slow_reason = None
        self._current_scan_started = None
        self._current_scan_stage = None
        self._current_scan_repo = None
        self._current_scan_pr = None
        self._scan_failure_reasons: list[str] = []
        self._last_driver_poll = None
        self._repo_backlog: dict[str, dict] = {}
        self._last_pr_attempt: dict[tuple[str, int], dict] = {}
        self._recent_command_records: dict[tuple[str, int, int], dict] = {}
        self._latest_recent_command_key: tuple[str, int, int] | None = None
        self._recent_discovery_stats: dict[str, int] = {
            "recent_comments_received": 0,
            "foreign_bot_filtered": 0,
            "invalid_issue_url": 0,
            "invalid_timestamp": 0,
            "unknown_command": 0,
            "baseline_cutoff_filtered": 0,
            "baseline_cutoff_unavailable": 0,
            "baseline_rejection_notices": 0,
            "discovery_deferred": 0,
            "eligible_commands": 0,
            "newly_discovered_prs": 0,
            "priority_queued": 0,
            "priority_retry": 0,
        }
        self._priority_item_failures: dict[tuple[str, int], int] = {}
        # Insertion-ordered maps used as bounded sets: the oldest entry is
        # evicted first so a long-running watcher never grows without limit.
        self._posted_error_replies: dict[tuple[str, int, int], None] = {}
        self._confirmed_command_results: dict[tuple[str, int, int], str] = {}
        # Commands that arrived before the fixed authorization baseline. They
        # must never execute, but they are not silently dropped: each one gets
        # exactly one rejection notice after its PR baseline completes.
        self._pending_baseline_notices: dict[tuple[str, int, int], None] = {}
        self._recent_discovery_at: dict[str, str] = {}
        self._recent_discovery_monotonic: dict[str, float] = {}
        self._recent_discovery_last_failure: dict[str, str | None] = {}
        self._cycle_durations: deque[float] = deque(maxlen=100)
        self._pr_durations: deque[float] = deque(maxlen=200)
        self._last_evidence_projection: dict[tuple[str, int], tuple[str, float]] = {}
        # Ready-evidence reconcile hints. One entry per repo/PR; the serial
        # worker decides what is missing from persisted records, so a hint is
        # only a scheduling nudge and never an instruction.
        self._evidence_sync_queue: deque[tuple[str, int]] = deque()
        self._evidence_sync_set: set[tuple[str, int]] = set()
        self._evidence_sync_failures: dict[tuple[str, int], int] = {}
        self._evidence_sync_retry_after: dict[tuple[str, int], float] = {}
        self._evidence_sync_seeded_repos: set[str] = set()
        # Read-only full-list queries run independently per authorized repo.
        # Their immutable snapshots are only scheduling hints; the serial
        # writer still re-reads each selected PR before any lifecycle write.
        self._open_pr_listing_tasks: dict[str, asyncio.Task] = {}
        self._open_pr_listing_snapshots: dict[str, dict] = {}
        self._open_pr_listing_next_attempt: dict[str, float] = {}
        self._open_pr_listing_failures: dict[str, int] = {}
        self._open_pr_listing_generation: dict[str, int] = {}
        self._open_pr_listing_status: dict[str, dict] = {}

    async def _validated_current_summary_cos_links(self, repo: str, pr_number: int) -> set[str]:
        """Return one-year COS URLs present in the trusted current Summary."""
        store = getattr(getattr(self.controller, "evidence_service", None), "store", None)
        if store is None or not callable(getattr(store, "download_url_expiry", None)):
            return set()
        pr = await self.proxy.get_pr(repo, pr_number)
        state = await self.proxy.read_hidden_state(repo, pr_number)
        lifecycle = await self.proxy.find_trusted_lifecycle_comment(repo, pr_number)
        if (not isinstance(pr, dict) or pr.get("state") != "open" or pr.get("merged")
                or not isinstance(state, dict)
                or not isinstance(lifecycle, dict)
                or (pr.get("head") or {}).get("sha") != state.get("head_sha")):
            return set()
        body = lifecycle.get("body", "")
        if not isinstance(body, str) or HIDDEN_STATE_MARKER not in body:
            return set()
        visible = body.split(HIDDEN_STATE_MARKER, 1)[0]
        urls = set(re.findall(r"<(https://[^<>\s]+)>", visible))
        if not urls:
            return set()

        objects = []
        metadata = state.get("cos")
        if isinstance(metadata, dict):
            object_key = metadata.get("object_key", "")
            try:
                from .cos_client import CosClient
                CosClient.validate_object_key(repo, pr_number, state["head_sha"], object_key)
            except (KeyError, TypeError, ValueError):
                pass
            else:
                if (isinstance(metadata.get("sha256"), str)
                        and re.fullmatch(r"[0-9a-f]{64}", metadata["sha256"])
                        and type(metadata.get("size")) is int and metadata["size"] > 0):
                    objects.append((object_key, object_key.rsplit("/", 1)[-1], None))

        try:
            from .evidence_models import round_id_for_state
            from .evidence_store import build_attachment_key
            current_round = round_id_for_state(state)
            records = await self.proxy.read_evidence_records(repo, pr_number)
        except (GitHubStateProxyError, ValueError, TypeError):
            return set()
        for record in records:
            if record.get("kind") != "attachment":
                continue
            item = record.get("data")
            if (not isinstance(item, dict) or item.get("status") != "ready"
                    or item.get("actor_verified") is not True
                    or item.get("head_sha") != state.get("head_sha")
                    or item.get("round_id") != current_round
                    or not isinstance(item.get("sha256"), str)
                    or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None
                    or type(item.get("size")) is not int or item["size"] <= 0):
                continue
            attachment_id = item.get("attachment_id")
            filename = item.get("filename")
            try:
                expected_key = build_attachment_key(
                    repo, pr_number, state["head_sha"], current_round,
                    attachment_id, item.get("created_at", ""), filename,
                )
            except (TypeError, ValueError):
                continue
            if item.get("object_key") == expected_key:
                objects.append((expected_key, filename, attachment_id))

        valid = set()
        for url in urls:
            for key, filename, attachment_id in objects:
                if store.download_url_expiry(
                        url, key=key, filename=filename, attachment_id=attachment_id) is not None:
                    valid.add(url)
                    break
        return valid

    def enqueue_pr(
        self, repo: str, pr_number: int, *, action=None, event_updated_at=None,
    ) -> bool:
        """Prioritize an authorized PR using only validated webhook hints."""
        if (not isinstance(repo, str)
                or not getattr(self.config, "auth_valid", False)
                or repo not in self.config.active_repos
                or repo not in self.config.github_repos
                or type(pr_number) is not int
                or pr_number <= 0):
            return False
        item = (repo, pr_number)
        if action == "ready_for_review":
            ready_at = self._parse_comment_time(event_updated_at)
            if ready_at is None:
                reason = (
                    "missing" if event_updated_at is None
                    or isinstance(event_updated_at, str) and not event_updated_at.strip()
                    else "invalid"
                )
                ready_at = datetime.now(timezone.utc)
                logger.warning(
                    "watcher ready_for_review timestamp fallback reason=%s",
                    reason,
                )
            previous_ready_at = self._ready_for_review_at.get(item)
            if previous_ready_at is None or ready_at > previous_ready_at:
                self._ready_for_review_at[item] = ready_at
            while len(self._ready_for_review_at) > 4096:
                oldest = min(
                    self._ready_for_review_at,
                    key=self._ready_for_review_at.get,
                )
                self._ready_for_review_at.pop(oldest, None)
        elif action == "converted_to_draft":
            self._ready_for_review_at.pop(item, None)
            self._baseline_progress.get(repo, set()).discard(pr_number)
        self._prioritize_new_external_baseline_retry(item)
        was_queued = item in self._priority_pr_queue
        previous_source = self._priority_pr_sources.get(item)
        queued = self._queue_priority_pr(item, "webhook")
        priority_changed = queued and (
            not was_queued or previous_source != self._priority_pr_sources.get(item)
        )
        if priority_changed:
            self._priority_generation += 1
            self._signal_wakeup()
        return queued

    def _queue_priority_pr(self, item: tuple[str, int], source: str) -> bool:
        """Requeue one PR hint without duplicates, preserving its strongest trigger."""
        source_rank = self._priority_source_rank
        if item in self._priority_pr_queue:
            current_source = self._priority_pr_sources.get(item, "webhook")
            if source_rank(source) < source_rank(current_source):
                self._priority_pr_queue.remove(item)
                self._priority_pr_sources[item] = source
                insert_at = next((index for index, queued in enumerate(self._priority_pr_queue)
                                  if source_rank(
                                      self._priority_pr_sources.get(queued, "webhook"),
                                  ) > source_rank(source)), len(self._priority_pr_queue))
                self._priority_pr_queue.insert(insert_at, item)
            return True
        if len(self._priority_pr_queue) >= 128:
            evicted = next((queued for queued in reversed(self._priority_pr_queue)
                            if source_rank(
                                self._priority_pr_sources.get(queued, "webhook"),
                            ) > source_rank(source)), None)
            if evicted is None:
                return False
            self._priority_pr_queue.remove(evicted)
            self._priority_pr_set.discard(evicted)
            self._priority_pr_enqueued_at.pop(evicted, None)
            self._priority_pr_sources.pop(evicted, None)
            self._clear_priority_baseline_retry(evicted)
            self._clear_priority_item_retry(evicted)
        insert_at = next((index for index, queued in enumerate(self._priority_pr_queue)
                          if source_rank(
                              self._priority_pr_sources.get(queued, "webhook"),
                          ) > source_rank(source)), len(self._priority_pr_queue))
        self._priority_pr_queue.insert(insert_at, item)
        self._priority_pr_set.add(item)
        self._priority_pr_sources[item] = source
        self._priority_pr_enqueued_at[item] = self._monotonic()
        self._recent_discovery_stats["priority_queued"] += 1
        return True

    @staticmethod
    def _priority_source_rank(source: str) -> int:
        return {
            "command": 0,
            "webhook": 1,
            "recent": 2,
            "machine": 3,
            "initialization": 4,
        }.get(source, 2)

    def _retry_priority_baseline(self, item: tuple[str, int], source: str) -> None:
        """Back off an incomplete baseline without dropping its priority hint."""
        failures = self._priority_baseline_failures.get(item, 0) + 1
        self._priority_baseline_failures[item] = failures
        self._recent_discovery_stats["priority_retry"] += 1
        base = max(PRIORITY_BASELINE_RETRY_BASE_SECONDS,
                   float(self.config.poll_interval_seconds))
        delay = min(PRIORITY_BASELINE_RETRY_MAX_SECONDS,
                    base * (2 ** min(failures - 1, 8)))
        self._priority_pr_retry_after[item] = self._monotonic() + delay
        if not self._queue_priority_pr(item, source):
            self._clear_priority_baseline_retry(item)
        logger.info(
            "watcher baseline retry deferred repo=%s pr=%s failures=%s delay_seconds=%.1f",
            item[0], item[1], failures, delay,
        )

    def _clear_priority_baseline_retry(self, item: tuple[str, int]) -> None:
        self._priority_baseline_failures.pop(item, None)
        self._priority_pr_retry_after.pop(item, None)
        self._priority_baseline_external_bypassed.discard(item)

    def _retry_priority_item(self, item: tuple[str, int], source: str, reason: str = "") -> None:
        """Back off a failed priority PR without dropping it, preventing starvation."""
        failures = self._priority_item_failures.get(item, 0) + 1
        self._priority_item_failures[item] = failures
        self._recent_discovery_stats["priority_retry"] += 1
        base = max(2.0, float(self.config.poll_interval_seconds))
        delay = min(60.0, base * (2 ** min(failures - 1, 4)))
        self._priority_pr_retry_after[item] = self._monotonic() + delay
        self._queue_priority_pr(item, source)
        logger.info(
            "watcher priority PR retry deferred repo=%s pr=%s reason=%s failures=%s delay_seconds=%.1f",
            item[0], item[1], reason, failures, delay,
        )

    def _clear_priority_item_retry(self, item: tuple[str, int]) -> None:
        self._priority_item_failures.pop(item, None)
        self._priority_pr_retry_after.pop(item, None)

    def _retry_machine_projection_refresh(
        self, item: tuple[str, int], reason: str,
    ) -> None:
        failures = min(8, self._machine_refresh_failures.get(item, 0) + 1)
        self._machine_refresh_failures[item] = failures
        base = max(2.0, float(self.config.poll_interval_seconds))
        delay = min(300.0, base * (2 ** min(failures - 1, 5)))
        self._machine_refresh_retry_after[item] = self._monotonic() + delay
        self._queue_priority_pr(item, "machine")
        logger.info(
            "watcher machine projection retry deferred repo=%s pr=%s reason=%s failures=%s delay_seconds=%.1f",
            item[0], item[1], reason, failures, delay,
        )

    def _clear_machine_projection_retry(self, item: tuple[str, int]) -> None:
        self._machine_refresh_failures.pop(item, None)
        self._machine_refresh_retry_after.pop(item, None)

    def _prioritize_new_external_baseline_retry(self, item: tuple[str, int]) -> None:
        """Let one fresh webhook/comment hint bypass an incomplete baseline delay.

        Internal retry hints use _queue_priority_pr and keep their deadline.
        This per-episode latch prevents repeated external hints from continually
        clearing a backoff while the same baseline keeps failing.
        """
        if (self._monotonic() < self._priority_pr_retry_after.get(item, 0.0)
                and item not in self._priority_baseline_external_bypassed):
            self._priority_baseline_external_bypassed.add(item)
            self._priority_baseline_failures.pop(item, None)
            self._priority_item_failures.pop(item, None)
            self._priority_pr_retry_after.pop(item, None)

    def _signal_wakeup(self) -> None:
        """Wake a started watcher; preserve queued hints before startup."""
        if self._wakeup is not None:
            self._wakeup.set()

    def schedule_evidence_sync(self, repo: str, pr_number: int) -> bool:
        """Queue one bounded ready-attachment reconcile hint for the writer.

        Called from the ready event and from read-only polls. The hint carries
        no attachment payload: the serial worker re-reads persisted records and
        the live lifecycle state before any write, so a stale hint is harmless.
        """
        item = (repo, pr_number)
        if (not isinstance(repo, str) or type(pr_number) is not int or pr_number <= 0
                or not getattr(self.config, "auth_valid", False)
                or repo not in self.config.active_repos
                or repo not in self.config.github_repos):
            return False
        # Clear evidence projection cache so ready evidence triggers projection
        self._last_evidence_projection.pop(item, None)
        self._clear_evidence_sync_retry(item)
        if item in self._evidence_sync_set:
            self._signal_wakeup()
            return True
        if len(self._evidence_sync_queue) >= EVIDENCE_SYNC_QUEUE_MAX:
            logger.warning(
                "watcher evidence sync queue full; hint was not queued repo=%s pr=%s",
                repo, pr_number,
            )
            return False
        self._evidence_sync_queue.append(item)
        self._evidence_sync_set.add(item)
        self._signal_wakeup()
        return True

    def _retry_evidence_sync(self, item: tuple[str, int]) -> None:
        """Keep a failed reconcile queued with capped exponential backoff."""
        failures = self._evidence_sync_failures.get(item, 0) + 1
        self._evidence_sync_failures[item] = failures
        base = max(EVIDENCE_SYNC_RETRY_BASE_SECONDS,
                   float(self.config.poll_interval_seconds))
        delay = min(EVIDENCE_SYNC_RETRY_MAX_SECONDS,
                    base * (2 ** min(failures - 1, 8)))
        self._evidence_sync_retry_after[item] = self._monotonic() + delay
        if item not in self._evidence_sync_set:
            if len(self._evidence_sync_queue) >= EVIDENCE_SYNC_QUEUE_MAX:
                # A retry just removed this item before other hints filled the
                # queue. Retain one overflow slot so this failure is not lost.
                logger.warning(
                    "watcher evidence retry retained beyond queue limit repo=%s pr=%s",
                    item[0], item[1],
                )
            self._evidence_sync_queue.append(item)
            self._evidence_sync_set.add(item)
        logger.warning(
            "watcher evidence sync deferred repo=%s pr=%s failures=%s delay_seconds=%.1f",
            item[0], item[1], failures, delay,
        )

    def _clear_evidence_sync_retry(self, item: tuple[str, int]) -> None:
        self._evidence_sync_failures.pop(item, None)
        self._evidence_sync_retry_after.pop(item, None)

    def _seed_evidence_sync_for_repo(self, repo: str, prs) -> None:
        """Seed restart recovery from the most recent open PRs only.

        Bounded per repository: an attachment verified before a restart is
        reconciled without scanning every PR. The reconcile itself decides
        from persisted records whether anything is actually missing.
        """
        if repo in self._evidence_sync_seeded_repos:
            return
        self._evidence_sync_seeded_repos.add(repo)
        candidates = []
        for item in prs or []:
            pr = item[1] if isinstance(item, tuple) and len(item) == 2 else item
            if not isinstance(pr, dict) or pr.get("draft") is True:
                continue
            number = pr.get("number")
            if type(number) is not int or number <= 0:
                continue
            candidates.append((str(pr.get("updated_at") or ""), number))
        candidates.sort(reverse=True)
        for _, number in candidates[:EVIDENCE_SYNC_STARTUP_SEED_PER_REPO]:
            self.schedule_evidence_sync(repo, number)

    async def _reconcile_ready_evidence(self, repo: str, pr_number: int) -> bool:
        """Run the bounded ready-evidence reconcile through the serial writer.

        The Summary is re-projected only when a verified ready attachment is
        not yet present in the trusted visible Summary. This does not depend on
        the PR ``updated_at`` version.
        """
        service = getattr(self, "evidence_service", None) or getattr(self.controller, "evidence_service", None)
        reconcile = getattr(service, "reconcile_ready_evidence", None)
        if not callable(reconcile):
            return True
        pr = await self.proxy.get_pr(repo, pr_number)
        if (not isinstance(pr, dict) or pr.get("state") != "open"
                or pr.get("merged") or pr.get("draft")):
            return True
        self._current_scan_stage = "evidence_sync"
        self._current_scan_repo = repo
        self._current_scan_pr = pr_number
        outcome = await reconcile(repo, pr_number)
        if not isinstance(outcome, dict):
            logger.warning(
                "watcher evidence reconcile returned malformed result %s#%s",
                repo, pr_number,
            )
            return False
        if outcome.get("error"):
            logger.warning(
                "watcher evidence reconcile unavailable %s#%s error=%s",
                repo, pr_number, outcome.get("error"),
            )
            return False
        if outcome.get("restore_pending"):
            logger.warning(
                "watcher evidence COS restore pending %s#%s count=%s",
                repo, pr_number, outcome.get("restore_pending"),
            )
        # The Summary link is the primary user-visible requirement, so it is
        # re-projected even when one comment still needs a retry.
        if outcome.get("needs_projection"):
            if self._defer_evidence_projection_for_priority(repo, pr_number):
                return False
            self._current_scan_stage = "evidence_sync_projection"
            await self.controller.project_evidence(repo, pr_number)
            self._last_evidence_projection[(repo, pr_number)] = (
                f"{pr.get('head', {}).get('sha')}:{pr.get('updated_at')}",
                self._monotonic(),
            )
        if outcome.get("pending"):
            # Keep lifecycle commands moving while retrying visible evidence
            # synchronization and pending COS restoration.
            return False
        if outcome.get("failed"):
            # Temporary GitHub failures stay pending and retry with backoff.
            return False
        return True

    async def _drain_evidence_sync(self, *, max_items: int = 2) -> bool:
        """Process bounded evidence-sync hints on the serial writer."""
        cycle_ok = True
        processed = 0
        while self._evidence_sync_queue and processed < max_items:
            item = self._evidence_sync_queue[0]
            if self._monotonic() < self._evidence_sync_retry_after.get(item, 0.0):
                # Rotate the queue so one backed-off PR cannot starve others.
                self._evidence_sync_queue.rotate(-1)
                if all(self._monotonic() < self._evidence_sync_retry_after.get(
                        queued, 0.0) for queued in self._evidence_sync_queue):
                    break
                continue
            self._evidence_sync_queue.popleft()
            self._evidence_sync_set.discard(item)
            repo, pr_number = item
            if (self.config.auth_valid is not True
                    or repo not in self.config.active_repos
                    or repo not in self.config.github_repos):
                self._clear_evidence_sync_retry(item)
                continue
            processed += 1
            try:
                succeeded = await self._reconcile_ready_evidence(repo, pr_number)
            except GitHubRateLimitError as exc:
                logger.warning(
                    "watcher rate limited during evidence sync %s#%s; retry_after=%.1f",
                    repo, pr_number, exc.retry_after_seconds,
                )
                self._retry_evidence_sync(item)
                cycle_ok = False
                break
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning(
                    "watcher evidence sync %s#%s failed: %s",
                    repo, pr_number, type(exc).__name__,
                )
                self._retry_evidence_sync(item)
                self._scan_failure_reasons.append(
                    f"evidence_sync:{repo}#{pr_number}:{type(exc).__name__}",
                )
                cycle_ok = False
                continue
            if succeeded:
                self._clear_evidence_sync_retry(item)
            else:
                self._retry_evidence_sync(item)
                cycle_ok = False
        return cycle_ok


    def start(self) -> None:
        if self._running:
            return
        self._wakeup = asyncio.Event()
        self._running = True
        self._task = asyncio.create_task(self._poll_loop())
        self._recent_discovery_task = asyncio.create_task(self._recent_discovery_loop())
        self._open_pr_listing_scheduler_task = asyncio.create_task(
            self._open_pr_listing_refresh_loop(),
        )

    def mark_repos_pending_baseline(
        self, repos: list[str], *, startup: bool = True,
    ) -> None:
        """Seed the pending-baseline gate for externally resolved repos.

        Startup and authorization recovery both establish a new generation.
        This includes the configured primary repository: commands posted during
        an authorization outage must never become fresh approvals on recovery.
        """
        cutoff_utc = datetime.now(timezone.utc)
        for repo in repos:
            if repo not in self.config.github_repos or repo not in self.config.active_repos:
                continue
            self._pending_baseline_repos.add(repo)
            self._baseline_progress[repo] = set()
            self._repo_baseline_cutoff_utc[repo] = cutoff_utc
            self._invalidate_open_pr_listing_repo(
                repo, status="rebaseline_required",
            )

    async def stop(self) -> None:
        self._running = False
        if self._open_pr_listing_scheduler_task is not None:
            self._open_pr_listing_scheduler_task.cancel()
            try:
                await self._open_pr_listing_scheduler_task
            except asyncio.CancelledError:
                pass
            self._open_pr_listing_scheduler_task = None
        if self._recent_discovery_task is not None:
            self._recent_discovery_task.cancel()
            try:
                await self._recent_discovery_task
            except asyncio.CancelledError:
                pass
            self._recent_discovery_task = None
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        listing_tasks = list(self._open_pr_listing_tasks.values())
        for task in listing_tasks:
            task.cancel()
        if listing_tasks:
            await asyncio.gather(*listing_tasks, return_exceptions=True)
        self._open_pr_listing_tasks.clear()

    async def _recent_discovery_loop(self) -> None:
        """Discover new comments independently; this task never writes PR state."""
        interval = max(1.0, min(10.0, float(self.config.poll_interval_seconds)))
        next_run = self._monotonic()
        while self._running:
            if (self.config.auth_valid is True and not self._auth_refresh_in_progress
                    and not self._github_backing_off()):
                repos = list(dict.fromkeys(self.config.active_repos))
                if repos:
                    try:
                        await self._discover_recent_command_prs(repos)
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        logger.warning(
                            "watcher independent recent discovery failed reason=%s",
                            type(exc).__name__,
                        )
            next_run += interval
            now = self._monotonic()
            if next_run <= now - interval:
                next_run = now + interval
            await asyncio.sleep(max(0.0, next_run - now))

    async def _open_pr_listing_refresh_loop(self) -> None:
        """Schedule independent read-only repository listings on their cadence."""
        interval = max(1.0, min(5.0, float(self.config.poll_interval_seconds)))
        while self._running:
            if self.config.auth_valid is not True:
                self._invalidate_all_open_pr_listing_snapshots()
            else:
                try:
                    repos = self._authorized_watcher_repos()
                except (TypeError, ValueError, RuntimeError) as exc:
                    self.config.auth_valid = False
                    self._invalidate_all_open_pr_listing_snapshots()
                    logger.warning(
                        "watcher PR listing scheduler authorization invalid reason=%s",
                        type(exc).__name__,
                    )
                else:
                    self._sync_open_pr_listing_repos(repos)
                    self._schedule_open_pr_listing_refreshes(repos)
            await asyncio.sleep(interval)

    async def _poll_loop(self) -> None:
        while self._running:
            try:
                await self._refresh_active_repos_if_needed()
                await self._refresh_active_repository_policies_if_due()
                await self._poll_once()
            except Exception as e:
                logger.error("command watcher poll cycle failed: %s", e)
                if isinstance(self._current_scan_started, (int, float)):
                    duration = max(0.0, self._monotonic() - self._current_scan_started)
                    self._last_completed_scan_at = datetime.now(timezone.utc).isoformat()
                    self._last_scan_duration = round(duration, 1)
                    self._last_scan_failure_reasons = [f"poll_loop:{type(e).__name__}"]
                    self._last_scan_slow_reason = (
                        f"slow_stage:{self._current_scan_stage or 'unknown'}"
                        if duration > 60.0 else None
                    )
                    self._cycle_durations.append(duration)
                    self._current_scan_started = None
                    self._current_scan_stage = None
                    self._current_scan_repo = None
                    self._current_scan_pr = None
            try:
                await asyncio.wait_for(
                    self._wakeup.wait(), timeout=self.config.poll_interval_seconds,
                )
                self._wakeup.clear()
            except asyncio.TimeoutError:
                pass

    async def _refresh_repo_policy_if_due(self, repo: str) -> None:
        """Refresh one currently authorized repo before it can handle a command."""
        if self.config.auth_valid is not True:
            return
        try:
            authorized_repos = resolve_authorized_repos(
                self.config.github_repos, self.config.active_repos,
            )
        except (TypeError, ValueError, RuntimeError) as exc:
            logger.warning(
                "repository policy refresh skipped because authorization is invalid (%s)",
                type(exc).__name__,
            )
            return
        if repo.casefold() not in {name.casefold() for name in authorized_repos}:
            return

        policy = getattr(self.controller, "policy", None)
        refresh = getattr(policy, "refresh_if_due", None)
        github_client = self._github or getattr(self.controller, "github", None)
        if not callable(refresh) or github_client is None:
            return
        try:
            await refresh(repo, github_client)
        except Exception as exc:
            # The policy store retains its last verified snapshot on fetch
            # errors; an unconfigured repo remains fail-closed in its getters.
            logger.warning(
                "repository policy refresh failed for %s (%s)",
                repo, type(exc).__name__,
            )

    async def _refresh_active_repository_policies_if_due(self) -> None:
        """Load policy for each repo authorized by the current App snapshot."""
        if self.config.auth_valid is not True:
            return
        try:
            authorized_repos = resolve_authorized_repos(
                self.config.github_repos, self.config.active_repos,
            )
        except (TypeError, ValueError, RuntimeError) as exc:
            logger.warning(
                "repository policy startup refresh skipped because authorization is invalid (%s)",
                type(exc).__name__,
            )
            return
        for repo in authorized_repos:
            if self.config.auth_valid is not True:
                return
            await self._refresh_repo_policy_if_due(repo)

    @property
    def recent_discovery_stats(self) -> dict[str, int]:
        return dict(self._recent_discovery_stats)

    def diagnostics(self) -> dict:
        now = self._monotonic()
        command_rows = [row for row in self._recent_command_records.values() if isinstance(row, dict)]
        last_success = max((row for row in command_rows
                            if row.get("status") == "handled"
                            and row.get("failure_reason") is None),
                           key=lambda row: row.get("processing_completed_at") or "", default=None)
        last_failure = max((row for row in command_rows if row.get("last_failure_reason")),
                           key=lambda row: row.get("last_failure_at") or "", default=None)
        pending_age = max((now - row["_discovered_monotonic"] for row in command_rows
                           if row.get("status") in {"discovered", "retry", "processing"}
                           and isinstance(row.get("_discovered_monotonic"), (int, float))),
                          default=0.0)
        oldest_age = max(
            (now - self._priority_pr_enqueued_at.get(item, now)
             for item in self._priority_pr_queue),
            default=0.0,
        )
        current_scan_seconds = (
            max(0.0, now - self._current_scan_started)
            if isinstance(self._current_scan_started, (int, float)) else None
        )
        return {
            "last_successful_cycle": self._last_successful_cycle,
            "last_completed_scan_at": self._last_completed_scan_at,
            "last_scan_duration_seconds": self._last_scan_duration,
            "last_scan_failure_count": len(self._last_scan_failure_reasons),
            "last_scan_failure_reasons": list(self._last_scan_failure_reasons),
            "last_scan_slow_reason": self._last_scan_slow_reason,
            "current_scan_duration_seconds": round(current_scan_seconds, 1)
            if current_scan_seconds is not None else None,
            "current_scan_stage": self._current_scan_stage,
            "current_scan_repo": self._current_scan_repo,
            "current_scan_pr": self._current_scan_pr,
            "last_driver_poll": self._last_driver_poll,
            "per_repo_backlog": {repo: dict(value) for repo, value in self._repo_backlog.items()},
            "priority_queue_length": len(self._priority_pr_queue),
            "oldest_queued_age_seconds": round(oldest_age, 1),
            "cycle_duration_seconds": round(self._cycle_durations[-1], 1) if self._cycle_durations else None,
            "cycle_duration_average_seconds": round(sum(self._cycle_durations) / len(self._cycle_durations), 1) if self._cycle_durations else None,
            "cycle_duration_p95_seconds": round(sorted(self._cycle_durations)[int((len(self._cycle_durations) - 1) * 0.95)], 1) if self._cycle_durations else None,
            "pr_duration_average_seconds": round(sum(self._pr_durations) / len(self._pr_durations), 1) if self._pr_durations else None,
            "pr_duration_p95_seconds": round(sorted(self._pr_durations)[int((len(self._pr_durations) - 1) * 0.95)], 1) if self._pr_durations else None,
            "recent_command": self._public_recent_command_metric(),
            "last_command_success": ({key: last_success.get(key) for key in
                                      ("processing_completed_at", "repo", "pr_number", "comment_id")}
                                     if last_success else None),
            "last_command_failure": ({key: last_failure.get(key) for key in
                                      ("last_failure_at", "repo", "pr_number", "comment_id",
                                       "last_failure_reason")}
                                     if last_failure else None),
            "oldest_pending_command_age_seconds": round(max(0.0, pending_age), 1),
            "ordinary_prs_skipped_last_cycle": self._last_ordinary_pr_skips,
            "open_pr_listing_by_repo": self._open_pr_listing_diagnostics(),
            "recent_command_discovery_at": dict(self._recent_discovery_at),
            "last_recent_command_discovery_at": max(
                self._recent_discovery_at.values(), default=None,
            ),
            "recent_command_discovery_last_failure": dict(self._recent_discovery_last_failure),
            "pr_442_last_attempt": dict(self._last_pr_attempt.get(("4paradigm/phanthymotus-driver", 442), {})),
            "recent_discovery_stats": dict(self._recent_discovery_stats),
            "recent_comments_received": self._recent_discovery_stats["recent_comments_received"],
            "foreign_bot_filtered": self._recent_discovery_stats["foreign_bot_filtered"],
            "invalid_issue_url": self._recent_discovery_stats["invalid_issue_url"],
            "invalid_timestamp": self._recent_discovery_stats["invalid_timestamp"],
            "unknown_command": self._recent_discovery_stats["unknown_command"],
            "baseline_cutoff_filtered": self._recent_discovery_stats["baseline_cutoff_filtered"],
            "baseline_cutoff_unavailable": self._recent_discovery_stats["baseline_cutoff_unavailable"],
            "baseline_rejection_notices": self._recent_discovery_stats["baseline_rejection_notices"],
            "baseline_notices_pending": len(self._pending_baseline_notices),
            "discovery_deferred": self._recent_discovery_stats["discovery_deferred"],
            "eligible_commands": self._recent_discovery_stats["eligible_commands"],
            "newly_discovered_prs": self._recent_discovery_stats["newly_discovered_prs"],
            "priority_queued": self._recent_discovery_stats["priority_queued"],
            "priority_retry": self._recent_discovery_stats["priority_retry"],
            "github_api": self._github.diagnostics() if callable(getattr(self._github, "diagnostics", None)) else {},
            "webhook_enabled": bool(getattr(self.config, "webhook_enabled", False)),
        }

    def _github_backing_off(self) -> bool:
        diagnostics = self._github.diagnostics() if callable(
            getattr(self._github, "diagnostics", None)
        ) else None
        if not isinstance(diagnostics, dict):
            return False
        return diagnostics.get(
            "authenticated_backing_off", diagnostics.get("backing_off", False),
        ) is True

    def _open_pr_listing_repo_is_authorized(self, repo: str) -> bool:
        repo_key = repo.casefold()
        active = {
            name.casefold() for name in self.config.active_repos
            if isinstance(name, str)
        }
        allowlist = {
            name.casefold() for name in self.config.github_repos
            if isinstance(name, str)
        }
        return (
            self.config.auth_valid is True
            and repo_key in active
            and repo_key in allowlist
        )

    def _authorized_watcher_repos(self) -> list[str]:
        authorized = set(resolve_authorized_repos(
            self.config.github_repos, self.config.active_repos,
        ))
        return [
            repo for repo in dict.fromkeys(self.config.active_repos)
            if repo.casefold() in authorized
        ]

    def _invalidate_open_pr_listing_repo(
        self, repo: str, *, status: str = "invalidated", remove: bool = False,
    ) -> None:
        self._open_pr_listing_generation[repo] = (
            self._open_pr_listing_generation.get(repo, 0) + 1
        )
        task = self._open_pr_listing_tasks.get(repo)
        if task is not None and not task.done():
            task.cancel()
        self._open_pr_listing_snapshots.pop(repo, None)
        self._open_pr_listing_failures.pop(repo, None)
        if remove:
            self._open_pr_listing_next_attempt.pop(repo, None)
            self._open_pr_listing_status.pop(repo, None)
            return
        self._open_pr_listing_next_attempt[repo] = self._monotonic()
        previous = self._open_pr_listing_status.get(repo, {})
        self._open_pr_listing_status[repo] = {
            "status": status,
            "last_attempt_at": previous.get("last_attempt_at"),
            "last_success_at": None,
            "duration_seconds": previous.get("duration_seconds"),
            "snapshot_count": 0,
            "failure_type": previous.get("failure_type")
            if status == "authorization_unavailable" else None,
        }

    def _clear_repo_transient_scheduling_state(self, repo: str) -> None:
        """Drop volatile work for an unauthorized repo without touching cursors."""
        self._machine_projection_versions.pop(repo, None)
        self._machine_refresh_pending.pop(repo, None)
        self._machine_version_api_missing_repos.discard(repo)
        for item in [item for item in self._machine_refresh_pr_versions
                     if item[0] == repo]:
            self._machine_refresh_pr_versions.pop(item, None)
        for item in [item for item in self._machine_refresh_last_results
                     if item[0] == repo]:
            self._machine_refresh_last_results.pop(item, None)
        for mapping in (
            self._machine_refresh_failures, self._machine_refresh_retry_after,
        ):
            for item in [item for item in mapping if item[0] == repo]:
                mapping.pop(item, None)
        for item in [item for item in self._priority_pr_queue if item[0] == repo]:
            self._priority_pr_queue.remove(item)
            self._priority_pr_set.discard(item)
            self._priority_pr_enqueued_at.pop(item, None)
            self._priority_pr_sources.pop(item, None)
        for mapping in (
            self._priority_baseline_failures,
            self._priority_pr_retry_after,
            self._priority_item_failures,
            self._priority_baseline_external_bypassed,
            self._new_pr_initialization_attempts,
            self._new_pr_initialization_retry_after,
            self._new_pr_initialization_snapshot,
            self._draft_label_attempts,
            self._draft_label_retry_after,
            self._ordinary_pr_scan_retries,
        ):
            if isinstance(mapping, set):
                for item in [item for item in mapping if item[0] == repo]:
                    mapping.discard(item)
            else:
                for item in [item for item in mapping if item[0] == repo]:
                    mapping.pop(item, None)
        self._priority_generation += 1

    def _clear_unauthorized_transient_scheduling_state(self) -> None:
        """Discard queued hints on auth loss; persisted command cursors stay intact."""
        repos = set(self.config.active_repos) | set(self.config.github_repos)
        repos.update(self._machine_projection_versions)
        repos.update(self._machine_refresh_pending)
        repos.update(repo for repo, _ in self._machine_refresh_pr_versions)
        repos.update(repo for repo, _ in self._machine_refresh_last_results)
        repos.update(repo for repo, _ in self._machine_refresh_failures)
        repos.update(repo for repo, _ in self._machine_refresh_retry_after)
        repos.update(self._machine_version_api_missing_repos)
        for mapping in (
            self._priority_baseline_failures,
            self._priority_pr_retry_after,
            self._priority_item_failures,
            self._priority_baseline_external_bypassed,
            self._new_pr_initialization_attempts,
            self._new_pr_initialization_retry_after,
            self._new_pr_initialization_snapshot,
            self._draft_label_attempts,
            self._draft_label_retry_after,
            self._ordinary_pr_scan_retries,
        ):
            repos.update(item[0] for item in mapping)
        repos.update(repo for repo, _ in self._priority_pr_queue)
        for repo in repos:
            self._clear_repo_transient_scheduling_state(repo)
        # A partially completed authorization generation is re-established by
        # mark_repos_pending_baseline() on recovery. Keep stored comment cursors
        # untouched so old commands cannot be replayed by queue cleanup.
        self._priority_pr_queue.clear()
        self._priority_pr_set.clear()
        self._priority_pr_enqueued_at.clear()
        self._priority_pr_sources.clear()
        self._priority_source_repo_cursor.clear()

    def _invalidate_all_open_pr_listing_snapshots(self) -> None:
        self._clear_unauthorized_transient_scheduling_state()
        repos = set(self._open_pr_listing_tasks)
        repos.update(self._open_pr_listing_snapshots)
        repos.update(self._open_pr_listing_status)
        repos.update(self._open_pr_listing_next_attempt)
        for repo in repos:
            task = self._open_pr_listing_tasks.get(repo)
            if (repo not in self._open_pr_listing_snapshots
                    and (task is None or task.done())
                    and self._open_pr_listing_status.get(repo, {}).get("status")
                    == "authorization_unavailable"):
                continue
            self._invalidate_open_pr_listing_repo(
                repo, status="authorization_unavailable",
            )

    def _sync_open_pr_listing_repos(self, repos: list[str]) -> None:
        authorized = set(repos)
        known = set(self._open_pr_listing_tasks)
        known.update(self._open_pr_listing_snapshots)
        known.update(self._open_pr_listing_status)
        known.update(self._open_pr_listing_next_attempt)
        known.update(self._machine_projection_versions)
        known.update(self._machine_refresh_pending)
        known.update(repo for repo, _ in self._machine_refresh_pr_versions)
        known.update(repo for repo, _ in self._machine_refresh_last_results)
        known.update(repo for repo, _ in self._machine_refresh_failures)
        known.update(repo for repo, _ in self._machine_refresh_retry_after)
        known.update(self._machine_version_api_missing_repos)
        for mapping in (
            self._priority_baseline_failures,
            self._priority_pr_retry_after,
            self._priority_item_failures,
            self._priority_baseline_external_bypassed,
            self._new_pr_initialization_attempts,
            self._new_pr_initialization_retry_after,
            self._new_pr_initialization_snapshot,
            self._draft_label_attempts,
            self._draft_label_retry_after,
            self._ordinary_pr_scan_retries,
        ):
            known.update(item[0] for item in mapping)
        known.update(repo for repo, _ in self._priority_pr_queue)
        for repo in known - authorized:
            self._invalidate_open_pr_listing_repo(repo, remove=True)
            self._clear_repo_transient_scheduling_state(repo)

    def _schedule_open_pr_listing_refreshes(self, repos: list[str]) -> None:
        if self._github_backing_off():
            return
        now = self._monotonic()
        for repo in repos:
            if not self._open_pr_listing_repo_is_authorized(repo):
                continue
            current = self._open_pr_listing_tasks.get(repo)
            if current is not None and not current.done():
                continue
            if current is not None:
                self._open_pr_listing_tasks.pop(repo, None)
            if now < self._open_pr_listing_next_attempt.get(repo, 0.0):
                continue
            previous = self._open_pr_listing_status.get(repo, {})
            snapshot = self._open_pr_listing_snapshots.get(repo)
            self._open_pr_listing_status[repo] = {
                "status": "running",
                "last_attempt_at": datetime.now(timezone.utc).isoformat(),
                "last_success_at": previous.get("last_success_at"),
                "duration_seconds": previous.get("duration_seconds"),
                "snapshot_count": len(snapshot.get("prs", []))
                if isinstance(snapshot, dict) else 0,
                "failure_type": previous.get("failure_type"),
            }
            generation = self._open_pr_listing_generation.get(repo, 0)
            task = asyncio.create_task(
                self._refresh_open_pr_listing(repo, generation),
            )
            self._open_pr_listing_tasks[repo] = task

    async def _refresh_open_pr_listing(self, repo: str, generation: int) -> None:
        task = asyncio.current_task()
        started = self._monotonic()
        returned_count = 0
        try:
            prs = await asyncio.wait_for(
                self.proxy.get_open_prs(repo),
                timeout=OPEN_PR_LIST_QUERY_TIMEOUT_SECONDS,
            )
            if not isinstance(prs, list):
                raise TypeError("open PR listing did not return a list")
            returned_count = len(prs)
            completed = self._monotonic()
            if generation != self._open_pr_listing_generation.get(repo, 0):
                return
            if not self._open_pr_listing_repo_is_authorized(repo):
                self._open_pr_listing_snapshots.pop(repo, None)
                state = self._open_pr_listing_status.get(repo, {})
                state.update({
                    "status": "authorization_unavailable",
                    "last_success_at": None,
                    "snapshot_count": 0,
                    "failure_type": None,
                })
                return
            completed_at = datetime.now(timezone.utc).isoformat()
            duration = max(0.0, completed - started)
            self._open_pr_listing_snapshots[repo] = {
                "prs": list(prs),
                "completed_monotonic": completed,
                "completed_at": completed_at,
            }
            self._open_pr_listing_failures.pop(repo, None)
            self._open_pr_listing_next_attempt[repo] = (
                completed + OPEN_PR_LIST_REFRESH_SECONDS
            )
            self._open_pr_listing_status[repo] = {
                "status": "succeeded",
                "last_attempt_at": self._open_pr_listing_status.get(repo, {}).get(
                    "last_attempt_at",
                ),
                "last_success_at": completed_at,
                "duration_seconds": round(duration, 1),
                "snapshot_count": returned_count,
                "failure_type": None,
            }
            logger.info(
                "watcher open PR listing completed repo=%s duration_seconds=%.1f returned_count=%s",
                repo, duration, returned_count,
            )
        except asyncio.CancelledError:
            if (generation == self._open_pr_listing_generation.get(repo, 0)
                    and self._open_pr_listing_repo_is_authorized(repo)):
                state = self._open_pr_listing_status.get(repo, {})
                state["status"] = "cancelled"
                state["duration_seconds"] = round(
                    max(0.0, self._monotonic() - started), 1,
                )
                self._open_pr_listing_next_attempt[repo] = self._monotonic()
            raise
        except Exception as exc:
            if generation == self._open_pr_listing_generation.get(repo, 0):
                authorized = self._open_pr_listing_repo_is_authorized(repo)
                previous = self._open_pr_listing_status.get(repo, {})
                snapshot = self._open_pr_listing_snapshots.get(repo)
                failures = self._open_pr_listing_failures.get(repo, 0) + 1
                self._open_pr_listing_failures[repo] = failures
                delay = min(
                    OPEN_PR_LIST_FAILURE_MAX_BACKOFF_SECONDS,
                    OPEN_PR_LIST_REFRESH_SECONDS * (2 ** min(failures - 1, 8)),
                )
                self._open_pr_listing_next_attempt[repo] = self._monotonic() + delay
                if not authorized:
                    self._open_pr_listing_snapshots.pop(repo, None)
                    snapshot = None
                self._open_pr_listing_status[repo] = {
                    "status": "failed" if authorized else "authorization_unavailable",
                    "last_attempt_at": previous.get("last_attempt_at"),
                    "last_success_at": previous.get("last_success_at")
                    if authorized else None,
                    "duration_seconds": round(
                        max(0.0, self._monotonic() - started), 1,
                    ),
                    "snapshot_count": len(snapshot.get("prs", []))
                    if isinstance(snapshot, dict) else 0,
                    "failure_type": type(exc).__name__,
                }
            logger.warning(
                "watcher open PR listing failed repo=%s duration_seconds=%.1f returned_count=%s failure_type=%s",
                repo, max(0.0, self._monotonic() - started), returned_count,
                type(exc).__name__,
            )
        finally:
            if self._open_pr_listing_tasks.get(repo) is task:
                self._open_pr_listing_tasks.pop(repo, None)

    def _usable_open_pr_snapshot(self, repo: str) -> dict | None:
        snapshot = self._open_pr_listing_snapshots.get(repo)
        if not isinstance(snapshot, dict):
            return None
        age = self._monotonic() - snapshot.get("completed_monotonic", 0.0)
        if 0.0 <= age <= OPEN_PR_SNAPSHOT_MAX_AGE_SECONDS:
            return snapshot
        return None

    def _open_pr_listing_diagnostics(self) -> dict:
        result = {}
        repos = list(dict.fromkeys(self.config.active_repos))
        for repo in repos:
            state = self._open_pr_listing_status.get(repo, {})
            snapshot = self._open_pr_listing_snapshots.get(repo)
            age = None
            fresh = False
            snapshot_count = 0
            if isinstance(snapshot, dict):
                snapshot_count = len(snapshot.get("prs", []))
                age = max(
                    0.0,
                    self._monotonic() - snapshot.get("completed_monotonic", 0.0),
                )
                fresh = age <= OPEN_PR_SNAPSHOT_MAX_AGE_SECONDS
            result[repo] = {
                "status": state.get("status", "idle"),
                "last_attempt_at": state.get("last_attempt_at"),
                "last_success_at": state.get("last_success_at"),
                "snapshot_count": snapshot_count,
                "snapshot_age_seconds": round(age, 1) if age is not None else None,
                "snapshot_fresh": fresh,
                "failure_type": state.get("failure_type"),
            }
        return result

    def _public_recent_command_metric(self) -> dict | None:
        key = self._latest_recent_command_key
        item = self._recent_command_records.get(key) if key is not None else None
        if not isinstance(item, dict):
            return None
        metric = {name: value for name, value in item.items()
                  if not name.startswith("_")}
        created_to_processing = None
        discovery_delay = item.get("discovery_delay_seconds")
        discovery_to_processing = item.get("discovery_to_processing_seconds")
        if isinstance(discovery_delay, (int, float)):
            completed_delay = item.get("discovery_to_completion_seconds")
            if item.get("status") in {"discovered", "retry", "processing"}:
                created_to_processing = self._recent_command_latency(item)
            elif (item.get("status") in {"handled", "already_processed"}
                    and isinstance(completed_delay, (int, float))):
                created_to_processing = discovery_delay + completed_delay
            elif isinstance(discovery_to_processing, (int, float)):
                created_to_processing = discovery_delay + discovery_to_processing
        metric["created_to_processing_seconds"] = (
            round(created_to_processing, 3)
            if isinstance(created_to_processing, (int, float)) else None
        )
        metric["over_60_seconds"] = bool(
            isinstance(created_to_processing, (int, float))
            and created_to_processing > 60.0
        )
        metric["latency_seconds"] = (
            self._recent_command_latency(item)
            if item.get("status") in {"discovered", "retry", "processing"}
            else item.get("latency_seconds")
        )
        if metric["over_60_seconds"] and not item.get("_over_60_diagnostic_logged"):
            item["_over_60_diagnostic_logged"] = True
            logger.warning(
                "watcher recent command processing exceeded 60 seconds repo=%s pr=%s trigger=%s comment_id=%s status=%s command_wait_seconds=%.3f comment_created_at=%s discovered_at=%s queued_at=%s dispatch_started_at=%s dispatch_completed_at=%s failure_reason=%s",
                item.get("repo"), item.get("pr_number"), item.get("event_type"),
                item.get("comment_id"), item.get("status"),
                created_to_processing, item.get("comment_created_at"),
                item.get("discovered_at"), item.get("queued_at"),
                item.get("dispatch_started_at"), item.get("dispatch_completed_at"),
                item.get("failure_reason"),
            )
        return metric

    def _recent_command_latency(self, record: dict, *, now: float | None = None) -> float | None:
        discovery_delay = record.get("discovery_delay_seconds")
        discovered_mono = record.get("_discovered_monotonic")
        if not isinstance(discovery_delay, (int, float)) or not isinstance(
                discovered_mono, (int, float)):
            return None
        current = self._monotonic() if now is None else now
        return round(max(0.0, discovery_delay + current - discovered_mono), 3)

    def _pending_command_wait(self, repo: str, pr_number: int) -> tuple[int | None, float | None]:
        pending = [
            record for (record_repo, record_pr, _comment_id), record
            in self._recent_command_records.items()
            if record_repo == repo and record_pr == pr_number
            and isinstance(record, dict)
            and record.get("event_type") == "slash_command"
            and record.get("status") not in {"handled", "already_processed"}
        ]
        record = min(
            pending, key=lambda item: item.get("comment_id", 0), default=None,
        )
        if not isinstance(record, dict):
            return None, None
        return record.get("comment_id"), self._recent_command_latency(record)

    def _log_recent_command_diagnostic(self, event: str, record: dict) -> None:
        logger.info(
            "watcher recent command event=%s repo=%s pr=%s trigger=%s comment_id=%s comment_created_at=%s discovered_at=%s queued_at=%s dispatch_started_at=%s dispatch_completed_at=%s command_wait_seconds=%s failure_reason=%s",
            event, record.get("repo"), record.get("pr_number"), record.get("event_type"),
            record.get("comment_id"), record.get("comment_created_at"),
            record.get("discovered_at"), record.get("queued_at"),
            record.get("dispatch_started_at"), record.get("dispatch_completed_at"),
            self._recent_command_latency(record), record.get("failure_reason"),
        )

    @staticmethod
    def _parse_comment_time(value) -> datetime | None:
        if not isinstance(value, str) or not value.strip():
            return None
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _comment_cursor_through_cutoff(
        comments: list[dict], cutoff: datetime, lower_bound: int = 0,
    ) -> int | None:
        """Advance through the ordered comment prefix no newer than cutoff."""
        if (not isinstance(comments, list)
                or not isinstance(cutoff, datetime)
                or cutoff.tzinfo is None or cutoff.utcoffset() is None
                or not isinstance(lower_bound, int) or isinstance(lower_bound, bool)
                or lower_bound < 0
                or any(not isinstance(comment, dict) for comment in comments)):
            return None
        try:
            ordered_comments = sorted(comments, key=lambda comment: comment.get("id"))
        except (TypeError, ValueError):
            return None
        cursor = lower_bound
        cutoff_utc = cutoff.astimezone(timezone.utc)
        for comment in ordered_comments:
            comment_id = comment.get("id")
            if (not isinstance(comment_id, int) or isinstance(comment_id, bool)
                    or comment_id < 0):
                return None
            if comment_id <= cursor:
                continue
            created_at = GitHubCommandWatcher._parse_comment_time(
                comment.get("created_at")
            )
            if created_at is None:
                return None
            if created_at > cutoff_utc:
                break
            cursor = comment_id
        return cursor

    def _recent_comment_pr_number(self, repo: str, comment: dict) -> int | None:
        issue_url = comment.get("issue_url") if isinstance(comment, dict) else None
        if not isinstance(issue_url, str) or not issue_url.strip():
            return None
        parsed = urlparse(issue_url.strip())
        api = urlparse(self.config.github_api_url)
        if (parsed.scheme.lower() != api.scheme.lower()
                or parsed.netloc.lower() != api.netloc.lower()):
            return None
        match = re.search(
            r"/repos/" + re.escape(repo) + r"/issues/([1-9][0-9]*)/?$",
            parsed.path,
            re.IGNORECASE,
        )
        if match is None:
            return None
        try:
            return int(match.group(1))
        except (TypeError, ValueError):
            return None

    def _is_foreign_bot_comment(self, comment: dict) -> bool:
        """Detect any bot-authored comment that is not our own App comment.

        ``proxy.is_bot_comment`` deliberately matches only the configured App,
        because that provenance is what lifecycle writes trust. Command
        parsing needs the wider complement: another GitHub App or bot can post
        text that happens to look like a command, and it must never be read as
        a human instruction. Only an explicit ``type == "Bot"`` user or a
        ``performed_via_github_app`` block counts here, so ordinary human
        comments (which never carry either field) are unaffected.
        """
        if not isinstance(comment, dict):
            return False
        # The configured review-agent account is a trusted protocol author.
        # Its terminal Build/Code Review comment must still reach reconcile,
        # even when GitHub also attributes it to a Bot user or another App, so
        # this exemption is checked before the generic bot detection below.
        if self._is_trusted_review_completion(comment):
            return False
        if self.proxy.is_bot_comment(comment):
            return True
        user = comment.get("user")
        if isinstance(user, dict) and user.get("type") == "Bot":
            return True
        return isinstance(comment.get("performed_via_github_app"), dict)

    def _is_trusted_review_completion(self, comment: dict) -> bool:
        """Recognize review completion hints without trusting Markdown alone."""
        user = comment.get("user")
        if not isinstance(user, dict):
            return False
        author_id = str(user.get("id", ""))
        author_login = user.get("login")
        if (not self.config.review_comment_author_id
                or author_id != self.config.review_comment_author_id
                or author_login != self.config.review_comment_author_login):
            return False
        body = comment.get("body")
        if not isinstance(body, str) or PR_REVIEW_MARKER not in body:
            return False
        # Only terminal Build Result / Code Review protocol comments should
        # accelerate reconciliation. Progress, test output, and arbitrary
        # comments from the trusted account remain on the ordinary scan path.
        return ((BUILD_HEADING in body and "Build Result" in body)
                or (CODE_REVIEW_HEADING in body and "Code Review" in body))

    def _has_pending_review_completion(
        self, repo: str, pr_number: int, comments, cursor: int,
    ) -> bool:
        """Return True only when a trusted Review Completion still needs reconcile.

        A baseline must refresh the lifecycle after consuming the cursor *only*
        when a terminal Build/Code-Review comment newer than the persisted
        cursor is waiting to be reflected. When the HEAD and lifecycle are
        already current this is False, so a same-HEAD baseline neither
        reconciles a second time nor re-archives the round.
        """
        if not isinstance(cursor, int) or isinstance(cursor, bool):
            return False
        if isinstance(comments, list):
            for comment in comments:
                if not isinstance(comment, dict):
                    continue
                comment_id = comment.get("id")
                if (type(comment_id) is int and comment_id > cursor
                        and self._is_trusted_review_completion(comment)):
                    return True
        for (observed_repo, observed_pr, comment_id), record in self._recent_command_records.items():
            if (observed_repo == repo and observed_pr == pr_number
                    and comment_id > cursor
                    and isinstance(record, dict)
                    and record.get("event_type") == "review_completion"
                    and record.get("status") not in {"handled", "already_processed"}):
                return True
        return False

    def _observe_recent_command(self, repo, pr_number, comment, created_at):
        comment_id = comment.get("id")
        if type(comment_id) is not int or comment_id <= 0:
            return None
        key = (repo, pr_number, comment_id)
        if key not in self._recent_command_records:
            is_review_completion = self._is_trusted_review_completion(comment)
            now_utc = datetime.now(timezone.utc)
            record = {
                "repo": repo, "pr_number": pr_number, "comment_id": comment_id,
                "event_type": "review_completion" if is_review_completion else "slash_command",
                "created_at": comment.get("created_at"),
                "comment_created_at": comment.get("created_at"),
                "discovered_at": now_utc.isoformat(),
                "discovery_delay_seconds": round(max(
                    0.0, (now_utc - created_at).total_seconds(),
                ), 3),
                "queued_at": None,
                "dispatch_started_at": None, "dispatch_completed_at": None,
                "latency_seconds": None,
                "processing_started_at": None, "processing_completed_at": None,
                "discovery_to_processing_seconds": None,
                "discovery_to_completion_seconds": None,
                "processing_duration_seconds": None,
                "failure_reason": None, "last_failure_reason": None,
                "status": "discovered",
                "_discovered_monotonic": self._monotonic(),
                "_created_sort": (created_at.timestamp(), comment_id),
            }
            self._recent_command_records[key] = record
            latest_key = self._latest_recent_command_key
            latest = self._recent_command_records.get(latest_key) if latest_key else None
            if latest is None or record["_created_sort"] >= latest.get("_created_sort", (0.0, 0)):
                self._latest_recent_command_key = key
            self._log_recent_command_diagnostic("discovered", record)
            if len(self._recent_command_records) > 512:
                # A record that still owes a one-time rejection notice must
                # survive eviction, otherwise the pre-baseline command would be
                # dropped without notice. Fall back to plain oldest-first only
                # if every record is pending.
                evictable = [
                    item for item in self._recent_command_records
                    if item not in self._pending_baseline_notices
                ] or list(self._recent_command_records)
                oldest = min(evictable,
                             key=lambda item: self._recent_command_records[item].get(
                                 "_discovered_monotonic", 0.0))
                self._recent_command_records.pop(oldest, None)
                if oldest == self._latest_recent_command_key:
                    self._latest_recent_command_key = max(
                        self._recent_command_records,
                        key=lambda item: self._recent_command_records[item].get("_created_sort", (0.0, 0)),
                        default=None,
                    )
        return key

    def _mark_recent_command_queued(self, repo, pr_number, comment_id, *, queued_at=None):
        record = self._recent_command_records.get((repo, pr_number, comment_id))
        if not isinstance(record, dict):
            return
        if not isinstance(record.get("queued_at"), str):
            record["queued_at"] = queued_at or datetime.now(timezone.utc).isoformat()
            self._log_recent_command_diagnostic("queued", record)

    def _mark_recent_command_processing(self, repo, pr_number, comment_id):
        key = (repo, pr_number, comment_id)
        record = self._recent_command_records.get(key)
        if not isinstance(record, dict):
            return
        started_at = datetime.now(timezone.utc).isoformat()
        elapsed = max(0.0, self._monotonic() - record.get("_discovered_monotonic", self._monotonic()))
        record.update(
            processing_started_at=started_at,
            processing_completed_at=None,
            dispatch_started_at=None, dispatch_completed_at=None,
            failure_reason=None, latency_seconds=None,
            discovery_to_processing_seconds=round(elapsed, 3),
            discovery_to_completion_seconds=None,
            processing_duration_seconds=None,
            _processing_started_monotonic=self._monotonic(),
            _processing_attempt_count=record.get("_processing_attempt_count", 0) + 1,
            status="processing",
        )
        self._log_recent_command_diagnostic("processing", record)

    def _mark_recent_command_dispatch_started(self, repo, pr_number, comment_id):
        record = self._recent_command_records.get((repo, pr_number, comment_id))
        if not isinstance(record, dict):
            return
        record["dispatch_started_at"] = datetime.now(timezone.utc).isoformat()
        self._log_recent_command_diagnostic("dispatch_started", record)

    def _mark_recent_command_dispatch_completed(self, repo, pr_number, comment_id):
        record = self._recent_command_records.get((repo, pr_number, comment_id))
        if not isinstance(record, dict):
            return
        record["dispatch_completed_at"] = datetime.now(timezone.utc).isoformat()

    def _finish_recent_command(
        self, repo, pr_number, comment_id, *, failure_reason=None, retryable=True,
    ):
        record = self._recent_command_records.get((repo, pr_number, comment_id))
        if not isinstance(record, dict):
            return
        if failure_reason is not None:
            record["last_failure_reason"] = failure_reason
            record["last_failure_at"] = datetime.now(timezone.utc).isoformat()
        record["failure_reason"] = failure_reason
        completed_mono = self._monotonic()
        record["processing_completed_at"] = datetime.now(timezone.utc).isoformat()
        if (record.get("dispatch_started_at") is not None
                and record.get("dispatch_completed_at") is None):
            record["dispatch_completed_at"] = record["processing_completed_at"]
        discovered_mono = record.get("_discovered_monotonic")
        if isinstance(discovered_mono, (int, float)):
            record["discovery_to_completion_seconds"] = round(
                max(0.0, completed_mono - discovered_mono), 3,
            )
        started_mono = record.get("_processing_started_monotonic")
        if isinstance(started_mono, (int, float)):
            record["processing_duration_seconds"] = round(
                max(0.0, completed_mono - started_mono), 3,
            )
        record["latency_seconds"] = self._recent_command_latency(
            record, now=completed_mono,
        )
        record["status"] = "retry" if failure_reason and retryable else "handled"
        self._log_recent_command_diagnostic(
            "dispatch_completed" if record.get("dispatch_started_at") else "finished",
            record,
        )

    def _mark_recent_command_already_processed(self, repo, pr_number, comment_id):
        record = self._recent_command_records.get((repo, pr_number, comment_id))
        if not isinstance(record, dict):
            return
        record.update(
            status="already_processed", failure_reason=None,
            processing_started_at=None, processing_completed_at=None,
            discovery_to_processing_seconds=None,
            discovery_to_completion_seconds=None,
            processing_duration_seconds=None,
        )

    def _recent_command_notice_posted(self, repo, pr_number, comment_id, topic) -> bool:
        record = self._recent_command_records.get((repo, pr_number, comment_id))
        if not isinstance(record, dict):
            return False
        return topic in set(record.get("posted_notices") or ())

    def _mark_recent_command_notice_posted(self, repo, pr_number, comment_id, topic):
        record = self._recent_command_records.get((repo, pr_number, comment_id))
        if not isinstance(record, dict):
            return
        notices = set(record.get("posted_notices") or ())
        notices.add(topic)
        record["posted_notices"] = sorted(notices)

    @staticmethod
    def _is_progress_reply_body(body):
        visible = re.sub(r"<!--.*?-->", "", body, flags=re.DOTALL).casefold()
        progress_phrases = (
            "正在检查部署条件",
            "预检已通过，正在准备部署请求",
            "部署条件已通过，正在准备发送部署请求",
            "部署 post 已发送，正在确认运行镜像",
            "正在核对结果，请勿重复审批",
            "尚未发送部署 post",
        )
        return any(phrase in visible for phrase in progress_phrases)

    async def _read_final_command_result(self, repo, pr_number, comment_id):
        """Confirm the Service's final result bound to the source comment ID."""
        key = (repo, pr_number, comment_id)
        cached = self._confirmed_command_results.get(key)
        if cached in {"accepted", "rejected", "uncertain"}:
            return cached
        try:
            comments = await self.proxy.get_issue_comments(repo, pr_number)
        except Exception as exc:
            logger.warning(
                "watcher final reply readback failed repo=%s pr=%s comment_id=%s reason=%s",
                repo, pr_number, comment_id, _github_failure_reason(exc),
            )
            return None
        if not isinstance(comments, list):
            return None
        reply_marker = re.compile(
            r"<!--\s*deploy-approval-reply-to-comment:(\d+)\s*-->"
        )
        result_marker = re.compile(
            r"<!--\s*deploy-approval-result:([a-z-]+)\s*-->"
        )
        qa_marker = re.compile(
            r"<!--\s*deploy-approval-qa:(.*?)\s*-->", re.DOTALL,
        )
        bound = []
        for comment in comments:
            if not isinstance(comment, dict) or not self.proxy.is_bot_comment(comment):
                continue
            body = comment.get("body")
            if not isinstance(body, str):
                continue
            if self._is_progress_reply_body(body):
                continue
            ids = reply_marker.findall(body)
            if str(comment_id) in ids:
                bound.append((body, ids, result_marker.findall(body), qa_marker.findall(body)))
        if len(bound) != 1:
            return None
        body, ids, results, qa_payloads = bound[0]
        if (ids != [str(comment_id)] or len(results) != 1
                or results[0] not in {"accepted", "rejected", "uncertain"}):
            return None
        result = results[0]
        if result == "rejected":
            if len(qa_payloads) != 1:
                return None
            try:
                qa = json.loads(qa_payloads[0])
            except (TypeError, ValueError):
                return None
            if (not isinstance(qa, dict)
                    or not isinstance(qa.get("status"), str)
                    or not isinstance(qa.get("error"), str)
                    or not qa["error"].strip()
                    or not isinstance(qa.get("head"), str)
                    or re.fullmatch(r"[0-9a-f]{40}", qa["head"]) is None
                    or not isinstance(qa.get("labels"), list)
                    or any(not isinstance(label, str) for label in qa["labels"])
                    or not isinstance(qa.get("next_commands"), list)
                    or any(not isinstance(command, str)
                           for command in qa["next_commands"])):
                return None
            qa_status = qa["status"].strip()
            if qa_status.casefold().startswith("status:"):
                qa_status = qa_status.split(":", 1)[1].strip()
            status_labels = [
                label for label in qa["labels"]
                if label.casefold().startswith("status:")
            ]
            if (len(status_labels) != 1
                    or status_labels[0].casefold() not in CANONICAL_STATUS_LABELS
                    or qa_status.casefold()
                    != status_labels[0].split(":", 1)[1].strip().casefold()):
                return None
            visible_body = re.sub(r"<!--.*?-->", "", body, flags=re.DOTALL)
            visible_command_reader = getattr(
                self.controller, "_visible_command_lines", None,
            )
            if not callable(visible_command_reader):
                return None
            visible_commands = visible_command_reader(visible_body)
            if not isinstance(visible_commands, list):
                return None
            visible_commands = [item for item in visible_commands
                                if isinstance(item, str)]
            if qa["next_commands"] != visible_commands:
                return None
        self._confirmed_command_results[key] = result
        while len(self._confirmed_command_results) > RECENT_COMMAND_NOTICE_MAX:
            self._confirmed_command_results.pop(
                next(iter(self._confirmed_command_results)),
            )
        record = self._recent_command_records.get(key)
        if isinstance(record, dict):
            record["final_result"] = result
        return result

    async def _source_has_final_reply_marker(self, repo, pr_number, comment_id):
        """Distinguish a delayed/invalid final reply from a reply that is absent."""
        try:
            comments = await self.proxy.get_issue_comments(repo, pr_number)
        except Exception:
            return True  # Fail closed: never create a competing final reply.
        if not isinstance(comments, list):
            return True
        marker = re.compile(
            r"<!--\s*deploy-approval-reply-to-comment:(\d+)\s*-->"
        )
        return any(
            isinstance(comment, dict)
            and self.proxy.is_bot_comment(comment)
            and isinstance(comment.get("body"), str)
            and not self._is_progress_reply_body(comment["body"])
            and str(comment_id) in marker.findall(comment["body"])
            for comment in comments
        )

    async def _consume_final_command_reply(self, repo, pr_number, comment_id):
        result = await self._read_final_command_result(repo, pr_number, comment_id)
        if result is None:
            return False
        consumed = await self._consume_comment_cursor(repo, pr_number, comment_id)
        self._finish_recent_command(
            repo, pr_number, comment_id,
            failure_reason=(None if consumed else "cursor_persist_not_confirmed"),
            retryable=not consumed,
        )
        return consumed

    async def _recover_final_command_reply_delivery(self, repo, pr_number, comment_id):
        """Recover only a source-bound final notice; never re-dispatch its command."""
        result = await self._read_final_command_result(repo, pr_number, comment_id)
        if result is not None:
            return result
        if await self._source_has_final_reply_marker(repo, pr_number, comment_id):
            return None
        post_reply = getattr(self.controller, "_post_command_reply", None)
        if not callable(post_reply):
            return None
        message = (
            "这条命令的处理结果暂时无法确认。系统不会重复执行这条命令；"
            "请以 PR Summary 当前显示的状态为准。"
        )
        try:
            delivered = await post_reply(
                repo, pr_number, comment_id, message,
                topic="command-result-uncertain",
                error=False, result="uncertain",
            )
        except Exception as exc:
            logger.warning(
                "watcher final reply recovery failed repo=%s pr=%s comment_id=%s reason=%s",
                repo, pr_number, comment_id, _github_failure_reason(exc),
            )
            return None
        if delivered is not True:
            return None
        return await self._read_final_command_result(repo, pr_number, comment_id)

    @staticmethod
    def _is_error_notice_topic(topic) -> bool:
        return isinstance(topic, str) and topic.startswith((
            "command-error-", "command-not-ready", "command-rejected-",
        ))

    def _recent_command_error_replied(self, repo, pr_number, comment_id) -> bool:
        """Whether this source comment already received one error reply.

        Every error entry point (parser rejection, boundary, terminal PR,
        handler failure) writes an error topic. The first confirmed notice wins:
        a later retry that reaches a different entry point must not post a
        second visible reply for the same source comment.
        """
        record = self._recent_command_records.get((repo, pr_number, comment_id))
        if not isinstance(record, dict):
            return False
        return any(
            self._is_error_notice_topic(topic)
            for topic in (record.get("posted_notices") or ())
        )

    async def _post_command_error_notice(
        self, repo, pr_number, comment_id, cmd, topic, *, message: str = "",
    ) -> bool:
        """Post the single bound error reply for one source command comment.

        Returns ``True`` when this source comment has a confirmed error reply —
        either just delivered now or already recorded earlier in this process,
        in which case no second visible comment is posted. A missing API or an
        unconfirmed POST returns ``False`` without advancing any cursor, so the
        caller can retry safely.
        """
        if await self._read_final_command_result(repo, pr_number, comment_id):
            return True
        if (self._recent_command_error_replied(repo, pr_number, comment_id)
                or (repo, pr_number, comment_id) in self._posted_error_replies):
            return False
        post_reply = getattr(self.controller, "_post_command_reply", None)
        if not callable(post_reply):
            return False
        try:
            delivered = await post_reply(
                repo, pr_number, comment_id, message, topic=topic, error=True,
            )
        except Exception as exc:
            logger.warning(
                "watcher command error notice failed repo=%s pr=%s comment_id=%s reason=%s",
                repo, pr_number, comment_id, _github_failure_reason(exc),
            )
            return False
        result = await self._read_final_command_result(repo, pr_number, comment_id)
        if result is None:
            return False
        self._posted_error_replies[(repo, pr_number, comment_id)] = None
        while len(self._posted_error_replies) > RECENT_COMMAND_NOTICE_MAX:
            self._posted_error_replies.pop(next(iter(self._posted_error_replies)))
        self._mark_recent_command_notice_posted(
            repo, pr_number, comment_id, topic,
        )
        return True

    async def _post_boundary_rejection(
        self, repo: str, pr_number: int, comment_id: int, *,
        cmd, reason: str,
    ) -> bool:
        """Post one public rejection notice for a dispatch-boundary decision.

        The Service formatter binds and confirms the notice to the source
        comment. Its stable per-command topic makes retries idempotent; a failed
        notice never advances the cursor.
        """
        kind = _command_kind(cmd)
        # The boundary code stays in the topic so the Service reason table can
        # explain it; the command kind keeps the per-command marker unique.
        code = _stable_error_code(reason)
        topic = (f"command-error-{code}-{kind}" if code
                 else f"command-error-{kind}")
        return await self._post_command_error_notice(
            repo, pr_number, comment_id, cmd, topic,
        )

    @staticmethod
    def _terminal_pr_reason(pr: dict | None) -> str:
        if not isinstance(pr, dict):
            return ""
        if pr.get("merged") is True:
            return "pr_merged"
        if pr.get("state") == "closed":
            return "pr_closed"
        if pr.get("draft") is True:
            return "pr_draft"
        return ""

    @staticmethod
    def _terminal_command_failure(reason: str) -> bool:
        return (reason in {"pr_is_draft", "pr_not_open", "dispatch_pr_not_open"}
                or reason.startswith((
                    "pr_closed", "pr_merged", "pr_draft",
                    "dispatch_pr_head_changed", "terminal_notice_pr_",
                    "terminal_pr_",
                )))

    async def _post_terminal_status_rejection(
        self, repo: str, pr_number: int, comment_id: int, *, cmd,
        expected_status: str, source_comment: dict,
    ) -> bool:
        """Post an idempotent comment for a trusted command on a terminal PR.

        Recheck the terminal PR, original comment ID, author, body, and timestamp
        before routing the rejection through the Service formatter. Never
        dispatch the command.
        """
        # Keep the terminal state in the topic so the Service reason table can
        # tell "PR closed", "PR merged" and "PR draft" apart while the marker
        # stays unique per command and comment.
        topic = f"command-error-{expected_status}-{_command_kind(cmd)}"
        if self._recent_command_notice_posted(repo, pr_number, comment_id, topic):
            return True
        try:
            pr = await self.proxy.get_pr(repo, pr_number)
            origin = await self.proxy.get_comment(repo, comment_id)
        except Exception as exc:
            logger.warning(
                "watcher terminal rejection context failed %s#%s comment_id=%s exception=%s",
                repo, pr_number, comment_id, type(exc).__name__,
            )
            return False
        base = pr.get("base", {}) if isinstance(pr, dict) else {}
        base_repo = base.get("repo", {}) if isinstance(base, dict) else {}
        head = pr.get("head", {}) if isinstance(pr, dict) else {}
        head_sha = head.get("sha") if isinstance(head, dict) else None
        if (not isinstance(pr, dict) or type(pr.get("number")) is not int
                or pr.get("number") != pr_number
                or not isinstance(base_repo.get("full_name"), str)
                or base_repo["full_name"].casefold() != repo.casefold()
                or not isinstance(head_sha, str)
                or re.fullmatch(r"[0-9a-f]{40}", head_sha) is None
                or self._terminal_pr_reason(pr) != expected_status
                or not isinstance(origin, dict) or type(origin.get("id")) is not int
                or origin.get("id") != comment_id
                or origin.get("body") != source_comment.get("body")
                or origin.get("created_at") != source_comment.get("created_at")
                or origin.get("updated_at") != source_comment.get("updated_at")
                or origin.get("created_at") != origin.get("updated_at")
                or self._is_foreign_bot_comment(origin)):
            return False
        expected_user = source_comment.get("user")
        actual_user = origin.get("user")
        if (not isinstance(expected_user, dict) or not isinstance(actual_user, dict)
                or type(expected_user.get("id")) is not int or expected_user.get("id") <= 0
                or expected_user.get("id") != actual_user.get("id")
                or not isinstance(expected_user.get("login"), str)
                or expected_user.get("login") != actual_user.get("login")):
            return False
        try:
            author_id, author_login = await self.proxy.comment_identity(repo, comment_id)
        except Exception:
            return False
        if (author_id != str(expected_user["id"])
                or author_login != expected_user["login"]):
            return False
        return await self._post_command_error_notice(
            repo, pr_number, comment_id, cmd, topic,
        )

    async def _handle_terminal_pr_commands(
        self, repo: str, pr_number: int, current_pr: dict, expected_status: str,
    ) -> bool:
        """Reply to one recent, trusted slash command without executing it."""
        try:
            state = await self.proxy.read_hidden_state(repo, pr_number)
            comments = await self.proxy.get_issue_comments(repo, pr_number)
        except (GitHubRateLimitError, GitHubTransientError,
                GitHubStateProxyError, asyncio.TimeoutError) as exc:
            # A shared API failure is retryable: keep the item queued so the
            # rejection notice is not lost.
            logger.warning(
                "watcher terminal PR command scan failed %s#%s exception=%s",
                repo, pr_number, type(exc).__name__,
            )
            return False
        except Exception as exc:
            # The PR is already closed/merged, so no queued command can ever
            # execute there and there is no Lifecycle to write. If the proxy
            # surface cannot be read at all, report the scan as done so the
            # terminal PR cannot occupy a priority slot forever.
            logger.warning(
                "watcher terminal PR command scan unavailable %s#%s exception=%s",
                repo, pr_number, type(exc).__name__,
            )
            return True
        if not isinstance(comments, list):
            return False
        cutoff = self._repo_baseline_cutoff_utc.get(repo)
        if (not isinstance(cutoff, datetime) or cutoff.tzinfo is None
                or cutoff.utcoffset() is None):
            return True
        cursor = state.get("last_processed_comment_id", 0) if isinstance(state, dict) else 0
        if type(cursor) is not int or cursor < 0:
            cursor = 0
        candidates = sorted(
            (item for item in comments
             if isinstance(item, dict) and type(item.get("id")) is int
             and item["id"] > cursor),
            key=lambda item: item["id"],
        )
        for listed in candidates:
            if self._is_foreign_bot_comment(listed):
                # Foreign bots never author deploy commands; skip before any
                # parse so their PR comments cannot trigger a reply.
                continue
            created = self._parse_comment_time(listed.get("created_at"))
            if (created is None or created <= cutoff.astimezone(timezone.utc)
                    or listed.get("updated_at") != listed.get("created_at")):
                continue
            body = listed.get("body")
            if not isinstance(body, str) or not body.strip():
                continue
            comment_id = listed["id"]
            cmd = commands_mod.parse_command(body, comment_id=comment_id)
            if not cmd.is_command:
                likely_intent = commands_mod.detect_deployment_command_intent(body)
                if likely_intent:
                    cmd.intent = likely_intent
                    cmd.raw = body
            if not cmd.is_command:
                continue
            try:
                fresh_pr = await self.proxy.get_pr(repo, pr_number)
                fresh_comment = await self.proxy.get_comment(repo, comment_id)
            except Exception:
                return False
            if (not isinstance(fresh_comment, dict)
                    or type(fresh_comment.get("id")) is not int
                    or fresh_comment.get("id") != comment_id
                    or fresh_comment.get("body") != body
                    or fresh_comment.get("created_at") != listed.get("created_at")
                    or fresh_comment.get("updated_at") != listed.get("updated_at")
                    or self._recent_comment_pr_number(repo, fresh_comment) != pr_number
                    or self._terminal_pr_reason(fresh_pr) != expected_status):
                continue
            self._observe_recent_command(
                repo, pr_number, fresh_comment, created.astimezone(timezone.utc),
            )
            if not await self._post_terminal_status_rejection(
                    repo, pr_number, comment_id, cmd=cmd,
                    expected_status=expected_status, source_comment=fresh_comment):
                return False
            consumed = (
                await self._consume_comment_cursor(repo, pr_number, comment_id)
                if isinstance(state, dict) else True
            )
            self._finish_recent_command(
                repo, pr_number, comment_id,
                failure_reason=(expected_status if consumed else
                                f"{expected_status}_cursor_persist_not_confirmed"),
                retryable=not consumed,
            )
            return consumed
        return True

    def _fail_recent_commands_for_pr(self, repo, pr_number, reason, *, retryable=True):
        for (observed_repo, observed_pr, comment_id), record in list(
                self._recent_command_records.items()):
            if (observed_repo == repo and observed_pr == pr_number
                    and record.get("status") not in {"handled", "already_processed"}):
                self._finish_recent_command(
                    repo, pr_number, comment_id, failure_reason=reason,
                    retryable=retryable,
                )

    async def _flush_pending_baseline_notices(self, repo: str, pr_number: int) -> bool:
        """Deliver one rejection notice per pre-baseline command.

        These commands are excluded by the fixed authorization cutoff and are
        never dispatched. Their PR baseline has completed by the time this runs,
        so each source comment gets exactly one visible rejection telling the
        developer the command did not execute and must be resent. A failed
        notice stays pending and is retried without advancing any cursor.
        """
        pending = sorted(
            comment_id for (notice_repo, notice_pr, comment_id)
            in self._pending_baseline_notices
            if notice_repo == repo and notice_pr == pr_number
        )
        if not pending:
            return True

        # Discovery caches are process-local. After a Controller restart they
        # must not resurrect comments already covered by the durable PR cursor.
        try:
            persisted_state = await self.proxy.read_hidden_state(repo, pr_number)
        except Exception as exc:
            logger.warning(
                "watcher baseline notice cursor read failed %s#%s reason=%s",
                repo, pr_number, type(exc).__name__,
            )
            return False
        if not isinstance(persisted_state, dict):
            return False
        persisted_cursor = persisted_state.get("last_processed_comment_id")
        if type(persisted_cursor) is not int or persisted_cursor < 0:
            return False

        ok = True
        for comment_id in pending:
            key = (repo, pr_number, comment_id)
            if comment_id <= persisted_cursor:
                self._pending_baseline_notices.pop(key, None)
                self._mark_recent_command_already_processed(
                    repo, pr_number, comment_id,
                )
                continue
            record = self._recent_command_records.get(key)
            if not isinstance(record, dict):
                self._pending_baseline_notices.pop(key, None)
                continue
            if record.get("status") in {"handled", "already_processed"}:
                self._pending_baseline_notices.pop(key, None)
                continue
            if self._recent_command_error_replied(repo, pr_number, comment_id):
                self._pending_baseline_notices.pop(key, None)
                self._finish_recent_command(
                    repo, pr_number, comment_id,
                    failure_reason="baseline_rejected_pre_authorization",
                    retryable=False,
                )
                continue
            if self._recent_command_notice_posted(
                    repo, pr_number, comment_id, "baseline-rejected"):
                self._pending_baseline_notices.pop(key, None)
                self._finish_recent_command(
                    repo, pr_number, comment_id,
                    failure_reason="baseline_rejected_pre_authorization",
                    retryable=False,
                )
                continue
            post_reply = getattr(self.controller, "_post_command_reply", None)
            if not callable(post_reply):
                ok = False
                continue
            # A non-error topic keeps the Service formatter from replacing this
            # explanation with a parser-error reason; the notice is still bound
            # to the source comment and its stable topic makes it idempotent.
            topic = "baseline-rejected"
            message = (
                "这条命令在部署审批授权生效之前发送，没有执行。"
                "请重新发送命令。"
            )
            try:
                delivered = await post_reply(
                    repo, pr_number, comment_id, message,
                    topic=topic, error=False,
                )
            except Exception as exc:
                logger.warning(
                    "watcher pre-baseline rejection notice failed repo=%s pr=%s comment_id=%s reason=%s",
                    repo, pr_number, comment_id, _github_failure_reason(exc),
                )
                delivered = False
            if delivered is not True:
                # Leave pending; retry next cycle without moving the cursor.
                ok = False
                continue
            self._mark_recent_command_notice_posted(repo, pr_number, comment_id, topic)
            self._posted_error_replies[key] = None
            while len(self._posted_error_replies) > RECENT_COMMAND_NOTICE_MAX:
                self._posted_error_replies.pop(next(iter(self._posted_error_replies)))
            self._pending_baseline_notices.pop(key, None)
            self._recent_discovery_stats["baseline_rejection_notices"] += 1
            self._finish_recent_command(
                repo, pr_number, comment_id,
                failure_reason="baseline_rejected_pre_authorization",
                retryable=False,
            )
            logger.info(
                "watcher pre-baseline command rejection delivered repo=%s pr=%s comment_id=%s",
                repo, pr_number, comment_id,
            )
        return ok

    async def _discover_recent_command_prs(self, repos: list[str]) -> bool:
        """Queue a small set of PRs referenced by the newest command comments."""
        list_recent = getattr(self._github, "list_recent_issue_comments", None)
        if not callable(list_recent):
            return False
        poll_interval = max(1.0, float(self.config.poll_interval_seconds))
        discovery_interval = max(5.0, min(10.0, poll_interval))
        discovery_timeout = min(8.0, max(5.0, poll_interval))
        candidates = {}
        newly_discovered_prs = set()
        for repo in repos:
            if (not self.config.auth_valid or repo not in self.config.active_repos
                    or repo not in self.config.github_repos):
                continue
            now = self._monotonic()
            if now - self._recent_discovery_monotonic.get(repo, float("-inf")) < discovery_interval:
                continue
            self._recent_discovery_monotonic[repo] = now
            self._recent_discovery_at[repo] = datetime.now(timezone.utc).isoformat()
            try:
                comments = await asyncio.wait_for(
                    list_recent(repo, limit=100), timeout=discovery_timeout,
                )
            except (GitHubRateLimitError, GitHubTransientError) as exc:
                reason = _github_failure_reason(exc)
                self._recent_discovery_last_failure[repo] = reason
                self._recent_discovery_stats["discovery_deferred"] += 1
                logger.warning(
                    "watcher recent command discovery deferred repo=%s reason=%s",
                    repo, reason,
                )
                if isinstance(exc, GitHubRateLimitError):
                    break
                if self._github_backing_off():
                    break
                continue
            except GitHubError as exc:
                if exc.status_code == 401:
                    self._recent_discovery_last_failure[repo] = "http_401_authentication_rejected"
                    logger.error(
                        "watcher recent command discovery authentication rejected repo=%s; authorization gate remains closed",
                        repo,
                    )
                    return
                # This optional endpoint may be unavailable under a valid App
                # installation. Keep the ordinary open-PR scan as the fallback.
                self._recent_discovery_last_failure[repo] = (
                    f"http_{exc.status_code}" if exc.status_code in (403, 404)
                    else type(exc).__name__
                )
                logger.warning(
                    "watcher recent command discovery unavailable repo=%s status=%s; falling back to PR scan",
                    repo, getattr(exc, "status_code", None),
                )
                continue
            except Exception as exc:
                self._recent_discovery_last_failure[repo] = type(exc).__name__
                logger.warning(
                    "watcher recent command discovery failed repo=%s reason=%s; falling back to PR scan",
                    repo, type(exc).__name__,
                )
                continue
            if (self.config.auth_valid is not True
                    or repo not in self.config.active_repos
                    or repo not in self.config.github_repos):
                continue
            self._recent_discovery_at[repo] = datetime.now(timezone.utc).isoformat()
            self._recent_discovery_last_failure[repo] = None
            if not isinstance(comments, list):
                self._recent_discovery_last_failure[repo] = "invalid_response"
                continue
            if repo.endswith("phanthymotus-driver"):
                self._last_driver_poll = self._recent_discovery_at[repo]
            per_pr = {}
            cutoff = self._repo_baseline_cutoff_utc.get(repo)
            for comment in comments[:100]:
                self._recent_discovery_stats["recent_comments_received"] += 1
                if not isinstance(comment, dict):
                    continue
                if self._is_foreign_bot_comment(comment):
                    # Never let another bot's text enqueue a PR for command
                    # processing.
                    self._recent_discovery_stats["foreign_bot_filtered"] += 1
                    logger.info(
                        "watcher recent comment filtered repo=%s comment_id=%s reason=foreign_bot",
                        repo, comment.get("id"),
                    )
                    continue
                number = self._recent_comment_pr_number(repo, comment)
                if number is None:
                    self._recent_discovery_stats["invalid_issue_url"] += 1
                    logger.info(
                        "watcher recent comment filtered repo=%s comment_id=%s reason=invalid_issue_url",
                        repo, comment.get("id"),
                    )
                    continue
                created_at = self._parse_comment_time(comment.get("created_at"))
                if created_at is None:
                    self._recent_discovery_stats["invalid_timestamp"] += 1
                    logger.info(
                        "watcher recent comment filtered repo=%s pr=%s comment_id=%s reason=invalid_timestamp",
                        repo, number, comment.get("id"),
                    )
                    continue
                body = comment.get("body", "")
                is_command = (
                    isinstance(body, str)
                    and (commands_mod.parse_command(body).is_command
                         or bool(commands_mod.detect_deployment_command_intent(body)))
                )
                is_review_completion = self._is_trusted_review_completion(comment)
                if not is_command and not is_review_completion:
                    self._recent_discovery_stats["unknown_command"] += 1
                    logger.info(
                        "watcher recent comment filtered repo=%s pr=%s comment_id=%s reason=unknown_command",
                        repo, number, comment.get("id"),
                    )
                    continue
                is_filtered_by_cutoff = False
                cutoff_is_authoritative = (
                    isinstance(cutoff, datetime)
                    and cutoff.tzinfo is not None
                    and cutoff.utcoffset() is not None
                )
                if is_command and not is_review_completion:
                    if not cutoff_is_authoritative:
                        # No fixed authorization boundary is published yet, so
                        # no command may execute. Keep it observed only.
                        is_filtered_by_cutoff = True
                        self._recent_discovery_stats["baseline_cutoff_unavailable"] += 1
                    elif created_at <= cutoff.astimezone(timezone.utc):
                        is_filtered_by_cutoff = True
                        self._recent_discovery_stats["baseline_cutoff_filtered"] += 1
                        logger.info(
                            "watcher recent command filtered by baseline cutoff repo=%s pr=%s comment_id=%s created_at=%s cutoff=%s",
                            repo, number, comment.get("id"), comment.get("created_at"),
                            cutoff.astimezone(timezone.utc).isoformat(),
                        )
                comment_id = comment.get("id")
                was_known = (
                    type(comment_id) is int and comment_id > 0
                    and (repo, number, comment_id) in self._recent_command_records
                )
                key = self._observe_recent_command(repo, number, comment, created_at)
                if key is None:
                    continue
                observed = self._recent_command_records[key]
                if is_filtered_by_cutoff:
                    if observed.get("status") in {"handled", "already_processed"}:
                        # Rejection already delivered (or command consumed).
                        self._pending_baseline_notices.pop(key, None)
                        continue
                    observed["failure_reason"] = "baseline_cutoff_filtered"
                    observed["last_failure_reason"] = "baseline_cutoff_filtered"
                    if not cutoff_is_authoritative:
                        # Authorization boundary is not established yet. Keep
                        # the command observed but neither execute nor notify;
                        # discovery retries once the fixed cutoff is published.
                        logger.info(
                            "watcher recent command held without authorization cutoff repo=%s pr=%s comment_id=%s; will not execute",
                            repo, number, comment.get("id"),
                        )
                        continue
                    # Clearly inside the pre-authorization window: never
                    # execute. Queue its PR so the fixed baseline completes and
                    # the one-time rejection notice can be delivered after it.
                    self._pending_baseline_notices[key] = None
                    while len(self._pending_baseline_notices) > RECENT_COMMAND_NOTICE_MAX:
                        self._pending_baseline_notices.pop(
                            next(iter(self._pending_baseline_notices)))
                    logger.info(
                        "watcher recent command registered for pre-baseline rejection repo=%s pr=%s comment_id=%s created_at=%s cutoff=%s",
                        repo, number, comment.get("id"), comment.get("created_at"),
                        cutoff.astimezone(timezone.utc).isoformat(),
                    )
                    if not was_known and (repo, number) not in newly_discovered_prs:
                        self._recent_discovery_stats["newly_discovered_prs"] += 1
                        newly_discovered_prs.add((repo, number))
                    source = "recent"
                    candidate = (
                        self._priority_source_rank(source), key[2], source, key,
                    )
                    previous = per_pr.get(number)
                    if previous is None or candidate[:2] < previous[:2]:
                        per_pr[number] = candidate
                    continue
                if not was_known and (is_command or is_review_completion):
                    self._recent_discovery_stats["eligible_commands"] += 1
                if observed.get("status") in {"handled", "already_processed", "processing"}:
                    continue
                if not was_known:
                    if (repo, number) not in newly_discovered_prs:
                        self._recent_discovery_stats["newly_discovered_prs"] += 1
                    newly_discovered_prs.add((repo, number))
                source = "command" if is_command else "recent"
                candidate = (
                    self._priority_source_rank(source), key[2], source, key,
                )
                previous = per_pr.get(number)
                if previous is None or candidate[:2] < previous[:2]:
                    per_pr[number] = candidate
            for number, candidate in per_pr.items():
                candidates[(repo, number)] = candidate

        # A source comment can promote one deduplicated PR hint, but cannot
        # create a second queue entry for that PR. Commands outrank repeated
        # review prompts; _process_pr still walks all comments by comment_id.
        if newly_discovered_prs:
            for item in newly_discovered_prs:
                self._prioritize_new_external_baseline_retry(item)
        ordered = sorted(
            candidates.items(), key=lambda item: (item[1][0], item[1][1]),
        )
        queued_priority = False
        for (repo, number), (_rank, _comment_id, source, key) in ordered:
            item = (repo, number)
            was_queued = item in self._priority_pr_queue
            previous_source = self._priority_pr_sources.get(item)
            if not self._queue_priority_pr(item, source):
                continue
            self._mark_recent_command_queued(repo, number, key[2])
            if not was_queued or previous_source != self._priority_pr_sources.get(item):
                queued_priority = True
        if queued_priority:
            self._priority_generation += 1
            # Wake the serial writer and interrupt its ordinary scan after the
            # currently active PR operation yields. Discovery itself stays read-only.
            self._signal_wakeup()
        return queued_priority

    def _record_pr_attempt(
        self, repo: str, pr_number: int, reason: str, duration_seconds: float | None = None,
    ) -> None:
        self._last_pr_attempt[(repo, pr_number)] = {
            "at": datetime.now(timezone.utc).isoformat(), "reason": reason,
        }
        if duration_seconds is not None:
            duration = max(0.0, duration_seconds)
            self._last_pr_attempt[(repo, pr_number)]["duration_seconds"] = round(duration, 1)
            self._pr_durations.append(duration)
        if len(self._last_pr_attempt) > 512:
            protected = ("4paradigm/phanthymotus-driver", 442)
            candidates = [key for key in self._last_pr_attempt if key != protected]
            oldest = min(candidates, key=lambda key: self._last_pr_attempt[key].get("at", ""))
            self._last_pr_attempt.pop(oldest, None)

    async def _refresh_active_repos_if_needed(self) -> None:
        """Periodically refresh runtime authorization before polling."""
        if self._github is None or self._github_auth is None:
            return
        if self._github_backing_off():
            return
        now = self._monotonic()
        if self._last_auth_refresh >= 0.0 and (
            (now - self._last_auth_refresh) < self._auth_refresh_interval
        ):
            return
        # Timestamp set BEFORE the attempt: a failed refresh still occupies
        # this interval slot, so the next cycle retries instead of hot-looping.
        self._last_auth_refresh = now
        self._auth_refresh_in_progress = True
        try:
            await self._refresh_active_repos()
        finally:
            self._auth_refresh_in_progress = False

    async def _refresh_active_repos(self) -> None:
        """Refresh ACTIVE_REPOS from GitHub App installation authorization.

        CORRECT AUTH SEQUENCE (fail-closed):
        1. Force fresh installation token under existing single-flight lock.
        2. GET /installation/repositories with the refreshed token.
        3. Validate complete paginated response.
        4. Intersect config.github_repos with authorized_names.
        5. Ensure required repo is present.
        6. Atomically publish new_active + auth_valid together.

        On any failure: auth_valid=False, do NOT publish new repos,
        and do NOT proceed with _poll_once() that cycle.
        """
        if self._github is None or self._github_auth is None:
            return
        old_active = list(self.config.active_repos)
        old_auth_valid = getattr(self.config, "auth_valid", True)
        try:
            # Step 1: FORCE fresh installation token FIRST
            try:
                await self._github_auth.refresh_installation_token()
            except Exception as tok_exc:
                logger.warning(
                    "auth refresh: forced token refresh failed \u2014 "
                    "keeping previous active repos: %s", old_active,
                )
                self.config.auth_valid = False
                return

            # Step 2: Query repos with refreshed token
            authorized_names = await self._github.list_installation_repositories()
            try:
                new_active = resolve_authorized_repos(self.config.github_repos, authorized_names)
                new_policy_active = resolve_authorized_repos(
                    list(DEFAULT_GITHUB_REPOS), authorized_names,
                )
            except RuntimeError:
                self.config.auth_valid = False
                self.config.active_repos = []
                logger.warning("auth refresh: configured primary repository is not authorized")
                return

            # Step 6: Atomically publish new_active + auth_valid
            self.config.active_repos = new_active
            self.config.policy_active_repos = new_policy_active
            self.config.auth_valid = True

            old_active_set = set(old_active)
            new_active_set = set(new_active)
            removed = old_active_set - new_active_set
            for repo in removed:
                self._pending_baseline_repos.discard(repo)
                self._baseline_progress.pop(repo, None)
                self._invalidate_open_pr_listing_repo(repo, remove=True)
                self._clear_repo_transient_scheduling_state(repo)
            newly_active = new_active_set if not old_auth_valid else new_active_set - old_active_set
            self.mark_repos_pending_baseline(sorted(newly_active), startup=False)
        except (GitHubRateLimitError, GitHubTransientError) as e:
            # API pressure or transport failure is not evidence that the
            # installation lost authorization; preserve the current snapshot
            # and avoid triggering a generation-wide baseline on recovery.
            self.config.auth_valid = old_auth_valid
            logger.warning(
                "auth refresh deferred reason=%s retry_after=%.1f",
                "rate_limited" if isinstance(e, GitHubRateLimitError) else "transient_api_error",
                e.retry_after_seconds,
            )
        except Exception as e:
            logger.warning(
                "auth refresh failed: %s \u2014 failing closed",
                type(e).__name__,
            )
            self.config.auth_valid = False

    @staticmethod
    def _pr_status_labels(pr: dict) -> set[str]:
        labels = pr.get("labels")
        if not isinstance(labels, list):
            return set()
        names = set()
        for label in labels:
            name = label if isinstance(label, str) else (
                label.get("name") if isinstance(label, dict) else None
            )
            if isinstance(name, str) and name.casefold() in CANONICAL_STATUS_LABELS:
                names.add(name.casefold())
        return names

    @staticmethod
    def _pr_labels_are_valid(pr: dict) -> bool:
        labels = pr.get("labels")
        return isinstance(labels, list) and all(
            (isinstance(label, str) and bool(label.strip()))
            or (isinstance(label, dict)
                and isinstance(label.get("name"), str)
                and bool(label["name"].strip()))
            for label in labels
        )

    def _authorization_baseline_required(self, repo: str, pr_number: int) -> bool:
        """Keep per-PR authorization baselines active after repo discovery ends."""
        if (repo, pr_number) in self._ready_for_review_at:
            return True
        generation_active = (
            repo in self._pending_baseline_repos
            or repo in self._repo_baseline_cutoff_utc
        )
        return (generation_active
                and pr_number not in self._baseline_progress.get(repo, set()))

    @staticmethod
    def _next_rotating_pr(
        repo: str, candidates: list[int], cursor: dict[str, int], excluded: set[int],
    ) -> int | None:
        if not candidates:
            return None
        start = cursor.get(repo, 0) % len(candidates)
        for offset in range(len(candidates)):
            index = (start + offset) % len(candidates)
            number = candidates[index]
            if number in excluded:
                continue
            cursor[repo] = (index + 1) % len(candidates)
            return number
        return None

    @staticmethod
    def _pr_snapshot_key(pr: dict) -> tuple:
        head = pr.get("head")
        return (
            pr.get("created_at"), pr.get("updated_at"),
            head.get("sha") if isinstance(head, dict) else None,
        )

    def _new_pr_initialization_retry_ready(self, repo: str, pr: dict) -> bool:
        number = pr.get("number")
        if type(number) is not int or number <= 0:
            return False
        item = (repo, number)
        snapshot_key = self._pr_snapshot_key(pr)
        if self._new_pr_initialization_snapshot.get(item) != snapshot_key:
            self._new_pr_initialization_snapshot[item] = snapshot_key
            self._new_pr_initialization_attempts.pop(item, None)
            self._new_pr_initialization_retry_after.pop(item, None)
        return self._monotonic() >= self._new_pr_initialization_retry_after.get(item, 0.0)

    def _retry_new_pr_initialization(
        self, repo: str, pr_number: int, pr: dict, reason: str,
    ) -> None:
        item = (repo, pr_number)
        snapshot_key = self._pr_snapshot_key(pr)
        if self._new_pr_initialization_snapshot.get(item) != snapshot_key:
            self._new_pr_initialization_attempts[item] = 0
            self._new_pr_initialization_snapshot[item] = snapshot_key
        attempts = min(8, self._new_pr_initialization_attempts.get(item, 0) + 1)
        self._new_pr_initialization_attempts[item] = attempts
        base = max(30.0, float(self.config.poll_interval_seconds))
        delay = min(900.0, base * (2 ** min(attempts - 1, 5)))
        self._new_pr_initialization_retry_after[item] = self._monotonic() + delay
        while len(self._new_pr_initialization_retry_after) > 4096:
            oldest = next(iter(self._new_pr_initialization_retry_after))
            self._new_pr_initialization_retry_after.pop(oldest, None)
            self._new_pr_initialization_attempts.pop(oldest, None)
            self._new_pr_initialization_snapshot.pop(oldest, None)
        logger.warning(
            "watcher new PR initialization deferred repo=%s pr=%s trigger=new_unlabeled_pr reason=%s attempts=%s retry_seconds=%.1f",
            repo, pr_number, reason, attempts, delay,
        )

    def _clear_new_pr_initialization_retry(self, repo: str, pr_number: int) -> None:
        item = (repo, pr_number)
        self._new_pr_initialization_attempts.pop(item, None)
        self._new_pr_initialization_retry_after.pop(item, None)
        self._new_pr_initialization_snapshot.pop(item, None)

    def _ordinary_pr_scan_retry_ready(self, repo: str, pr: dict) -> bool:
        number = pr.get("number")
        if type(number) is not int or number <= 0:
            return False
        item = (repo, number)
        retry = self._ordinary_pr_scan_retries.get(item)
        if not isinstance(retry, dict):
            return True
        snapshot_key = self._pr_snapshot_key(pr)
        if retry.get("snapshot") != snapshot_key:
            self._ordinary_pr_scan_retries.pop(item, None)
            return True
        return self._monotonic() >= retry.get("retry_after", 0.0)

    def _defer_ordinary_pr_scan(
        self, repo: str, pr_number: int, pr: dict, reason: str,
        *, minimum_delay: float = 0.0,
    ) -> None:
        item = (repo, pr_number)
        previous = self._ordinary_pr_scan_retries.get(item, {})
        snapshot_key = self._pr_snapshot_key(pr)
        failures = 1
        if isinstance(previous, dict) and previous.get("snapshot") == snapshot_key:
            failures = min(8, int(previous.get("attempts", 0)) + 1)
        base = max(30.0, float(self.config.poll_interval_seconds))
        delay = min(900.0, base * (2 ** min(failures - 1, 5)))
        delay = max(delay, min(900.0, max(0.0, minimum_delay)))
        self._ordinary_pr_scan_retries[item] = {
            "attempts": failures,
            "retry_after": self._monotonic() + delay,
            "snapshot": snapshot_key,
        }
        while len(self._ordinary_pr_scan_retries) > 4096:
            self._ordinary_pr_scan_retries.pop(
                next(iter(self._ordinary_pr_scan_retries)), None,
            )
        logger.info(
            "watcher ordinary PR scan deferred repo=%s pr=%s reason=%s attempts=%s retry_seconds=%.1f",
            repo, pr_number, reason, failures, delay,
        )

    def _clear_ordinary_pr_scan_retry(self, repo: str, pr_number: int) -> None:
        self._ordinary_pr_scan_retries.pop((repo, pr_number), None)

    def _machine_projection_version(self, repo: str):
        policy = getattr(self.controller, "policy", None)
        version_fn = getattr(policy, "machine_projection_version", None)
        if not callable(version_fn):
            if repo not in self._machine_version_api_missing_repos:
                self._machine_version_api_missing_repos.add(repo)
                logger.warning(
                    "watcher machine configuration refresh unavailable repo=%s trigger=machine_projection_change result=version_api_missing",
                    repo,
                )
            return None
        self._machine_version_api_missing_repos.discard(repo)
        try:
            version = version_fn(repo)
        except Exception as exc:
            logger.warning(
                "watcher machine configuration version read failed repo=%s trigger=machine_projection_change reason=%s",
                repo, type(exc).__name__,
            )
            return None
        if version is None or isinstance(version, (dict, list, set)):
            return None
        return version

    def _machine_projection_refresh_candidates(self, valid_prs: list[tuple[int, dict]]) -> list[int]:
        refresh_labels = frozenset({
            "status: deploy-ready", "status: deploy-requested",
            "status: testing", "status: acceptance-required",
            "status: succeeded", "status: failed",
        })
        candidates = []
        for number, pr in valid_prs:
            if pr.get("draft") is True or not self._pr_labels_are_valid(pr):
                continue
            if self._pr_status_labels(pr).intersection(refresh_labels):
                candidates.append(number)
        return candidates

    def _machine_projection_pr_signature(self, pr: dict) -> tuple:
        head = pr.get("head")
        head_sha = head.get("sha") if isinstance(head, dict) else None
        statuses = tuple(sorted(self._pr_status_labels(pr).intersection({
            "status: deploy-ready", "status: deploy-requested",
            "status: testing", "status: acceptance-required",
            "status: succeeded", "status: failed",
        })))
        return head_sha, statuses

    def _queue_machine_projection_refreshes(self, repo: str, *, max_items: int = 2) -> int:
        pending = self._machine_refresh_pending.get(repo)
        if not isinstance(pending, dict):
            return 0
        numbers = pending.get("numbers")
        cursor = pending.get("cursor")
        if not isinstance(numbers, list) or type(cursor) is not int:
            self._machine_refresh_pending.pop(repo, None)
            return 0
        queued = 0
        if not numbers:
            self._machine_refresh_pending.pop(repo, None)
            return 0
        inspected = 0
        while inspected < len(numbers) and queued < max_items:
            index = cursor % len(numbers)
            number = numbers[index]
            cursor = (index + 1) % len(numbers)
            inspected += 1
            item = (repo, number)
            if self._monotonic() < self._machine_refresh_retry_after.get(item, 0.0):
                continue
            if item not in self._machine_refresh_pr_versions:
                if len(self._machine_refresh_pr_versions) >= 4096:
                    continue
                self._machine_refresh_pr_versions[item] = pending.get("version")
            elif self._machine_refresh_pr_versions[item] != pending.get("version"):
                self._machine_refresh_pr_versions[item] = pending.get("version")
            if item in self._priority_pr_queue:
                continue
            if len(self._priority_pr_queue) >= 128:
                break
            if self._queue_priority_pr(item, "machine"):
                queued += 1
            else:
                break
        pending["cursor"] = cursor
        return queued

    def _observe_machine_projection_change(
        self, repo: str, valid_prs: list[tuple[int, dict]],
    ) -> None:
        version = self._machine_projection_version(repo)
        if version is None:
            return
        candidates = self._machine_projection_refresh_candidates(valid_prs)
        candidate_set = set(candidates)
        self._prune_machine_projection_refreshes(repo, candidate_set)
        if repo not in self._machine_projection_versions:
            self._machine_projection_versions[repo] = version
            self._schedule_machine_projection_refreshes(repo, version, candidates)
            queued = self._queue_machine_projection_refreshes(repo)
            logger.info(
                "watcher machine configuration version recorded repo=%s trigger=machine_projection_change result=baseline_recorded candidate_prs=%s queued_prs=%s pending_prs=%s",
                repo, len(candidates), queued, max(0, len(candidates) - queued),
            )
            return
        previous = self._machine_projection_versions[repo]
        if version != previous:
            self._machine_projection_versions[repo] = version
            self._schedule_machine_projection_refreshes(repo, version, candidates)
            scheduled = True
        else:
            now = self._monotonic()
            prs_by_number = dict(valid_prs)
            due = []
            for number in candidates:
                item = (repo, number)
                completed = self._machine_refresh_last_results.get(item)
                signature = self._machine_projection_pr_signature(prs_by_number[number])
                if (not isinstance(completed, dict)
                        or completed.get("version") != version
                        or completed.get("signature") != signature
                        or now - completed.get("at", 0.0)
                        >= MACHINE_PROJECTION_REFRESH_SECONDS):
                    due.append(number)
            if due:
                self._schedule_machine_projection_refreshes(
                    repo, version, due, replace=False,
                )
            scheduled = bool(due)
        queued = self._queue_machine_projection_refreshes(repo)
        logger.info(
            "watcher machine configuration inspection repo=%s trigger=machine_projection_change result=%s candidate_prs=%s queued_prs=%s pending_prs=%s",
            repo, "scheduled" if scheduled else "unchanged",
            len(candidates), queued, max(0, len(candidates) - queued),
        )

    def _schedule_machine_projection_refreshes(
        self, repo: str, version: object, candidates: list[int], *, replace: bool = True,
    ) -> None:
        pending = self._machine_refresh_pending.get(repo)
        if replace or not isinstance(pending, dict) or pending.get("version") != version:
            for item in [item for item in self._machine_refresh_pr_versions
                         if item[0] == repo]:
                self._machine_refresh_pr_versions.pop(item, None)
            for item in [item for item in self._machine_refresh_last_results
                         if item[0] == repo]:
                self._machine_refresh_last_results.pop(item, None)
            for item in [item for item in self._machine_refresh_retry_after
                         if item[0] == repo]:
                self._clear_machine_projection_retry(item)
            pending_candidates = list(dict.fromkeys(candidates))
            candidate_set = set(pending_candidates)
            for item in [item for item in self._priority_pr_queue
                         if item[0] == repo
                         and self._priority_pr_sources.get(item) == "machine"
                         and item[1] not in candidate_set]:
                self._priority_pr_queue.remove(item)
                self._priority_pr_set.discard(item)
                self._priority_pr_enqueued_at.pop(item, None)
                self._priority_pr_sources.pop(item, None)
                self._clear_priority_baseline_retry(item)
                self._clear_priority_item_retry(item)
            for item in [item for item in self._priority_pr_queue
                         if item[0] == repo
                         and self._priority_pr_sources.get(item) == "machine"]:
                self._clear_priority_baseline_retry(item)
                self._clear_priority_item_retry(item)
            self._machine_refresh_pending[repo] = {
                "version": version,
                "numbers": pending_candidates,
                "cursor": 0,
            }
            return

        existing = set(pending.get("numbers", []))
        pending["numbers"].extend(
            number for number in dict.fromkeys(candidates)
            if number not in existing
        )

    def _prune_machine_projection_refreshes(
        self, repo: str, eligible_numbers: set[int],
    ) -> None:
        for item in [item for item in self._machine_refresh_pr_versions
                     if item[0] == repo and item[1] not in eligible_numbers]:
            self._machine_refresh_pr_versions.pop(item, None)
            self._clear_machine_projection_retry(item)
            if (item in self._priority_pr_queue
                    and self._priority_pr_sources.get(item) == "machine"):
                self._priority_pr_queue.remove(item)
                self._priority_pr_set.discard(item)
                self._priority_pr_enqueued_at.pop(item, None)
                self._priority_pr_sources.pop(item, None)
                self._clear_priority_baseline_retry(item)
                self._clear_priority_item_retry(item)
        for item in [item for item in self._machine_refresh_last_results
                     if item[0] == repo and item[1] not in eligible_numbers]:
            self._machine_refresh_last_results.pop(item, None)
        pending = self._machine_refresh_pending.get(repo)
        if isinstance(pending, dict):
            pending["numbers"] = [
                number for number in pending.get("numbers", [])
                if number in eligible_numbers
            ]
            pending["cursor"] = 0
            if not pending["numbers"]:
                self._machine_refresh_pending.pop(repo, None)

    def _log_machine_projection_refresh_result(
        self, repo: str, pr_number: int, result: str, *, complete: bool,
    ) -> None:
        item = (repo, pr_number)
        if item not in self._machine_refresh_pr_versions:
            return
        logger.info(
            "watcher machine configuration refresh repo=%s pr=%s trigger=machine_projection_change result=%s",
            repo, pr_number, result,
        )
        if complete and result == "refreshed":
            completed_version = self._machine_refresh_pr_versions.pop(item, None)
            self._clear_machine_projection_retry(item)
            pending = self._machine_refresh_pending.get(repo)
            if (isinstance(pending, dict)
                    and pending.get("version") == completed_version):
                pending["numbers"] = [
                    number for number in pending.get("numbers", [])
                    if number != pr_number
                ]
                pending["cursor"] = 0
                if not pending["numbers"]:
                    self._machine_refresh_pending.pop(repo, None)

    def _forget_machine_projection_refresh(self, repo: str, pr_number: int) -> None:
        """Forget a stale candidate only after the PR is confirmed ineligible."""
        item = (repo, pr_number)
        self._machine_refresh_pr_versions.pop(item, None)
        self._clear_machine_projection_retry(item)
        pending = self._machine_refresh_pending.get(repo)
        if isinstance(pending, dict):
            pending["numbers"] = [
                number for number in pending.get("numbers", [])
                if number != pr_number
            ]
            pending["cursor"] = 0
            if not pending["numbers"]:
                self._machine_refresh_pending.pop(repo, None)

    def _remember_machine_projection_result(
        self, repo: str, pr_number: int, version: object,
        pr_data: dict, result: str,
    ) -> None:
        item = (repo, pr_number)
        self._machine_refresh_last_results[item] = {
            "version": version,
            "signature": self._machine_projection_pr_signature(pr_data),
            "at": self._monotonic(),
            "result": result,
        }
        while len(self._machine_refresh_last_results) > 4096:
            self._machine_refresh_last_results.pop(
                next(iter(self._machine_refresh_last_results)), None,
            )

    async def _refresh_machine_adaptation_for_pr(
        self, repo: str, pr_number: int,
    ) -> str:
        """Run the controller's unified machine projection refresh in the writer."""
        if (not self._open_pr_listing_repo_is_authorized(repo)
                or (repo, pr_number) not in self._machine_refresh_pr_versions):
            return "incomplete"
        queued_version = self._machine_refresh_pr_versions[(repo, pr_number)]
        version_before = self._machine_projection_version(repo)
        if version_before is None or version_before != queued_version:
            return "incomplete"
        try:
            pr_data = await self.proxy.get_pr(repo, pr_number)
        except GitHubError as exc:
            if exc.status_code == 404:
                return "stale"
            raise
        if (not isinstance(pr_data, dict) or pr_data.get("state") != "open"
                or pr_data.get("merged") or pr_data.get("draft")):
            return "stale"
        state = await self.proxy.read_hidden_state(repo, pr_number)
        if not isinstance(state, dict):
            return "incomplete"
        if state.get("status") == "deploying":
            self._remember_machine_projection_result(
                repo, pr_number, version_before, pr_data, "stale",
            )
            return "stale"
        refresh = getattr(self.controller, "refresh_machine_projection", None)
        if not callable(refresh):
            logger.warning(
                "watcher machine projection refresh unavailable repo=%s pr=%s reason=controller_refresh_api_missing",
                repo, pr_number,
            )
            return "incomplete"
        result = await refresh(repo, pr_number)
        version_after = self._machine_projection_version(repo)
        if version_after is None or version_after != version_before:
            return "incomplete"
        if result not in {"refreshed", "incomplete", "stale"}:
            return "incomplete"
        if result in {"refreshed", "stale"}:
            self._remember_machine_projection_result(
                repo, pr_number, version_after, pr_data, result,
            )
        return result

    def _record_draft_label_attempt(self, repo: str, pr_number: int) -> None:
        key = (repo, pr_number)
        attempts = min(8, self._draft_label_attempts.get(key, 0) + 1)
        self._draft_label_attempts[key] = attempts
        base = max(PRIORITY_BASELINE_RETRY_BASE_SECONDS,
                   float(self.config.poll_interval_seconds))
        delay = min(PRIORITY_BASELINE_RETRY_MAX_SECONDS,
                    base * (2 ** min(attempts - 1, 8)))
        self._draft_label_retry_after[key] = self._monotonic() + delay
        while len(self._draft_label_retry_after) > 4096:
            oldest = next(iter(self._draft_label_retry_after))
            self._draft_label_retry_after.pop(oldest, None)
            self._draft_label_attempts.pop(oldest, None)
        logger.info(
            "watcher draft status label retry scheduled repo=%s pr=%s reason=label_missing_in_open_pr_snapshot attempts=%s retry_seconds=%.1f",
            repo, pr_number, attempts, delay,
        )

    def _draft_label_retry_ready(self, repo: str, pr_number: int) -> bool:
        key = (repo, pr_number)
        retry_after = self._draft_label_retry_after.get(key, 0.0)
        projection_cache = getattr(self.proxy, "_status_label_projection", None)
        cached_projection = (
            projection_cache.get(key) if isinstance(projection_cache, dict) else None
        )
        if isinstance(cached_projection, dict):
            proxy_retry_after = cached_projection.get("retry_at")
            if isinstance(proxy_retry_after, (int, float)):
                retry_after = max(retry_after, proxy_retry_after)
        return self._monotonic() >= retry_after

    def _log_draft_label_retry_state(self, repo: str, pr_number: int) -> None:
        projection_cache = getattr(self.proxy, "_status_label_projection", None)
        cached_projection = (
            projection_cache.get((repo, pr_number))
            if isinstance(projection_cache, dict) else None
        )
        if not isinstance(cached_projection, dict) or not cached_projection.get("failures"):
            return
        retry_after = cached_projection.get("retry_at", 0.0)
        retry_seconds = max(0.0, retry_after - self._monotonic()) \
            if isinstance(retry_after, (int, float)) else 0.0
        logger.warning(
            "watcher draft status label projection deferred repo=%s pr=%s reason=proxy_label_retry failures=%s retry_seconds=%.1f",
            repo, pr_number, cached_projection.get("failures"), retry_seconds,
        )

    def _ordinary_pr_cache_fresh(self, repo: str, pr_number: int, pr: dict, *, force: bool = False) -> bool:
        if force or self._authorization_baseline_required(repo, pr_number):
            return False
        updated_at = pr.get("updated_at")
        head = pr.get("head")
        head_sha = head.get("sha") if isinstance(head, dict) else None
        if not isinstance(updated_at, str) or not updated_at or not isinstance(head_sha, str):
            return False
        cached = self._pr_reconcile_cache.get((repo, pr_number))
        if not isinstance(cached, dict) or cached.get("requires_reconcile") is True:
            return False
        if cached.get("updated_at") != updated_at or cached.get("head_sha") != head_sha:
            return False
        expected_label = cached.get("projected_label")
        if self._pr_labels_are_valid(pr):
            observed_labels = self._pr_status_labels(pr)
            if (not isinstance(expected_label, str)
                    or expected_label not in observed_labels
                    or any(label != expected_label for label in observed_labels)):
                return False
        processed_at = cached.get("processed_at")
        return (isinstance(processed_at, (int, float))
                and self._monotonic() - processed_at < PR_RECONCILE_CACHE_SECONDS)

    def _terminal_runtime_scan_due(
        self, repo: str, pr_number: int, pr: dict, status_labels: set[str],
    ) -> bool:
        """Schedule terminal open PRs until hidden state confirms deployment presence."""
        terminal_labels = status_labels.intersection({
            "status: succeeded", "status: failed",
        })
        if not terminal_labels:
            return False

        expected_label = next(iter(terminal_labels)) if len(terminal_labels) == 1 else None
        expected_status = (
            expected_label.removeprefix("status: ").strip()
            if expected_label is not None else None
        )
        head = pr.get("head")
        head_sha = head.get("sha") if isinstance(head, dict) else None
        cached = self._pr_reconcile_cache.get((repo, pr_number))
        cache_matches_pr = (
            isinstance(cached, dict)
            and cached.get("updated_at") == pr.get("updated_at")
            and cached.get("head_sha") == head_sha
        )
        if not cache_matches_pr:
            return True

        cached_status = cached.get("status")
        if (expected_status is not None
                and cached_status in {"succeeded", "failed"}
                and cached_status != expected_status):
            return True
        has_deployed_components = cached.get("has_deployed_components")
        if has_deployed_components is True:
            return True
        if (has_deployed_components is False
                and expected_label is not None
                and cached_status == expected_status
                and cached.get("projected_label") == expected_label):
            return False

        # Unknown or unreadable hidden state is retried with the existing
        # bounded PR reconcile interval instead of occupying a slot each cycle.
        processed_at = cached.get("processed_at")
        if not isinstance(processed_at, (int, float)):
            return True
        return self._monotonic() - processed_at >= PR_RECONCILE_CACHE_SECONDS

    async def _remember_pr_schedule(self, repo: str, pr_number: int, pr: dict) -> None:
        updated_at = pr.get("updated_at")
        head = pr.get("head")
        head_sha = head.get("sha") if isinstance(head, dict) else None
        if not isinstance(updated_at, str) or not isinstance(head_sha, str):
            self._pr_reconcile_cache.pop((repo, pr_number), None)
            return
        state = None
        try:
            state = await self.proxy.read_hidden_state(repo, pr_number)
        except Exception:
            # Missing state means the hint cannot justify skipping a later
            # reconciliation; it never changes an authorization decision.
            pass
        command = state.get("command") if isinstance(state, dict) else None
        args = command.get("args") if isinstance(command, dict) else None
        pending_ids = args.get("pending_component_ids") if isinstance(args, dict) else None
        deployments = state.get("deployments", []) if isinstance(state, dict) else []
        same_head = isinstance(state, dict) and state.get("head_sha") == head_sha
        has_deployed_components = (
            isinstance(deployments, list)
            and any(isinstance(item, dict) and item.get("phase") == "deployed"
                    and isinstance(item.get("component_ids"), list)
                    and bool(item.get("component_ids")) for item in deployments)
        ) if same_head and isinstance(deployments, list) else None
        projected_label = None
        if same_head:
            status = state.get("status")
            if isinstance(status, str):
                candidate_label = f"status: {status}".casefold()
                if candidate_label in CANONICAL_STATUS_LABELS:
                    projected_label = candidate_label
            acceptance = state.get("acceptance_request")
            if (status == "testing" and isinstance(acceptance, dict)
                    and acceptance.get("status") == "pending"
                    and acceptance.get("head_sha") == head_sha):
                try:
                    from .evidence_models import round_id_for_state
                    if acceptance.get("round_id") == round_id_for_state(state):
                        projected_label = "status: acceptance-required"
                except (TypeError, ValueError):
                    pass
        requires_reconcile = (
            not isinstance(state, dict)
            or not same_head
            or projected_label is None
            or state.get("status") in {"deploy-requested", "deploying", "testing"}
            or isinstance(command, dict) and command.get("phase") in {"executing", "uncertain"}
            or isinstance(pending_ids, list) and bool(pending_ids)
        )
        cursor = state.get("last_processed_comment_id") if isinstance(state, dict) else None
        key = (repo, pr_number)
        self._pr_reconcile_cache.pop(key, None)
        self._pr_reconcile_cache[key] = {
            "updated_at": updated_at, "head_sha": head_sha,
            "cursor": cursor if isinstance(cursor, int) and not isinstance(cursor, bool) else None,
            "status": state.get("status") if isinstance(state, dict) else None,
            "has_deployed_components": has_deployed_components,
            "projected_label": projected_label,
            "requires_reconcile": requires_reconcile,
            "processed_at": self._monotonic(),
        }
        while len(self._pr_reconcile_cache) > 4096:
            self._pr_reconcile_cache.pop(next(iter(self._pr_reconcile_cache)))

    def _defer_evidence_projection_for_priority(
        self, repo: str, pr_number: int,
    ) -> bool:
        """Yield optional historical evidence work when a priority hint waits."""
        if not self._priority_pr_queue:
            return False
        self._last_evidence_projection.pop((repo, pr_number), None)
        self._current_scan_stage = "priority_wait_before_evidence_projection"
        logger.info(
            "watcher deferred evidence projection for queued priority work repo=%s pr=%s queued=%s",
            repo, pr_number, len(self._priority_pr_queue),
        )
        return True

    def _priority_work_waiting_for_other_pr(self, repo: str, pr_number: int) -> bool:
        """Yield normal comment-history reads to an already queued PR hint."""
        now = self._monotonic()
        return any(
            queued_repo != repo or queued_pr != pr_number
            for queued_repo, queued_pr in self._priority_pr_queue
            if now >= self._priority_pr_retry_after.get((queued_repo, queued_pr), 0.0)
            and (self._priority_pr_sources.get((queued_repo, queued_pr)) != "machine"
                 or now >= self._machine_refresh_retry_after.get(
                     (queued_repo, queued_pr), 0.0,
                 ))
        )

    async def _process_scheduled_pr(
        self, repo: str, pr_number: int, *, priority_path: bool = False,
    ) -> bool:
        """Run one PR through the existing serial writer and evidence path."""
        baseline_done = self._baseline_progress.setdefault(repo, set())
        baseline_required = self._authorization_baseline_required(repo, pr_number)
        baseline_ran = False
        baseline_succeeded = True
        if baseline_required:
            baseline_ran = True
            self._current_scan_stage = "comment_baseline"
            if await self._baseline_pr(repo, pr_number):
                baseline_done.add(pr_number)
                # The fixed authorization cutoff now applies to a completed
                # baseline. Deliver the one-time rejection notices for commands
                # that were sent before that boundary; they never execute.
                await self._flush_pending_baseline_notices(repo, pr_number)
            else:
                baseline_succeeded = False
        else:
            self._current_scan_stage = "command_reconcile_and_dispatch"
            # Pending pre-baseline notices are strictly older than anything this
            # cycle may dispatch, so deliver them first. That keeps the visible
            # conversation ordered: a later command never appears to overtake an
            # earlier command that still owes a rejection.
            await self._flush_pending_baseline_notices(repo, pr_number)
            await self._process_pr(repo, pr_number, yield_for_priority=not priority_path)
            # A comment may have been registered during _process_pr itself;
            # flush again so it is not delayed until the next cycle.
            await self._flush_pending_baseline_notices(repo, pr_number)
        if (self.config.auth_valid is not True or repo not in self.config.active_repos
                or repo not in self.config.github_repos):
            return False
        if self._defer_evidence_projection_for_priority(repo, pr_number):
            return baseline_succeeded
        self._current_scan_stage = "post_command_pr_validation"
        current_pr = await self.proxy.get_pr(repo, pr_number)
        if self._defer_evidence_projection_for_priority(repo, pr_number):
            return baseline_succeeded
        if (isinstance(current_pr, dict) and current_pr.get("state") == "open"
                and not current_pr.get("merged") and not current_pr.get("draft")):
            updated_at = current_pr.get("updated_at")
            head_sha = current_pr.get("head", {}).get("sha")
            projection_version = (
                f"{head_sha}:{updated_at}"
                if isinstance(head_sha, str) and isinstance(updated_at, str) else ""
            )
            key = (repo, pr_number)
            previous = self._last_evidence_projection.get(key)
            now = self._monotonic()
            refresh_due = previous is None or now - previous[1] >= 6 * 24 * 60 * 60
            changed = not projection_version or previous is None or previous[0] != projection_version

            item = (repo, pr_number)
            # Reconcile ready attachments when scheduled, when the PR changed,
            # or when a previous reconcile is due for retry. Never re-enqueue
            # unconditionally on every routine scan pass.
            if item in self._evidence_sync_set or changed:
                if self._monotonic() >= self._evidence_sync_retry_after.get(item, 0.0):
                    try:
                        succeeded = await self._reconcile_ready_evidence(repo, pr_number)
                    except Exception as exc:
                        logger.warning(
                            "watcher scheduled evidence reconcile failed %s#%s: %s",
                            repo, pr_number, type(exc).__name__,
                        )
                        self._scan_failure_reasons.append(
                            f"evidence_sync:{repo}#{pr_number}:{type(exc).__name__}",
                        )
                        succeeded = False
                    if succeeded:
                        self._clear_evidence_sync_retry(item)
                        if item in self._evidence_sync_set:
                            self._evidence_sync_set.discard(item)
                            try:
                                self._evidence_sync_queue.remove(item)
                            except ValueError:
                                pass
                    else:
                        self._retry_evidence_sync(item)
                    previous = self._last_evidence_projection.get(key)
                    changed = not projection_version or previous is None or previous[0] != projection_version

            if changed or refresh_due:
                self._current_scan_stage = "evidence_projection"
                projection_succeeded = True
                try:
                    await self.controller.project_evidence(repo, pr_number)
                except Exception as exc:
                    logger.warning(
                        "evidence projection failed %s#%s: %s; retry scheduled",
                        repo, pr_number, type(exc).__name__,
                    )
                    self._scan_failure_reasons.append(
                        f"evidence_projection:{repo}#{pr_number}:{type(exc).__name__}",
                    )
                    self._retry_evidence_sync(item)
                    projection_succeeded = False
                if self._defer_evidence_projection_for_priority(repo, pr_number):
                    return baseline_succeeded
                self._current_scan_stage = "visible_archive_migration"
                try:
                    await self.proxy.ensure_visible_evidence_archive_comments(
                        repo, pr_number, limit=2,
                    )
                except Exception as exc:
                    logger.warning(
                        "visible archive migration failed %s#%s: %s; retry scheduled",
                        repo, pr_number, type(exc).__name__,
                    )
                    self._scan_failure_reasons.append(
                        f"evidence_archive:{repo}#{pr_number}:{type(exc).__name__}",
                    )
                    self._retry_evidence_sync(item)
                    projection_succeeded = False
                if self._defer_evidence_projection_for_priority(repo, pr_number):
                    return baseline_succeeded
                self._current_scan_stage = "legacy_reply_retirement"
                try:
                    valid_cos_links = await self._validated_current_summary_cos_links(repo, pr_number)
                    if self._defer_evidence_projection_for_priority(repo, pr_number):
                        return baseline_succeeded
                    await self.proxy.retire_legacy_evidence_link_replies(
                        repo, pr_number, valid_cos_links, limit=2,
                    )
                except Exception as exc:
                    logger.warning(
                        "legacy evidence reply retirement failed %s#%s: %s; retry scheduled",
                        repo, pr_number, type(exc).__name__,
                    )
                    self._scan_failure_reasons.append(
                        f"evidence_retirement:{repo}#{pr_number}:{type(exc).__name__}",
                    )
                    self._retry_evidence_sync(item)
                    projection_succeeded = False
                if projection_version and projection_succeeded:
                    self._last_evidence_projection.pop(key, None)
                    self._last_evidence_projection[key] = (projection_version, now)
                    if len(self._last_evidence_projection) > 4096:
                        self._last_evidence_projection.pop(next(iter(self._last_evidence_projection)))
            if baseline_succeeded and not baseline_ran:
                await self._remember_pr_schedule(repo, pr_number, current_pr)
            else:
                self._pr_reconcile_cache.pop((repo, pr_number), None)
        else:
            self._pr_reconcile_cache.pop((repo, pr_number), None)
        return baseline_succeeded

    async def _drain_priority_prs(
        self, priority_done, priority_attempted, recent_attempted,
        *, allowed_sources, max_items=2,
    ) -> bool:
        """Process a bounded priority tier through the existing serial PR path."""
        max_items = min(4, max(0, max_items))
        cycle_ok = True
        processed_items = 0
        for stale in list(self._priority_pr_queue):
            stale_repo, _ = stale
            if (stale_repo not in self.config.active_repos
                    or stale_repo not in self.config.github_repos):
                self._priority_pr_queue.remove(stale)
                self._priority_pr_set.discard(stale)
                self._priority_pr_enqueued_at.pop(stale, None)
                self._priority_pr_sources.pop(stale, None)
                self._clear_priority_baseline_retry(stale)
                self._clear_priority_item_retry(stale)
        sources = ("command", "webhook", "recent", "machine", "initialization")
        selected_repos = set()
        repo_order = list(dict.fromkeys(self.config.active_repos))
        machine_items = 0
        while processed_items < max_items:
            now = self._monotonic()
            ready_command_waiting = any(
                self._priority_pr_sources.get(queued) == "command"
                and now >= self._priority_pr_retry_after.get(queued, 0.0)
                for queued in self._priority_pr_queue
            )
            if (self._priority_pr_queue and not ready_command_waiting
                    and self.config.auth_valid is True):
                try:
                    await self._discover_recent_command_prs(
                        list(dict.fromkeys(self.config.active_repos)),
                    )
                except Exception as exc:
                    logger.warning(
                        "watcher priority command recheck failed reason=%s",
                        type(exc).__name__,
                    )
            chosen = None
            chosen_source = None
            chosen_index = None
            for source in sources:
                if source not in allowed_sources or (source == "machine" and machine_items >= 2):
                    continue
                source_candidates = [
                    queued for queued in self._priority_pr_queue
                    if self._priority_pr_sources.get(queued, "webhook") == source
                    and self._monotonic() >= self._priority_pr_retry_after.get(queued, 0.0)
                    and (source != "machine"
                         or self._monotonic() >= self._machine_refresh_retry_after.get(
                             queued, 0.0,
                         ))
                ]
                if not source_candidates:
                    continue
                start = self._priority_source_repo_cursor.get(source, 0)
                start = start % len(repo_order) if repo_order else 0
                for prefer_unselected in (True, False):
                    for offset in range(len(repo_order)):
                        index = (start + offset) % len(repo_order)
                        candidate_repo = repo_order[index]
                        if prefer_unselected and candidate_repo in selected_repos:
                            continue
                        candidate = next((queued for queued in source_candidates
                                          if queued[0] == candidate_repo), None)
                        if candidate is not None:
                            chosen = candidate
                            chosen_index = index
                            break
                    if chosen is not None:
                        break
                if chosen is None:
                    chosen = source_candidates[0]
                    chosen_index = (
                        repo_order.index(chosen[0]) if chosen[0] in repo_order else start
                    )
                chosen_source = source
                break
            if chosen is None:
                break
            item = chosen
            selected_repos.add(item[0])
            self._priority_source_repo_cursor[chosen_source] = (
                (chosen_index + 1) % len(repo_order) if repo_order else 0
            )
            if item not in self._priority_pr_queue:
                continue
            if self._monotonic() < self._priority_pr_retry_after.get(item, 0.0):
                continue
            self._priority_pr_queue.remove(item)
            processed_items += 1
            queued_repo, pr_number = item
            source = self._priority_pr_sources.get(item, "webhook")
            if source == "machine" and item in self._machine_refresh_pr_versions:
                machine_items += 1
            trigger = {
                "webhook": "pull_request_webhook",
                "command": "new_developer_command",
                "recent": "review_or_historical_comment",
                "machine": "machine_projection_change",
                "initialization": "new_unlabeled_pr",
            }.get(source, source)
            pending_comment_id, command_wait = self._pending_command_wait(
                queued_repo, pr_number,
            )
            logger.info(
                "watcher priority work started repo=%s pr=%s trigger=%s comment_id=%s command_wait_seconds=%s",
                queued_repo, pr_number, trigger, pending_comment_id, command_wait,
            )
            if self.config.auth_valid is not True:
                self._queue_priority_pr(item, source)
                cycle_ok = False
                break
            if (queued_repo not in self.config.active_repos
                    or queued_repo not in self.config.github_repos):
                self._priority_pr_set.discard(item)
                self._priority_pr_enqueued_at.pop(item, None)
                self._priority_pr_sources.pop(item, None)
                self._clear_priority_baseline_retry(item)
                continue
            source_attempted = (priority_attempted.setdefault(queued_repo, [])
                                if source == "webhook"
                                else recent_attempted.setdefault(queued_repo, []))
            if pr_number not in source_attempted:
                source_attempted.append(pr_number)
            if (source != "webhook"
                    and pr_number not in priority_attempted.setdefault(queued_repo, [])):
                priority_attempted.setdefault(queued_repo, []).append(pr_number)
            self._current_scan_stage = "priority_pr_validation"
            self._current_scan_repo = queued_repo
            self._current_scan_pr = pr_number
            try:
                current_pr = await self.proxy.get_pr(queued_repo, pr_number)
            except GitHubRateLimitError as exc:
                self._retry_priority_item(item, source, "github_rate_limited")
                self._priority_pr_retry_after[item] = max(
                    self._priority_pr_retry_after.get(item, 0.0),
                    self._monotonic() + max(0.0, exc.retry_after_seconds),
                )
                self._fail_recent_commands_for_pr(queued_repo, pr_number, "github_rate_limited")
                self._record_pr_attempt(queued_repo, pr_number, "github_rate_limited")
                self._scan_failure_reasons.append(
                    f"priority_read:{queued_repo}#{pr_number}:rate_limited",
                )
                logger.warning("watcher rate limited before priority PR; retry_after=%.1f", exc.retry_after_seconds)
                cycle_ok = False
                break
            except GitHubError as exc:
                if exc.status_code == 404:
                    self._fail_recent_commands_for_pr(
                        queued_repo, pr_number, "pr_not_found", retryable=False,
                    )
                    self._forget_machine_projection_refresh(queued_repo, pr_number)
                    while item in self._priority_pr_queue:
                        self._priority_pr_queue.remove(item)
                    self._priority_pr_set.discard(item)
                    self._priority_pr_enqueued_at.pop(item, None)
                    self._priority_pr_sources.pop(item, None)
                    self._clear_priority_baseline_retry(item)
                    logger.info(
                        "watcher priority candidate is not an open PR repo=%s number=%s source=%s",
                        queued_repo, pr_number, source,
                    )
                    continue
                self._retry_priority_item(item, source, type(exc).__name__)
                self._fail_recent_commands_for_pr(queued_repo, pr_number, type(exc).__name__)
                self._record_pr_attempt(queued_repo, pr_number, type(exc).__name__)
                self._scan_failure_reasons.append(
                    f"priority_read:{queued_repo}#{pr_number}:http_{exc.status_code}",
                )
                logger.warning(
                    "watcher priority PR read %s#%s failed: %s",
                    queued_repo, pr_number, type(exc).__name__,
                )
                cycle_ok = False
                if self._github_backing_off():
                    break
                continue
            except Exception as exc:
                self._retry_priority_item(item, source, type(exc).__name__)
                self._fail_recent_commands_for_pr(queued_repo, pr_number, type(exc).__name__)
                self._record_pr_attempt(queued_repo, pr_number, type(exc).__name__)
                self._scan_failure_reasons.append(
                    f"priority_read:{queued_repo}#{pr_number}:{type(exc).__name__}",
                )
                logger.warning("watcher priority PR read %s#%s failed: %s", queued_repo, pr_number, type(exc).__name__)
                cycle_ok = False
                if self._github_backing_off():
                    break
                continue
            draft_pr = (
                isinstance(current_pr, dict)
                and current_pr.get("state") == "open"
                and not current_pr.get("merged")
                and current_pr.get("draft") is True
            )
            draft_labels_valid = (
                self._pr_labels_are_valid(current_pr) if draft_pr else False
            )
            draft_has_status = bool(
                self._pr_status_labels(current_pr)
                if draft_pr and draft_labels_valid else set()
            )
            if (draft_pr and draft_labels_valid and not draft_has_status
                    and self._draft_label_retry_ready(queued_repo, pr_number)):
                try:
                    self._record_draft_label_attempt(queued_repo, pr_number)
                    # The controller's draft-only path projects the trusted
                    # status label without creating or advancing lifecycle.
                    await self.controller.reconcile_pr(queued_repo, pr_number)
                    self._log_draft_label_retry_state(queued_repo, pr_number)
                except Exception as exc:
                    self._priority_pr_set.discard(item)
                    self._priority_pr_enqueued_at.pop(item, None)
                    self._priority_pr_sources.pop(item, None)
                    self._clear_priority_baseline_retry(item)
                    self._record_pr_attempt(queued_repo, pr_number, type(exc).__name__)
                    self._scan_failure_reasons.append(
                        f"draft_label:{queued_repo}#{pr_number}:{type(exc).__name__}",
                    )
                    cycle_ok = False
                    logger.warning(
                        "watcher draft status label projection %s#%s failed: %s",
                        queued_repo, pr_number, type(exc).__name__,
                    )
                    if self._github_backing_off():
                        break
                    continue
            elif draft_pr and draft_has_status:
                self._draft_label_retry_after.pop((queued_repo, pr_number), None)
                self._draft_label_attempts.pop((queued_repo, pr_number), None)
            if (not isinstance(current_pr, dict) or current_pr.get("state") != "open"
                    or current_pr.get("merged") or current_pr.get("draft")):
                terminal_status = self._terminal_pr_reason(current_pr)
                if terminal_status and not await self._handle_terminal_pr_commands(
                        queued_repo, pr_number, current_pr, terminal_status):
                    self._retry_priority_item(item, source, "terminal_command_notice")
                    cycle_ok = False
                    self._scan_failure_reasons.append(
                        f"terminal_command_notice:{queued_repo}#{pr_number}:retry",
                    )
                    continue
                failure_reason = terminal_status or ("pr_is_draft" if draft_pr else "pr_not_open")
                self._forget_machine_projection_refresh(queued_repo, pr_number)
                for observed_repo, observed_pr, observed_comment_id in list(
                        self._recent_command_records):
                    if observed_repo == queued_repo and observed_pr == pr_number:
                        self._finish_recent_command(
                            queued_repo, pr_number, observed_comment_id,
                            failure_reason=failure_reason, retryable=False,
                        )
                priority_attempted[queued_repo].remove(pr_number)
                while item in self._priority_pr_queue:
                    self._priority_pr_queue.remove(item)
                self._priority_pr_set.discard(item)
                self._priority_pr_enqueued_at.pop(item, None)
                self._priority_pr_sources.pop(item, None)
                self._clear_priority_baseline_retry(item)
                if self._github_backing_off():
                    cycle_ok = False
                    break
                continue
            if item not in self._priority_pr_queue:
                self._priority_pr_set.discard(item)
                self._priority_pr_enqueued_at.pop(item, None)
                self._priority_pr_sources.pop(item, None)
            baseline_only = (
                self._authorization_baseline_required(queued_repo, pr_number)
            )
            attempt_started = self._monotonic()
            self._current_scan_stage = "priority_pr_processing"
            self._current_scan_repo = queued_repo
            self._current_scan_pr = pr_number
            try:
                succeeded = await self._process_scheduled_pr(
                    queued_repo, pr_number, priority_path=True,
                )
                if not succeeded:
                    self._fail_recent_commands_for_pr(queued_repo, pr_number, "baseline_incomplete")
                    self._retry_priority_baseline(item, source)
                    self._record_pr_attempt(
                        queued_repo, pr_number, "baseline_retry",
                        self._monotonic() - attempt_started,
                    )
                    self._scan_failure_reasons.append(
                        f"baseline:{queued_repo}#{pr_number}:incomplete",
                    )
                    logger.info(
                        "watcher priority work finished repo=%s pr=%s trigger=%s result=baseline_incomplete command_wait_seconds=%s",
                        queued_repo, pr_number, trigger, command_wait,
                    )
                    self._log_machine_projection_refresh_result(
                        queued_repo, pr_number, "retry_baseline_incomplete",
                        complete=False,
                    )
                    cycle_ok = False
                    continue
                if pr_number not in priority_done[queued_repo]:
                    priority_done[queued_repo].append(pr_number)
                self._clear_priority_baseline_retry(item)
                self._clear_priority_item_retry(item)
                if (baseline_only
                        and pr_number in self._baseline_progress.get(queued_repo, set())):
                    if self._queue_priority_pr(item, "webhook"):
                        self._signal_wakeup()
                if queued_repo.endswith("phanthymotus-driver"):
                    self._last_driver_poll = datetime.now(timezone.utc).isoformat()
                self._record_pr_attempt(
                    queued_repo, pr_number, "webhook_priority_processed",
                    self._monotonic() - attempt_started,
                )
                logger.info(
                    "watcher priority work finished repo=%s pr=%s trigger=%s result=processed command_wait_seconds=%s",
                    queued_repo, pr_number, trigger, command_wait,
                )
                if item in self._machine_refresh_pr_versions:
                    if baseline_only:
                        self._log_machine_projection_refresh_result(
                            queued_repo, pr_number, "baseline_only", complete=False,
                        )
                    elif self._monotonic() < self._machine_refresh_retry_after.get(
                            item, 0.0,
                    ):
                        self._log_machine_projection_refresh_result(
                            queued_repo, pr_number, "refresh_backoff", complete=False,
                        )
                        self._queue_priority_pr(item, "machine")
                    elif source != "machine" and machine_items >= 2:
                        self._log_machine_projection_refresh_result(
                            queued_repo, pr_number, "refresh_quota_deferred",
                            complete=False,
                        )
                        self._queue_priority_pr(item, "machine")
                    else:
                        if source != "machine":
                            machine_items += 1
                        self._current_scan_stage = "machine_projection_refresh"
                        refresh_result = await self._refresh_machine_adaptation_for_pr(
                            queued_repo, pr_number,
                        )
                        if refresh_result == "refreshed":
                            self._log_machine_projection_refresh_result(
                                queued_repo, pr_number, "refreshed", complete=True,
                            )
                        elif refresh_result == "stale":
                            self._log_machine_projection_refresh_result(
                                queued_repo, pr_number, "stale", complete=False,
                            )
                            self._forget_machine_projection_refresh(
                                queued_repo, pr_number,
                            )
                        else:
                            self._log_machine_projection_refresh_result(
                                queued_repo, pr_number,
                                "refresh_incomplete", complete=False,
                            )
                            self._retry_machine_projection_refresh(
                                item, "machine_projection_refresh_incomplete",
                            )
                            cycle_ok = False
            except GitHubRateLimitError as exc:
                if (item in self._machine_refresh_pr_versions
                        and self._current_scan_stage == "machine_projection_refresh"):
                    self._retry_machine_projection_refresh(item, "github_rate_limited")
                else:
                    self._retry_priority_item(item, source, "github_rate_limited")
                    self._priority_pr_retry_after[item] = max(
                        self._priority_pr_retry_after.get(item, 0.0),
                        self._monotonic() + max(0.0, exc.retry_after_seconds),
                    )
                self._fail_recent_commands_for_pr(queued_repo, pr_number, "github_rate_limited")
                self._record_pr_attempt(
                    queued_repo, pr_number, "github_rate_limited",
                    self._monotonic() - attempt_started,
                )
                self._scan_failure_reasons.append(
                    f"priority:{queued_repo}#{pr_number}:rate_limited",
                )
                logger.warning("watcher rate limited during priority PR; retry_after=%.1f", exc.retry_after_seconds)
                self._log_machine_projection_refresh_result(
                    queued_repo, pr_number, "retry_rate_limited", complete=False,
                )
                cycle_ok = False
                break
            except Exception as exc:
                if (item in self._machine_refresh_pr_versions
                        and self._current_scan_stage == "machine_projection_refresh"):
                    self._retry_machine_projection_refresh(item, type(exc).__name__)
                else:
                    self._retry_priority_item(item, source, type(exc).__name__)
                self._fail_recent_commands_for_pr(queued_repo, pr_number, type(exc).__name__)
                self._record_pr_attempt(
                    queued_repo, pr_number, type(exc).__name__, self._monotonic() - attempt_started,
                )
                self._scan_failure_reasons.append(
                    f"priority:{queued_repo}#{pr_number}:{type(exc).__name__}",
                )
                logger.warning("watcher priority PR %s#%s failed: %s", queued_repo, pr_number, type(exc).__name__)
                self._log_machine_projection_refresh_result(
                    queued_repo, pr_number, "retry_error", complete=False,
                )
                cycle_ok = False
        return cycle_ok

    async def _poll_once(self) -> None:
        """Drain queued work, then run a bounded fair scan through the single writer."""
        if self.config.auth_valid is not True:
            self._invalidate_all_open_pr_listing_snapshots()
            return
        try:
            authorized_repos = self._authorized_watcher_repos()
        except (TypeError, ValueError, RuntimeError) as exc:
            self.config.auth_valid = False
            self._invalidate_all_open_pr_listing_snapshots()
            logger.warning(
                "watcher PR listing authorization snapshot invalid reason=%s",
                type(exc).__name__,
            )
            return
        self._sync_open_pr_listing_repos(authorized_repos)
        if not authorized_repos:
            return
        cycle_started = self._monotonic()
        self._current_scan_started = cycle_started
        self._current_scan_stage = "starting"
        self._current_scan_repo = None
        self._current_scan_pr = None
        self._scan_failure_reasons = []
        repos = list(dict.fromkeys(authorized_repos))
        if repos:
            repo_start = self._repo_poll_cursor % len(repos)
            repos = repos[repo_start:] + repos[:repo_start]
        self._schedule_open_pr_listing_refreshes(authorized_repos)
        priority_done: dict[str, list[int]] = {repo: [] for repo in repos}
        priority_attempted: dict[str, list[int]] = {repo: [] for repo in repos}
        recent_attempted: dict[str, list[int]] = {repo: [] for repo in repos}
        cycle_ok = True
        ordinary_prs_skipped = 0
        normal_prs_processed: dict[str, int] = {repo: 0 for repo in repos}
        for repo in repos:
            self._queue_machine_projection_refreshes(repo, max_items=2)

        # Discovery is read-only and runs independently; this remains the
        # single serial worker for every Lifecycle or evidence write.
        self._current_scan_stage = "priority_queue"
        cycle_ok = await self._drain_priority_prs(
            priority_done, priority_attempted, recent_attempted,
            allowed_sources={"webhook", "command", "recent", "machine", "initialization"},
            max_items=4,
        ) and cycle_ok
        # Ready-evidence hints are bounded and yield to priority work: they
        # only read persisted records and re-project when a link is missing.
        # At least one item is still attempted under a continuous priority
        # backlog so a ready attachment is never stranded indefinitely.
        # Evidence sync failures or rate limits must not taint cycle_ok or
        # block priority commands (/request_acceptance, approve, etc.).
        self._current_scan_stage = "evidence_sync"
        evidence_budget = 1 if self._priority_pr_queue else 2
        await self._drain_evidence_sync(max_items=evidence_budget)
        priority_generation_after_drain = self._priority_generation
        interrupted_for_new_priority = False

        def interrupt_ordinary_scan_for_new_priority() -> bool:
            nonlocal interrupted_for_new_priority
            if (self._priority_generation != priority_generation_after_drain
                    and self._priority_pr_queue):
                interrupted_for_new_priority = True
                self._signal_wakeup()
                return True
            return False

        if self._priority_pr_queue:
            # Keep one ordinary slot even under a continuous priority backlog.
            normal_pr_budget = 1
        else:
            # Bound normal work for the whole cycle, then distribute it over
            # the rotated repository order. A large first repo must not consume
            # every slot and starve later repositories.
            normal_pr_budget = 8
        normal_budget_by_repo = {repo: 0 for repo in repos}
        if repos and normal_pr_budget:
            per_repo, remainder = divmod(normal_pr_budget, len(repos))
            for index, repo in enumerate(repos):
                normal_budget_by_repo[repo] = per_repo + (1 if index < remainder else 0)
        if self.config.auth_valid is not True:
            cycle_ok = False
            self._scan_failure_reasons.append("authorization_gate_closed")

        # Full PR listings refresh independently in read-only tasks. The
        # writer only consumes a complete, recent snapshot and never waits for
        # an in-flight repository query.
        if self._github_backing_off():
            cycle_ok = False
            self._scan_failure_reasons.append("authenticated_github_backoff")
        else:
            for repo in repos:
                if interrupt_ordinary_scan_for_new_priority():
                    break
                if not self._open_pr_listing_repo_is_authorized(repo):
                    continue
                snapshot = self._usable_open_pr_snapshot(repo)
                if snapshot is None:
                    cycle_ok = False
                    self._scan_failure_reasons.append(
                        f"list_prs:{repo}:snapshot_unavailable",
                    )
                    continue
                repo_normal_budget = normal_budget_by_repo.get(repo, 0)
                authorization_generation = self._repo_baseline_cutoff_utc.get(repo)
                self._current_scan_stage = "scanning_open_pr_snapshot"
                self._current_scan_repo = repo
                prs = snapshot.get("prs")
                if not isinstance(prs, list):
                    cycle_ok = False
                    self._scan_failure_reasons.append(
                        f"list_prs:{repo}:snapshot_malformed",
                    )
                    continue

                valid_prs = []
                for pr in prs:
                    if not isinstance(pr, dict):
                        continue
                    try:
                        number = int(pr.get("number") or 0)
                    except (TypeError, ValueError):
                        continue
                    if (number > 0 and pr.get("state", "open") == "open"
                            and not pr.get("merged")):
                        valid_prs.append((number, pr))
                valid_prs.sort(key=lambda item: item[0])
                open_numbers = [number for number, _ in valid_prs]
                pr_by_number = {number: pr for number, pr in valid_prs}
                self._observe_machine_projection_change(repo, valid_prs)
                if repo_normal_budget <= 0:
                    continue
                # Restart recovery: seed a bounded set of recent open PRs so a
                # ready attachment persisted before the restart is reconciled
                # without waiting for a new commit or a manual status request.
                self._seed_evidence_sync_for_repo(repo, valid_prs)
                baseline_numbers = [
                    number for number, pr in valid_prs if pr.get("draft") is not True
                ]
                ordinary_scan_ready = {
                    number: self._ordinary_pr_scan_retry_ready(repo, pr)
                    for number, pr in valid_prs
                }
                active_pr_numbers = []
                unlabeled_pr_numbers = []
                new_initialization_prs = []
                draft_missing_label_numbers = []
                for number, pr in valid_prs:
                    labels_valid = self._pr_labels_are_valid(pr)
                    if not labels_valid:
                        continue
                    status_labels = self._pr_status_labels(pr)
                    if pr.get("draft") is True:
                        draft_key = (repo, number)
                        if status_labels:
                            self._draft_label_retry_after.pop(draft_key, None)
                            self._draft_label_attempts.pop(draft_key, None)
                        elif (ordinary_scan_ready.get(number, True)
                              and self._draft_label_retry_ready(repo, number)):
                            draft_missing_label_numbers.append(number)
                        continue
                    self._draft_label_retry_after.pop((repo, number), None)
                    self._draft_label_attempts.pop((repo, number), None)
                    if not status_labels:
                        unlabeled_pr_numbers.append(number)
                        if (ordinary_scan_ready.get(number, True)
                                and self._new_pr_initialization_retry_ready(repo, pr)):
                            new_initialization_prs.append(number)
                        continue
                    self._clear_new_pr_initialization_retry(repo, number)
                    terminal_runtime_due = self._terminal_runtime_scan_due(
                        repo, number, pr, status_labels,
                    )
                    if (ordinary_scan_ready.get(number, True)
                            and (status_labels.intersection(ACTIVE_PROJECTION_STATUS_LABELS)
                                 or terminal_runtime_due)):
                        active_pr_numbers.append(number)
                new_initialization_prs.sort(
                    key=lambda number: (
                        self._parse_comment_time(
                            pr_by_number[number].get("created_at"),
                        ).timestamp()
                        if self._parse_comment_time(
                            pr_by_number[number].get("created_at"),
                        ) is not None else float("-inf"),
                        number,
                    ),
                    reverse=True,
                )
                baseline_all = repo in self._pending_baseline_repos
                selected = list(priority_attempted.get(repo, []))
                priority_count = len(selected)
                remaining_normal = max(
                    0, repo_normal_budget - normal_prs_processed.get(repo, 0),
                )
                pr_work_budget = priority_count + remaining_normal
                fast_lane_size = 6
                selected_set = set(selected)
                selected_set.update(
                    queued_number for queued_repo, queued_number in self._priority_pr_queue
                    if queued_repo == repo
                )
                reserve_ordinary = 0 if remaining_normal == 1 else min(1, remaining_normal)
                active_selected = 0
                initialization_selected = 0
                draft_selected = 0
                skipped_numbers: set[int] = set()
                scan_start = self._pr_scan_cursor.get(repo, 0) % len(open_numbers) if open_numbers else 0
                ordinary = open_numbers[scan_start:] + open_numbers[:scan_start]
                cursor_after = {}
                lane_cursor_after: dict[int, tuple[dict[str, int], int]] = {}

                def select_rotating_lane(
                    candidates: list[int], cursor: dict[str, int],
                ) -> bool:
                    tentative_cursor = {repo: cursor.get(repo, 0)}
                    number = self._next_rotating_pr(
                        repo, candidates, tentative_cursor, selected_set,
                    )
                    if number is None:
                        return False
                    selected.append(number)
                    selected_set.add(number)
                    lane_cursor_after[number] = (
                        cursor, tentative_cursor.get(repo, cursor.get(repo, 0)),
                    )
                    return True

                lane_candidates = (
                    (0, active_pr_numbers, self._active_pr_cursor),
                    (1, new_initialization_prs, None),
                    (2, draft_missing_label_numbers, self._draft_pr_cursor),
                    (3, None, None),
                )
                lane_start = self._normal_pr_lane_cursor.get(repo, 0) % 4
                special_budget = (
                    1 if remaining_normal == 1
                    else max(0, remaining_normal - reserve_ordinary)
                )
                selected_special = 0
                for offset in range(4):
                    if selected_special >= special_budget:
                        break
                    lane, candidates, cursor = lane_candidates[(lane_start + offset) % 4]
                    if lane == 3:
                        number = None
                        for index, candidate in enumerate(ordinary):
                            if (candidate in selected_set or candidate in unlabeled_pr_numbers
                                    or candidate in active_pr_numbers
                                    or pr_by_number[candidate].get("draft") is True
                                    or not ordinary_scan_ready.get(candidate, True)):
                                continue
                            if self._ordinary_pr_cache_fresh(
                                    repo, candidate, pr_by_number[candidate], force=baseline_all):
                                skipped_numbers.add(candidate)
                                continue
                            number = candidate
                            cursor_after[number] = (scan_start + index + 1) % len(open_numbers)
                            break
                        if number is None:
                            continue
                        selected.append(number)
                        selected_set.add(number)
                    if lane == 3:
                        pass
                    elif lane == 1:
                        number = next((candidate for candidate in candidates
                                       if candidate not in selected_set), None)
                        if number is None:
                            continue
                        selected.append(number)
                        selected_set.add(number)
                        initialization_selected += 1
                    elif select_rotating_lane(candidates, cursor):
                        if lane == 0:
                            active_selected += 1
                        else:
                            draft_selected += 1
                    else:
                        if lane != 3:
                            continue
                    selected_special += 1
                    self._normal_pr_lane_cursor[repo] = ((lane + 1) % 4)
                # Rotate the fallback lane across ALL eligible open PRs, not a
                # recency-capped subset. A fixed top-N window re-selects the
                # same newest PRs every cycle and starves high-numbered PRs once
                # they fall outside it. Sweeping the whole pool keeps each cycle
                # bounded by ``recent_budget`` while guaranteeing every PR is
                # eventually visited. The cursor advances past the entries this
                # cycle actually examined, so nothing is skipped.
                recent_pool = sorted(
                    [(number, pr) for number, pr in valid_prs
                     if pr.get("draft") is not True
                     and number not in active_pr_numbers
                     and number not in unlabeled_pr_numbers],
                    # Newest first; equal timestamps fall back to ascending
                    # number so the rotation is deterministic.
                    key=lambda item: (str(item[1].get("updated_at") or ""), -item[0]),
                    reverse=True,
                )
                recent_budget = min(
                    fast_lane_size,
                    max(0, remaining_normal - reserve_ordinary
                        - active_selected - initialization_selected - draft_selected),
                )
                if recent_pool and recent_budget > 0:
                    recent_start = self._recent_pr_cursor.get(repo, 0) % len(recent_pool)
                    recent_order = recent_pool[recent_start:] + recent_pool[:recent_start]
                    recent_examined = 0
                    recent_cursor_after = {}
                    recent_selected = False
                    for number, pr in recent_order:
                        if len(selected) >= pr_work_budget or recent_budget <= 0:
                            break
                        if (number in selected_set
                                or not ordinary_scan_ready.get(number, True)):
                            continue
                        recent_examined += 1
                        if self._ordinary_pr_cache_fresh(repo, number, pr, force=baseline_all):
                            skipped_numbers.add(number)
                            continue
                        selected.append(number)
                        selected_set.add(number)
                        recent_budget -= 1
                        recent_cursor_after[number] = (
                            recent_start + recent_examined
                        ) % len(recent_pool)
                        recent_selected = True
                    if recent_examined and not recent_selected:
                        self._recent_pr_cursor[repo] = (
                            recent_start + recent_examined
                        ) % len(recent_pool)
                else:
                    recent_cursor_after = {}

                def advance_pr_cursors(pr_number: int) -> None:
                    if pr_number in cursor_after:
                        self._pr_scan_cursor[repo] = cursor_after[pr_number]
                    if pr_number in recent_cursor_after:
                        self._recent_pr_cursor[repo] = recent_cursor_after[pr_number]
                    lane_advance = lane_cursor_after.get(pr_number)
                    if lane_advance is not None:
                        cursor, next_index = lane_advance
                        cursor[repo] = next_index

                already_selected_normal = max(0, len(selected) - priority_count)
                ordinary_slots = max(0, remaining_normal - already_selected_normal)
                ordinary_cursor_after = scan_start
                scanned = 0
                if ordinary_slots:
                    for number in ordinary:
                        scanned += 1
                        ordinary_cursor_after = (scan_start + scanned) % len(open_numbers)
                        if number in selected_set or number in skipped_numbers:
                            continue
                        if (pr_by_number[number].get("draft") is True
                                or number in active_pr_numbers
                                or number in unlabeled_pr_numbers
                                or not ordinary_scan_ready.get(number, True)):
                            continue
                        if self._ordinary_pr_cache_fresh(
                                repo, number, pr_by_number[number], force=baseline_all):
                            skipped_numbers.add(number)
                            continue
                        selected.append(number)
                        selected_set.add(number)
                        cursor_after[number] = ordinary_cursor_after
                        if len(cursor_after) >= ordinary_slots:
                            break
                ordinary_prs_skipped += len(skipped_numbers)

                processed = []
                for number in selected[:pr_work_budget]:
                    snapshot_completed = snapshot.get("completed_monotonic")
                    snapshot_age = (
                        self._monotonic() - snapshot_completed
                        if isinstance(snapshot_completed, (int, float)) else float("inf")
                    )
                    current_snapshot = self._usable_open_pr_snapshot(repo)
                    if ((snapshot_age < 0.0
                         or snapshot_age > OPEN_PR_SNAPSHOT_MAX_AGE_SECONDS)
                            and current_snapshot is None):
                        cycle_ok = False
                        self._scan_failure_reasons.append(
                            f"list_prs:{repo}:snapshot_expired",
                        )
                        break
                    if (not self._open_pr_listing_repo_is_authorized(repo)
                            or self._repo_baseline_cutoff_utc.get(repo)
                            != authorization_generation):
                        cycle_ok = False
                        self._scan_failure_reasons.append(
                            f"authorization:{repo}:generation_changed",
                        )
                        break
                    if number in priority_attempted.get(repo, []):
                        if number in priority_done.get(repo, []):
                            processed.append(number)
                        continue
                    if interrupt_ordinary_scan_for_new_priority():
                        break
                    if not self._open_pr_listing_repo_is_authorized(repo):
                        cycle_ok = False
                        self._scan_failure_reasons.append(
                            f"authorization:{repo}:invalid_before_pr_read",
                        )
                        break
                    selected_pr = pr_by_number[number]
                    is_initialization = number in new_initialization_prs
                    processing_trigger = (
                        "new_unlabeled_pr_initialization"
                        if is_initialization else "ordinary_scan"
                    )
                    pending_comment_id, command_wait = self._pending_command_wait(
                        repo, number,
                    )
                    try:
                        current_pr = await self.proxy.get_pr(repo, number)
                    except GitHubError as exc:
                        if exc.status_code == 404:
                            processed.append(number)
                            self._clear_new_pr_initialization_retry(repo, number)
                            self._clear_ordinary_pr_scan_retry(repo, number)
                            self._fail_recent_commands_for_pr(
                                repo, number, "pr_not_found", retryable=False,
                            )
                            advance_pr_cursors(number)
                            logger.info(
                                "watcher ordinary PR skipped repo=%s pr=%s trigger=%s result=pr_invalid comment_id=%s command_wait_seconds=%s",
                                repo, number, processing_trigger,
                                pending_comment_id, command_wait,
                            )
                            continue
                        self._scan_failure_reasons.append(
                            f"pr_read:{repo}#{number}:http_{exc.status_code}",
                        )
                        if is_initialization:
                            self._retry_new_pr_initialization(
                                repo, number, selected_pr,
                                f"http_{exc.status_code}",
                            )
                        self._defer_ordinary_pr_scan(
                            repo, number, selected_pr, f"http_{exc.status_code}",
                            minimum_delay=(exc.retry_after_seconds
                                           if isinstance(exc, GitHubRateLimitError)
                                           else 0.0),
                        )
                        logger.warning(
                            "watcher ordinary PR revalidation failed repo=%s pr=%s trigger=%s result=retry reason=http_%s comment_id=%s command_wait_seconds=%s",
                            repo, number, processing_trigger, exc.status_code,
                            pending_comment_id, command_wait,
                        )
                        cycle_ok = False
                        if self._github_backing_off():
                            break
                        continue
                    except Exception as exc:
                        self._scan_failure_reasons.append(
                            f"pr_read:{repo}#{number}:{type(exc).__name__}",
                        )
                        if is_initialization:
                            self._retry_new_pr_initialization(
                                repo, number, selected_pr, type(exc).__name__,
                            )
                        self._defer_ordinary_pr_scan(
                            repo, number, selected_pr, type(exc).__name__,
                        )
                        logger.warning(
                            "watcher ordinary PR revalidation failed repo=%s pr=%s trigger=%s result=retry reason=%s comment_id=%s command_wait_seconds=%s",
                            repo, number, processing_trigger, type(exc).__name__,
                            pending_comment_id, command_wait,
                        )
                        cycle_ok = False
                        if self._github_backing_off():
                            break
                        continue
                    if (not self._open_pr_listing_repo_is_authorized(repo)
                            or self._repo_baseline_cutoff_utc.get(repo)
                            != authorization_generation):
                        cycle_ok = False
                        self._scan_failure_reasons.append(
                            f"authorization:{repo}:generation_changed_before_pr_processing",
                        )
                        break
                    if (not isinstance(current_pr, dict)
                            or type(current_pr.get("number")) is not int
                            or current_pr.get("number") != number
                            or current_pr.get("state") != "open"
                            or current_pr.get("merged")):
                        processed.append(number)
                        self._clear_new_pr_initialization_retry(repo, number)
                        self._clear_ordinary_pr_scan_retry(repo, number)
                        self._fail_recent_commands_for_pr(
                            repo, number, "pr_not_open", retryable=False,
                        )
                        advance_pr_cursors(number)
                        logger.info(
                            "watcher ordinary PR skipped repo=%s pr=%s trigger=%s result=pr_invalid comment_id=%s command_wait_seconds=%s",
                            repo, number, processing_trigger,
                            pending_comment_id, command_wait,
                        )
                        continue
                    selected_head = (
                        selected_pr.get("head", {}).get("sha")
                        if isinstance(selected_pr.get("head"), dict) else None
                    )
                    current_head = (
                        current_pr.get("head", {}).get("sha")
                        if isinstance(current_pr.get("head"), dict) else None
                    )
                    if (isinstance(selected_head, str) and selected_head
                            and isinstance(current_head, str) and current_head
                            and selected_head != current_head):
                        self._scan_failure_reasons.append(
                            f"pr_snapshot:{repo}#{number}:head_changed",
                        )
                        self._defer_ordinary_pr_scan(
                            repo, number, selected_pr, "head_changed",
                        )
                        logger.info(
                            "watcher ordinary PR deferred repo=%s pr=%s trigger=%s result=snapshot_expired comment_id=%s command_wait_seconds=%s",
                            repo, number, processing_trigger,
                            pending_comment_id, command_wait,
                        )
                        continue
                    normal_prs_processed[repo] = normal_prs_processed.get(repo, 0) + 1
                    attempt_started = self._monotonic()
                    self._current_scan_stage = "ordinary_pr_processing"
                    self._current_scan_repo = repo
                    self._current_scan_pr = number
                    initialization_retry_scheduled = False
                    initialization_snapshot_pr = current_pr
                    try:
                        if current_pr.get("draft") is True:
                            # Drafts share the single serial scan, but never
                            # enter baseline dispatch, reconciliation of review
                            # evidence, or command handling. Only the trusted
                            # status-label projection runs.
                            self._record_draft_label_attempt(repo, number)
                            await self.controller.reconcile_pr(repo, number)
                            self._log_draft_label_retry_state(repo, number)
                            self._fail_recent_commands_for_pr(
                                repo, number, "pr_is_draft", retryable=False,
                            )
                            processed.append(number)
                            if is_initialization:
                                self._clear_new_pr_initialization_retry(repo, number)
                            self._record_pr_attempt(
                                repo, number, "draft_status_projected",
                                self._monotonic() - attempt_started,
                            )
                            self._clear_ordinary_pr_scan_retry(repo, number)
                            logger.info(
                                "watcher ordinary PR finished repo=%s pr=%s trigger=draft_status_projection result=processed comment_id=%s command_wait_seconds=%s",
                                repo, number, pending_comment_id, command_wait,
                            )
                            advance_pr_cursors(number)
                            if self._github_backing_off():
                                cycle_ok = False
                                break
                            if interrupt_ordinary_scan_for_new_priority():
                                break
                            continue
                        if (self.config.auth_valid is not True
                                or repo not in self.config.active_repos
                                or repo not in self.config.github_repos
                                or self._repo_baseline_cutoff_utc.get(repo)
                                != authorization_generation):
                            cycle_ok = False
                            self._scan_failure_reasons.append(
                                f"authorization:{repo}:changed_before_pr_processing",
                            )
                            break
                        succeeded = await self._process_scheduled_pr(repo, number)
                        if succeeded and is_initialization:
                            projected_pr = await self.proxy.get_pr(repo, number)
                            if isinstance(projected_pr, dict):
                                initialization_snapshot_pr = projected_pr
                            if (not isinstance(projected_pr, dict)
                                    or projected_pr.get("state") != "open"
                                    or projected_pr.get("merged")
                                    or projected_pr.get("draft")
                                    or not self._pr_status_labels(projected_pr)):
                                succeeded = False
                                self._retry_new_pr_initialization(
                                    repo, number, initialization_snapshot_pr,
                                    "status_label_not_projected",
                                )
                                initialization_retry_scheduled = True
                        self._record_pr_attempt(
                            repo, number,
                            "fallback_processed" if succeeded else "baseline_retry",
                            self._monotonic() - attempt_started,
                        )
                        if not succeeded:
                            if is_initialization and not initialization_retry_scheduled:
                                self._retry_new_pr_initialization(
                                    repo, number, initialization_snapshot_pr,
                                    "baseline_incomplete",
                                )
                            cycle_ok = False
                            self._scan_failure_reasons.append(
                                f"baseline:{repo}#{number}:incomplete",
                            )
                            self._defer_ordinary_pr_scan(
                                repo, number, initialization_snapshot_pr,
                                "baseline_incomplete",
                            )
                            logger.info(
                                "watcher ordinary PR finished repo=%s pr=%s trigger=%s result=retry comment_id=%s command_wait_seconds=%s",
                                repo, number, processing_trigger,
                                pending_comment_id, command_wait,
                            )
                            if self._github_backing_off():
                                break
                            continue
                        processed.append(number)
                        self._clear_ordinary_pr_scan_retry(repo, number)
                        if is_initialization:
                            self._clear_new_pr_initialization_retry(repo, number)
                        advance_pr_cursors(number)
                        logger.info(
                            "watcher ordinary PR finished repo=%s pr=%s trigger=%s result=processed comment_id=%s command_wait_seconds=%s",
                            repo, number, processing_trigger,
                            pending_comment_id, command_wait,
                        )
                    except GitHubRateLimitError as exc:
                        if is_initialization:
                            self._retry_new_pr_initialization(
                                repo, number, initialization_snapshot_pr,
                                "github_rate_limited",
                            )
                        self._defer_ordinary_pr_scan(
                            repo, number, initialization_snapshot_pr,
                            "github_rate_limited",
                            minimum_delay=exc.retry_after_seconds,
                        )
                        logger.warning("watcher rate limited processing %s#%s; retry_after=%.1f", repo, number, exc.retry_after_seconds)
                        cycle_ok = False
                        self._scan_failure_reasons.append(
                            f"process:{repo}#{number}:rate_limited",
                        )
                        if self._github_backing_off():
                            break
                        continue
                    except Exception as exc:
                        if is_initialization:
                            self._retry_new_pr_initialization(
                                repo, number, initialization_snapshot_pr,
                                type(exc).__name__,
                            )
                        self._defer_ordinary_pr_scan(
                            repo, number, initialization_snapshot_pr,
                            type(exc).__name__,
                        )
                        self._record_pr_attempt(
                            repo, number, type(exc).__name__, self._monotonic() - attempt_started,
                        )
                        logger.warning("watcher process %s#%s failed: %s", repo, number, type(exc).__name__)
                        cycle_ok = False
                        self._scan_failure_reasons.append(
                            f"process:{repo}#{number}:{type(exc).__name__}",
                        )
                        if self._github_backing_off():
                            break
                        continue
                    if self._github_backing_off():
                        cycle_ok = False
                        break
                    if interrupt_ordinary_scan_for_new_priority():
                        break

                snapshot_still_current = (
                    self._open_pr_listing_repo_is_authorized(repo)
                    and self._repo_baseline_cutoff_utc.get(repo)
                    == authorization_generation
                    and self._usable_open_pr_snapshot(repo) is not None
                )
                if baseline_all and snapshot_still_current:
                    progress = self._baseline_progress.setdefault(repo, set())
                    if all(number in progress for number in baseline_numbers):
                        self._pending_baseline_repos.discard(repo)
                elif baseline_all:
                    cycle_ok = False
                    self._scan_failure_reasons.append(
                        f"baseline:{repo}:snapshot_or_authorization_expired",
                    )
                remaining = (
                    sum(number not in self._baseline_progress.get(repo, set()) for number in baseline_numbers)
                    if repo in self._pending_baseline_repos else 0
                )
                self._repo_backlog[repo] = {
                    "open_prs": len(open_numbers), "remaining_baselines": remaining,
                    "ordinary_prs_skipped": len(skipped_numbers),
                    "queued_prs": sum(1 for queued_repo, _ in self._priority_pr_queue if queued_repo == repo),
                    "oldest_queued_age_seconds": round(max((
                        self._monotonic() - self._priority_pr_enqueued_at.get((queued_repo, number), self._monotonic())
                        for queued_repo, number in self._priority_pr_queue if queued_repo == repo
                    ), default=0.0), 1),
                }
                if repo.endswith("phanthymotus-driver"):
                    self._last_driver_poll = datetime.now(timezone.utc).isoformat()
                logger.info(
                    "watcher poll %s selected_prs=%s priority_prs=%s processed_prs=%s ordinary_prs_skipped=%s remaining_baselines=%s scan_cursor=%s",
                    repo, selected[:pr_work_budget], priority_attempted.get(repo, []), processed,
                    len(skipped_numbers),
                    remaining, self._pr_scan_cursor.get(repo, 0),
                )
                if interrupted_for_new_priority:
                    break
        for repo in repos:
            if self._usable_open_pr_snapshot(repo) is None:
                cycle_ok = False
                reason = f"list_prs:{repo}:snapshot_unavailable"
                if reason not in self._scan_failure_reasons:
                    self._scan_failure_reasons.append(reason)
        if repos:
            self._repo_poll_cursor = (repo_start + 1) % len(repos)
        self._last_ordinary_pr_skips = ordinary_prs_skipped
        completed_at = datetime.now(timezone.utc).isoformat()
        cycle_duration = max(0.0, self._monotonic() - cycle_started)
        self._last_completed_scan_at = completed_at
        self._last_scan_duration = round(cycle_duration, 1)
        self._last_scan_failure_reasons = self._scan_failure_reasons[:10]
        self._last_scan_slow_reason = None
        if cycle_ok:
            self._last_successful_cycle = completed_at
        self._cycle_durations.append(cycle_duration)
        if cycle_duration > 60.0:
            reason = (self._scan_failure_reasons[-1] if self._scan_failure_reasons
                      else f"slow_stage:{self._current_scan_stage or 'unknown'}")
            self._last_scan_slow_reason = reason
            logger.warning(
                "watcher scan exceeded 60 seconds duration_seconds=%.1f stage=%s repo=%s pr=%s queued_age_seconds=%.1f reason=%s",
                cycle_duration, self._current_scan_stage, self._current_scan_repo,
                self._current_scan_pr,
                max((self._monotonic() - self._priority_pr_enqueued_at.get(item, self._monotonic())
                     for item in self._priority_pr_queue), default=0.0),
                reason,
            )
        self._current_scan_started = None
        self._current_scan_stage = None
        self._current_scan_repo = None
        self._current_scan_pr = None
        if (self.config.auth_valid is True and not self._github_backing_off()
                and any(
                    self._open_pr_listing_repo_is_authorized(repo)
                    and self._monotonic() >= self._priority_pr_retry_after.get(
                        (repo, pr_number), 0.0,
                    )
                    and (self._priority_pr_sources.get((repo, pr_number)) != "machine"
                         or self._monotonic() >= self._machine_refresh_retry_after.get(
                             (repo, pr_number), 0.0,
                         ))
                    and pr_number not in priority_attempted.get(repo, [])
                    for repo, pr_number in self._priority_pr_queue
                )):
            self._signal_wakeup()
        metrics = self.diagnostics()
        logger.info(
            "watcher metrics last_successful_cycle=%s last_completed_scan_at=%s scan_seconds=%s scan_failures=%s recent_discovery_at=%s last_driver_poll=%s backlog=%s queued=%s oldest_queued_age_seconds=%s cycle_seconds=%s cycle_avg_seconds=%s cycle_p95_seconds=%s pr_avg_seconds=%s pr_p95_seconds=%s pr442_last_attempt=%s github_api=%s webhook_enabled=%s",
            metrics["last_successful_cycle"], metrics["last_completed_scan_at"],
            metrics["last_scan_duration_seconds"], metrics["last_scan_failure_reasons"],
            metrics["last_recent_command_discovery_at"], metrics["last_driver_poll"],
            metrics["per_repo_backlog"], metrics["priority_queue_length"],
            metrics["oldest_queued_age_seconds"], metrics["cycle_duration_seconds"],
            metrics["cycle_duration_average_seconds"], metrics["cycle_duration_p95_seconds"],
            metrics["pr_duration_average_seconds"], metrics["pr_duration_p95_seconds"],
            metrics["pr_442_last_attempt"],
            metrics["github_api"], metrics["webhook_enabled"],
        )

    async def _baseline_pr(self, repo: str, pr_number: int) -> bool:
        """Baseline old commands without replaying historical business commands.

        Used on first observation AND when a repo is newly (re)activated by an
        authorization refresh or a Ready-for-Review event. Advance only
        through comments at or before the effective cutoff; later comments
        remain eligible for subsequent cycles after the cursor is persisted.

        For PRs that already have a baselined cursor (existing lifecycle state
        from a previous authorized period), preserve that cursor as a lower
        bound while advancing through eligible comments.
        """
        from .evidence_models import EvidenceError, round_id_for_state

        key = (repo, pr_number)
        authorization_cutoff = self._repo_baseline_cutoff_utc.get(repo)
        ready_cutoff = self._ready_for_review_at.get(key)
        if (authorization_cutoff is not None
                and (not isinstance(authorization_cutoff, datetime)
                     or authorization_cutoff.tzinfo is None
                     or authorization_cutoff.utcoffset() is None)):
            logger.warning("watcher baseline authorization cutoff invalid %s#%s", repo, pr_number)
            return False
        if repo in self._pending_baseline_repos and authorization_cutoff is None:
            logger.warning("watcher baseline authorization cutoff missing %s#%s", repo, pr_number)
            return False
        if (ready_cutoff is not None
                and (not isinstance(ready_cutoff, datetime)
                     or ready_cutoff.tzinfo is None or ready_cutoff.utcoffset() is None)):
            logger.warning("watcher ready baseline cutoff invalid %s#%s", repo, pr_number)
            return False
        cutoffs = [cutoff.astimezone(timezone.utc)
                   for cutoff in (authorization_cutoff, ready_cutoff)
                   if isinstance(cutoff, datetime)]
        effective_cutoff = max(cutoffs) if cutoffs else None

        def baseline_boundary_current() -> bool:
            if (not self.config.auth_valid or repo not in self.config.active_repos
                    or repo not in self.config.github_repos
                    or self._repo_baseline_cutoff_utc.get(repo) != authorization_cutoff):
                return False
            current_ready_cutoff = self._ready_for_review_at.get(key)
            if current_ready_cutoff is None:
                return True
            if (not isinstance(current_ready_cutoff, datetime)
                    or current_ready_cutoff.tzinfo is None
                    or current_ready_cutoff.utcoffset() is None):
                return False
            return (effective_cutoff is not None
                    and current_ready_cutoff <= effective_cutoff)

        try:
            initial_state = await self.proxy.read_hidden_state(repo, pr_number)
        except Exception as exc:
            logger.warning(
                "watcher baseline state read failed %s#%s error=%s",
                repo, pr_number, type(exc).__name__,
            )
            return False
        expected_state = initial_state

        baseline_id = 0
        post_cursor_reconcile = False
        if _needs_initial_comment_baseline(initial_state):
            # --- First-observation / baseline-incomplete path ---
            try:
                pr_info = await self.proxy.get_pr(repo, pr_number)
            except Exception as exc:
                logger.warning(
                    "watcher baseline PR read failed %s#%s error=%s",
                    repo, pr_number, type(exc).__name__,
                )
                return False
            if (not pr_info or pr_info.get("state") != "open"
                    or pr_info.get("merged") or pr_info.get("draft")):
                if initial_state is None:
                    await self.controller.reconcile_pr(
                        repo, pr_number, defer_machine_projection=True,
                    )
                return False

            # BEFORE reconcile: snapshot current comments.
            try:
                comments_before = await self.proxy.get_issue_comments(repo, pr_number)
            except Exception as e:
                logger.warning(
                    "watcher baseline snapshot-before %s#%s: %s \u2014 fail closed",
                    repo, pr_number, e,
                )
                return False
            if (not isinstance(comments_before, list)
                    or any(not isinstance(comment, dict) for comment in comments_before)):
                return False

            max_cid_before = 0
            for c in comments_before:
                cid = c.get("id")
                if isinstance(cid, int) and not isinstance(cid, bool) and cid > max_cid_before:
                    max_cid_before = cid

            # Reconcile (may create lifecycle hidden state).
            try:
                await self.controller.reconcile_pr(
                    repo, pr_number, defer_machine_projection=True,
                )
            except Exception as e:
                logger.warning(
                    "watcher reconcile %s#%s: %s \u2014 skip baseline this cycle",
                    repo, pr_number, e,
                )
                return False

            # After reconcile: fresh read state.
            state_after = await self.proxy.read_hidden_state(repo, pr_number)
            if state_after is None:
                return False
            expected_state = state_after

            # AFTER reconcile: second snapshot.
            try:
                comments_after = await self.proxy.get_issue_comments(repo, pr_number)
            except Exception as e:
                logger.warning(
                    "watcher baseline snapshot-after %s#%s: %s \u2014 fail closed",
                    repo, pr_number, e,
                )
                return False
            if (not isinstance(comments_after, list)
                    or any(not isinstance(comment, dict) for comment in comments_after)):
                return False

            old_cursor = 0
            if isinstance(initial_state, dict):
                old_cursor = initial_state.get("last_processed_comment_id", 0)
                if (not isinstance(old_cursor, int) or isinstance(old_cursor, bool)
                        or old_cursor < 0):
                    return False
            if effective_cutoff is None:
                logger.warning("watcher baseline cutoff missing %s#%s — fail closed", repo, pr_number)
                return False
            baseline_id = self._comment_cursor_through_cutoff(
                comments_before + comments_after, effective_cutoff,
                lower_bound=old_cursor,
            )
            if baseline_id is None:
                logger.warning(
                    "watcher baseline comment cutoff invalid %s#%s \u2014 fail closed",
                    repo, pr_number,
                )
                return False

            # Reconcile again only if a trusted Review Completion arrived after
            # the first snapshot (i.e. between reconcile and the second read).
            # Otherwise the lifecycle created above is already current and a
            # second reconcile would duplicate writes for no new evidence.
            post_cursor_reconcile = self._has_pending_review_completion(
                repo, pr_number, comments_after, max(old_cursor, max_cid_before),
            )
        else:
            # --- Existing baselined PR \u2014 reactivation cursor advance ---
            # The PR has a real cursor state. Advance cursor to max(old, observed)
            # without resetting business fields.
            try:
                pr_info = await self.proxy.get_pr(repo, pr_number)
            except Exception as exc:
                logger.warning(
                    "watcher baseline PR read failed %s#%s error=%s",
                    repo, pr_number, type(exc).__name__,
                )
                return False
            if (not pr_info or pr_info.get("state") != "open"
                    or pr_info.get("merged") or pr_info.get("draft")):
                if initial_state is None:
                    await self.controller.reconcile_pr(
                        repo, pr_number, defer_machine_projection=True,
                    )
                return False

            pr_head = ((pr_info.get("head") or {}).get("sha")
                       if isinstance(pr_info, dict) else None)
            if (not isinstance(pr_head, str)
                    or re.fullmatch(r"[0-9a-f]{40}", pr_head) is None):
                logger.warning("watcher baseline invalid PR HEAD %s#%s", repo, pr_number)
                return False
            if (self.config.auth_valid is not True
                    or repo not in self.config.active_repos
                    or repo not in self.config.github_repos):
                logger.warning("watcher baseline authorization rejected %s#%s", repo, pr_number)
                return False
            old_head = initial_state.get("head_sha")
            if old_head != pr_head:
                try:
                    old_round = round_id_for_state(initial_state)
                except (ValueError, TypeError):
                    return False
                logger.info(
                    "watcher baseline HEAD drift detected %s#%s old_head=%s new_head=%s",
                    repo, pr_number, old_head if isinstance(old_head, str) else "invalid", pr_head,
                )
                try:
                    before_reconcile = await self.proxy.read_hidden_state(repo, pr_number)
                    if before_reconcile != initial_state:
                        logger.warning("watcher baseline state replaced %s#%s", repo, pr_number)
                        return False
                    if not baseline_boundary_current():
                        logger.warning("watcher baseline authorization rejected %s#%s", repo, pr_number)
                        return False
                    await self.controller.reconcile_pr(
                        repo, pr_number, defer_machine_projection=True,
                    )
                    state_after = await self.proxy.read_hidden_state(repo, pr_number)
                    pr_after = await self.proxy.get_pr(repo, pr_number)
                except Exception as e:
                    logger.warning(
                        "watcher baseline reconcile failed %s#%s error=%s",
                        repo, pr_number, type(e).__name__,
                    )
                    return False
                archive = state_after.get("round_archive") if isinstance(state_after, dict) else None
                archive_keys = set(archive) if isinstance(archive, dict) else set()
                legacy_archive = archive_keys == {"round_id", "sha256", "comment_id", "url"}
                archive_valid = (
                    archive_keys in ({"round_id", "sha256"},
                                     {"round_id", "sha256", "comment_id", "url"})
                    and archive.get("round_id") == old_round
                    and isinstance(archive.get("sha256"), str)
                    and re.fullmatch(r"[0-9a-f]{64}", archive["sha256"]) is not None
                    and (not legacy_archive or (type(archive.get("comment_id")) is int
                         and archive["comment_id"] > 0
                         and isinstance(archive.get("url"), str)
                         and archive["url"].startswith("https://github.com/")))
                )
                old_cursor = initial_state.get("last_processed_comment_id")
                new_cursor = state_after.get("last_processed_comment_id") if isinstance(state_after, dict) else None
                if (not isinstance(state_after, dict) or not isinstance(pr_after, dict)
                        or pr_after.get("state") != "open" or pr_after.get("merged")
                        or pr_after.get("draft")
                        or (pr_after.get("head") or {}).get("sha") != pr_head
                        or state_after.get("head_sha") != pr_head
                        or state_after.get("status") != "review-required"
                        or state_after.get("review_evidence") != {}
                        or state_after.get("components") != []
                        or state_after.get("deployments") != []
                        or not archive_valid
                        or type(old_cursor) is not int or old_cursor < 0
                        or type(new_cursor) is not int or new_cursor < old_cursor
                        or state_after.get("command") != {
                            "comment_id": new_cursor, "kind": "",
                            "phase": "completed", "args": {},
                        }):
                    logger.warning("watcher baseline reconcile incomplete %s#%s", repo, pr_number)
                    return False
                if not baseline_boundary_current():
                    logger.warning("watcher baseline authorization rejected %s#%s", repo, pr_number)
                    return False
                expected_state = state_after
                pr_info = pr_after
                logger.info("watcher baseline reconcile completed %s#%s", repo, pr_number)

            try:
                comments = await self.proxy.get_issue_comments(repo, pr_number)
            except Exception as e:
                logger.warning(
                    "watcher baseline snapshot-before %s#%s: %s \u2014 fail closed",
                    repo, pr_number, e,
                )
                return False
            if (not isinstance(comments, list)
                    or any(not isinstance(comment, dict) for comment in comments)):
                return False

            old_cursor = initial_state.get("last_processed_comment_id", 0)
            if (not isinstance(old_cursor, int) or isinstance(old_cursor, bool)
                    or old_cursor < 0):
                return False
            if effective_cutoff is None:
                logger.warning("watcher baseline cutoff missing %s#%s — fail closed", repo, pr_number)
                return False
            try:
                ordered_comments = sorted(comments, key=lambda comment: comment["id"])
            except (KeyError, TypeError, ValueError):
                return False
            baseline_id = self._comment_cursor_through_cutoff(
                ordered_comments, effective_cutoff, lower_bound=old_cursor,
            )
            if baseline_id is None:
                logger.warning(
                    "watcher baseline comment cutoff invalid %s#%s \u2014 fail closed",
                    repo, pr_number,
                )
                return False

            # A restart/authorization baseline must not jump over unarchived
            # evidence from the active testing round. Recover only ordinary
            # comments newer than round_started_at; command comments remain
            # governed by the baseline and are never dispatched here.
            if expected_state.get("status") == "testing":
                head_sha = expected_state.get("head_sha")
                try:
                    round_id = round_id_for_state(expected_state)
                    round_started_at = expected_state.get("round_started_at")
                    round_started = datetime.fromisoformat(
                        str(round_started_at).replace("Z", "+00:00")
                    )
                    if (round_started.tzinfo is None
                            or not isinstance(head_sha, str)
                            or len(head_sha) != 40):
                        raise ValueError
                except (TypeError, ValueError):
                    logger.warning("watcher evidence baseline context invalid %s#%s", repo, pr_number)
                    return False
                pr_head = (pr_info.get("head") or {}).get("sha")
                if (pr_info.get("state") != "open" or pr_info.get("merged")
                        or pr_info.get("draft") or pr_head != head_sha):
                    return False
                evidence_service = getattr(self.controller, "evidence_service", None)
                for candidate in ordered_comments:
                    comment_id = candidate.get("id")
                    if comment_id <= old_cursor:
                        continue
                    if self._is_foreign_bot_comment(candidate):
                        continue
                    body = candidate.get("body", "")
                    if (not isinstance(body, str) or not body.strip()
                            or commands_mod.command_starts_line_any(body)
                            or commands_mod.detect_deployment_command_intent(body)
                            or _top_level_command(body, "authorize_evidence")
                            or _top_level_command(body, "submit_cos_evidence")):
                        continue
                    try:
                        created = datetime.fromisoformat(
                            str(candidate.get("created_at", "")).replace("Z", "+00:00")
                        )
                    except ValueError:
                        return False
                    if (created.tzinfo is None or created.utcoffset() is None):
                        return False
                    if created <= round_started:
                        continue
                    if evidence_service is None:
                        return False
                    try:
                        fresh_comment = await self.proxy.get_comment(repo, comment_id)
                    except Exception as e:
                        logger.warning(
                            "watcher evidence recovery comment %s#%s #%s: %s",
                            repo, pr_number, comment_id, type(e).__name__,
                        )
                        return False
                    if (not isinstance(fresh_comment, dict)
                            or fresh_comment.get("id") != comment_id):
                        return False
                    if self._is_foreign_bot_comment(fresh_comment):
                        continue
                    fresh_body = fresh_comment.get("body", "")
                    if (not isinstance(fresh_body, str) or not fresh_body.strip()
                            or commands_mod.command_starts_line_any(fresh_body)
                            or commands_mod.detect_deployment_command_intent(fresh_body)
                            or _top_level_command(fresh_body, "authorize_evidence")
                            or _top_level_command(fresh_body, "submit_cos_evidence")):
                        continue
                    try:
                        fresh_created = datetime.fromisoformat(
                            str(fresh_comment.get("created_at", "")).replace("Z", "+00:00")
                        )
                    except ValueError:
                        return False
                    if (fresh_created.tzinfo is None or fresh_created <= round_started
                            or fresh_comment.get("created_at") != candidate.get("created_at")):
                        return False
                    if (not self.config.auth_valid or repo not in self.config.active_repos
                            or repo not in self.config.github_repos):
                        return False
                    try:
                        current_pr = await self.proxy.get_pr(repo, pr_number)
                        current_state = await self.proxy.read_hidden_state(repo, pr_number)
                    except Exception as e:
                        logger.warning(
                            "watcher evidence recovery state %s#%s: %s",
                            repo, pr_number, type(e).__name__,
                        )
                        return False
                    if (not isinstance(current_pr, dict) or current_pr.get("state") != "open"
                            or current_pr.get("merged") or current_pr.get("draft")
                            or (current_pr.get("head") or {}).get("sha") != head_sha
                            or not isinstance(current_state, dict)
                            or current_state.get("status") != "testing"
                            or current_state.get("head_sha") != head_sha):
                        return False
                    try:
                        if round_id_for_state(current_state) != round_id:
                            return False
                    except ValueError:
                        return False
                    user = fresh_comment.get("user", {})
                    actor_id = user.get("id") if isinstance(user, dict) else None
                    actor_login = user.get("login") if isinstance(user, dict) else None
                    if (isinstance(actor_id, bool) or not str(actor_id or "").isdigit()
                            or not isinstance(actor_login, str) or not actor_login.strip()):
                        return False
                    try:
                        await evidence_service.handle_native_comment(
                            repo=repo, pr_number=pr_number, comment_id=comment_id,
                            actor_id=int(actor_id), actor_login=actor_login,
                            action="submit_evidence", arguments={}, automatic=True,
                        )
                    except EvidenceError as e:
                        if (e.status_code in {400, 403, 404, 410, 413}
                                and e.code not in {"app_access_revoked", "repository_not_authorized"}):
                            logger.info(
                                "watcher evidence recovery skipped %s#%s comment=%s reason=%s",
                                repo, pr_number, comment_id, e.code,
                            )
                            continue
                        logger.warning(
                            "watcher evidence recovery retry %s#%s comment=%s reason=%s",
                            repo, pr_number, comment_id, e.code,
                        )
                        return False
                    except Exception as e:
                        logger.warning(
                            "watcher evidence recovery retry %s#%s comment=%s error=%s",
                            repo, pr_number, comment_id, type(e).__name__,
                        )
                        return False
            # Reconcile a second time only when the baseline is about to consume
            # a trusted Review Completion the lifecycle has not reflected yet.
            # Cursor reference is the lifecycle cursor after the reconcile that
            # already ran (or the persisted cursor when no reconcile was needed),
            # so a same-HEAD baseline never re-reconciles or re-archives.
            if isinstance(expected_state, dict):
                reconcile_cursor = expected_state.get("last_processed_comment_id")
            else:
                reconcile_cursor = old_cursor
            post_cursor_reconcile = self._has_pending_review_completion(
                repo, pr_number, ordered_comments,
                reconcile_cursor if isinstance(reconcile_cursor, int) else old_cursor,
            )
        # Revalidate the PR, authorization generation, and lifecycle identity
        # after all reads/recovery work and immediately before cursor mutation.
        if (not self.config.auth_valid or repo not in self.config.active_repos
                or repo not in self.config.github_repos):
            return False
        try:
            latest_pr = await self.proxy.get_pr(repo, pr_number)
            latest_state = await self.proxy.read_hidden_state(repo, pr_number)
        except Exception as e:
            logger.warning("watcher baseline recheck %s#%s: %s — fail closed", repo, pr_number, type(e).__name__)
            return False
        expected_head = expected_state.get("head_sha") if isinstance(expected_state, dict) else None
        expected_status = expected_state.get("status") if isinstance(expected_state, dict) else None
        if (not isinstance(latest_pr, dict) or latest_pr.get("state") != "open"
                or latest_pr.get("merged") or latest_pr.get("draft")
                or (latest_pr.get("head") or {}).get("sha") != expected_head
                or not isinstance(expected_state, dict)
                or not isinstance(latest_state, dict)
                or latest_state.get("head_sha") != expected_head
                or latest_state.get("status") != expected_status
                or any(
                    latest_state.get(field) != expected_state.get(field)
                    for field in ("round_archive", "round_id", "command",
                                  "review_evidence", "components", "deployments",
                                  "last_processed_comment_id")
                )):
            return False
        if not baseline_boundary_current():
            logger.warning(
                "watcher baseline boundary changed %s#%s \u2014 fail closed",
                repo, pr_number,
            )
            return False

        # Persist baseline cursor (shared by both paths).
        try:
            persisted = await self.proxy.persist_cursor(repo, pr_number, baseline_id)
        except Exception as e:
            logger.warning(
                "watcher persist baseline %s#%s: %s \u2014 fail closed",
                repo, pr_number, e,
            )
            return False

        if not isinstance(persisted, dict):
            logger.warning(
                "watcher persist baseline %s#%s returned %s \u2014 fail closed",
                repo, pr_number, type(persisted).__name__,
            )
            return False
        persisted_cid = persisted.get("last_processed_comment_id")
        if not isinstance(persisted_cid, int) or isinstance(persisted_cid, bool):
            logger.warning(
                "watcher persist baseline %s#%s invalid cursor \u2014 fail closed",
                repo, pr_number,
            )
            return False
        if persisted_cid < baseline_id:
            logger.warning(
                "watcher persist baseline %s#%s cursor %s < requested %s \u2014 fail closed",
                repo, pr_number, persisted_cid, baseline_id,
            )
            return False
        logger.info(
            "watcher baseline persisted %s#%s cursor=%s previous_cursor=%s",
            repo, pr_number, persisted_cid,
            old_cursor if isinstance(old_cursor, int) else 0,
        )
        if not baseline_boundary_current():
            logger.warning(
                "watcher baseline boundary changed after cursor write %s#%s \u2014 retry required",
                repo, pr_number,
            )
            return False
        # Reconcile after the cursor only when a trusted Review Completion the
        # lifecycle has not yet reflected would otherwise be consumed silently.
        # A same-HEAD reactivation has nothing new, so it must not reconcile or
        # archive a second time.
        if post_cursor_reconcile:
            try:
                await self.controller.reconcile_pr(
                    repo, pr_number, defer_machine_projection=True,
                )
            except Exception as exc:
                # The cursor is already durable. Keep it intact and retry reconcile
                # on the next scan; never roll the cursor back to replay commands.
                logger.warning(
                    "watcher post-cursor baseline reconcile failed %s#%s cursor=%s error=%s",
                    repo, pr_number, persisted_cid, type(exc).__name__,
                )
                return False
        latest_ready_cutoff = self._ready_for_review_at.get(key)
        if (latest_ready_cutoff is not None and effective_cutoff is not None
                and latest_ready_cutoff <= effective_cutoff):
            self._ready_for_review_at.pop(key, None)
        return True

    async def _process_pr(
        self, repo: str, pr_number: int, *, yield_for_priority: bool = False,
    ) -> None:
        """Process commands for one PR.

        Reads hidden state, fetches comments, processes in ascending id order.
        Transient failures stop processing later commands in this PR for this cycle.

        After one recognized command is dispatched, stops processing that PR
        for the current poll cycle.

        First-observation safety: when no Deploy Approval hidden state exists
        yet, baseline the cursor to the maximum comment id observed so GitHub
        will not replay historical commands on a future restart.

        Baseline-incomplete recovery: when hidden state exists but still
        represents an un-consumed reconcile-initial state (cursor=0, empty
        command), the watcher re-runs the baseline cycle.  This prevents
        historical commands from being replayed after a transient
        persist_cursor failure.
        """
        from .evidence_models import EvidenceError

        initial_state = await self.proxy.read_hidden_state(repo, pr_number)

        if (
            _needs_initial_comment_baseline(initial_state)
            and pr_number not in self._baseline_progress.get(repo, set())
        ):
            if await self._baseline_pr(repo, pr_number):
                self._baseline_progress.setdefault(repo, set()).add(pr_number)
                await self._flush_pending_baseline_notices(repo, pr_number)
            return

        # Existing state PR — normal processing path.
        await self.controller.reconcile_pr(
            repo, pr_number, defer_machine_projection=True,
        )
        state = await self.proxy.read_hidden_state(repo, pr_number)
        if state is None:
            return
        cursor = state.get("last_processed_comment_id", 0)
        for (observed_repo, observed_pr, observed_comment_id), observed in list(
                self._recent_command_records.items()):
            if (observed_repo == repo and observed_pr == pr_number
                    and observed_comment_id <= cursor
                    and observed.get("status") not in {"handled", "already_processed"}):
                self._mark_recent_command_already_processed(
                    repo, pr_number, observed_comment_id,
                )

        # Fetch comments
        try:
            comments = await self.proxy.get_issue_comments(repo, pr_number)
        except GitHubStateProxyError as e:
            logger.warning("watcher get comments %s#%s: %s", repo, pr_number, e)
            self._fail_recent_commands_for_pr(repo, pr_number, type(e).__name__)
            return

        # Filter new comments, sort ascending
        new_comments = [
            c for c in comments
            if isinstance(c.get("id"), int) and not isinstance(c.get("id"), bool) and c["id"] > cursor
        ]
        new_comments.sort(key=lambda c: c["id"])
        persisted_command = state.get("command")
        persisted_comment_id = (
            persisted_command.get("comment_id")
            if isinstance(persisted_command, dict) else None
        )
        if (type(persisted_comment_id) is int
                and persisted_comment_id > 0
                and persisted_comment_id == cursor
                and persisted_command.get("phase") == "completed"):
            source_comment = next(
                (item for item in comments if isinstance(item, dict)
                 and item.get("id") == persisted_comment_id),
                None,
            )
            source_body = (
                source_comment.get("body") if isinstance(source_comment, dict) else ""
            )
            source_command = commands_mod.parse_command(
                source_body if isinstance(source_body, str) else "",
                comment_id=persisted_comment_id,
            )
            if source_command.is_command:
                final_result = await self._recover_final_command_reply_delivery(
                    repo, pr_number, persisted_comment_id,
                )
                if final_result is None:
                    return
                consumed = await self._consume_final_command_reply(
                    repo, pr_number, persisted_comment_id,
                )
                if not consumed:
                    return
        native_comment_budget = 3
        native_comments_processed = 0

        for c in new_comments:
            comment_id = c["id"]
            recent_command = self._recent_command_records.get(
                (repo, pr_number, comment_id),
            )
            if (yield_for_priority
                    and self._priority_work_waiting_for_other_pr(repo, pr_number)):
                logger.info(
                    "watcher yielded normal comment scan to queued priority repo=%s pr=%s cursor=%s",
                    repo, pr_number, comment_id,
                )
                return
            if (isinstance(recent_command, dict)
                    and str(recent_command.get("failure_reason", "")).startswith(
                        "dispatch_outcome_unknown")):
                # Recover only the source-bound final reply. The deployment
                # handler may already have sent its POST, so never dispatch it
                # again while the outcome or reply is uncertain.
                result = await self._recover_final_command_reply_delivery(
                    repo, pr_number, comment_id,
                )
                if result is not None:
                    await self._consume_final_command_reply(
                        repo, pr_number, comment_id,
                    )
                return
            if (isinstance(recent_command, dict)
                    and recent_command.get("failure_reason") == "cursor_persist_not_confirmed"
                    and recent_command.get("dispatch_completed_at")):
                if await self._read_final_command_result(
                        repo, pr_number, comment_id) is None:
                    return
                if await self._consume_comment_cursor(repo, pr_number, comment_id):
                    self._finish_recent_command(repo, pr_number, comment_id)
                    continue
                return
            if (isinstance(recent_command, dict)
                    and recent_command.get("failure_reason") in {
                        "comment_edited", "comment_edited_cursor_persist_not_confirmed",
                        "dispatch_comment_edited",
                        "dispatch_comment_edited_cursor_persist_not_confirmed",
                    }):
                consumed = await self._consume_comment_cursor(repo, pr_number, comment_id)
                self._finish_recent_command(
                    repo, pr_number, comment_id,
                    failure_reason=("comment_edited" if consumed
                                    else "comment_edited_cursor_persist_not_confirmed"),
                    retryable=not consumed,
                )
                if not consumed:
                    return
                continue
            if (isinstance(recent_command, dict)
                    and self._terminal_command_failure(
                        str(recent_command.get("failure_reason") or ""),
                    )):
                if not await self._consume_comment_cursor(repo, pr_number, comment_id):
                    return
                continue

            # Skip bot's own lifecycle comments — fresh-read body to avoid stale-body TOCTOU
            try:
                fresh_comment_obj = await self.proxy.get_comment(repo, comment_id)
            except Exception as e:
                logger.warning(
                    "watcher fresh-read comment %s#%s #%s failed reason=%s — skip this cycle",
                    repo, pr_number, comment_id, _github_failure_reason(e),
                )
                self._finish_recent_command(
                    repo, pr_number, comment_id,
                    failure_reason=_github_failure_reason(e),
                )
                return

            if fresh_comment_obj is None:
                # Comment was deleted between list and get — skip this cycle
                self._finish_recent_command(
                    repo, pr_number, comment_id,
                    failure_reason="comment_unavailable", retryable=False,
                )
                return

            if self._is_foreign_bot_comment(fresh_comment_obj):
                # Another GitHub App or bot may post text that resembles a
                # command. Its comment is ordinary history: never parse it as
                # an instruction and never treat its attachments as test
                # evidence. Only the configured App's own comments and a
                # trusted human author can drive this watcher. A trusted
                # review-completion comment is exempted inside the helper.
                if state.get("head_sha"):
                    state = await self.proxy.persist_cursor(
                        repo, pr_number, comment_id,
                    ) or state
                continue

            # Validate fresh comment ID matches candidate
            fresh_id = fresh_comment_obj.get("id")
            if not isinstance(fresh_id, int) or isinstance(fresh_id, bool) or fresh_id != comment_id:
                logger.warning(
                    "watcher fresh comment id %s (type=%s) != candidate %s — skip this cycle",
                    fresh_id, type(fresh_id).__name__, comment_id,
                )
                return

            fresh_body = fresh_comment_obj.get("body", "")
            if not isinstance(fresh_body, str) or not fresh_body.strip():
                if state.get("head_sha"):
                    state = await self.proxy.persist_cursor(
                        repo, pr_number, comment_id,
                    ) or state
                continue

            if self._is_trusted_review_completion(fresh_comment_obj):
                if not await self._consume_comment_cursor(repo, pr_number, comment_id):
                    return
                self._finish_recent_command(
                    repo, pr_number, comment_id,
                    failure_reason=None,
                    retryable=False,
                )
                continue

            if _top_level_command(fresh_body, "authorize_evidence"):
                # This comment proves browser identity; it is not test evidence.
                if not await self._consume_comment_cursor(repo, pr_number, comment_id):
                    return
                continue

            if _top_level_command(fresh_body, "submit_cos_evidence"):
                # Retire the former COS receipt command without treating its
                # payload as evidence or sending it to a second writer.
                if not await self._consume_comment_cursor(repo, pr_number, comment_id):
                    return
                continue

            cmd = commands_mod.parse_command(fresh_body, comment_id=comment_id)
            if not cmd.is_command:
                likely_intent = commands_mod.detect_deployment_command_intent(fresh_body)
                if likely_intent:
                    cmd.intent = likely_intent
                    cmd.raw = fresh_body

            if not cmd.is_command:
                if state.get("status") == "testing":
                    if native_comments_processed >= native_comment_budget:
                        return
                    if (not self.config.auth_valid or repo not in self.config.active_repos
                            or repo not in self.config.github_repos):
                        return
                    try:
                        pr_info = await self.proxy.get_pr(repo, pr_number)
                    except Exception as e:
                        logger.warning(
                            "watcher native evidence PR read %s#%s: %s",
                            repo, pr_number, type(e).__name__,
                        )
                        return
                    if (isinstance(pr_info, dict) and pr_info.get("state") == "open"
                            and not pr_info.get("merged") and not pr_info.get("draft")):
                        pr_head = (pr_info.get("head") or {}).get("sha")
                        if pr_head != state.get("head_sha"):
                            return
                        evidence_service = getattr(self.controller, "evidence_service", None)
                        if evidence_service is None:
                            logger.warning(
                                "watcher native evidence unavailable %s#%s comment=%s",
                                repo, pr_number, comment_id,
                            )
                            return
                        user = fresh_comment_obj.get("user", {})
                        actor_id = user.get("id") if isinstance(user, dict) else None
                        actor_login = user.get("login") if isinstance(user, dict) else None
                        if (isinstance(actor_id, bool)
                                or not str(actor_id or "").isdigit()
                                or not isinstance(actor_login, str) or not actor_login.strip()):
                            logger.info(
                                "watcher native evidence skipped %s#%s comment=%s reason=identity_missing",
                                repo, pr_number, comment_id,
                            )
                            if state.get("head_sha"):
                                await self._consume_comment_cursor(repo, pr_number, comment_id)
                            return
                        try:
                            await evidence_service.handle_native_comment(
                                repo=repo, pr_number=pr_number, comment_id=comment_id,
                                actor_id=int(actor_id), actor_login=actor_login,
                                action="submit_evidence", arguments={}, automatic=True,
                            )
                        except EvidenceError as e:
                            terminal_skip = (
                                e.status_code in {400, 401, 403, 404, 409, 410, 413}
                                and e.code not in {
                                    "attachment_retry_conflict", "comment_unavailable",
                                    "object_not_verified",
                                }
                            )
                            if terminal_skip:
                                logger.info(
                                    "watcher native evidence skipped %s#%s comment=%s reason=%s",
                                    repo, pr_number, comment_id, e.code,
                                )
                                await self._consume_comment_cursor(repo, pr_number, comment_id)
                                return
                            logger.warning(
                                "watcher native evidence retry %s#%s comment=%s reason=%s",
                                repo, pr_number, comment_id, e.code,
                            )
                            return
                        except Exception as e:
                            logger.warning(
                                "watcher native evidence retry %s#%s comment=%s error=%s",
                                repo, pr_number, comment_id, type(e).__name__,
                            )
                            return
                        await self._consume_comment_cursor(repo, pr_number, comment_id)
                        try:
                            state = await self.proxy.read_hidden_state(repo, pr_number)
                        except Exception:
                            return
                        cursor_after = (state.get("last_processed_comment_id", 0)
                                        if isinstance(state, dict) else 0)
                        if (not isinstance(cursor_after, int) or isinstance(cursor_after, bool)
                                or cursor_after < comment_id):
                            return
                        native_comments_processed += 1
                        continue
                # Non-command comment — use cursor-only persistence
                if state.get("head_sha"):
                    state = await self.proxy.persist_cursor(
                        repo, pr_number, comment_id,
                    ) or state
                continue

            # Keep the existing one-business-action-per-PR-cycle behavior:
            # comments after this cycle's recovered evidence wait for the next
            # poll before command dispatch.
            if native_comments_processed:
                return

            cutoff = self._repo_baseline_cutoff_utc.get(repo)
            created_at = fresh_comment_obj.get("created_at")
            if (not isinstance(cutoff, datetime) or cutoff.tzinfo is None
                    or not isinstance(created_at, str) or not created_at.strip()):
                self._finish_recent_command(
                    repo, pr_number, comment_id, failure_reason="comment_timestamp_unavailable",
                )
                logger.warning(
                    "watcher command timestamp unavailable %s#%s #%s — fail closed",
                    repo, pr_number, comment_id,
                )
                return
            try:
                created_utc = datetime.fromisoformat(
                    created_at.strip().replace("Z", "+00:00")
                )
            except ValueError:
                self._finish_recent_command(
                    repo, pr_number, comment_id, failure_reason="comment_timestamp_invalid",
                )
                return
            if created_utc.tzinfo is None or created_utc.utcoffset() is None:
                self._finish_recent_command(
                    repo, pr_number, comment_id, failure_reason="comment_timestamp_timezone_missing",
                )
                return
            if created_utc.astimezone(timezone.utc) <= cutoff.astimezone(timezone.utc):
                # A pre-generation command is never dispatched as a fresh
                # approval. It is not silently dropped either: register one
                # rejection notice for after the PR baseline completes, then
                # consume it as history so later commands can proceed.
                if commands_mod.parse_command(
                        fresh_body if isinstance(fresh_body, str) else ""
                ).is_command or commands_mod.detect_deployment_command_intent(
                        fresh_body if isinstance(fresh_body, str) else ""
                ):
                    observed_key = self._observe_recent_command(
                        repo, pr_number, fresh_comment_obj,
                        created_utc.astimezone(timezone.utc),
                    )
                    if observed_key is not None:
                        self._pending_baseline_notices[observed_key] = None
                        while (len(self._pending_baseline_notices)
                               > RECENT_COMMAND_NOTICE_MAX):
                            self._pending_baseline_notices.pop(
                                next(iter(self._pending_baseline_notices)))
                await self._consume_comment_cursor(repo, pr_number, comment_id)
                return
            self._observe_recent_command(
                repo, pr_number, fresh_comment_obj, created_utc.astimezone(timezone.utc),
            )
            updated_at = fresh_comment_obj.get("updated_at")
            if not isinstance(updated_at, str) or not updated_at.strip():
                self._finish_recent_command(
                    repo, pr_number, comment_id, failure_reason="comment_update_time_unavailable",
                )
                return
            try:
                updated_utc = datetime.fromisoformat(
                    updated_at.strip().replace("Z", "+00:00")
                )
            except ValueError:
                self._finish_recent_command(
                    repo, pr_number, comment_id, failure_reason="comment_update_time_invalid",
                )
                return
            if updated_utc.tzinfo is None or updated_utc.utcoffset() is None:
                self._finish_recent_command(
                    repo, pr_number, comment_id, failure_reason="comment_update_timezone_missing",
                )
                return
            if updated_utc.astimezone(timezone.utc) != created_utc.astimezone(timezone.utc):
                # GitHub edits retain created_at; an edited command is not a
                # newly authored approval and is terminally skipped.
                consumed = await self._consume_comment_cursor(repo, pr_number, comment_id)
                self._finish_recent_command(
                    repo, pr_number, comment_id,
                    failure_reason=("comment_edited" if consumed
                                    else "comment_edited_cursor_persist_not_confirmed"),
                    retryable=not consumed,
                )
                return

            queued_mono = self._priority_pr_enqueued_at.get((repo, pr_number))
            if isinstance(queued_mono, (int, float)):
                queued_elapsed = max(0.0, self._monotonic() - queued_mono)
                queued_at = datetime.fromtimestamp(
                    datetime.now(timezone.utc).timestamp() - queued_elapsed,
                    timezone.utc,
                ).isoformat()
                self._mark_recent_command_queued(
                    repo, pr_number, comment_id, queued_at=queued_at,
                )
            self._mark_recent_command_processing(repo, pr_number, comment_id)

            # Re-read both records at the dispatch boundary. The earlier list
            # and comment reads may be separated from execution by reconciliation
            # or evidence work, so they cannot serve as the final identity proof.
            try:
                dispatch_pr = await self.proxy.get_pr(repo, pr_number)
                dispatch_comment = await self.proxy.get_comment(repo, comment_id)
            except Exception as exc:
                self._finish_recent_command(
                    repo, pr_number, comment_id,
                    failure_reason=f"dispatch_identity_read_{_github_failure_reason(exc)}",
                )
                return
            if (not isinstance(dispatch_comment, dict)
                    or type(dispatch_comment.get("id")) is not int
                    or dispatch_comment.get("id") != comment_id):
                self._finish_recent_command(
                    repo, pr_number, comment_id,
                    failure_reason="dispatch_comment_id_mismatch",
                )
                return
            if self._recent_comment_pr_number(repo, dispatch_comment) != pr_number:
                self._finish_recent_command(
                    repo, pr_number, comment_id,
                    failure_reason="dispatch_comment_pr_mismatch",
                )
                return
            initial_user = fresh_comment_obj.get("user")
            dispatch_user = dispatch_comment.get("user")
            if (not isinstance(initial_user, dict) or not isinstance(dispatch_user, dict)
                    or type(initial_user.get("id")) is not int
                    or initial_user.get("id") <= 0
                    or not isinstance(initial_user.get("login"), str)
                    or not initial_user.get("login", "").strip()
                    or type(dispatch_user.get("id")) is not int
                    or dispatch_user.get("id") <= 0
                    or not isinstance(dispatch_user.get("login"), str)
                    or not dispatch_user.get("login", "").strip()
                    or dispatch_user.get("id") != initial_user.get("id")
                    or dispatch_user.get("login") != initial_user.get("login")):
                self._finish_recent_command(
                    repo, pr_number, comment_id,
                    failure_reason="dispatch_comment_author_mismatch",
                )
                return
            dispatch_created = self._parse_comment_time(
                dispatch_comment.get("created_at"),
            )
            dispatch_updated = self._parse_comment_time(
                dispatch_comment.get("updated_at"),
            )
            if dispatch_created is None or dispatch_updated is None:
                self._finish_recent_command(
                    repo, pr_number, comment_id,
                    failure_reason="dispatch_comment_timestamp_invalid",
                )
                return
            if (dispatch_created != created_utc.astimezone(timezone.utc)
                    or dispatch_updated != dispatch_created
                    or dispatch_comment.get("updated_at") != fresh_comment_obj.get("updated_at")):
                consumed = await self._consume_comment_cursor(repo, pr_number, comment_id)
                self._finish_recent_command(
                    repo, pr_number, comment_id,
                    failure_reason=("dispatch_comment_edited" if consumed
                                    else "dispatch_comment_edited_cursor_persist_not_confirmed"),
                    retryable=not consumed,
                )
                return
            if (dispatch_comment.get("body") != fresh_body
                    or dispatch_comment.get("created_at") != fresh_comment_obj.get("created_at")):
                consumed = await self._consume_comment_cursor(repo, pr_number, comment_id)
                self._finish_recent_command(
                    repo, pr_number, comment_id,
                    failure_reason=("dispatch_comment_edited" if consumed
                                    else "dispatch_comment_edited_cursor_persist_not_confirmed"),
                    retryable=not consumed,
                )
                return
            dispatch_head = (
                dispatch_pr.get("head", {}).get("sha")
                if isinstance(dispatch_pr, dict)
                and isinstance(dispatch_pr.get("head"), dict) else None
            )
            base = dispatch_pr.get("base") if isinstance(dispatch_pr, dict) else None
            base_repo = base.get("repo") if isinstance(base, dict) else None
            base_name = base_repo.get("full_name") if isinstance(base_repo, dict) else None
            if (not isinstance(dispatch_pr, dict)
                    or type(dispatch_pr.get("number")) is not int
                    or dispatch_pr.get("number") != pr_number
                    or not isinstance(base_name, str)
                    or base_name.casefold() != repo.casefold()
                    or not isinstance(dispatch_head, str)
                    or not re.fullmatch(r"[0-9a-f]{40}", dispatch_head)):
                # PR identity is unreadable, so no reply can be bound to it.
                self._finish_recent_command(
                    repo, pr_number, comment_id,
                    failure_reason="dispatch_pr_identity_or_head_mismatch",
                )
                return
            terminal_status = self._terminal_pr_reason(dispatch_pr)
            if terminal_status:
                # The dispatch-boundary identity check above proves the PR and
                # source comment. Report terminal PR state by comment_id, but
                # never send this command to the controller.
                posted = await self._post_terminal_status_rejection(
                    repo, pr_number, comment_id, cmd=cmd,
                    expected_status=terminal_status,
                    source_comment=dispatch_comment,
                )
                if not posted:
                    self._finish_recent_command(
                        repo, pr_number, comment_id,
                        failure_reason=f"terminal_notice_{terminal_status}_retry",
                    )
                    return
                consumed = await self._consume_comment_cursor(repo, pr_number, comment_id)
                self._finish_recent_command(
                    repo, pr_number, comment_id,
                    failure_reason=(terminal_status if consumed else
                                    f"{terminal_status}_cursor_persist_not_confirmed"),
                    retryable=not consumed,
                )
                return
            if dispatch_head != state.get("head_sha"):
                state_head = state.get("head_sha")
                if not isinstance(state_head, str) or not re.fullmatch(
                        r"[0-9a-f]{40}", state_head):
                    # Lifecycle HEAD is unreadable — treat like identity loss.
                    self._finish_recent_command(
                        repo, pr_number, comment_id,
                        failure_reason="dispatch_pr_identity_or_head_mismatch",
                    )
                    return
                # Do not advance the cursor until the bound rejection comment
                # has been confirmed. A failed post remains safely retryable.
                posted = await self._post_boundary_rejection(
                    repo, pr_number, comment_id,
                    cmd=cmd, reason="head_changed",
                )
                if not posted:
                    self._finish_recent_command(
                        repo, pr_number, comment_id,
                        failure_reason="dispatch_pr_head_changed_notice_not_confirmed",
                        retryable=True,
                    )
                    return
                consumed = await self._consume_comment_cursor(repo, pr_number, comment_id)
                self._finish_recent_command(
                    repo, pr_number, comment_id,
                    failure_reason=("dispatch_pr_head_changed" if consumed
                                    else "dispatch_pr_head_changed_cursor_persist_not_confirmed"),
                    retryable=not consumed,
                )
                return

            await self._refresh_repo_policy_if_due(repo)

            # TOCTOU recheck: the auth snapshot was validated at cycle start,
            # but awaits have run since. Fail closed if authorization was
            # revoked while we were reading GitHub state.
            if (not self.config.auth_valid or repo not in self.config.active_repos
                    or repo not in self.config.github_repos):
                self._finish_recent_command(
                    repo, pr_number, comment_id, failure_reason="authorization_changed",
                )
                logger.warning(
                    "watcher auth snapshot invalid before dispatch %s#%s \u2014 fail closed",
                    repo, pr_number,
                )
                return

            if getattr(cmd, "error", "") or getattr(cmd, "intent", "") or cmd.kind == "unknown":
                # Keep parser validation strict and report its stable code from
                # the watcher, where live PR and repository-policy context is
                # available. Reconfirm the source author before posting.
                try:
                    author_id, author_login = await self.proxy.comment_identity(
                        repo, comment_id,
                    )
                except Exception as exc:
                    self._finish_recent_command(
                        repo, pr_number, comment_id,
                        failure_reason=f"rejection_author_read_{_github_failure_reason(exc)}",
                    )
                    return
                user = dispatch_comment.get("user", {})
                if (not isinstance(user, dict)
                        or author_id != str(user.get("id") or "")
                        or author_login != user.get("login")):
                    self._finish_recent_command(
                        repo, pr_number, comment_id,
                        failure_reason="rejection_author_identity_mismatch",
                    )
                    return
                posted = await self._post_command_error_notice(
                    repo, pr_number, comment_id, cmd,
                    f"command-error-{_command_kind(cmd)}",
                )
                if posted is not True:
                    self._finish_recent_command(
                        repo, pr_number, comment_id,
                        failure_reason="rejection_notice_not_confirmed",
                        retryable=True,
                    )
                    return
                consumed = await self._consume_comment_cursor(repo, pr_number, comment_id)
                self._finish_recent_command(
                    repo, pr_number, comment_id,
                    failure_reason=(None if consumed else "cursor_persist_not_confirmed"),
                    retryable=not consumed,
                )
                return

            # Dispatch to controller — transient failure must NOT advance cursor
            try:
                begin_reply_tracking = getattr(
                    self.controller, "begin_command_reply_tracking", None,
                )
                if (callable(begin_reply_tracking)
                        and not asyncio.iscoroutinefunction(begin_reply_tracking)):
                    begin_reply_tracking(repo, pr_number, comment_id)
                self._mark_recent_command_dispatch_started(
                    repo, pr_number, comment_id,
                )
                await self.controller.on_command(
                    cmd, repo, pr_number, comment_id,
                )
                self._mark_recent_command_dispatch_completed(
                    repo, pr_number, comment_id,
                )
                take_reply_delivery = getattr(
                    self.controller, "take_command_reply_delivery", None,
                )
                if (callable(take_reply_delivery)
                        and not asyncio.iscoroutinefunction(take_reply_delivery)):
                    # This boolean is only delivery telemetry. It is not a
                    # source-bound final result and cannot advance the cursor.
                    take_reply_delivery(repo, pr_number, comment_id)
                result = await self._read_final_command_result(
                    repo, pr_number, comment_id,
                )
                if result is None:
                    result = await self._recover_final_command_reply_delivery(
                        repo, pr_number, comment_id,
                    )
                if result is not None:
                    await self._consume_final_command_reply(
                        repo, pr_number, comment_id,
                    )
                else:
                    # The command may already have performed a deployment POST.
                    # Preserve its source comment and suppress handler replay.
                    self._finish_recent_command(
                        repo, pr_number, comment_id,
                        failure_reason="dispatch_outcome_unknown_final_reply_not_confirmed",
                        retryable=True,
                    )
                return
            except DeployCommandError as e:
                logger.warning(
                    "command %s comment %s in %s#%s rejected error=%s",
                    cmd.kind, comment_id, repo, pr_number, type(e).__name__,
                )
                take_reply_delivery = getattr(
                    self.controller, "take_command_reply_delivery", None,
                )
                if (callable(take_reply_delivery)
                        and not asyncio.iscoroutinefunction(take_reply_delivery)):
                    take_reply_delivery(repo, pr_number, comment_id)
                result = await self._read_final_command_result(
                    repo, pr_number, comment_id,
                )
                if result is None:
                    await self._post_command_error_notice(
                        repo, pr_number, comment_id, cmd,
                        f"command-error-{_command_kind(cmd)}",
                    )
                    result = await self._read_final_command_result(
                        repo, pr_number, comment_id,
                    )
                if result is not None:
                    await self._consume_final_command_reply(
                        repo, pr_number, comment_id,
                    )
                else:
                    self._finish_recent_command(
                        repo, pr_number, comment_id,
                        failure_reason="dispatch_outcome_unknown_final_reply_not_confirmed",
                        retryable=True,
                    )
                return
            except Exception as e:
                exception_code = _exception_code(e)
                normalized_code = _stable_error_code(exception_code)
                if normalized_code in _REJECTION_CODES:
                    take_reply_delivery = getattr(
                        self.controller, "take_command_reply_delivery", None,
                    )
                    if (callable(take_reply_delivery)
                            and not asyncio.iscoroutinefunction(take_reply_delivery)):
                        take_reply_delivery(repo, pr_number, comment_id)
                    result = await self._read_final_command_result(
                        repo, pr_number, comment_id,
                    )
                    if result is None:
                        await self._post_command_error_notice(
                            repo, pr_number, comment_id, cmd,
                            f"command-error-{_command_kind(cmd)}",
                        )
                        result = await self._read_final_command_result(
                            repo, pr_number, comment_id,
                        )
                    if result is not None:
                        await self._consume_final_command_reply(
                            repo, pr_number, comment_id,
                        )
                    else:
                        self._finish_recent_command(
                            repo, pr_number, comment_id,
                            failure_reason="dispatch_outcome_unknown_final_reply_not_confirmed",
                            retryable=True,
                        )
                    return
                result = await self._recover_final_command_reply_delivery(
                    repo, pr_number, comment_id,
                )
                if result is not None:
                    await self._consume_final_command_reply(
                        repo, pr_number, comment_id,
                    )
                    return
                self._finish_recent_command(
                    repo, pr_number, comment_id,
                    failure_reason=(
                        "dispatch_outcome_unknown_"
                        + _github_failure_reason(e)
                        + "_final_reply_not_confirmed"
                    ),
                    retryable=True,
                )
                logger.error(
                    "command handler outcome unknown command=%s comment_id=%s repo=%s pr=%s error=%s; automatic replay suppressed",
                    cmd.kind, comment_id, repo, pr_number, _github_failure_reason(e),
                )
                return

    async def _consume_comment_cursor(self, repo: str, pr_number: int, comment_id: int) -> bool:
        """Advance and confirm the cursor without changing business lifecycle state."""
        if type(comment_id) is not int or comment_id <= 0:
            return False

        try:
            state = await self.proxy.read_hidden_state(repo, pr_number)
        except Exception as e:
            logger.warning(
                "watcher consume cursor read %s#%s failure_reason=%s",
                repo, pr_number, _github_failure_reason(e),
            )
            return False
        if not isinstance(state, dict):
            return False
        cursor = state.get("last_processed_comment_id")
        if type(cursor) is not int or cursor < 0:
            return False
        if cursor >= comment_id:
            return True
        try:
            persisted = await self.proxy.persist_cursor(repo, pr_number, comment_id)
        except Exception as e:
            logger.warning(
                "watcher consume cursor write %s#%s failure_reason=%s",
                repo, pr_number, _github_failure_reason(e),
            )
            return False
        if not isinstance(persisted, dict):
            return False
        persisted_cursor = persisted.get("last_processed_comment_id")
        return type(persisted_cursor) is int and persisted_cursor >= comment_id
