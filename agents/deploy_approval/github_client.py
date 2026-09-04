"""GitHub API client for comments, PR state and approver identity.

Only trusts the GitHub REST API after re-reading it (webhook payloads are used
solely as a hint; comment text and author are re-fetched). Team membership is
checked via the documented API when the approval source needs it.
"""

from __future__ import annotations

from dataclasses import dataclass

import logging

import httpx

from .config import Config
from .clients_common import (
    SecurityError,
    enforce_body_size,
    require_2xx,
    require_http_policy,
    stream_request,
)

logger = logging.getLogger(__name__)

@dataclass
class PrSnapshot:
    """A strict, fail-closed snapshot of a PR's deploy-relevant fields.

    ``state`` is exactly ``"open"`` or ``"closed"``. ``merged``/``merged_at``/
    ``merge_commit_sha``/``head_sha`` are only the GitHub-verified values.
    ``author_login``/``author_id`` are the PR author's GitHub identity from the
    SAME fetched PR (``user.login`` + immutable numeric ``user.id``) and are
    used as the auto-discovered candidate's requester identity (self-approval
    gate). When any field is missing, the wrong type, or the state is unknown,
    ``pr_state`` returns None so the caller fails closed (never a candidate).
    """
    state: str
    head_sha: str
    merged: bool
    merged_at: str
    merge_commit_sha: str
    author_login: str = ""
    author_id: str = ""


class GitHubError(Exception):
    pass


class GitHubClient:
    def __init__(self, config: Config, http: httpx.AsyncClient | None = None):
        self.config = config
        self.http = http or httpx.AsyncClient(
            timeout=httpx.Timeout(
                config.total_timeout,
                connect=config.connect_timeout,
                read=config.read_timeout,
                pool=config.connect_timeout,
            ),
            follow_redirects=False,
        )

    def _headers(self):
        if not self.config.github_token:
            raise GitHubError("GITHUB_TOKEN is not configured")
        return {
            "Authorization": "Bearer " + self.config.github_token,
            "Accept": "application/vnd.github+json",
        }

    def api(self, path: str) -> str:
        return self.config.github_api_url.rstrip("/") + "/" + path.lstrip("/")

    async def _read_json(self, resp: httpx.Response) -> dict:
        resp = await enforce_body_size(resp, self.config.max_response_bytes)
        data = resp.json()
        if not isinstance(data, dict):
            raise GitHubError("github returned a non-object payload")
        return data

    async def _read_json_list(self, resp: httpx.Response) -> list:
        resp = await enforce_body_size(resp, self.config.max_response_bytes)
        data = resp.json()
        if not isinstance(data, list):
            raise GitHubError("github returned a non-array payload")
        return data

    async def get_pr(self, repo: str, pr_number: int) -> dict:
        path = f"/repos/{repo}/pulls/{pr_number}"
        require_http_policy(
            self.api(path), self.config, allow_private=self.config.allow_private_http
        )
        resp = await stream_request(
            self.http, "GET", self.api(path), self.config.max_response_bytes,
            headers=self._headers(), timeout=self.config.total_timeout)
        try:
            require_2xx(resp.status_code, "github get PR")
        except SecurityError as e:
            raise GitHubError(str(e)) from e
        return await self._read_json(resp)

    async def get_issue_comments(self, repo: str, pr_number: int) -> list[dict]:
        """All comments in the PR main conversation, with a HARD bound.

        The aggregate is capped by an explicit maximum number of pages, an
        explicit maximum number of comments and a maximum accumulated JSON size
        (the raw response byte cap already applies per page). Beyond any cap the
        call is refused fail-closed (never an unlimited in-memory scan).
        """
        url = self.api(f"/repos/{repo}/issues/{pr_number}/comments")
        require_http_policy(
            url, self.config, allow_private=self.config.allow_private_http
        )
        comments: list[dict] = []
        page = 1
        max_pages = getattr(self.config, "github_comment_max_pages", 20)
        max_comments = getattr(self.config, "github_comment_max_comments", 500)
        max_bytes = getattr(self.config, "github_comment_max_bytes", 4 * 1024 * 1024)
        seen_bytes = 0
        while True:
            if page > max_pages:
                raise GitHubError(
                    f"github comment pagination exceeded {max_pages} pages "
                    f"for {repo}#{pr_number}"
                )
            resp = await stream_request(
                self.http, "GET", url, self.config.max_response_bytes,
                headers=self._headers(),
                params={"per_page": 100, "page": page}, timeout=self.config.total_timeout)
            try:
                require_2xx(resp.status_code, "github list comments")
            except SecurityError as e:
                raise GitHubError(str(e)) from e
            batch = await self._read_json_list(resp)
            import json as _json
            for c in batch:
                if len(comments) >= max_comments:
                    raise GitHubError(
                        f"github comment count exceeded {max_comments} for "
                        f"{repo}#{pr_number}"
                    )
                payload = _json.dumps(c, sort_keys=True).encode("utf-8")
                seen_bytes += len(payload)
                if seen_bytes > max_bytes:
                    raise GitHubError(
                        f"github comment aggregation exceeded {max_bytes} bytes "
                        f"for {repo}#{pr_number}"
                    )
                comments.append(c)
            if len(batch) < 100:
                break
            page += 1
        return comments

    async def list_open_prs(self, repo: str) -> list[dict]:
        """List all open PRs for a repo, newest-first, with page overlap dedupe."""
        seen: dict[int, dict] = {}
        page = 1
        while True:
            url = self.api(f"/repos/{repo}/pulls")
            require_http_policy(
                url, self.config,
                allow_private=self.config.allow_private_http
            )
            resp = await stream_request(
                self.http, "GET", url, self.config.max_response_bytes,
                headers=self._headers(),
                params={
                    "state": "open",
                    "sort": "updated",
                    "direction": "desc",
                    "per_page": 100,
                    "page": page,
                }, timeout=self.config.total_timeout)
            try:
                require_2xx(resp.status_code, "github list open PRs")
            except SecurityError as e:
                raise GitHubError(str(e)) from e
            batch = await self._read_json_list(resp)
            if not batch:
                break
            for pr in batch:
                if not isinstance(pr, dict):
                    continue
                num = pr.get("number")
                if isinstance(num, bool) or not isinstance(num, int) or num <= 0:
                    continue
                seen[num] = pr
            if len(batch) < 100:
                break
            page += 1

        def _sort_key(pr: dict):
            updated = pr.get("updated_at")
            if not isinstance(updated, str):
                updated = ""
            try:
                from datetime import datetime, timezone

                ts = datetime.fromisoformat(updated.replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                return (1, ts.timestamp(), updated)
            except (TypeError, ValueError):
                return (0, 0.0, updated)

        return sorted(seen.values(), key=_sort_key, reverse=True)

    async def get_comment(self, repo: str, comment_id: int) -> dict:
        url = self.api(f"/repos/{repo}/issues/comments/{comment_id}")
        require_http_policy(
            url, self.config, allow_private=self.config.allow_private_http
        )
        resp = await stream_request(
            self.http, "GET", url, self.config.max_response_bytes,
            headers=self._headers(), timeout=self.config.total_timeout)
        try:
            require_2xx(resp.status_code, "github get comment")
        except SecurityError as e:
            raise GitHubError(str(e)) from e
        return await self._read_json(resp)

    async def post_issue_comment(
        self, repo: str, pr_number: int, body: str
    ) -> dict:
        url = self.api(f"/repos/{repo}/issues/{pr_number}/comments")
        require_http_policy(
            url, self.config, allow_private=self.config.allow_private_http
        )
        resp = await stream_request(
            self.http, "POST", url, self.config.max_response_bytes,
            headers=self._headers(), json={"body": body}, timeout=self.config.total_timeout)
        try:
            require_2xx(resp.status_code, "github post comment")
        except SecurityError as e:
            raise GitHubError(str(e)) from e
        return await self._read_json(resp)

    async def update_comment(self, repo: str, comment_id: int, body: str):
        url = self.api(f"/repos/{repo}/issues/comments/{comment_id}")
        require_http_policy(
            url, self.config, allow_private=self.config.allow_private_http
        )
        headers = {**self._headers(), "Accept": "application/vnd.github+json"}
        resp = await stream_request(
            self.http, "PATCH", url, self.config.max_response_bytes,
            headers=headers, json={"body": body}, timeout=self.config.total_timeout)
        try:
            require_2xx(resp.status_code, "github update comment")
        except SecurityError as e:
            raise GitHubError(str(e)) from e

    async def get_pr_file_at_exact_head(
        self, repo: str, pr_number: int, head_sha: str, path: str
    ) -> bytes:
        """Read a file from the exact PR HEAD via the GitHub Contents API.

        Args:
            repo: Full repo name (e.g., "4paradigm/phanthymotus").
            pr_number: The PR number used for error messages.
            head_sha: The exact commit SHA to read from.
            path: Repo-relative file path (must be validated by caller).

        Returns:
            The raw file bytes.

        Raises:
            GitHubError: If the file cannot be read, or the HEAD does not match.
        """
        # First, verify the PR still has the expected head_sha
        pr = await self.get_pr(repo, pr_number)
        current_head = (pr.get("head") or {}).get("sha", "")
        if current_head != head_sha:
            raise GitHubError(
                f"PR head has changed: expected {head_sha[:7]}, got {current_head[:7]}"
            )
        # Get the head repo full_name (supports fork PRs)
        head_repo = (pr.get("head") or {}).get("repo") or {}
        head_full_name = head_repo.get("full_name", "") or repo
        # Read file from the exact head SHA
        url = self.api(
            f"/repos/{head_full_name}/contents/{path.lstrip('/')}"
            f"?ref={head_sha}"
        )
        require_http_policy(
            url, self.config, allow_private=self.config.allow_private_http
        )
        resp = await stream_request(
            self.http, "GET", url, self.config.max_response_bytes,
            headers=self._headers(), timeout=self.config.total_timeout)
        try:
            require_2xx(resp.status_code, "github get file contents")
        except SecurityError as e:
            raise GitHubError(str(e)) from e
        data = await self._read_json(resp)
        content_type = data.get("type", "")
        if content_type != "file":
            raise GitHubError(
                f"Path {path!r} is a {content_type}, not a file"
            )
        encoded = data.get("content", "")
        encoding = data.get("encoding", "")
        import base64
        if encoding == "base64":
            try:
                return base64.b64decode(encoded)
            except Exception as e:
                raise GitHubError(f"File content decode failed: {e}")
        elif encoding == "none" or encoding == "":
            return encoded.encode("utf-8")
        else:
            raise GitHubError(f"Unsupported file encoding: {encoding}")

    async def get_issue_labels(self, repo: str, issue_number: int) -> list[str]:
        """Get the current labels for an issue/PR."""
        url = self.api(f"/repos/{repo}/issues/{issue_number}/labels")
        require_http_policy(
            url, self.config, allow_private=self.config.allow_private_http
        )
        resp = await stream_request(
            self.http, "GET", url, self.config.max_response_bytes,
            headers=self._headers(), timeout=self.config.total_timeout)
        try:
            require_2xx(resp.status_code, "github get labels")
        except SecurityError as e:
            raise GitHubError(str(e)) from e
        data = await self._read_json_list(resp)
        return [l.get("name", "") for l in data if isinstance(l, dict) and l.get("name")]

    async def set_issue_labels(self, repo: str, issue_number: int,
                                labels: list[str]) -> None:
        """Replace all labels on an issue/PR.

        Preserves non-status:* labels by only managing status:* labels.
        Caller should pass the full desired label set.
        """
        if not labels:
            labels = []
        url = self.api(f"/repos/{repo}/issues/{issue_number}/labels")
        require_http_policy(
            url, self.config, allow_private=self.config.allow_private_http
        )
        headers = {**self._headers(), "Accept": "application/vnd.github+json"}
        resp = await stream_request(
            self.http, "PUT", url, self.config.max_response_bytes,
            headers=headers, json={"labels": labels},
            timeout=self.config.total_timeout)
        try:
            require_2xx(resp.status_code, "github set labels")
        except SecurityError as e:
            raise GitHubError(str(e)) from e

    async def add_issue_label(self, repo: str, issue_number: int,
                               label: str) -> None:
        """Add a single label to an issue/PR."""
        url = self.api(f"/repos/{repo}/issues/{issue_number}/labels")
        require_http_policy(
            url, self.config, allow_private=self.config.allow_private_http
        )
        headers = {**self._headers(), "Accept": "application/vnd.github+json"}
        resp = await stream_request(
            self.http, "POST", url, self.config.max_response_bytes,
            headers=headers, json={"labels": [label]},
            timeout=self.config.total_timeout)
        try:
            require_2xx(resp.status_code, "github add label")
        except SecurityError as e:
            raise GitHubError(str(e)) from e

    async def remove_issue_label(self, repo: str, issue_number: int,
                                  label: str) -> None:
        """Remove a single label from an issue/PR."""
        url = self.api(f"/repos/{repo}/issues/{issue_number}/labels/{label}")
        require_http_policy(
            url, self.config, allow_private=self.config.allow_private_http
        )
        headers = {**self._headers(), "Accept": "application/vnd.github+json"}
        resp = await stream_request(
            self.http, "DELETE", url, self.config.max_response_bytes,
            headers=headers, timeout=self.config.total_timeout)
        # 404 is ok (label already doesn't exist)
        if resp.status_code not in (200, 204, 404):
            try:
                require_2xx(resp.status_code, "github remove label")
            except SecurityError as e:
                raise GitHubError(str(e)) from e

    async def pr_merged(self, repo: str, pr_number: int) -> tuple[bool, str, str]:
        """Return (merged, merged_at, merge_commit_sha)."""
        pr = await self.get_pr(repo, pr_number)
        merged = pr.get("merged") is True  # strict: only JSON true counts
        return merged, str(pr.get("merged_at") or ""), str(pr.get("merge_commit_sha") or "")

    async def pr_head_sha(self, repo: str, pr_number: int) -> str:
        pr = await self.get_pr(repo, pr_number)
        return str((pr.get("head") or {}).get("sha") or "")
    async def pr_state(self, repo: str, pr_number: int) -> PrSnapshot | None:
        """Strict, fail-closed snapshot of a PR for candidate creation.

        Returns None when the PR cannot be read, the state is unknown, or any
        deploy-relevant field is missing / the wrong type (bool/int confusion,
        null). ``merged`` must be an explicit JSON boolean; ``head_sha`` must be
        a non-empty string; a closed+merged PR must also carry ``merged_at`` and
        ``merge_commit_sha``.
        """
        pr = await self.get_pr(repo, pr_number)
        state = pr.get("state")
        if not isinstance(state, str) or state not in ("open", "closed"):
            return None
        head = pr.get("head")
        if not isinstance(head, dict):
            return None
        head_sha = head.get("sha")
        if not isinstance(head_sha, str) or not head_sha:
            return None
        merged = pr.get("merged")
        if type(merged) is not bool:
            return None
        merged_at = pr.get("merged_at")
        merge_commit_sha = pr.get("merge_commit_sha")
        if not isinstance(merged_at, str):
            merged_at = ""
        if not isinstance(merge_commit_sha, str):
            merge_commit_sha = ""
        if state == "closed" and merged:
            if not merged_at or not merge_commit_sha:
                # Closed+merged but without merge identity -> fail closed.
                return None
        user = pr.get("user")
        author_login = ""
        author_id = ""
        if isinstance(user, dict):
            login = user.get("login")
            uid = user.get("id")
            if isinstance(login, str) and login.strip():
                author_login = login.strip()
            if isinstance(uid, int) and not isinstance(uid, bool) and uid:
                author_id = str(uid)
        if not author_login or not author_id:
            # The PR author identity is required for the auto-candidate's
            # requester (self-approval gate). Fail closed when missing.
            return None
        return PrSnapshot(
            state=state,
            head_sha=head_sha,
            merged=merged,
            merged_at=merged_at,
            merge_commit_sha=merge_commit_sha,
            author_login=author_login,
            author_id=author_id,
        )


    async def collaborator_permission(self, repo: str, username: str) -> str:
        """Return the collaborator permission for ``username`` in ``repo``.

        Only the REST API is authoritative (``GET /repos/{repo}/collaborators/{user}``).
        Returns the raw permission string, which the caller maps to a decision
        (write/maintain/admin pass; read/triage/none fail). Any API error, 404,
        non-2xx, or schema/type failure fails closed (returns an empty string).
        """
        url = self.api(f"/repos/{repo}/collaborators/{username}")
        require_http_policy(
            url, self.config, allow_private=self.config.allow_private_http
        )
        resp = None
        try:
            resp = await stream_request(
                self.http, "GET", url, self.config.max_response_bytes,
                headers=self._headers(), timeout=self.config.total_timeout)
        except httpx.HTTPError as e:
            logger.warning("collaborator permission check failed: %s", e)
            return ""
        except SecurityError as e:
            logger.warning("collaborator permission check blocked: %s", e)
            return ""
        if resp.status_code in (401, 403, 404):
            return ""
        try:
            require_2xx(resp.status_code, "github collaborator permission")
        except SecurityError as e:
            logger.warning("collaborator permission HTTP %s: %s", resp.status_code, e)
            return ""
        data = await self._read_json(resp)
        perm = data.get("permission")
        if not isinstance(perm, str) or not perm:
            return ""
        return perm

    async def user_in_team(self, team: str, username: str) -> bool:
        """Live GitHub team membership check (always authoritative, fail-closed).

        ``team`` is ``org/slug``. The endpoint is
        ``GET /orgs/{org}/teams/{slug}/memberships/{username}``; only an
        explicit 200 with ``state == "active"`` passes. Any API error, 404,
        non-2xx, malformed payload or unknown/absent team returns False.
        """
        team = (team or "").strip().strip("/")
        username = (username or "").strip()
        if "/" not in team or not username:
            return False
        org, _, slug = team.partition("/")
        if not org or not slug:
            return False
        url = self.api(
            f"/orgs/{org}/teams/{slug}/memberships/{username}"
        )
        require_http_policy(
            url, self.config, allow_private=self.config.allow_private_http
        )
        try:
            resp = await stream_request(
                self.http, "GET", url, self.config.max_response_bytes,
                headers=self._headers(), timeout=self.config.total_timeout,
            )
        except (httpx.HTTPError, SecurityError) as e:
            logger.warning("team membership check failed for %s: %s", team, e)
            return False
        if resp.status_code in (401, 403, 404):
            return False
        try:
            require_2xx(resp.status_code, "github team membership")
        except SecurityError as e:
            logger.warning("team membership HTTP %s: %s", resp.status_code, e)
            return False
        data = await self._read_json(resp)
        return data.get("state") == "active"

    async def get_current_user(self) -> dict:
        """Fetch the authenticated user's GitHub identity.

        GET /user. Returns a dict with ``id`` (int) and ``login`` (str).
        Raises GitHubError on failure.
        """
        url = self.api("/user")
        require_http_policy(
            url, self.config, allow_private=self.config.allow_private_http
        )
        resp = await stream_request(
            self.http, "GET", url, self.config.max_response_bytes,
            headers=self._headers(), timeout=self.config.total_timeout,
        )
        try:
            require_2xx(resp.status_code, "github current user")
        except SecurityError as e:
            raise GitHubError(str(e)) from e
        return await self._read_json(resp)

    async def list_repository_labels(self, repo: str) -> list[dict]:
        """List all labels in a repository with bounded pagination."""
        url = self.api(f"/repos/{repo}/labels")
        require_http_policy(
            url, self.config, allow_private=self.config.allow_private_http
        )
        labels: list[dict] = []
        max_pages = 20
        for page in range(1, max_pages + 1):
            resp = await stream_request(
                self.http, "GET", url, self.config.max_response_bytes,
                headers=self._headers(),
                params={"per_page": 100, "page": page},
                timeout=self.config.total_timeout,
            )
            try:
                require_2xx(resp.status_code, "github list repository labels")
            except SecurityError as e:
                raise GitHubError(str(e)) from e
            batch = await self._read_json_list(resp)
            for item in batch:
                if not isinstance(item, dict):
                    raise GitHubError("github returned a malformed label record")
                labels.append(item)
            if len(batch) < 100:
                return labels
        raise GitHubError(
            f"github label pagination exceeded {max_pages} pages for {repo}"
        )

    async def create_repository_label(
        self, repo: str, name: str, color: str, description: str,
    ) -> dict:
        """Create a repository label using the authenticated GitHub token."""
        url = self.api(f"/repos/{repo}/labels")
        require_http_policy(
            url, self.config, allow_private=self.config.allow_private_http
        )
        resp = await stream_request(
            self.http, "POST", url, self.config.max_response_bytes,
            headers=self._headers(),
            json={"name": name, "color": color, "description": description},
            timeout=self.config.total_timeout,
        )
        try:
            require_2xx(resp.status_code, "github create repository label")
        except SecurityError as e:
            raise GitHubError(str(e)) from e
        return await self._read_json(resp)

    async def comment_identity(self, repo: str, comment_id: int) -> tuple[str, str]:
        """Re-read a comment from GitHub and return its immutable author
        ``(user_id, login)``.

        The Webhook payload's login/id is never trusted: the comment is re-fetched
        by id so a spoofed event body cannot forge the approver. Returns empty
        strings when the comment cannot be read or the user object is malformed.
        """
        try:
            c = await self.get_comment(repo, comment_id)
        except (GitHubError, httpx.HTTPError) as e:
            logger.warning("re-read comment %s failed: %s", comment_id, e)
            return "", ""
        user = c.get("user")
        if not isinstance(user, dict):
            return "", ""
        uid = user.get("id")
        login = user.get("login")
        if not isinstance(uid, int) or uid is None:
            return "", ""
        return str(uid), str(login or "")
