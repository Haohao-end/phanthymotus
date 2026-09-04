"""Client for the PR Review Agent's raw JSON API.

Independent from ``agents.pr_review``. Only reads the documented job data and
performs no mutation. Credentials are never echoed.
"""

from __future__ import annotations

import logging
import math
import re
from datetime import datetime, timezone
from typing import Any

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

_JOB_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def _normalize_job_timestamp(value: Any) -> float | None:
    """Return a non-negative finite Unix timestamp or None.

    Accepts numeric timestamps, numeric strings, and a narrow ISO-8601
    compatibility subset. All malformed values fail closed to None.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        ts = float(value)
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            ts = float(text)
        except ValueError:
            iso_text = text[:-1] + "+00:00" if text.endswith("Z") else text
            try:
                dt = datetime.fromisoformat(iso_text)
            except ValueError:
                return None
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            ts = dt.astimezone(timezone.utc).timestamp()
        except (TypeError, OverflowError):
            return None
    else:
        return None

    if not math.isfinite(ts) or ts < 0:
        return None
    return ts

class ReviewJobInfo:
    """Parsed view of one Review Agent job row (dict-like for read access)."""

    def __init__(self, raw: dict):
        self.raw = raw
        self.id = raw.get("id", "")
        self.repo = raw.get("repo", "")
        self.pr_number = int(raw.get("pr_number") or 0)
        self.head_sha = raw.get("head_sha", "") or raw.get("pr_head_sha", "") or ""
        self.build_ref_sha = raw.get("build_ref_sha", "") or ""
        self.merge_commit_sha = raw.get("merge_commit_sha", "") or ""
        self.merged_at = raw.get("merged_at", "") or ""
        self.status = raw.get("status", "") or ""
        self.findings = raw.get("findings", []) or []
        self.review_text = raw.get("review_text", "") or ""
        # ``options`` carry Review Agent job options. ``build_only`` must be an
        # explicit JSON boolean ``False`` to be deployable; anything else
        # (missing, null, string, number, True) fails the deploy gate.
        self._has_options = "options" in raw
        opts = raw.get("options")
        self.options = opts if isinstance(opts, dict) else None
        self.build_results = [
            BuildResultInfo(
                idx=int(b.get("idx") or 0),
                target=str(b.get("target") or ""),
                driver_path=str(b.get("driver_path") or ""),
                success=b.get("success") is True,  # strict: only JSON true counts
                image_tag=str(b.get("image_tag") or ""),
                container_name=str(b.get("container_name") or ""),
                variant=str(b.get("variant") or ""),
            )
            for b in (raw.get("build_results") or [])
        ]

    @property
    def build_only(self) -> bool | None:
        """The strict ``options.build_only`` value.

        Returns True/False only when ``options`` is a dict and ``build_only`` is
        an explicit JSON boolean; returns None on any missing/malformed value so
        the caller can fail closed.
        """
        if not self._has_options or self.options is None:
            return None
        if "build_only" not in self.options:
            return None
        val = self.options["build_only"]
        if type(val) is bool:
            return val
        return None

    def review_complete(self) -> bool:
        """True only when this job represents a real, reviewed run:
        ``review_done`` status, ``options.build_only is False`` (strict), and a
        non-empty string ``review_text`` (never inferred from Markdown content).
        """
        if self.status != "review_done":
            return False
        if self.build_only is not False:
            return False
        if not isinstance(self.review_text, str) or not self.review_text.strip():
            return False
        return True

    @property
    def job_id(self) -> str:
        return self.id

    @property
    def builds(self) -> list:
        return self.build_results

    @property
    def completed_at(self) -> float | None:
        """Return the latest compatible timestamp from the raw API response."""
        for key in ("completed_at", "updated_at", "created_at"):
            ts = _normalize_job_timestamp(self.raw.get(key))
            if ts is not None:
                return ts
        return None

    def __getitem__(self, key: str):
        return self.raw[key]


class BuildResultInfo:
    def __init__(self, **kw):
        self.idx = int(kw.get("idx") or 0)
        self.target = str(kw.get("target") or "")
        self.driver_path = str(kw.get("driver_path") or "")
        self.success = kw.get("success") is True
        self.image_tag = str(kw.get("image_tag") or "")
        self.container_name = str(kw.get("container_name") or "")
        self.variant = str(kw.get("variant") or "")

    def label(self) -> str:
        return self.driver_path or self.target


class ReviewAgentError(Exception):
    pass


class ReviewAgentClient:
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

    def base(self) -> str:
        return self.config.review_agent_base_url.rstrip("/")

    def _headers(self) -> dict:
        if self.config.review_agent_api_token:
            return {"Authorization": "Bearer " + self.config.review_agent_api_token}
        return {}

    async def _get_any(self, path: str, params: dict | None = None):
        url = f"{self.base()}{path}"
        require_http_policy(
            url, self.config, allow_private=self.config.allow_private_http,
            review_agent=True,
        )
        resp = await stream_request(
            self.http, "GET", url, self.config.max_response_bytes,
            headers=self._headers(), params=params, timeout=self.config.total_timeout)
        try:
            require_2xx(resp.status_code, f"Review Agent {path}")
        except SecurityError as e:
            raise ReviewAgentError(str(e)) from e
        resp = await enforce_body_size(resp, self.config.max_response_bytes)
        try:
            data = resp.json()
        except ValueError:
            raise ReviewAgentError("Review Agent returned non-JSON")
        if not isinstance(data, (dict, list)):
            raise ReviewAgentError("unexpected Review Agent payload")
        return data

    async def _get(self, path: str) -> dict:
        data = await self._get_any(path)
        if not isinstance(data, dict):
            raise ReviewAgentError("unexpected Review Agent payload")
        return data

    async def status(self) -> dict:
        return await self._get("/api/status")

    async def list_jobs(
        self,
        limit: int = 100,
        offset: int = 0,
        status: str = "",
        repo: str = "",
    ) -> list[dict]:
        """List Review Agent jobs with bounded pagination.

        Pass ``limit``/``offset`` for bounded scanning; ``status``/``repo`` are
        optional server-side filters when the Review Agent supports them. The
        response array (or ``jobs`` / ``items`` key) is validated fail-closed.
        """
        params = {"limit": limit, "offset": offset}
        if status:
            params["status"] = status
        if repo:
            params["repo"] = repo
        data = await self._get_any("/api/jobs", params=params)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("jobs", "items", "results"):
                val = data.get(key)
                if isinstance(val, list):
                    return val
        raise ReviewAgentError("unexpected Review Agent jobs payload")

    async def get_job(self, job_id: str) -> ReviewJobInfo:
        if not _JOB_ID_RE.fullmatch(job_id or ""):
            raise ReviewAgentError(
                f"job id {job_id!r} is not a bare single path segment"
            )
        data = await self._get(f"/api/jobs/{job_id}")
        return ReviewJobInfo(data)

    async def get_job_detail(self, job_id: str) -> dict | None:
        """Get the full raw job detail dict.

        Returns None if the job does not exist or cannot be parsed.
        """
        if not _JOB_ID_RE.fullmatch(job_id or ""):
            return None
        try:
            data = await self._get(f"/api/jobs/{job_id}")
            if isinstance(data, dict):
                return data
            return None
        except Exception:
            return None
