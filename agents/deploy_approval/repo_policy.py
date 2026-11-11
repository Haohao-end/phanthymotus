"""Repository-scoped policy snapshots sourced from main or an allowed fallback."""

from __future__ import annotations

import asyncio
import copy
import errno
import hashlib
import logging
import os
import re
import stat
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from .config import MAX_REPO_POLICY_FILE_BYTES, validate_repository_names
from .models import MachineInfo

logger = logging.getLogger(__name__)

POLICY_REFRESH_SECONDS = 30 * 60
_POLICY_FILES = ("machines.yaml", "test_reviewers.yaml")
_POLICY_REPOSITORY_ALIASES = {
    "4paradigm/phanthymotus": "4paradigm/phanthymotus",
    "4paradigm/phanthymotus-driver": "4paradigm/phanthymotus-driver",
    # PRs are watched in the deployment service's user-owned forks. These
    # aliases select only the corresponding official policy source below.
    "haohao-end/phanthymotus": "4paradigm/phanthymotus",
    "haohao-end/phanthymotus-driver": "4paradigm/phanthymotus-driver",
}
_LOCAL_POLICY_DIRECTORY_BY_REPO = {
    "4paradigm/phanthymotus": "core",
    "4paradigm/phanthymotus-driver": "driver",
}
_LOCAL_POLICY_ROOT = "/run/deploy-approval/policy-candidates"
BLOCKED_REPOSITORY_POLICY_NOT_CONFIGURED = "BLOCKED_REPOSITORY_POLICY_NOT_CONFIGURED"


class _LocalPolicyValidationError(ValueError):
    """A candidate path or file failed local policy security checks."""


class _LocalPolicyReadError(OSError):
    """A candidate changed or could not be read consistently."""


@dataclass
class _RepositoryPolicy:
    machines: dict[str, MachineInfo] | None = None
    reviewers: list[str] | None = None
    source_sha: dict[str, str] = field(default_factory=dict)
    local_sha256: dict[str, str] = field(default_factory=dict)
    file_source: dict[str, str] = field(default_factory=dict)
    etag: dict[str, str] = field(default_factory=dict)
    file_status: dict[str, str] = field(default_factory=dict)
    file_checked_at: dict[str, float] = field(default_factory=dict)
    file_last_checked: dict[str, str] = field(default_factory=dict)
    rejected_sha: dict[str, str] = field(default_factory=dict)
    rejected_local_sha256: dict[str, str] = field(default_factory=dict)
    rejected_reason: dict[str, str] = field(default_factory=dict)
    last_attempt_status: dict[str, str] = field(default_factory=dict)
    last_attempt_reason: dict[str, str] = field(default_factory=dict)
    last_attempt_source: dict[str, str] = field(default_factory=dict)
    last_attempt_sha: dict[str, str] = field(default_factory=dict)
    github_authorized: bool | None = None
    last_checked: float | None = None
    last_checked_at: str | None = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class RepositoryPolicyStore:
    """Keep independently validated policy snapshots for the two controlled repos.

    Each snapshot uses its official repository's main branch, with a local
    repository-specific candidate only when that exact main file is absent.
    """

    def __init__(self, config, *, machine_parser: Callable, reviewer_parser: Callable):
        self._config = config
        self._machine_parser = machine_parser
        self._reviewer_parser = reviewer_parser
        self._repositories: dict[str, _RepositoryPolicy] = {}
        self._reported_unconfigured: set[tuple[str, str]] = set()
        self._reported_authorization: set[str] = set()

    @staticmethod
    def _canonical_repo(repo: str) -> str | None:
        try:
            canonical = validate_repository_names([repo])[0]
        except (TypeError, ValueError):
            return None
        return _POLICY_REPOSITORY_ALIASES.get(canonical)

    def _state(self, repo: str) -> _RepositoryPolicy:
        return self._repositories.setdefault(repo, _RepositoryPolicy())

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    @classmethod
    def _set_file_status(
        cls, state: _RepositoryPolicy, filename: str, status: str,
    ) -> None:
        state.file_status[filename] = status
        state.file_checked_at[filename] = time.monotonic()
        state.file_last_checked[filename] = cls._timestamp()

    @classmethod
    def _record_attempt(
        cls, state: _RepositoryPolicy, filename: str, status: str, *,
        source: str, sha: str = "", reason: str = "",
    ) -> None:
        state.last_attempt_status[filename] = status
        state.last_attempt_source[filename] = source
        if sha:
            state.last_attempt_sha[filename] = sha
        else:
            state.last_attempt_sha.pop(filename, None)
        if reason:
            state.last_attempt_reason[filename] = reason
        else:
            state.last_attempt_reason.pop(filename, None)
        state.file_checked_at[filename] = time.monotonic()
        state.file_last_checked[filename] = cls._timestamp()

    @classmethod
    def _mark_unavailable(cls, state: _RepositoryPolicy, filename: str) -> None:
        cls._mark_network_error(state, filename)

    @classmethod
    def _mark_network_error(cls, state: _RepositoryPolicy, filename: str) -> None:
        previous_status = state.file_status.get(filename, "unconfigured")
        has_known_good = (
            cls._has_trusted_snapshot(state, filename)
            and (
                previous_status in {"valid", "stale"}
                or previous_status == "unauthorized"
                and state.github_authorized is True
            )
        )
        if has_known_good:
            # A transient failure does not revoke the last successfully parsed
            # file. The failed sync is visible separately and retried next cycle.
            cls._set_file_status(state, filename, "valid")
        elif previous_status not in {
            "unauthorized", "missing", "invalid_schema",
            "invalid_response",
        }:
            cls._set_file_status(state, filename, "unavailable")
        cls._record_attempt(
            state, filename, "network_error", source="main",
            reason="temporary official policy read failure",
        )

    @classmethod
    def _mark_unauthorized(cls, state: _RepositoryPolicy) -> None:
        state.github_authorized = False
        for filename in _POLICY_FILES:
            cls._set_file_status(state, filename, "unauthorized")
            cls._record_attempt(
                state, filename, "unauthorized", source="main",
                reason="GitHub App is not authorized for the official repository",
            )
        # Force a fresh authorized read if the installation scope is restored.
        state.last_checked = None
        state.last_checked_at = cls._timestamp()

    @classmethod
    def _confirm_repository_access(cls, state: _RepositoryPolicy) -> None:
        state.github_authorized = True

    def _parse_candidate(self, filename: str, content: bytes):
        if len(content) > MAX_REPO_POLICY_FILE_BYTES:
            raise ValueError("policy file exceeds the size limit")
        if filename == "machines.yaml":
            candidate = self._machine_parser(content)
            if not isinstance(candidate, dict) or not candidate:
                raise ValueError("machines policy must not be empty")
        else:
            candidate = self._reviewer_parser(content)
            if not isinstance(candidate, list) or not candidate:
                raise ValueError("reviewer policy must not be empty")
        return candidate

    @staticmethod
    def _set_candidate(state: _RepositoryPolicy, filename: str, candidate) -> None:
        if filename == "machines.yaml":
            state.machines = candidate
        else:
            state.reviewers = candidate

    @staticmethod
    def _read_local_candidate(canonical_repo: str, filename: str) -> bytes:
        directory = _LOCAL_POLICY_DIRECTORY_BY_REPO.get(canonical_repo)
        if directory is None or filename not in _POLICY_FILES:
            raise _LocalPolicyValidationError("unsupported local policy candidate")
        if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            raise _LocalPolicyValidationError("safe local file opening is unavailable")

        directory_flags = (
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
        )
        file_flags = (
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        directory_fd = os.open("/", directory_flags)
        file_fd = None
        try:
            for component in (*_LOCAL_POLICY_ROOT.strip("/").split("/"), directory):
                next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd
                directory_stat = os.fstat(directory_fd)
                if (not stat.S_ISDIR(directory_stat.st_mode)
                        or directory_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                    raise _LocalPolicyValidationError(
                        "local policy directory is not safely protected",
                    )

            path_stat = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
            if (not stat.S_ISREG(path_stat.st_mode)
                    or path_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                    or path_stat.st_size < 0
                    or path_stat.st_size > MAX_REPO_POLICY_FILE_BYTES):
                raise _LocalPolicyValidationError(
                    "local policy candidate failed file validation",
                )
            file_fd = os.open(filename, file_flags, dir_fd=directory_fd)
            before = os.fstat(file_fd)
            if (not stat.S_ISREG(before.st_mode)
                    or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                    or before.st_size < 0
                    or before.st_size > MAX_REPO_POLICY_FILE_BYTES):
                raise _LocalPolicyValidationError(
                    "local policy candidate failed file validation",
                )

            chunks = []
            total = 0
            while total <= MAX_REPO_POLICY_FILE_BYTES:
                chunk = os.read(
                    file_fd,
                    min(64 * 1024, MAX_REPO_POLICY_FILE_BYTES + 1 - total),
                )
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            after = os.fstat(file_fd)
            final_path_stat = os.stat(
                filename, dir_fd=directory_fd, follow_symlinks=False,
            )
            final_signature = (
                final_path_stat.st_dev, final_path_stat.st_ino,
                final_path_stat.st_mode, final_path_stat.st_size,
                final_path_stat.st_mtime_ns, final_path_stat.st_ctime_ns,
            )
            before_signature = (
                before.st_dev, before.st_ino, before.st_mode, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns,
            )
            after_signature = (
                after.st_dev, after.st_ino, after.st_mode, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns,
            )
            if (not stat.S_ISREG(after.st_mode)
                    or after.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                    or after.st_size > MAX_REPO_POLICY_FILE_BYTES
                    or not stat.S_ISREG(final_path_stat.st_mode)
                    or final_path_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                    or final_path_stat.st_size > MAX_REPO_POLICY_FILE_BYTES):
                raise _LocalPolicyValidationError(
                    "local policy candidate failed file validation",
                )
            if (total > MAX_REPO_POLICY_FILE_BYTES
                    or total != before.st_size
                    or before_signature != after_signature
                    or after_signature != final_signature):
                raise _LocalPolicyReadError(
                    "local policy candidate changed while being read",
                )
            return b"".join(chunks)
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise _LocalPolicyValidationError(
                    "local policy path contains a symbolic link or non-directory component",
                ) from None
            raise
        finally:
            if file_fd is not None:
                os.close(file_fd)
            os.close(directory_fd)

    def _load_local_fallback(
        self, canonical_repo: str, filename: str, state: _RepositoryPolicy,
    ) -> str:
        try:
            content = self._read_local_candidate(canonical_repo, filename)
        except FileNotFoundError:
            self._clear_file_snapshot(state, filename)
            self._set_file_status(state, filename, "missing_local")
            self._record_attempt(
                state, filename, "missing_local", source="local_fallback",
                reason=(
                    "official main is missing and the repository-specific local candidate is missing"
                ),
            )
            return "missing_local"
        except _LocalPolicyValidationError:
            self._clear_file_snapshot(state, filename)
            self._set_file_status(state, filename, "invalid_local")
            self._record_attempt(
                state, filename, "invalid_local", source="local_fallback",
                reason="repository-specific local candidate failed security validation",
            )
            logger.warning(
                "local repository policy candidate failed security validation for %s/%s",
                canonical_repo, filename,
            )
            return "invalid_local"
        except OSError as exc:
            retained = (
                state.file_source.get(filename) == "local_fallback"
                and state.local_sha256.get(filename)
                and self._has_file_config(state, filename)
            )
            if retained:
                self._set_file_status(state, filename, "valid")
            else:
                self._clear_file_snapshot(state, filename)
                self._set_file_status(state, filename, "unavailable")
            self._record_attempt(
                state, filename, "local_read_error", source="local_fallback",
                reason="repository-specific local candidate could not be read",
            )
            logger.warning(
                "local repository policy candidate read failed for %s/%s (%s)%s",
                canonical_repo, filename, type(exc).__name__,
                "; prior verified local snapshot retained" if retained else "",
            )
            return "local_read_error"

        digest = hashlib.sha256(content).hexdigest()
        if (state.file_source.get(filename) == "local_fallback"
                and state.local_sha256.get(filename) == digest
                and self._has_file_config(state, filename)):
            self._record_attempt(
                state, filename, "local_fallback", source="local_fallback",
                reason="local candidate is unchanged",
            )
            self._set_file_status(state, filename, "valid")
            self._reported_unconfigured.discard((canonical_repo, filename))
            return "unchanged_local_fallback"
        if state.rejected_local_sha256.get(filename) == digest:
            self._clear_file_snapshot(state, filename)
            state.rejected_local_sha256[filename] = digest
            self._set_file_status(state, filename, "invalid_local")
            self._record_attempt(
                state, filename, "invalid_local", source="local_fallback",
                reason="local YAML/schema validation failed",
            )
            return "invalid_local"

        try:
            candidate = self._parse_candidate(filename, content)
        except Exception as exc:
            self._clear_file_snapshot(state, filename)
            state.rejected_local_sha256[filename] = digest
            self._set_file_status(state, filename, "invalid_local")
            self._record_attempt(
                state, filename, "invalid_local", source="local_fallback",
                reason="local YAML/schema validation failed",
            )
            logger.warning(
                "local repository policy candidate failed schema validation for %s/%s (%s)",
                canonical_repo, filename, type(exc).__name__,
            )
            return "invalid_local"

        self._set_candidate(state, filename, candidate)
        state.file_source[filename] = "local_fallback"
        state.source_sha.pop(filename, None)
        state.local_sha256[filename] = digest
        state.etag.pop(filename, None)
        state.rejected_sha.pop(filename, None)
        state.rejected_reason.pop(filename, None)
        state.rejected_local_sha256.pop(filename, None)
        self._record_attempt(
            state, filename, "local_fallback", source="local_fallback",
            reason="official main is missing; validated repository-specific candidate is active",
        )
        self._set_file_status(state, filename, "valid")
        self._reported_unconfigured.discard((canonical_repo, filename))
        return "local_fallback"

    @classmethod
    def _clear_file_snapshot(cls, state: _RepositoryPolicy, filename: str) -> None:
        cls._set_candidate(state, filename, None)
        for mapping in (
            state.source_sha, state.local_sha256, state.file_source, state.etag,
            state.rejected_sha, state.rejected_local_sha256, state.rejected_reason,
        ):
            mapping.pop(filename, None)

    @staticmethod
    def _effective_file_status(
        state: _RepositoryPolicy | None, filename: str, now: float | None = None,
    ) -> str:
        if state is None:
            return "missing"
        configured = RepositoryPolicyStore._has_file_config(state, filename)
        status = state.file_status.get(filename, "missing")
        if not configured:
            return status
        checked_at = state.file_checked_at.get(filename)
        now = time.monotonic() if now is None else now
        if (status != "valid" or checked_at is None
                or now - checked_at >= POLICY_REFRESH_SECONDS):
            return "stale" if status == "valid" else status
        return "valid"

    @staticmethod
    def _has_file_config(state: _RepositoryPolicy, filename: str) -> bool:
        if filename == "machines.yaml":
            return state.machines is not None
        if filename == "test_reviewers.yaml":
            return state.reviewers is not None
        return False

    @classmethod
    def _has_trusted_snapshot(cls, state: _RepositoryPolicy, filename: str) -> bool:
        return bool(
            cls._has_file_config(state, filename)
            and (
                (
                    state.file_source.get(filename) == "main"
                    and state.source_sha.get(filename)
                )
                or (
                    state.file_source.get(filename) == "local_fallback"
                    and state.local_sha256.get(filename)
                )
            )
        )

    @classmethod
    def _reject_invalid_update(
        cls, state: _RepositoryPolicy, filename: str,
    ) -> bool:
        # A changed official file that fails validation can no longer authorize
        # operations. Keep only rejection diagnostics; never serve the older
        # policy as if it still reflected the official main branch.
        cls._set_candidate(state, filename, None)
        for mapping in (
            state.source_sha, state.local_sha256, state.file_source, state.etag,
        ):
            mapping.pop(filename, None)
        cls._set_file_status(state, filename, "invalid_schema")
        return False

    @staticmethod
    def _sync_status(state: _RepositoryPolicy | None) -> str:
        if state is None:
            return "unknown"
        if not state.last_attempt_status:
            return "unknown"
        statuses = set(state.last_attempt_status.values())
        if statuses.intersection({
            "network_error", "invalid_schema", "invalid_local", "local_read_error",
            "missing_local", "unauthorized", "invalid_response",
        }):
            return "error"
        if any(
            state.last_attempt_status.get(filename) == "not_found"
            and state.file_status.get(filename) != "valid"
            for filename in _POLICY_FILES
        ):
            return "error"
        return "current"

    def _app_authorized(self, repo: str) -> bool:
        if self._config.auth_valid is not True:
            authorized = False
        else:
            try:
                policy_active = set(validate_repository_names(
                    list(self._config.policy_active_repos),
                    label="authorized official policy repositories",
                    allow_empty=True,
                ))
            except (TypeError, ValueError):
                authorized = False
            else:
                # The policy source is the official upstream repository. Do not
                # reuse active_repos, which may contain only code forks.
                authorized = repo in policy_active
        if not authorized:
            state = self._repositories.get(repo)
            if state is not None:
                self._mark_unauthorized(state)
        if authorized:
            self._reported_authorization.discard(repo)
        elif repo not in self._reported_authorization:
            logger.warning(
                "repository policy access is blocked for %s: current GitHub App installation authorization is missing",
                repo,
            )
            self._reported_authorization.add(repo)
        return authorized

    def machines_for(self, repo: str) -> dict[str, MachineInfo]:
        canonical = self._canonical_repo(repo)
        if canonical is None:
            logger.warning("repository machine policy requested for an unsupported repository")
            return {}
        if not self._app_authorized(canonical):
            return {}
        state = self._state(canonical)
        if self._effective_file_status(state, "machines.yaml") != "valid":
            self._warn_unconfigured(canonical, "machines.yaml")
            return {}
        return copy.deepcopy(state.machines or {})

    def machine_for(self, alias: str, repo: str) -> MachineInfo | None:
        if not isinstance(alias, str) or not alias:
            return None
        canonical = self._canonical_repo(repo)
        if canonical is None:
            logger.warning("repository machine policy requested for an unsupported repository")
            return None
        if not self._app_authorized(canonical):
            return None
        state = self._state(canonical)
        if self._effective_file_status(state, "machines.yaml") != "valid":
            self._warn_unconfigured(canonical, "machines.yaml")
            return None
        machine = (state.machines or {}).get(alias)
        return copy.deepcopy(machine) if machine is not None else None

    def reviewers_for_repo(self, repo: str) -> list[str]:
        canonical = self._canonical_repo(repo)
        if canonical is None:
            logger.warning("repository acceptance policy requested for an unsupported repository")
            return []
        if not self._app_authorized(canonical):
            return []
        state = self._state(canonical)
        if self._effective_file_status(state, "test_reviewers.yaml") != "valid":
            self._warn_unconfigured(canonical, "test_reviewers.yaml")
            return []
        return list(state.reviewers or [])

    def status(self, repo: str) -> dict:
        canonical = self._canonical_repo(repo)
        if canonical is None:
            return {
                "status": "unsupported_repository",
                "machines_configured": False,
                "reviewers_configured": False,
                "machines_yaml_status": "unsupported_repository",
                "test_reviewers_yaml_status": "unsupported_repository",
                "machines_source": "",
                "test_reviewers_source": "",
                "source_sha": {},
                "local_sha256": {},
                "last_attempt_status": {},
                "last_attempt_reason": {},
                "last_attempt_source": {},
                "last_attempt_sha": {},
                "rejected_sha": {},
                "rejected_reason": {},
                "sync_status": "unknown",
                "last_checked": None,
                "missing_files": list(_POLICY_FILES),
                "blocking_reason": BLOCKED_REPOSITORY_POLICY_NOT_CONFIGURED,
            }
        if not self._app_authorized(canonical):
            state = self._repositories.get(canonical)
            return {
                "status": "unauthorized",
                "authorized": False,
                "machines_configured": False,
                "reviewers_configured": False,
                "machines_yaml_status": "unauthorized",
                "test_reviewers_yaml_status": "unauthorized",
                "machines_source": (
                    state.file_source.get("machines.yaml", "") if state else ""
                ),
                "test_reviewers_source": (
                    state.file_source.get("test_reviewers.yaml", "") if state else ""
                ),
                "source_sha": copy.deepcopy(state.source_sha) if state else {},
                "local_sha256": copy.deepcopy(state.local_sha256) if state else {},
                "last_attempt_status": (
                    copy.deepcopy(state.last_attempt_status) if state else {
                        filename: "unauthorized" for filename in _POLICY_FILES
                    }
                ),
                "last_attempt_reason": (
                    copy.deepcopy(state.last_attempt_reason) if state else {
                        filename: "GitHub App is not authorized for the official repository"
                        for filename in _POLICY_FILES
                    }
                ),
                "last_attempt_source": (
                    copy.deepcopy(state.last_attempt_source) if state else {
                        filename: "main" for filename in _POLICY_FILES
                    }
                ),
                "last_attempt_sha": copy.deepcopy(state.last_attempt_sha) if state else {},
                "rejected_sha": copy.deepcopy(state.rejected_sha) if state else {},
                "rejected_reason": (
                    copy.deepcopy(state.rejected_reason) if state else {}
                ),
                "sync_status": "error" if state is None else self._sync_status(state),
                "last_checked": state.last_checked_at if state else None,
                "file_last_checked": (
                    copy.deepcopy(state.file_last_checked) if state else {}
                ),
                "missing_files": [],
                "blocking_reason": None,
            }
        state = self._repositories.get(canonical)
        if state and state.github_authorized is False:
            return {
                "status": "unauthorized",
                "authorized": False,
                "machines_configured": False,
                "reviewers_configured": False,
                "machines_yaml_status": state.file_status.get(
                    "machines.yaml", "unauthorized",
                ),
                "test_reviewers_yaml_status": state.file_status.get(
                    "test_reviewers.yaml", "unauthorized",
                ),
                "machines_source": state.file_source.get("machines.yaml", ""),
                "test_reviewers_source": state.file_source.get("test_reviewers.yaml", ""),
                "source_sha": copy.deepcopy(state.source_sha),
                "local_sha256": copy.deepcopy(state.local_sha256),
                "last_attempt_status": copy.deepcopy(state.last_attempt_status),
                "last_attempt_reason": copy.deepcopy(state.last_attempt_reason),
                "last_attempt_source": copy.deepcopy(state.last_attempt_source),
                "last_attempt_sha": copy.deepcopy(state.last_attempt_sha),
                "rejected_sha": copy.deepcopy(state.rejected_sha),
                "rejected_reason": copy.deepcopy(state.rejected_reason),
                "sync_status": self._sync_status(state),
                "last_checked": state.last_checked_at,
                "file_last_checked": copy.deepcopy(state.file_last_checked),
                "missing_files": [],
                "blocking_reason": None,
            }
        now = time.monotonic()
        machines_status = self._effective_file_status(state, "machines.yaml", now)
        reviewers_status = self._effective_file_status(state, "test_reviewers.yaml", now)
        machine_configured = machines_status == "valid"
        reviewers_configured = reviewers_status == "valid"
        missing_files = []
        if not machine_configured:
            missing_files.append("machines.yaml")
            if machines_status in {
                "missing", "unconfigured", "stale", "unavailable", "invalid",
                "invalid_response", "invalid_schema", "invalid_local", "missing_local",
            }:
                self._warn_unconfigured(canonical, "machines.yaml")
        if not reviewers_configured:
            missing_files.append("test_reviewers.yaml")
            if reviewers_status in {
                "missing", "unconfigured", "stale", "unavailable", "invalid",
                "invalid_response", "invalid_schema", "invalid_local", "missing_local",
            }:
                self._warn_unconfigured(canonical, "test_reviewers.yaml")
        if machine_configured and reviewers_configured:
            policy_status = "configured"
        elif machine_configured or reviewers_configured:
            policy_status = "partially_configured"
        else:
            policy_status = "unconfigured"
        return {
            "status": policy_status,
            "authorized": True,
            "machines_configured": machine_configured,
            "reviewers_configured": reviewers_configured,
            "machines_yaml_status": machines_status,
            "test_reviewers_yaml_status": reviewers_status,
            "machines_source": (
                state.file_source.get("machines.yaml", "") if state else ""
            ),
            "test_reviewers_source": (
                state.file_source.get("test_reviewers.yaml", "") if state else ""
            ),
            "source_sha": copy.deepcopy(state.source_sha) if state else {},
            "local_sha256": copy.deepcopy(state.local_sha256) if state else {},
            "last_attempt_status": (
                copy.deepcopy(state.last_attempt_status) if state else {}
            ),
            "last_attempt_reason": (
                copy.deepcopy(state.last_attempt_reason) if state else {}
            ),
            "last_attempt_source": (
                copy.deepcopy(state.last_attempt_source) if state else {}
            ),
            "last_attempt_sha": (
                copy.deepcopy(state.last_attempt_sha) if state else {}
            ),
            "rejected_sha": copy.deepcopy(state.rejected_sha) if state else {},
            "rejected_reason": (
                copy.deepcopy(state.rejected_reason) if state else {}
            ),
            "sync_status": self._sync_status(state),
            "last_checked": state.last_checked_at if state else None,
            "file_last_checked": (
                copy.deepcopy(state.file_last_checked) if state else {}
            ),
            "missing_files": missing_files,
            "blocking_reason": (
                BLOCKED_REPOSITORY_POLICY_NOT_CONFIGURED if missing_files else None
            ),
            "last_check_age_seconds": (
                max(0, int(time.monotonic() - state.last_checked))
                if state and state.last_checked is not None else None
            ),
            "file_last_check_age_seconds": {
                filename: (
                    max(0, int(now - state.file_checked_at[filename]))
                    if state and filename in state.file_checked_at else None
                )
                for filename in _POLICY_FILES
            },
        }

    async def refresh_if_due(self, repo: str, github_client) -> dict:
        canonical = self._canonical_repo(repo)
        if canonical is None:
            logger.warning("repository policy refresh rejected for an unsupported repository")
            return {"status": "unsupported_repository", "updated": []}

        state = self._state(canonical)
        async with state.lock:
            if not self._app_authorized(canonical):
                return {
                    "status": "unauthorized",
                    "updated": [],
                    "files": {filename: "unauthorized" for filename in _POLICY_FILES},
                    "file_source": copy.deepcopy(state.file_source),
                    "source_sha": copy.deepcopy(state.source_sha),
                    "local_sha256": copy.deepcopy(state.local_sha256),
                    "last_attempt_status": copy.deepcopy(state.last_attempt_status),
                    "last_attempt_sha": copy.deepcopy(state.last_attempt_sha),
                    "sync_status": self._sync_status(state),
                    "last_checked": state.last_checked_at,
                }
            now = time.monotonic()
            if (state.last_checked is not None
                    and now - state.last_checked < POLICY_REFRESH_SECONDS):
                return {
                    "status": "not_due",
                    "updated": [],
                    "files": {
                        filename: self._effective_file_status(state, filename, now)
                        for filename in _POLICY_FILES
                    },
                    "machines_configured": (
                        self._effective_file_status(state, "machines.yaml", now) == "valid"
                    ),
                    "reviewers_configured": (
                        self._effective_file_status(state, "test_reviewers.yaml", now) == "valid"
                    ),
                    "file_source": copy.deepcopy(state.file_source),
                    "source_sha": copy.deepcopy(state.source_sha),
                    "local_sha256": copy.deepcopy(state.local_sha256),
                    "last_attempt_status": copy.deepcopy(state.last_attempt_status),
                    "last_attempt_sha": copy.deepcopy(state.last_attempt_sha),
                    "sync_status": self._sync_status(state),
                    "last_checked": state.last_checked_at,
                }

            # Each official file has its own source and cache.
            updated: list[str] = []
            file_results: dict[str, str] = {}
            getter = getattr(github_client, "get_repository_file_at_ref", None)
            if not callable(getter):
                for filename in _POLICY_FILES:
                    self._mark_unavailable(state, filename)
                state.last_checked = time.monotonic()
                state.last_checked_at = self._timestamp()
                logger.warning(
                    "repository policy refresh unavailable for %s: GitHub client has no policy file reader",
                    canonical,
                )
                return {
                    "status": "network_error", "updated": [],
                    "files": {
                        filename: state.last_attempt_status.get(filename, "network_error")
                        for filename in _POLICY_FILES
                    },
                    "file_source": copy.deepcopy(state.file_source),
                    "source_sha": copy.deepcopy(state.source_sha),
                    "local_sha256": copy.deepcopy(state.local_sha256),
                    "last_attempt_status": copy.deepcopy(state.last_attempt_status),
                    "last_attempt_sha": copy.deepcopy(state.last_attempt_sha),
                    "sync_status": self._sync_status(state),
                    "last_checked": state.last_checked_at,
                }

            for filename in _POLICY_FILES:
                remote_result = None
                state.last_attempt_source[filename] = "main"
                state.last_attempt_sha.pop(filename, None)
                try:
                    remote_result = await getter(
                        canonical,
                        filename,
                        ref="main",
                        etag=state.etag.get(filename),
                    )
                except Exception as exc:
                    status_code = getattr(exc, "status_code", None)
                    if status_code in (401, 403):
                        self._mark_unauthorized(state)
                        file_results[filename] = "unauthorized"
                        for remaining in _POLICY_FILES:
                            if remaining not in file_results:
                                file_results[remaining] = "unauthorized"
                        logger.warning(
                            "repository policy read is unauthorized for %s/%s (%s)",
                            canonical, filename, type(exc).__name__,
                        )
                        break
                    if status_code == 404:
                        remote_result = None
                    elif (status_code is None or status_code in (408, 425, 429)
                          or isinstance(status_code, int) and status_code >= 500):
                        self._mark_network_error(state, filename)
                        logger.warning(
                            "temporary official policy read failure for %s/%s (%s); retaining the last trusted snapshot",
                            canonical,
                            filename,
                            type(exc).__name__,
                        )
                        file_results[filename] = "network_error"
                        continue
                    else:
                        self._set_file_status(state, filename, "invalid_response")
                        self._record_attempt(
                            state, filename, "invalid_response", source="main",
                            reason="official policy read returned an unexpected error",
                        )
                        logger.warning(
                            "official policy read returned an unexpected error for %s/%s (%s)",
                            canonical,
                            filename,
                            type(exc).__name__,
                        )
                        file_results[filename] = "invalid_response"
                        continue

                # A completed official contents read (including a documented
                # 404) confirms that this installation can access the repo.
                if remote_result is None or isinstance(remote_result, dict):
                    self._confirm_repository_access(state)
                if remote_result is None:
                    if state.file_source.get(filename) != "local_fallback":
                        self._clear_file_snapshot(state, filename)
                    state.etag.pop(filename, None)
                    fallback_status = self._load_local_fallback(
                        canonical, filename, state,
                    )
                    file_results[filename] = fallback_status
                    if fallback_status == "local_fallback":
                        updated.append(filename)
                    continue

                if not isinstance(remote_result, dict):
                    state.last_attempt_source[filename] = "main"
                    self._set_file_status(state, filename, "invalid_response")
                    self._record_attempt(
                        state, filename, "invalid_response", source="main",
                        reason="official policy response is not an object",
                    )
                    state.etag.pop(filename, None)
                    logger.warning(
                        "repository policy file response for %s/%s is invalid",
                        canonical, filename,
                    )
                    file_results[filename] = "invalid_response"
                    continue

                if remote_result.get("not_modified") is True:
                    response_etag = remote_result.get("etag", "")
                    if (state.file_source.get(filename) == "main"
                            and self._has_file_config(state, filename)
                            and state.etag.get(filename)
                            and isinstance(response_etag, str)
                            and len(response_etag) <= 512
                            and not any(ord(ch) < 32 or ord(ch) == 127
                                        for ch in response_etag)):
                        if response_etag:
                            state.etag[filename] = response_etag
                        state.rejected_sha.pop(filename, None)
                        state.rejected_reason.pop(filename, None)
                        active_sha = state.source_sha.get(filename, "")
                        self._record_attempt(
                            state, filename, "not_modified", source="main",
                            sha=active_sha,
                        )
                        self._set_file_status(state, filename, "valid")
                        self._reported_unconfigured.discard((canonical, filename))
                        file_results[filename] = "unchanged"
                    else:
                        self._record_attempt(
                            state, filename, "invalid_response", source="main",
                            reason="unexpected not-modified response without a trusted main snapshot",
                        )
                        self._set_file_status(state, filename, "invalid_response")
                        logger.warning(
                            "repository policy file response for %s/%s was unexpectedly not modified",
                            canonical, filename,
                        )
                        file_results[filename] = "invalid_response"
                    continue

                source_path = remote_result.get("path")
                source_sha = remote_result.get("sha")
                content = remote_result.get("content")
                source_etag = remote_result.get("etag", "")
                if (source_path != filename
                        or not isinstance(source_sha, str)
                        or re.fullmatch(r"[0-9a-fA-F]{40}", source_sha) is None
                        or not isinstance(content, bytes)
                        or len(content) > MAX_REPO_POLICY_FILE_BYTES
                        or not isinstance(source_etag, str)
                        or len(source_etag) > 512
                        or any(ord(char) < 32 or ord(char) == 127 for char in source_etag)):
                    self._record_attempt(
                        state, filename, "invalid_response", source="main",
                        reason="official policy response failed metadata validation",
                        sha=(source_sha.lower() if isinstance(source_sha, str)
                             and re.fullmatch(r"[0-9a-fA-F]{40}", source_sha)
                             else ""),
                    )
                    self._set_file_status(state, filename, "invalid_response")
                    state.etag.pop(filename, None)
                    logger.warning(
                        "repository policy file response for %s/%s failed validation",
                        canonical,
                        filename,
                    )
                    file_results[filename] = "invalid_response"
                    continue
                source_sha = source_sha.lower()

                if state.rejected_sha.get(filename) == source_sha:
                    reason = state.rejected_reason.get(
                        filename, "official YAML/schema validation failed",
                    )
                    self._record_attempt(
                        state, filename, "invalid_schema", source="main",
                        sha=source_sha, reason=reason,
                    )
                    self._reject_invalid_update(state, filename)
                    state.etag.pop(filename, None)
                    file_results[filename] = "invalid_schema"
                    continue

                # Reuse a validated main snapshot only when the actual Git
                # blob SHA is unchanged. A local SHA256 can never masquerade
                # as a Git blob revision.
                if (state.file_source.get(filename) == "main"
                        and state.source_sha.get(filename) == source_sha
                        and self._has_file_config(state, filename)):
                    if source_etag:
                        state.etag[filename] = source_etag
                    else:
                        state.etag.pop(filename, None)
                    state.rejected_sha.pop(filename, None)
                    state.rejected_reason.pop(filename, None)
                    self._record_attempt(
                        state, filename, "success", source="main", sha=source_sha,
                    )
                    self._set_file_status(state, filename, "valid")
                    self._reported_unconfigured.discard((canonical, filename))
                    file_results[filename] = "unchanged"
                    continue

                try:
                    candidate = self._parse_candidate(filename, content)
                except Exception as exc:
                    # The exception may contain values from untrusted YAML.
                    # Report the failed file and exception class only.
                    state.rejected_sha[filename] = source_sha
                    state.rejected_reason[filename] = "official YAML/schema validation failed"
                    self._record_attempt(
                        state, filename, "invalid_schema", source="main",
                        sha=source_sha,
                        reason=state.rejected_reason[filename],
                    )
                    self._reject_invalid_update(state, filename)
                    state.etag.pop(filename, None)
                    logger.warning(
                        "repository policy file %s/%s failed schema validation (%s); authorization for this file was withdrawn",
                        canonical,
                        filename,
                        type(exc).__name__,
                    )
                    file_results[filename] = "invalid_schema"
                    continue

                self._set_candidate(state, filename, candidate)
                state.file_source[filename] = "main"
                state.source_sha[filename] = source_sha
                state.local_sha256.pop(filename, None)
                state.rejected_sha.pop(filename, None)
                state.rejected_reason.pop(filename, None)
                if source_etag:
                    state.etag[filename] = source_etag
                else:
                    state.etag.pop(filename, None)
                self._record_attempt(
                    state, filename, "success", source="main", sha=source_sha,
                )
                self._set_file_status(state, filename, "valid")
                self._reported_unconfigured.discard((canonical, filename))
                updated.append(filename)
                file_results[filename] = "updated"

            state.last_checked = time.monotonic()
            state.last_checked_at = self._timestamp()
            if state.file_status.get("machines.yaml") != "valid":
                self._warn_unconfigured(canonical, "machines.yaml")
            if state.file_status.get("test_reviewers.yaml") != "valid":
                self._warn_unconfigured(canonical, "test_reviewers.yaml")

            if any(value == "unauthorized" for value in file_results.values()):
                overall = "unauthorized"
            elif any(value in {
                "error", "invalid_response", "invalid_schema", "invalid_local",
                "local_read_error", "unavailable", "network_error",
            } for value in file_results.values()):
                overall = "partial_error"
            elif any(value in {"missing", "missing_local"} for value in file_results.values()):
                overall = "missing_source"
            elif updated:
                overall = "updated"
            else:
                overall = "unchanged"
            return {
                "status": overall,
                "updated": updated,
                "files": file_results,
                "machines_configured": (
                    self._effective_file_status(state, "machines.yaml") == "valid"
                ),
                "reviewers_configured": (
                    self._effective_file_status(state, "test_reviewers.yaml") == "valid"
                ),
                "file_source": copy.deepcopy(state.file_source),
                "source_sha": copy.deepcopy(state.source_sha),
                "local_sha256": copy.deepcopy(state.local_sha256),
                "last_attempt_status": copy.deepcopy(state.last_attempt_status),
                "last_attempt_sha": copy.deepcopy(state.last_attempt_sha),
                "sync_status": self._sync_status(state),
                "last_checked": state.last_checked_at,
            }

    def _warn_unconfigured(self, repo: str, filename: str) -> None:
        marker = (repo, filename)
        if marker in self._reported_unconfigured:
            return
        logger.warning(
            "%s: repository %s has no usable verified %s; access is fail-closed. "
            "Configure %s/%s on official main; local fallback applies only when main returns 404",
            BLOCKED_REPOSITORY_POLICY_NOT_CONFIGURED,
            repo, filename, repo, filename,
        )
        self._reported_unconfigured.add(marker)
