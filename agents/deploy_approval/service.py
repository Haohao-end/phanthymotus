"""Deploy Controller — stateless command handler for Deploy Approval.

The Deploy Controller is stateless between commands. Its ONLY persistence is
the GitHub lifecycle comment hidden state, read/written through GitHubStateProxy.

Commands:
  - /request_deploy — PR Author requests deployment for current HEAD
  - /approve_deploy — Machine Owner approves and binds machine
  - /record_test — Overall validation verdict

State machine (hidden state only):
  review-required -> reviewing -> deploy-ready -> deploying
  deploy-ready -> deploy-requested -> deploying -> testing -> succeeded | failed
"""

from __future__ import annotations

import hashlib
import re
import inspect
import ipaddress
import math

import asyncio
import json
import logging
import time
import copy
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit
from zoneinfo import ZoneInfo

from . import comments as comments_mod
from .agent_core_client import (
    AgentCoreClient,
    AgentCoreDeployOutcomeUncertain,
    AgentCoreError,
)
from .case_runner import CaseRunner
from .config import (
    Config, DEFAULT_GITHUB_REPOS, is_evidence_ingress_url,
    is_stable_public_base_url, validate_repository_names, _LOGIN_RE,
)
from .cos_client import CosClient
from .evidence_builder import EvidenceBuilder
from .evidence_models import (
    archive_snapshot, make_round_id, round_id_for_state, trusted_round_numbers, utc_now,
)
from .github_client import (
    GitHubClient, GitHubError, GitHubRateLimitError, GitHubTransientError,
)
from .github_state_proxy import (
    GitHubStateProxy,
    GitHubStateProxyError,
    _ALLOWED_STATUS_LABELS,
    _validate_hidden_state,
    _extract_hidden_state,
    _build_hidden_state_body,
    _insert_history_into_visible,
    _count_visible_bytes,
    _truncate_events_to_fit,
    _MAX_VISIBLE_LIFECYCLE_BYTES,
    HISTORY_ARCHIVE_MARKER_PREFIX,
    HISTORY_EVENT_DELIMITER,
    STATUS_PREFIX,
    _next_history_archive_page,
    _build_archive_body,
    _parse_visible_history,
    _build_history_block,
    VISIBLE_HISTORY_START_MARKER,
    VISIBLE_HISTORY_END_MARKER,
)
from .models import BuildInfo
from .policy import Policy, PolicyError
from .review_comment_parser import (
    extract_review_evidence,
    ReviewCommentEvidence,
)
from .image_ref import validate_image_ref, get_deploy_platform

logger = logging.getLogger(__name__)

AGENT_CORE_STATUS_PROBE_TIMEOUT_SECONDS = 4.0
RUNTIME_IMAGE_CHECK_INTERVAL_SECONDS = 30 * 60
DEPLOYMENT_UNCERTAIN_ESCALATION_SECONDS = 900


class DeployControllerError(Exception):
    pass


class DeployOutcomeUncertain(DeployControllerError):
    pass


class DeployPreflightUnavailable(DeployControllerError):
    pass


def _short(sha: str) -> str:
    return (sha or "")[:7]


def _invalid_ip_machine_selector(value: str) -> bool:
    """Return whether a rejected selector is malformed or unsupported IP text."""
    if ":" in value:
        return True  # IPv6 is not a supported machine selector.
    if re.fullmatch(r"[\d.]+", value):
        try:
            ipaddress.IPv4Address(value)
        except ValueError:
            return True
    return False


def _is_machine_not_found_error(message: str) -> bool:
    """Match machine lookup failures without treating malformed IPs as missing."""
    if not isinstance(message, str):
        return False
    lowered = message.casefold()
    cues = (
        "invalid machine selector",
        "not a known alias",
        "unknown machine alias",
        "no machine found with",
    )
    if not any(cue in lowered for cue in cues):
        return False

    selector_match = re.search(
        r"(?:invalid machine selector|unknown machine alias|"
        r"no machine found with(?:\s+IP)?)\s*[:=]?\s*"
        r"(['\"`])(?P<selector>[^'\"`]+)\1",
        message,
        re.IGNORECASE,
    )
    if (selector_match
            and _invalid_ip_machine_selector(selector_match.group("selector"))):
        return False
    return True



def _is_supported_target(target: str) -> bool:
    return target in ("core", "perception", "actucore", "driver")


def _image_repository(ref: str) -> str:
    ref = str(ref or "").strip()
    if not ref:
        return ""
    if "@sha256:" in ref:
        return ref.split("@sha256:", 1)[0]
    slash = ref.rfind("/")
    colon = ref.rfind(":")
    if colon > slash:
        return ref[:colon]
    return ref


def _target_tag_from_image_ref(ref: str) -> str:
    """Extract the tag portion from an image reference.

    Returns empty string if no tag can be resolved (e.g. repo@sha256:...).
    For image:tag returns *tag*.  For repo@sha256: returns "".
    """
    ref = str(ref or "").strip()
    if not ref:
        return ""
    if "@sha256:" in ref:
        return ""
    slash = ref.rfind("/")
    colon = ref.rfind(":")
    if colon > slash:
        return ref[colon + 1:]
    return ""


_CANONICAL_VARIANTS = {"5.11", "6.1"}
_LEGACY_VARIANTS = {
    "jetson-jp5.11": "5.11",
    "jetson-jp6.1": "6.1",
}

MAX_RECENT_APPROVE_ATTEMPTS = 4
AGENT_CORE_ENDPOINT_CACHE_TTL_SECONDS = 60.0

_REVIEW_EVIDENCE_IDENTITY_FIELDS = frozenset({
    "build_comment_id",
    "build_comment_updated_at",
    "commit_prefix",
    "resolved_head_sha",
    "test_comment_id",
    "test_comment_updated_at",
    "code_review_comment_id",
    "code_review_comment_updated_at",
    "review_author_id",
})


def _normalize_variant(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if raw in _CANONICAL_VARIANTS:
        return raw
    if raw in _LEGACY_VARIANTS:
        return _LEGACY_VARIANTS[raw]
    raise DeployControllerError(f"unsupported variant: {raw!r}")


def _is_deployable_build(repo: str, build, configured_repos: list[str] | None = None) -> bool:
    target = str(build.target or "").strip()
    if not _is_supported_target(target):
        return False
    if not build.success:
        return False
    if not build.image_tag:
        return False
    # The protected configuration selects the main repository, not its owner.
    # Additional controlled repositories retain the driver-only contract.
    try:
        repos = validate_repository_names(list(DEFAULT_GITHUB_REPOS) if configured_repos is None else configured_repos)
    except ValueError:
        return False
    repo_lower = (repo or "").lower()
    if repo_lower in repos[1:]:
        # Driver family: only driver with non-empty driver_path is deployable
        if target != "driver":
            return False
        driver_path = getattr(build, "driver_path", "") or ""
        if not driver_path.strip():
            return False
        return True
    if repo_lower == repos[0]:
        # Core family: core, perception, and actucore are deployable; driver is NOT
        if target == "driver":
            return False
        if target in ("core", "perception", "actucore"):
            return True
        return False
    # Unknown repository: nothing is deployable
    return False

def _component_id_set(deployments: list[dict]) -> set[str]:
    deployed: set[str] = set()
    for dep in deployments:
        if not isinstance(dep, dict) or dep.get("phase") != "deployed":
            continue
        for cid in dep.get("component_ids", []):
            if isinstance(cid, str) and cid:
                deployed.add(cid)
    return deployed


_REVIEW_ACTIVE_STATUSES = {
    "queued",
    "running",
    "retrying",
    "build_success",
}

_REVIEW_FAILED_STATUSES = {
    "build_failed",
    "cancelled",
    "timeout",
    "error",
}


class DeployController:
    """Stateless Deploy Controller.

    Reads/writes hidden state through GitHubStateProxy.
    No SQLite, no DeploymentStore, no in-memory lifecycle state.
    """

    def __init__(
        self,
        config: Config,
        proxy: GitHubStateProxy,
        policy: Policy,
        github: GitHubClient,
        agent_core_factory: object = None,
    ):
        self.config = config
        self.proxy = proxy
        self.policy = policy
        self.github = github
        self._agent_core_factory = agent_core_factory
        self._core_clients: dict[tuple[str, str], AgentCoreClient] = {}
        self._core_client_fingerprints: dict[tuple[str, str], tuple[str, str, str]] = {}
        self._agent_core_health: dict[
            tuple[str, str], tuple[float, tuple[str, str, str], str]
        ] = {}
        # V49 Codex C contract: Agent Core-verified endpoint bindings. Only
        # endpoints that pass live Agent Core authentication, identity, and
        # component-runtime checks can generate new approval commands. Cache
        # keys bind the repository, device, endpoint, credential, snapshots,
        # policy version, and requested component set.
        self._agent_core_verified_endpoints_cache: dict[
            tuple, tuple[float, dict[str, object]]
        ] = {}
        self.cos = CosClient(config)
        self._case_runner: CaseRunner | None = None
        self._evidence_lock = asyncio.Lock()
        self.evidence_service = None  # B attaches the shared EvidenceService instance.
        # Retry scheduling only; durable terminal state identifies pending COS
        # after restart. At most five attempts per binding per process.
        self._cos_retries: dict[tuple[str, int, str, int], tuple[int, float]] = {}
        self._command_reply_tracking: set[tuple[str, int, int]] = set()
        self._command_reply_delivery: dict[tuple[str, int, int], bool] = {}

    @staticmethod
    def _command_reply_key(repo: str, pr_number: int, comment_id: int):
        return repo.casefold(), pr_number, comment_id

    def begin_command_reply_tracking(
        self, repo: str, pr_number: int, comment_id: int,
    ) -> None:
        key = self._command_reply_key(repo, pr_number, comment_id)
        self._command_reply_tracking.add(key)
        self._command_reply_delivery.pop(key, None)

    def take_command_reply_delivery(
        self, repo: str, pr_number: int, comment_id: int,
    ) -> bool | None:
        key = self._command_reply_key(repo, pr_number, comment_id)
        self._command_reply_tracking.discard(key)
        return self._command_reply_delivery.pop(key, None)

    def _record_command_reply_delivery(
        self, repo: str, pr_number: int, comment_id: int, delivered: bool,
    ) -> None:
        key = self._command_reply_key(repo, pr_number, comment_id)
        if key not in self._command_reply_tracking:
            return
        previous = self._command_reply_delivery.get(key, False)
        self._command_reply_delivery[key] = previous or delivered

    async def aclose(self) -> None:
        for core in self._core_clients.values():
            try:
                await core.aclose()
            except Exception:
                pass
        self._core_clients.clear()
        self._core_client_fingerprints.clear()

    # ── Core helpers ──

    def _resolve_policy_machine_selector(
        self, selector: str, repo: str,
    ) -> tuple[object, str]:
        """Resolve an alias or any confirmed address without crossing devices."""
        machines = self.policy.get_machines(repo=repo)
        if not isinstance(machines, list):
            raise PolicyError("current machine policy is unavailable")
        policy_resolver = getattr(self.policy, "resolve_machine_selector", None)
        if callable(policy_resolver):
            try:
                parameters = list(inspect.signature(policy_resolver).parameters.values())
            except (TypeError, ValueError):
                parameters = []
            if len(parameters) >= 2 and parameters[1].name in {"repo", "repository"}:
                resolved = policy_resolver(selector, repo)
                resolved_machine, resolved_endpoint = resolved, ""
                if (isinstance(resolved, tuple) and len(resolved) == 2):
                    resolved_machine, resolved_endpoint = resolved
                if isinstance(resolved_machine, str):
                    resolved_alias = resolved_machine
                    resolved_machine = next((item for item in machines
                                             if getattr(item, "alias", None) == resolved_alias), None)
                if resolved_machine is not None:
                    resolved_alias = str(getattr(resolved_machine, "alias", "") or "")
                    current_matches = [item for item in machines
                                       if getattr(item, "alias", None) == resolved_alias]
                    if len(current_matches) != 1:
                        raise PolicyError("machine selector is ambiguous in current repository policy")
                    resolved_machine = current_matches[0]
                    selected = self._canonical_primary_ipv4(resolved_endpoint)
                    if not selected and self._canonical_primary_ipv4(selector):
                        selected = self._canonical_primary_ipv4(selector)
                    endpoints = {
                        item["ip"] for item in self._policy_machine_endpoints(
                            resolved_machine, repo,
                        )
                    }
                    endpoint_confirmed = (
                        self._endpoint_allowed_for_repository(
                            repo, resolved_machine, selected,
                            policy_machines=machines,
                        ) if selected else any(
                            self._endpoint_allowed_for_repository(
                                repo, resolved_machine, endpoint,
                                policy_machines=machines,
                            ) for endpoint in endpoints
                        )
                    )
                    if (selected and selected not in endpoints
                            or not endpoints or not endpoint_confirmed):
                        raise PolicyError("machine selector is not a confirmed endpoint")
                    return resolved_machine, selected
        by_alias = {
            str(getattr(item, "alias", "") or ""): item for item in machines
            if getattr(item, "alias", None)
        }
        if selector in by_alias:
            machine = by_alias[selector]
            endpoints = self._policy_machine_endpoints(machine, repo)
            if not endpoints or not any(
                    self._endpoint_allowed_for_repository(
                        repo, machine, endpoint["ip"],
                        policy_machines=machines,
                    ) for endpoint in endpoints):
                raise PolicyError("machine identity or endpoints are not confirmed")
            return machine, ""
        endpoint = self._canonical_primary_ipv4(selector)
        if not endpoint:
            raise PolicyError("invalid machine selector")
        matches = [machine for machine in machines
                   if endpoint in {item["ip"] for item in
                                   self._policy_machine_endpoints(machine, repo)}
                   and self._endpoint_allowed_for_repository(
                       repo, machine, endpoint, policy_machines=machines)]
        if len(matches) != 1:
            raise PolicyError("machine endpoint is missing or ambiguous")
        return matches[0], endpoint

    def _policy_machine_identity(self, machine, repo: str):
        identity = getattr(self.policy, "machine_identity", None)
        if callable(identity):
            return identity(machine, repo)
        # Legacy Policy has no endpoint inventory. This binds only its primary
        # address and never grants an unconfirmed secondary address.
        return (
            str(getattr(machine, "alias", "") or ""),
            str(getattr(machine, "node_id", "") or ""),
            self._canonical_primary_ipv4(getattr(machine, "node_host", "")),
        )

    @staticmethod
    def _machine_identity_is_confirmed(identity) -> bool:
        if identity is None or identity is False or identity == "":
            return False
        if isinstance(identity, dict):
            return identity.get("confirmed") is True and identity.get("stale") is not True
        return True

    @staticmethod
    def _physical_machine_identity_key(identity):
        if isinstance(identity, dict):
            addresses = identity.get("addresses", [])
            if isinstance(addresses, dict):
                addresses = [addresses]
            address_keys = []
            for item in addresses if isinstance(addresses, (list, tuple, set)) else []:
                if isinstance(item, dict):
                    address_keys.append((str(item.get("ip", "")), str(item.get("label", ""))))
                elif isinstance(item, str):
                    address_keys.append((item, ""))
            return (
                identity.get("number"), identity.get("brand"), identity.get("model"),
                tuple(sorted(address_keys)),
            )
        return identity

    def _policy_machine_endpoints(self, machine, repo: str) -> list[dict[str, str]]:
        """Return only current, Policy-confirmed IPv4 endpoints for one machine."""
        resolver = getattr(self.policy, "get_machine_endpoints", None)
        if not callable(resolver):
            return []
        try:
            raw_endpoints = resolver(machine, repo)
        except Exception as exc:
            logger.warning("machine endpoint policy unavailable repo=%s machine=%s reason=%s",
                           repo, getattr(machine, "alias", ""), type(exc).__name__)
            return []
        if not isinstance(raw_endpoints, list):
            return []
        primary_ip = self._canonical_primary_ipv4(
            getattr(machine, "node_host", ""),
        )
        normalized: list[dict[str, str]] = []
        seen: set[str] = set()
        for item in raw_endpoints:
            # Policy's current contract is list[dict[str, str]]. Continue
            # accepting historical string/object entries, but only values
            # returned by Policy count as endpoint confirmation.
            if isinstance(item, str):
                address, label = item, ""
            elif isinstance(item, dict):
                address, label = item.get("ip"), item.get("label", "")
            else:
                address = getattr(item, "ip", None)
                label = getattr(item, "label", "")
            endpoint = self._canonical_primary_ipv4(address)
            if not endpoint or endpoint in seen:
                continue
            seen.add(endpoint)
            normalized.append({
                "ip": endpoint,
                "label": label.strip() if isinstance(label, str) else "",
            })
        if primary_ip:
            normalized.sort(key=lambda item: item["ip"] != primary_ip)
        return normalized

    def _machine_endpoint_is_current(
        self, machine, endpoint: str, repo: str, expected_identity=None,
    ) -> bool:
        if (not self._endpoint_allowed_for_repository(
                    repo, machine, endpoint,
                )
                or endpoint not in {item["ip"] for item in self._policy_machine_endpoints(machine, repo)}):
            return False
        current_identity = self._policy_machine_identity(machine, repo)
        return (self._machine_identity_is_confirmed(current_identity)
                and (expected_identity is None or current_identity == expected_identity))

    def _machine_endpoint_has_unambiguous_identity(
        self, machine, endpoint: str, repo: str, expected_identity,
    ) -> bool:
        if not self._machine_endpoint_is_current(
                machine, endpoint, repo, expected_identity):
            return False
        try:
            peers = self.policy.get_machines(repo=repo)
        except Exception:
            return False
        if not isinstance(peers, list):
            return False
        expected_key = self._physical_machine_identity_key(expected_identity)
        if (not expected_key
                or (isinstance(expected_identity, dict)
                    and (not expected_identity.get("number")
                         or not expected_identity.get("addresses")))):
            return False
        expected_addresses = (
            expected_identity.get("addresses", [])
            if isinstance(expected_identity, dict) else []
        )
        if isinstance(expected_addresses, list) and any(
            isinstance(item, dict)
            and self._canonical_primary_ipv4(item.get("ip")) == endpoint
            and str(item.get("ambiguous", "false")).casefold() == "true"
            for item in expected_addresses
        ):
            return False
        for peer in peers:
            try:
                peer_primary = self._canonical_primary_ipv4(
                    getattr(peer, "node_host", ""),
                )
                peer_endpoints = self._policy_machine_endpoints(peer, repo)
                if endpoint not in {item["ip"] for item in peer_endpoints} and endpoint != peer_primary:
                    continue
                peer_identity = self._policy_machine_identity(peer, repo)
            except Exception:
                return False
            if (not self._machine_identity_is_confirmed(peer_identity)
                    or self._physical_machine_identity_key(peer_identity) != expected_key):
                return False
        return True

    def _endpoint_connection_fingerprint(self, machine, endpoint: str) -> tuple[str, str, str]:
        alias = str(getattr(machine, "alias", "") or "")
        token = self._agent_core_token(alias)
        return (
            str(getattr(machine, "node_id", "") or ""), endpoint,
            self._credential_fingerprint(token)
            or ("injected-factory" if self._agent_core_factory is not None else ""),
        )

    async def _core_for_machine_endpoint(
        self, machine, endpoint: str, repo: str, *, timeout: float | None = None,
    ) -> AgentCoreClient:
        """Authenticate one endpoint belonging to this exact policy machine."""
        identity = self._policy_machine_identity(machine, repo)
        if (not self._machine_identity_is_confirmed(identity)
                or not self._machine_endpoint_has_unambiguous_identity(
                    machine, endpoint, repo, identity,
                )):
            raise DeployControllerError("machine endpoint identity is not confirmed")
        endpoint = self._canonical_primary_ipv4(endpoint)
        alias = str(getattr(machine, "alias", "") or "")
        if not alias or not endpoint:
            raise DeployControllerError("machine endpoint is invalid")
        try:
            policy_status = self.policy.repo_policy_status(repo)
            machines = self.policy.get_machines(repo=repo)
        except Exception as exc:
            raise DeployControllerError(
                f"cannot verify current machine policy for {repo}: {type(exc).__name__}"
            ) from exc
        if (not isinstance(policy_status, dict)
                or policy_status.get("authorized") is not True
                or policy_status.get("machines_configured") is not True
                or not isinstance(machines, list)):
            raise DeployControllerError("current repository machine policy is unavailable")
        matches = [item for item in machines if getattr(item, "alias", None) == alias]
        if len(matches) != 1 or not self._endpoint_allowed_for_repository(
                repo, matches[0], endpoint, policy_machines=machines):
            raise DeployControllerError(
                f"machine endpoint {endpoint} is not confirmed for {alias} in {repo}"
            )
        current = matches[0]
        if str(getattr(current, "node_id", "") or "") != str(
                getattr(machine, "node_id", "") or ""):
            raise DeployControllerError("machine identity changed before Agent Core authentication")
        primary_ip = self._canonical_primary_ipv4(getattr(current, "node_host", ""))
        if endpoint == primary_ip:
            return await self._core_for_node(
                current.node_id, repo, timeout=timeout,
                record_machine_health=False,
            )
        token = self._agent_core_token(alias)
        if not token:
            raise DeployControllerError(
                f"no current agent_core_token is configured for machine {alias!r} in {repo}"
            )
        self._assert_repo_machine_credential_scope(repo, current)
        fingerprint = (
            str(getattr(current, "node_id", "") or ""), endpoint,
            self._credential_fingerprint(token),
        )
        cache_key = (repo.casefold(), f"{alias}@{endpoint}")
        cached = self._core_clients.get(cache_key)
        if cached is not None and self._core_client_fingerprints.get(cache_key) == fingerprint:
            return cached
        if cached is not None:
            await self._close_core_client(cache_key)
        endpoint_machine = copy.copy(current)
        endpoint_machine.node_host = endpoint
        client = await self._resolve_core_client(
            current.node_id, repo, machine=endpoint_machine, token=token,
            timeout=timeout, use_factory=False,
        )
        try:
            latest = self.policy.get_machines(repo=repo)
            latest_matches = [item for item in latest
                              if getattr(item, "alias", None) == alias] if isinstance(latest, list) else []
            if (len(latest_matches) != 1
                    or self._machine_connection_fingerprint(latest_matches[0])
                    != self._machine_connection_fingerprint(current)
                    or not self._endpoint_allowed_for_repository(
                        repo, latest_matches[0], endpoint, policy_machines=latest)):
                await self._close_client(client)
                raise DeployControllerError(
                    "machine identity, endpoints, or credentials changed during Agent Core authentication"
                )
        except Exception:
            await self._close_client(client)
            raise
        self._core_clients[cache_key] = client
        self._core_client_fingerprints[cache_key] = fingerprint
        return client

    async def _core_for_node(
        self, node_id: str, repo: str, *, timeout: float | None = None,
        record_machine_health: bool = True,
    ) -> AgentCoreClient:
        repo_key = repo.casefold()
        try:
            machines = self.policy.get_machines(repo=repo)
        except Exception as exc:
            await self._close_core_clients_for_repo(repo_key)
            raise DeployControllerError(
                f"cannot verify current machine policy for {repo}: {type(exc).__name__}"
            ) from exc
        if not isinstance(machines, list):
            await self._close_core_clients_for_repo(repo_key)
            raise DeployControllerError(
                f"cannot verify current machine policy for {repo}"
            )

        current_bindings: dict[tuple[str, str], tuple[str, str, str]] = {}
        for current in machines:
            alias = getattr(current, "alias", "")
            current_node_id = getattr(current, "node_id", "")
            node_host = getattr(current, "node_host", "")
            if not all(isinstance(value, str) and value for value in
                       (alias, current_node_id, node_host)):
                continue
            token = self._agent_core_token(alias)
            credential_fingerprint = self._credential_fingerprint(token)
            if self._agent_core_factory is not None and not credential_fingerprint:
                credential_fingerprint = "injected-factory"
            current_bindings[(repo_key, alias)] = (
                current_node_id, node_host, credential_fingerprint,
            )

        # Policy may refresh machine IPs, node IDs, aliases, or credentials
        # while this controller remains alive. Drop any cached connection whose
        # repository binding no longer matches the current public policy view.
        for key in list(self._core_clients):
            if key[0] != repo_key:
                continue
            if self._core_client_fingerprints.get(key) != current_bindings.get(key):
                await self._close_core_client(key)

        matches = [machine for machine in machines
                   if getattr(machine, "node_id", None) == node_id]
        if len(matches) != 1:
            detail = "not present" if not matches else "ambiguous"
            raise DeployControllerError(
                f"machine node {node_id!r} is {detail} in the current policy for {repo}; no Agent Core request was sent"
            )
        machine = matches[0]
        alias = getattr(machine, "alias", "")
        node_host = getattr(machine, "node_host", "")
        token = self._agent_core_token(alias)
        if not isinstance(node_host, str) or not node_host:
            raise DeployControllerError(
                f"machine {alias!r} has no current node_host in {repo}; no Agent Core request was sent"
            )
        if self._agent_core_factory is None and not token:
            raise DeployControllerError(
                f"no current agent_core_token is configured for machine {alias!r} in {repo}; no Agent Core request was sent"
            )
        self._assert_repo_machine_credential_scope(repo, machine)
        fingerprint = (
            node_id, node_host,
            self._credential_fingerprint(token) or "injected-factory",
        )
        key = (repo_key, alias)
        cached = self._core_clients.get(key)
        if cached is not None and self._core_client_fingerprints.get(key) == fingerprint:
            return cached
        if cached is not None:
            await self._close_core_client(key)

        try:
            client = await self._resolve_core_client(
                node_id, repo, machine=machine, token=token, timeout=timeout,
            )
        except Exception:
            if record_machine_health:
                self._record_agent_core_health(repo, machine, "unavailable")
            raise
        if any(
            key[0] != repo_key and existing is client
            for key, existing in self._core_clients.items()
        ):
            raise DeployControllerError(
                f"Agent Core client factory reused one connection across repositories for machine {alias!r}; no request was sent"
            )
        # Fail closed if the policy/credential binding changed while the new
        # client was being verified. Never cache or use a stale destination.
        try:
            refreshed = self.policy.get_machines(repo=repo)
        except Exception as exc:
            await self._close_client(client)
            raise DeployControllerError(
                f"cannot confirm current machine policy for {repo}: {type(exc).__name__}"
            ) from exc
        if not isinstance(refreshed, list):
            await self._close_client(client)
            raise DeployControllerError(
                f"cannot confirm current machine policy for {repo}"
            )
        refreshed_matches = [item for item in refreshed
                             if getattr(item, "alias", None) == alias]
        if (len(refreshed_matches) != 1
                or self._machine_connection_fingerprint(refreshed_matches[0]) != fingerprint
                or self._credential_fingerprint(self._agent_core_token(alias))
                != self._credential_fingerprint(token)):
            await self._close_client(client)
            raise DeployControllerError(
                f"machine configuration or credentials changed while verifying {alias!r} in {repo}; no deployment was started"
            )
        self._core_clients[key] = client
        self._core_client_fingerprints[key] = fingerprint
        if record_machine_health:
            self._record_agent_core_health(repo, machine, "available")
        return client

    async def _resolve_core_client(
        self, node_id: str, repo: str, *, machine=None, token: str = "",
        timeout: float | None = None, use_factory: bool = True,
    ) -> AgentCoreClient:
        if use_factory and self._agent_core_factory is not None:
            client = self._agent_core_factory(node_id)
            if client is not None:
                return client
        node_host = getattr(machine, "node_host", "") if machine is not None else ""
        if (machine is None or machine.node_id != node_id
                or not isinstance(node_host, str) or not node_host):
            raise DeployControllerError(
                f"machine node {node_id!r} is missing a configured node_host"
            )
        if not token:
            raise DeployControllerError(
                f"no agent_core_token configured for machine {machine.alias!r} in {repo}"
            )
        base_url = f"https://{node_host}:15678"
        # This deployment path keeps the policy-bound legacy HTTPS + token contract.
        core_config = copy.copy(self.config)
        core_config.agent_core_tls_mode = "legacy"
        core = AgentCoreClient(
            core_config,
            base_url,
            node_host=node_host,
            machine_alias=machine.alias,
            access_token=token,
            repository_machine=machine,
        )
        try:
            if timeout is None:
                await core.verify()
            else:
                await asyncio.wait_for(core.verify(), timeout=timeout)
        except asyncio.TimeoutError as e:
            await core.aclose()
            raise DeployControllerError(
                f"Agent Core {node_id} verification timed out"
            ) from e
        except AgentCoreError as e:
            await core.aclose()
            raise DeployControllerError(
                f"Agent Core {node_id} unreachable: {e}"
            )
        return core

    @staticmethod
    def _credential_fingerprint(token: str | None) -> str:
        if not isinstance(token, str) or not token:
            return ""
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _agent_core_token(self, alias: str) -> str:
        tokens = getattr(self.config, "agent_core_tokens", {})
        token = tokens.get(alias) if isinstance(tokens, dict) else None
        return token if isinstance(token, str) and token else ""

    def _assert_repo_machine_credential_scope(self, repo: str, machine) -> None:
        """Reject alias-only credentials when another repo maps that alias elsewhere."""
        active_repos = getattr(self.config, "active_repos", [])
        if not isinstance(active_repos, list):
            raise DeployControllerError("cannot verify active repository machine credential scope")
        for other_repo in active_repos:
            if not isinstance(other_repo, str) or other_repo.casefold() == repo.casefold():
                continue
            try:
                status = self.policy.repo_policy_status(other_repo)
                if not isinstance(status, dict):
                    raise ValueError("invalid repository policy status")
                if not status.get("machines_configured"):
                    # An unconfigured repository has no machine binding to
                    # collide with. Its own get_machines(repo=...) remains
                    # empty and therefore fails closed independently.
                    continue
                other_machines = self.policy.get_machines(repo=other_repo)
            except DeployControllerError:
                raise
            except Exception as exc:
                raise DeployControllerError(
                    f"cannot confirm machine alias credential scope for {repo}: {type(exc).__name__}"
                ) from exc
            if not isinstance(other_machines, list):
                raise DeployControllerError(
                    f"cannot confirm machine alias credential scope for {repo}"
                )
            for other in other_machines:
                if (getattr(other, "alias", "").casefold()
                        != getattr(machine, "alias", "").casefold()):
                    continue
                # The same physical machine may be independently authorized by
                # both repositories. Credentials are keyed by the exact alias,
                # so refuse any alias spelling or endpoint identity drift.
                if (
                    getattr(other, "alias", "") == getattr(machine, "alias", "")
                    and getattr(other, "node_id", "") == getattr(machine, "node_id", "")
                    and getattr(other, "node_host", "") == getattr(machine, "node_host", "")
                ):
                    continue
                raise DeployControllerError(
                    f"machine alias {machine.alias!r} is shared by {repo} and {other_repo} with conflicting machine identity; Agent Core credentials are keyed only by alias"
                )

    def _machine_connection_fingerprint(self, machine) -> tuple[str, str, str]:
        alias = getattr(machine, "alias", "")
        return (
            str(getattr(machine, "node_id", "") or ""),
            str(getattr(machine, "node_host", "") or ""),
            self._credential_fingerprint(self._agent_core_token(alias))
            or ("injected-factory" if self._agent_core_factory is not None else ""),
        )

    async def _close_core_client(self, key: tuple[str, str]) -> None:
        client = self._core_clients.pop(key, None)
        self._core_client_fingerprints.pop(key, None)
        if client is not None:
            await self._close_client(client)

    @staticmethod
    async def _close_client(client) -> None:
        try:
            await client.aclose()
        except Exception:
            pass

    async def _close_core_clients_for_repo(self, repo_key: str) -> None:
        for key in list(self._core_clients):
            if key[0] == repo_key:
                await self._close_core_client(key)

    def _get_case_runner(self) -> CaseRunner:
        if self._case_runner is None:
            self._case_runner = CaseRunner(self.config)
        return self._case_runner

    def _extract_trusted_review_evidence(self, comments: list[dict], *, head_sha: str = ""):
        # Even an injected/incomplete Config must not turn exact login matching
        # into the parser's optional ID-only compatibility path.
        author_id = self.config.review_comment_author_id
        author_login = self.config.review_comment_author_login
        if not isinstance(author_id, str) or not author_id or not isinstance(author_login, str) or not author_login:
            return None
        return extract_review_evidence(comments, author_id, author_login, head_sha=head_sha)

    async def _review_evidence_from_comments(
        self, repo: str, pr_number: int, head_sha: str, comments: list[dict],
        *, recheck_latest_comments: bool = True,
        require_exact_pr_context: bool = False,
        resolved_head: str | None = None,
        expected_review_comment_fingerprints: dict[int, dict] | None = None,
        failure_reason: list[str] | None = None,
    ):
        """Authenticate the real triggering comment and recheck HEAD after awaits.

        Parsed unbound evidence remains available for inspection, but its
        blocking flag forbids readiness, requests and pre-POST revalidation.
        """
        if failure_reason is not None:
            failure_reason.clear()

        def reject(reason: str):
            if failure_reason is not None:
                failure_reason[:] = [reason]
            if evidence is not None:
                evidence.run_binding_valid = False
            return evidence

        evidence = self._extract_trusted_review_evidence(comments, head_sha=head_sha)
        if evidence is not None and evidence.test_results_block_deployment:
            logger.warning("REVIEW_EVIDENCE_BLOCKED TEST_RESULTS_STATE=%s TEST_FAILED=%s REQUEST_RUN_BOUND=%s",
                           evidence.test_status, evidence.test_failed, evidence.run_binding_valid)
        if evidence is None:
            if failure_reason is not None:
                failure_reason[:] = ["review_incomplete_or_ambiguous"]
            return None
        if evidence.request_comment is None or not evidence.run_binding_valid:
            if failure_reason is not None:
                failure_reason[:] = ["review_source_or_run_untrusted"]
            return evidence
        request = evidence.request_comment
        original_evidence = copy.deepcopy(evidence)
        evidence.run_binding_valid = False
        try:
            fresh = await self.proxy.get_comment(repo, int(request["id"]))
            if not isinstance(fresh, dict):
                return reject("review_request_unavailable")
            for key in ("id", "body", "created_at", "updated_at", "user"):
                if fresh.get(key) != request.get(key):
                    return reject("review_request_changed")
            user = fresh["user"]
            pr = await self.proxy.get_pr(repo, pr_number)
            if not isinstance(pr, dict):
                return reject("pr_unavailable")
            if (require_exact_pr_context
                    and not self._review_recovery_pr_matches(
                        pr, repo, pr_number, head_sha,
                    )):
                return reject("pr_identity_or_status_mismatch")
            if (not isinstance(pr.get("head"), dict)
                    or pr["head"].get("sha") != head_sha or pr.get("state") != "open"
                    or pr.get("merged") or pr.get("draft") is True):
                return reject("pr_head_or_status_mismatch")
            author = pr.get("user", {})
            if (str(author.get("id", "")) != str(user["id"])
                    or author.get("login", "").casefold() != user["login"].casefold()):
                permission = await self.proxy.collaborator_permission(repo, user["login"])
                if not Policy.collaborator_can_approve(permission):
                    return reject("review_request_unauthorized")
            if (resolved_head is not None and resolved_head != head_sha):
                return reject("review_commit_resolution_failed")
            if (resolved_head is None
                    and await self._resolve_commit_prefix_for_head(
                        repo, head_sha, evidence.commit_prefix,
                    ) != head_sha):
                return reject("review_commit_resolution_failed")
            # Permission/commit lookups await GitHub too. A newer run, deleted
            # evidence or an edited result during those awaits must revoke this
            # snapshot even when the PR HEAD itself has not changed.
            if recheck_latest_comments:
                latest_comments = await self.proxy.get_issue_comments(repo, pr_number)
                if not isinstance(latest_comments, list):
                    return reject("review_comments_unavailable")
                if expected_review_comment_fingerprints is not None:
                    latest_by_id = {
                        comment.get("id"): comment for comment in latest_comments
                        if isinstance(comment, dict)
                    }
                    for comment_id, expected_fingerprint in expected_review_comment_fingerprints.items():
                        if self._review_recovery_comment_fingerprint(
                            latest_by_id.get(comment_id),
                        ) != expected_fingerprint:
                            return reject("review_comment_changed_during_check")
                if (require_exact_pr_context
                        and self._has_untrusted_newer_review_comment(
                            latest_comments, original_evidence.build_comment_id,
                        )):
                    return reject("untrusted_newer_review_run")
                latest_evidence = self._extract_trusted_review_evidence(latest_comments, head_sha=head_sha)
                if latest_evidence != original_evidence:
                    return reject("review_updated_during_check")
            final_pr = await self.proxy.get_pr(repo, pr_number)
            if (require_exact_pr_context
                    and not self._review_recovery_pr_matches(
                        final_pr, repo, pr_number, head_sha,
                    )):
                return reject("pr_identity_or_status_mismatch")
            if (not isinstance(final_pr, dict)
                    or not isinstance(final_pr.get("head"), dict)
                    or final_pr["head"].get("sha") != head_sha
                    or final_pr.get("state") != "open" or final_pr.get("merged")
                    or final_pr.get("draft") is True):
                return reject("pr_changed_during_check")
        except Exception:
            return reject("temporary_read_failure")
        evidence.head_sha = head_sha
        evidence.run_binding_valid = True
        if evidence.code_review_binding == "LEGACY_CONTIGUOUS_CHAIN_NO_DIRECT_SHA":
            logger.info("CODE_REVIEW_HEAD_BINDING=INDIRECT_LEGACY_CHAIN DIRECT_SHA_PROOF=NO build_comment_id=%s", evidence.build_comment_id)
        return evidence

    @staticmethod
    def _empty_cos() -> dict[str, Any]:
        return {"object_key": "", "sha256": "", "size": 0}

    @staticmethod
    def _review_evidence_snapshot(
        evidence: "ReviewCommentEvidence",
        resolved_head: str,
    ) -> dict:
        """Return the canonical review evidence snapshot."""
        return {
            "build_comment_id": evidence.build_comment_id,
            "build_comment_updated_at": evidence.build_comment_updated_at,
            "commit_prefix": evidence.commit_prefix,
            "resolved_head_sha": resolved_head,
            "test_comment_id": evidence.test_comment_id,
            "test_comment_updated_at": evidence.test_comment_updated_at,
            "code_review_comment_id": evidence.code_review_comment_id,
            "code_review_comment_updated_at": evidence.code_review_comment_updated_at,
            "review_author_id": evidence.review_author_id,
            "test_passed": evidence.test_passed,
            "test_failed": evidence.test_failed,
            "test_skipped": evidence.test_skipped,
        }

    @staticmethod
    def _review_evidence_identity(snapshot: dict) -> dict:
        """Return provenance fields used to identify the reviewed run.

        Test totals are evidence metadata, not a new review run.  Ignoring
        them here keeps old nine-field lifecycle snapshots migration-safe.
        """
        return {
            key: snapshot.get(key)
            for key in _REVIEW_EVIDENCE_IDENTITY_FIELDS
            if key in snapshot
        }

    def _review_recovery_state_is_eligible(
        self, state: dict, current_head: str,
    ) -> bool:
        """Allow review recovery only before any approval/deployment activity."""
        if not isinstance(state, dict) or state.get("status") != "deploy-requested":
            return False
        if state.get("head_sha") != current_head:
            return False
        review = state.get("review_evidence")
        if (not isinstance(review, dict)
                or type(review.get("build_comment_id")) is not int
                or review.get("build_comment_id", 0) <= 0
                or review.get("resolved_head_sha") != current_head
                or type(review.get("code_review_comment_id")) is not int
                or review.get("code_review_comment_id", 0) <= 0
                or not isinstance(state.get("components"), list)
                or not state.get("components")):
            return False
        command = state.get("command")
        if (not isinstance(command, dict)
                or command.get("kind") != "request_deploy"
                or command.get("phase") != "completed"
                or not isinstance(command.get("args"), dict)
                or command.get("args") != {}):
            return False
        request_comment_id = command.get("comment_id")
        cursor = state.get("last_processed_comment_id")
        if (type(request_comment_id) is not int or request_comment_id <= 0
                or type(cursor) is not int or cursor < request_comment_id):
            return False
        try:
            if round_id_for_state(state) != make_round_id(current_head, request_comment_id):
                return False
        except (TypeError, ValueError):
            return False
        if (state.get("deployments") != []
                or state.get("approve_attempts") != []
                or type(state.get("approve_attempts_total")) is not int
                or state.get("approve_attempts_total") != 0
                or state.get("approve_attempts_truncated") is not False
                or state.get("deployment_logs") not in (None, {})
                or state.get("case_results") != {}
                or state.get("test_result") != ""
                or state.get("acceptance_request") is not None
                or state.get("cos") != self._empty_cos()):
            return False
        return True

    @staticmethod
    def _review_recovery_position(comment: dict) -> tuple[datetime, int] | None:
        if (not isinstance(comment, dict) or type(comment.get("id")) is not int
                or comment["id"] <= 0):
            return None
        try:
            created = datetime.fromisoformat(
                str(comment.get("created_at", "")).replace("Z", "+00:00"),
            )
            updated = datetime.fromisoformat(
                str(comment.get("updated_at", "")).replace("Z", "+00:00"),
            )
        except (TypeError, ValueError):
            return None
        if (created.tzinfo is None or created.utcoffset() is None
                or updated.tzinfo is None or updated.utcoffset() is None
                or updated < created):
            return None
        return created, comment["id"]

    def _review_recovery_comment_is_scoped(
        self,
        repo: str,
        pr_number: int,
        comment_id: int,
        comment: dict,
        expected_author_id: str,
        expected_author_login: str,
        *,
        allow_edited: bool = False,
    ) -> bool:
        """Verify comment scope and identity, with edits allowed only by caller."""
        if (type(comment_id) is not int or comment_id <= 0
                or not isinstance(comment, dict)):
            return False
        api_base = self.config.github_api_url.rstrip("/")
        expected_url = f"{api_base}/repos/{repo}/issues/comments/{comment_id}"
        expected_issue_url = f"{api_base}/repos/{repo}/issues/{pr_number}"
        user = comment.get("user")
        return (
            type(comment.get("id")) is int and comment.get("id") == comment_id
            and isinstance(comment.get("body"), str)
            and isinstance(comment.get("created_at"), str)
            and isinstance(comment.get("updated_at"), str)
            and (allow_edited
                 or comment.get("created_at") == comment.get("updated_at"))
            and comment.get("url") == expected_url
            and comment.get("issue_url") == expected_issue_url
            and self._review_recovery_position(comment) is not None
            and isinstance(user, dict)
            and str(user.get("id", "")) == str(expected_author_id)
            and user.get("login") == expected_author_login
        )

    @staticmethod
    def _review_recovery_comment_fingerprint(comment: dict | None) -> dict | None:
        """Capture fields that must remain byte-for-byte stable across a reread."""
        if (not isinstance(comment, dict)
                or DeployController._review_recovery_position(comment) is None
                or not isinstance(comment.get("body"), str)
                or not isinstance(comment.get("user"), dict)):
            return None
        return {
            "id": comment.get("id"),
            "body": comment.get("body"),
            "created_at": comment.get("created_at"),
            "updated_at": comment.get("updated_at"),
            "url": comment.get("url"),
            "issue_url": comment.get("issue_url"),
            "user": copy.deepcopy(comment.get("user")),
        }

    def _has_untrusted_newer_review_comment(
        self, comments: list[dict], frozen_build_comment_id: int,
    ) -> bool:
        """Do not let newer untrusted Review protocol comments expose an older run."""
        from .review_comment_parser import (
            CODE_REVIEW_HEADING,
            ERROR_HEADING,
            PR_REVIEW_MARKER,
            TEST_HEADING,
            _is_review_job_anchor_body,
        )

        trusted_id = self.config.review_comment_author_id
        trusted_login = self.config.review_comment_author_login
        frozen_comment = next((comment for comment in comments
                               if isinstance(comment, dict)
                               and type(comment.get("id")) is int
                               and comment.get("id") == frozen_build_comment_id), None)
        frozen_position = self._review_recovery_position(frozen_comment)
        if frozen_position is None:
            return True
        for comment in comments:
            if not isinstance(comment, dict):
                continue
            body = str(comment.get("body", "") or "")
            is_review_protocol_comment = (
                _is_review_job_anchor_body(body)
                or (PR_REVIEW_MARKER in body and any(
                    heading in body for heading in (
                        TEST_HEADING, CODE_REVIEW_HEADING, ERROR_HEADING,
                    )
                ))
            )
            if not is_review_protocol_comment:
                continue
            user = comment.get("user", {})
            is_trusted = (
                isinstance(user, dict)
                and str(user.get("id", "")) == str(trusted_id)
                and user.get("login") == trusted_login
            )
            if is_trusted:
                continue
            position = self._review_recovery_position(comment)
            try:
                updated = datetime.fromisoformat(
                    str(comment.get("updated_at", "")).replace("Z", "+00:00"),
                )
            except (TypeError, ValueError):
                updated = None
            if (position is None
                    or comment.get("id", 0) > frozen_build_comment_id
                    or position > frozen_position
                    or (updated is not None and updated.tzinfo is not None
                        and updated.utcoffset() is not None
                        and updated > frozen_position[0])):
                return True
        return False

    @staticmethod
    def _review_recovery_pr_matches(
        pr: dict, repo: str, pr_number: int, expected_head: str,
    ) -> bool:
        if (not isinstance(pr, dict) or type(pr.get("number")) is not int
                or pr.get("number") != pr_number or pr.get("state") != "open"
                or pr.get("merged") is not False or pr.get("draft") is not False):
            return False
        base = pr.get("base")
        base_repo = base.get("repo") if isinstance(base, dict) else None
        if (not isinstance(base_repo, dict)
                or not isinstance(base_repo.get("full_name"), str)
                or base_repo["full_name"].casefold() != repo.casefold()):
            return False
        head = pr.get("head")
        sha = head.get("sha") if isinstance(head, dict) else None
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
            return False
        user = pr.get("user")
        if (not isinstance(user, dict) or not str(user.get("id", "")).isdigit()
                or not isinstance(user.get("login"), str) or not user["login"]):
            return False
        return sha == expected_head

    async def _review_recovery_candidate(
        self,
        repo: str,
        pr_number: int,
        state: dict,
        expected_head: str,
        *,
        final_recheck: bool = True,
    ) -> tuple[str, dict | None]:
        """Return a fully revalidated newer Review Run, or a fail-closed reason."""
        if not self._review_recovery_state_is_eligible(state, expected_head):
            return "lifecycle_not_safely_recoverable", None
        try:
            comments = await self.proxy.get_issue_comments(repo, pr_number)
        except Exception:
            return "temporary_read_failure", None
        if not isinstance(comments, list):
            return "temporary_read_failure", None

        from .commands import _iter_top_level_command_lines, parse_command
        from .review_comment_parser import (
            _parse_review_request,
            extract_latest_review_job_anchor,
        )
        cursor = state["last_processed_comment_id"]
        for comment in comments:
            if (not isinstance(comment, dict) or type(comment.get("id")) is not int
                    or comment["id"] <= cursor
                    or not isinstance(comment.get("body"), str)):
                continue
            if parse_command(comment["body"]).kind == "approve_deploy":
                return "approval_command_pending", None
        author_id = self.config.review_comment_author_id
        author_login = self.config.review_comment_author_login
        if (not isinstance(author_id, str) or not author_id
                or not isinstance(author_login, str) or not author_login):
            return "review_agent_identity_unconfigured", None
        saved_review = state["review_evidence"]
        old_build_id = saved_review["build_comment_id"]
        if self._has_untrusted_newer_review_comment(comments, old_build_id):
            return "untrusted_newer_review_run", None

        latest_anchor = extract_latest_review_job_anchor(
            comments, author_id, author_login,
        )
        if latest_anchor is None:
            return "no_trusted_review_run", None
        review_comments = {
            comment["id"]: comment for comment in comments
            if isinstance(comment, dict) and type(comment.get("id")) is int
        }
        old_comment = review_comments.get(old_build_id)
        if latest_anchor.comment_id == old_build_id:
            if (old_comment is not None
                    and old_comment.get("updated_at")
                    == saved_review.get("build_comment_updated_at")):
                return "no_new_review_run", None
            return "frozen_review_comment_changed", None
        if latest_anchor.state == "reviewing":
            return "latest_review_still_running", None
        if latest_anchor.state == "terminal":
            return "latest_review_failed", None
        if latest_anchor.state != "build-succeeded":
            return "latest_review_state_ambiguous", None
        if old_comment is None:
            return "frozen_review_origin_unverifiable", None

        old_anchor = extract_latest_review_job_anchor(
            [old_comment], author_id, author_login,
        )
        old_position = self._review_recovery_position(old_comment)
        new_anchor_comment = review_comments.get(latest_anchor.comment_id)
        new_position = self._review_recovery_position(new_anchor_comment)
        if (old_anchor is None or old_position is None or new_position is None
                or old_anchor.comment_id != old_build_id
                or old_anchor.state != "build-succeeded"
                or old_anchor.commit_prefix != saved_review.get("commit_prefix")
                or old_comment.get("updated_at") != saved_review.get("build_comment_updated_at")
                or new_anchor_comment.get("updated_at") != latest_anchor.updated_at
                or latest_anchor.comment_id <= max(
                    state["command"]["comment_id"], old_build_id,
                )
                or not old_position < new_position):
            return "review_run_identity_mismatch", None

        try:
            pr = await self.proxy.get_pr(repo, pr_number)
        except Exception:
            return "temporary_read_failure", None
        pr_head = pr.get("head", {}).get("sha") if isinstance(pr, dict) else None
        if pr_head != expected_head:
            return "head_changed", None
        if not self._review_recovery_pr_matches(pr, repo, pr_number, expected_head):
            return "pr_identity_or_status_mismatch", None

        request_id = state["command"]["comment_id"]
        try:
            original_request = await self.proxy.get_comment(repo, request_id)
        except Exception:
            return "temporary_read_failure", None
        original_body = original_request.get("body", "") if isinstance(original_request, dict) else ""
        request_lines = [
            line for line in _iter_top_level_command_lines(original_body)
            if re.match(r"^/request_deploy(?:\s|$)", line, re.I)
        ] if isinstance(original_body, str) else []
        parsed_original = parse_command(original_body) if isinstance(original_body, str) else None
        pr_author = pr.get("user", {})
        if (not isinstance(original_request, dict)
                or type(original_request.get("id")) is not int
                or original_request.get("id") != request_id
                or not request_lines or len(request_lines) != 1
                or parsed_original is None or parsed_original.kind != "request_deploy"
                or self.proxy.is_bot_comment(original_request)
                or original_request.get("url")
                != f"{self.config.github_api_url.rstrip('/')}/repos/{repo}/issues/comments/{request_id}"
                or original_request.get("issue_url")
                != f"{self.config.github_api_url.rstrip('/')}/repos/{repo}/issues/{pr_number}"
                or original_request.get("created_at") != original_request.get("updated_at")
                or self._review_recovery_position(original_request) is None
                or not isinstance(original_request.get("user"), dict)
                or str(original_request["user"].get("id", "")) != str(pr_author.get("id", ""))
                or not isinstance(original_request["user"].get("login"), str)
                or not isinstance(pr_author.get("login"), str)
                or original_request["user"]["login"].casefold()
                != pr_author["login"].casefold()):
            return "original_request_identity_unverifiable", None
        original_request_position = self._review_recovery_position(original_request)
        if (original_request_position is None
                or not original_request_position < new_position):
            return "review_run_order_mismatch", None

        try:
            resolved_head = await self.github.resolve_commit_sha(
                repo, latest_anchor.commit_prefix,
            )
        except Exception as exc:
            status_code = getattr(exc, "status_code", None)
            if status_code in {400, 404, 422}:
                return "review_commit_identity_mismatch", None
            return "temporary_read_failure", None
        if not isinstance(resolved_head, str) or not re.fullmatch(r"[0-9a-f]{40}", resolved_head):
            return "review_commit_identity_mismatch", None
        if resolved_head != expected_head:
            return "review_head_mismatch", None

        evidence = self._extract_trusted_review_evidence(comments, head_sha=expected_head)
        if evidence is None:
            return "latest_review_incomplete_or_ambiguous", None
        if (not evidence.run_binding_valid
                or evidence.build_comment_id != latest_anchor.comment_id
                or evidence.review_author_id != author_id
                or evidence.review_author_login != author_login
                or evidence.commit_prefix != latest_anchor.commit_prefix
                or evidence.test_results_block_deployment):
            return "review_source_or_matrix_untrusted", None
        request_comment = evidence.request_comment
        parsed_request = _parse_review_request(
            str((request_comment or {}).get("body", "")),
        )
        request_position = self._review_recovery_position(request_comment)
        if (parsed_request is None or not parsed_request.get("valid")
                or not isinstance(request_comment, dict)
                or type(request_comment.get("id")) is not int
                or request_comment.get("id") <= request_id
                or request_position is None
                or not original_request_position < request_position
                or not request_position < new_position):
            return "review_request_identity_mismatch", None

        if (not evidence.test_comment_id
                and not (evidence.skip_tests_requested and evidence.test_skipped)):
            return "review_test_evidence_incomplete", None
        if (request_comment.get("created_at") != request_comment.get("updated_at")
                or request_comment.get("id") not in review_comments
                or not isinstance(request_comment.get("user"), dict)):
            return "review_request_was_edited_or_mismatched", None

        build_comment = review_comments.get(evidence.build_comment_id)
        if (not isinstance(build_comment, dict)
                or build_comment.get("id") != latest_anchor.comment_id
                or build_comment.get("created_at") != evidence.build_comment_created_at
                or build_comment.get("updated_at") != evidence.build_comment_updated_at
                or build_comment.get("updated_at") != latest_anchor.updated_at
                or self._review_recovery_position(build_comment) is None):
            return "review_build_identity_or_time_mismatch", None

        immutable_result_sources = [
            (evidence.code_review_comment_id, evidence.code_review_created_at,
             evidence.code_review_comment_updated_at),
        ]
        if evidence.test_comment_id:
            immutable_result_sources.append((
                evidence.test_comment_id, evidence.test_comment_created_at,
                evidence.test_comment_updated_at,
            ))
        elif not (evidence.skip_tests_requested and evidence.test_skipped):
            return "review_test_evidence_incomplete", None
        for comment_id, created_at, updated_at in immutable_result_sources:
            listed = review_comments.get(comment_id)
            if (not isinstance(listed, dict)
                    or listed.get("created_at") != created_at
                    or listed.get("updated_at") != updated_at
                    or created_at != updated_at):
                return "review_result_was_edited_or_mismatched", None

        scoped_ids = [
            (request_comment["id"], request_comment["user"].get("id"),
             request_comment["user"].get("login"), False),
            (old_build_id, author_id, author_login, True),
            (evidence.build_comment_id, author_id, author_login, True),
        ]
        scoped_ids.extend(
            (comment_id, author_id, author_login, False)
            for comment_id, _, _ in immutable_result_sources
        )
        for comment_id, expected_id, expected_login, allow_edited in scoped_ids:
            listed = review_comments.get(comment_id)
            if (not isinstance(listed, dict)
                    or not self._review_recovery_comment_is_scoped(
                        repo, pr_number, comment_id, listed,
                        str(expected_id), expected_login,
                        allow_edited=allow_edited,
                    )):
                return "review_comment_identity_mismatch", None

        prior_result_sources = [
            (saved_review.get("code_review_comment_id"),
             saved_review.get("code_review_comment_updated_at")),
        ]
        if saved_review.get("test_comment_id"):
            prior_result_sources.append((
                saved_review.get("test_comment_id"),
                saved_review.get("test_comment_updated_at"),
            ))
        for comment_id, persisted_updated_at in prior_result_sources:
            prior = review_comments.get(comment_id)
            if (type(comment_id) is not int or not isinstance(prior, dict)
                    or prior.get("updated_at") != persisted_updated_at
                    or prior.get("created_at") != persisted_updated_at
                    or not self._review_recovery_comment_is_scoped(
                        repo, pr_number, comment_id, prior, author_id, author_login,
                    )):
                return "frozen_review_result_was_edited_or_mismatched", None

        expected_comment_fingerprints = {}
        for comment_id in {
            request_comment["id"], old_build_id, evidence.build_comment_id,
            evidence.code_review_comment_id,
            *([evidence.test_comment_id] if evidence.test_comment_id else []),
        }:
            fingerprint = self._review_recovery_comment_fingerprint(
                review_comments.get(comment_id),
            )
            if fingerprint is None:
                return "review_comment_identity_mismatch", None
            expected_comment_fingerprints[comment_id] = fingerprint

        validation_reason: list[str] = []
        validated = await self._review_evidence_from_comments(
            repo, pr_number, expected_head, comments,
            recheck_latest_comments=final_recheck,
            require_exact_pr_context=True,
            resolved_head=resolved_head,
            expected_review_comment_fingerprints=expected_comment_fingerprints,
            failure_reason=validation_reason,
        )
        if validated is None:
            return (validation_reason[0] if validation_reason
                    else "latest_review_incomplete_or_ambiguous"), None
        if not validated.run_binding_valid or validated.head_sha != expected_head:
            reason = validation_reason[0] if validation_reason else "review_source_or_run_untrusted"
            if reason in {
                "temporary_read_failure", "review_request_unavailable",
                "pr_unavailable", "review_comments_unavailable",
                "review_commit_resolution_failed",
            }:
                return "temporary_read_failure", None
            if reason == "review_updated_during_check":
                return reason, None
            return reason, None
        evidence = validated

        builds = self._review_build_infos(repo, evidence)
        try:
            components = await self._build_component_snapshot(
                repo, pr_number, expected_head, builds,
            )
        except Exception:
            return "review_component_identity_unavailable", None
        if (not components or any(
                item.get("image_ref") != item.get("review_image_tag")
                or item.get("resolved_platform") != get_deploy_platform()
                for item in components)):
            return "review_component_matrix_or_image_mismatch", None
        snapshot = self._review_evidence_snapshot(evidence, resolved_head)
        fingerprint = self._review_recovery_fingerprint(
            evidence, snapshot, components, expected_comment_fingerprints,
        )
        return "ready", {
            "evidence": evidence,
            "snapshot": snapshot,
            "components": components,
            "builds": builds,
            "fingerprint": fingerprint,
            "head_sha": expected_head,
        }

    @staticmethod
    def _review_recovery_fingerprint(
        evidence: "ReviewCommentEvidence", snapshot: dict,
        components: list[dict],
        comment_fingerprints: dict[int, dict],
    ) -> dict:
        request = evidence.request_comment or {}
        user = request.get("user", {}) if isinstance(request, dict) else {}
        return {
            "snapshot": copy.deepcopy(snapshot),
            "request": {
                "id": request.get("id"),
                "body": request.get("body"),
                "created_at": request.get("created_at"),
                "updated_at": request.get("updated_at"),
                "url": request.get("url"),
                "issue_url": request.get("issue_url"),
                "user_id": user.get("id") if isinstance(user, dict) else None,
                "user_login": user.get("login") if isinstance(user, dict) else None,
            },
            "build_created_at": evidence.build_comment_created_at,
            "test_created_at": evidence.test_comment_created_at,
            "code_review_created_at": evidence.code_review_created_at,
            "code_review_text": evidence.code_review_text,
            "code_review_binding": evidence.code_review_binding,
            "skip_tests_requested": evidence.skip_tests_requested,
            "builds": [
                (build.target, build.driver_path, build.variant,
                 build.success, build.image_tag)
                for build in evidence.builds
            ],
            "components": DeployController._canonical_component_snapshot(components),
            "comments": {
                comment_id: copy.deepcopy(comment_fingerprints[comment_id])
                for comment_id in sorted(comment_fingerprints)
            },
        }

    async def _recover_deploy_requested_review(
        self, repo: str, pr_number: int, state: dict, current_head: str,
    ) -> dict:
        """Supersede an untouched frozen request after a verified newer Review Run."""
        status, candidate = await self._review_recovery_candidate(
            repo, pr_number, state, current_head, final_recheck=False,
        )
        if status != "ready" or candidate is None:
            if status not in {"no_new_review_run", "lifecycle_not_safely_recoverable"}:
                logger.debug(
                    "review recovery deferred %s#%s reason=%s",
                    repo, pr_number, status,
                )
            return state

        evidence = candidate["evidence"]
        next_state = copy.deepcopy(state)
        review_comment_ids = [
            evidence.build_comment_id,
            evidence.code_review_comment_id,
            evidence.request_comment["id"],
        ]
        if evidence.test_comment_id:
            review_comment_ids.append(evidence.test_comment_id)
        cursor = max(
            int(state.get("last_processed_comment_id", 0) or 0),
            *review_comment_ids,
        )
        next_state["status"] = "deploy-ready"
        next_state["review_evidence"] = candidate["snapshot"]
        next_state["components"] = candidate["components"]
        next_state.pop("runtime_checks", None)
        next_state.pop("runtime_redeploy", None)
        next_state["last_processed_comment_id"] = cursor
        next_state["round_id"] = make_round_id(
            current_head, evidence.build_comment_id,
        )
        next_state["round_started_at"] = utc_now()
        next_state["command"] = {
            "comment_id": cursor,
            "kind": "",
            "phase": "completed",
            "args": {},
        }
        # Consume commands posted before the complete Review result, while
        # preserving monotonicity. The next deploy request must follow the
        # newest reviewed comment. The history-aware writer archives the
        # frozen request once and links it to the existing chain.
        event = {
            "event": "New trusted Review Run invalidated the frozen deployment request",
            "lifecycle": "`deploy-requested` → `deploy-ready`",
            "review_build_comment_id": evidence.build_comment_id,
            "review_code_comment_id": evidence.code_review_comment_id,
            "timestamp": comments_mod.beijing_now_str(),
        }

        async def guard_latest_review() -> bool:
            guard_status, latest = await self._review_recovery_candidate(
                repo, pr_number, state, current_head,
            )
            return (
                guard_status == "ready" and latest is not None
                and latest["fingerprint"] == candidate["fingerprint"]
            )

        all_machine_groups = self._get_machine_groups_for_components(
            candidate["components"], repo,
        )
        verified_groups = await self._machine_groups_verify_endpoints(
            all_machine_groups, repo, candidate["components"],
        )
        markdown = comments_mod.deploy_ready(
            repo, pr_number, current_head, candidate["builds"],
            review_evidence=candidate["snapshot"],
            machine_groups=verified_groups,
            components=candidate["components"],
        )
        try:
            written = await self._write_lifecycle_with_history(
                repo, pr_number, next_state, markdown, event=event,
                expected_lifecycle_state=state, write_guard=guard_latest_review,
                archive_reason=(
                    "New trusted Review Run invalidated frozen deployment request"
                ),
            )
        except Exception:
            logger.warning("review recovery write failed %s#%s", repo, pr_number)
            return state
        if not written:
            return state
        await self._post_deploy_ready_notice(
            repo, pr_number, head_sha=current_head,
            round_id=round_id_for_state(next_state),
            review_evidence=candidate["snapshot"],
            components=candidate["components"],
        )
        return next_state

    async def _resolve_commit_prefix_for_head(
        self,
        repo: str,
        fresh_head: str,
        commit_prefix: str,
    ) -> str | None:
        """Resolve commit_prefix to full SHA and verify == fresh_head."""
        if not isinstance(fresh_head, str) or not re.fullmatch(r"[0-9a-f]{40}", fresh_head):
            return None
        if not isinstance(commit_prefix, str) or not re.fullmatch(r"[0-9a-f]{7,40}", commit_prefix):
            return None
        try:
            resolved = await self.github.resolve_commit_sha(repo, commit_prefix)
        except Exception as e:
            logger.warning("resolve_commit_sha %s %s: %s", repo, commit_prefix, e)
            return None
        if not isinstance(resolved, str) or not re.fullmatch(r"[0-9a-f]{40}", resolved):
            logger.warning("resolve_commit_sha returned malformed sha: %r", resolved)
            return None
        if resolved != fresh_head:
            return None
        return resolved

    def _init_hidden_state(
        self,
        *,
        head_sha: str,
        status: str,
        review_evidence: dict | None = None,
        components: list[dict] | None = None,
        deployments: list[dict] | None = None,
    ) -> dict:
        state = {
            "version": 1,
            "head_sha": head_sha,
            "status": status,
            "review_evidence": dict(review_evidence or {}),
            "components": list(components or []),
            "deployments": list(deployments or []),
            "case_results": {},
            "test_result": "",
            "cos": self._empty_cos(),
            "approve_attempts": [],
            "approve_attempts_total": 0,
            "approve_attempts_truncated": False,
            "command": {
                "comment_id": 0,
                "kind": "",
                "phase": "completed",
                "args": {},
            },
            "last_processed_comment_id": 0,
            "round_archive": None,
        }
        self._validate_hidden_state(state)
        return state

    def _record_approve_attempt(self, state: dict, attempt: dict) -> None:
        attempts = list(state.get("approve_attempts", []))
        attempts_total = int(state.get("approve_attempts_total", 0) or 0)
        attempts_total += 1
        attempts.append(attempt)
        if len(attempts) > MAX_RECENT_APPROVE_ATTEMPTS:
            attempts = attempts[-MAX_RECENT_APPROVE_ATTEMPTS:]
        state["approve_attempts"] = attempts
        state["approve_attempts_total"] = attempts_total
        state["approve_attempts_truncated"] = attempts_total > len(attempts)

    @staticmethod
    def _reset_review_lifecycle_state(
        state: dict,
        *,
        head_sha: str,
        status: str,
        review_evidence: dict | None = None,
    ) -> None:
        state["head_sha"] = head_sha
        state["round_id"] = make_round_id(
            head_sha, int(state.get("last_processed_comment_id", 0) or 0),
        )
        state["round_started_at"] = utc_now()
        state.pop("deployment_logs", None)
        state.pop("runtime_checks", None)
        state.pop("runtime_redeploy", None)
        state["status"] = status
        state["review_evidence"] = dict(review_evidence or {})
        state["components"] = []
        state["deployments"] = []
        state["approve_attempts"] = []
        state["approve_attempts_total"] = 0
        state["approve_attempts_truncated"] = False
        state["case_results"] = {}
        state["test_result"] = ""
        state.pop("acceptance_request", None)
        state["cos"] = {"object_key": "", "sha256": "", "size": 0}
        state["command"] = {
            "comment_id": int(state.get("last_processed_comment_id", 0) or 0),
            "kind": "",
            "phase": "completed",
            "args": {},
        }

    @staticmethod
    def _canonical_component_snapshot(components: list[dict]) -> list[dict]:
        canonical: list[dict] = []
        for component in components or []:
            if not isinstance(component, dict):
                continue
            canonical.append({
                "component_id": str(component.get("component_id", "") or ""),
                "target": str(component.get("target", "") or ""),
                "driver_path": str(component.get("driver_path", "") or ""),
                "variant": str(component.get("variant", "") or ""),
                "review_image_tag": str(component.get("review_image_tag", "") or ""),
                "image_ref": str(component.get("image_ref", "") or ""),
                "resolved_platform": str(component.get("resolved_platform", "") or ""),
            })
        canonical.sort(key=lambda comp: comp["component_id"])
        return canonical

    @staticmethod
    def _fresh_component_runtime_binding(component: dict) -> dict:
        """Normalize runtime identity for a fresh component snapshot.

        Core is its own runtime and therefore carries a static binding from
        the review snapshot onward.  Other targets are dynamically resolved
        during preflight; a fresh snapshot must not retain an old binding.
        """
        item = dict(component)
        if item.get("target") == "core":
            item["runtime_id"] = "core"
        else:
            item.pop("runtime_id", None)
        return item

    @staticmethod
    def _components_with_preserved_runtime_bindings(
        fresh_components: list[dict],
        old_components: list[dict],
        deployments: list[dict],
    ) -> list[dict] | None:
        deployed_component_ids: set[str] = set()
        for deployment in deployments or []:
            if not isinstance(deployment, dict):
                return None
            if deployment.get("phase") != "deployed":
                continue
            component_ids = deployment.get("component_ids", [])
            if not isinstance(component_ids, list) or not component_ids:
                return None
            for component_id in component_ids:
                if not isinstance(component_id, str) or not component_id:
                    return None
                deployed_component_ids.add(component_id)

        old_runtime_bindings: dict[str, str] = {}
        for component in old_components or []:
            if not isinstance(component, dict):
                return None
            component_id = component.get("component_id", "")
            if not isinstance(component_id, str) or not component_id:
                return None
            runtime_id = component.get("runtime_id")
            if component_id in deployed_component_ids and component.get("target") != "core":
                if not isinstance(runtime_id, str) or not runtime_id:
                    return None
                old_runtime_bindings[component_id] = runtime_id

        rebuilt: list[dict] = []
        for component in fresh_components or []:
            if not isinstance(component, dict):
                return None
            item = dict(component)
            component_id = item.get("component_id", "")
            if not isinstance(component_id, str) or not component_id:
                return None
            item = DeployController._fresh_component_runtime_binding(item)
            if component_id in deployed_component_ids and item.get("target") != "core":
                runtime_id = old_runtime_bindings.get(component_id)
                if not isinstance(runtime_id, str) or not runtime_id:
                    return None
                item["runtime_id"] = runtime_id
            rebuilt.append(item)
        return rebuilt

    @staticmethod
    def _component_semantic_key(component: dict) -> tuple:
        """Stable semantic key for migration compatibility.

        Based ONLY on identity fields, NOT on image_ref/digest/runtime_id.
        """
        return (
            component.get("target", ""),
            component.get("driver_path", ""),
            component.get("variant", ""),
            component.get("review_image_tag", ""),
        )

    def _review_build_infos(self, repo: str, evidence: "ReviewCommentEvidence") -> list[BuildInfo]:
        """Keep deployment candidates while ignoring the legacy CORE summary row.

        ``CORE`` (uppercase) is a non-deployable aggregate row in the legacy
        alignment scenario. It must never be normalized into the deployable
        ``core`` target. Keeping it beside a real component rejected the entire
        snapshot, even when the requested deployable matrix was valid.
        All other rows remain subject to the existing strict target/build
        checks in ``_build_component_snapshot``.
        """
        return [
            BuildInfo(
                target=build.target,
                driver_path=build.driver_path,
                variant=build.variant,
                success=build.success,
                image_tag=build.image_tag,
                deployable=_is_deployable_build(repo, build, self.config.github_repos),
            )
            for build in evidence.builds
            if not (
                str(getattr(build, "target", "") or "").strip() == "CORE"
                and not str(getattr(build, "driver_path", "") or "").strip()
                and not str(getattr(build, "variant", "") or "").strip()
            )
        ]

    async def _build_component_snapshot(
        self,
        repo: str,
        pr_number: int,
        head_sha: str,
        builds: list[BuildInfo],
    ) -> list[dict] | None:
        """Build component snapshot from trusted Review Agent build evidence.

        No Registry access.  Image references come directly from the trusted
        GitHub comment.  Platform is policy-derived (linux/arm64).
        """
        if not builds:
            return None
        snapshot: list[dict] = []
        seen_semantic_keys: set[tuple] = set()
        for build in builds:
            # A requested matrix is indivisible: never deploy its successful subset.
            if (not build.success or not build.deployable
                    or not _is_deployable_build(repo, build, self.config.github_repos)):
                return None
            review_image_tag = str(build.image_tag or "")
            if not review_image_tag:
                return None
            try:
                validated_tag = validate_image_ref(review_image_tag)
            except ValueError:
                return None
            resolved_platform = get_deploy_platform()
            if not resolved_platform:
                return None
            component_id = hashlib.sha256(
                f"{build.target}|{build.driver_path}|{build.variant}|{validated_tag}".encode()
            ).hexdigest()[:16]
            skey = (
                build.target,
                build.driver_path,
                build.variant,
            )
            if skey in seen_semantic_keys:
                return None
            seen_semantic_keys.add(skey)
            component = {
                "component_id": component_id,
                "target": build.target,
                "driver_path": build.driver_path,
                "variant": build.variant,
                "review_image_tag": validated_tag,
                "image_ref": validated_tag,
                "resolved_platform": resolved_platform,
            }
            if build.target == "core":
                component["driver_path"] = ""
                component["variant"] = ""
                component["runtime_id"] = "core"
            snapshot.append(component)
        return snapshot

    async def _rebind_terminal_cos_if_current(
        self,
        repo: str,
        pr_number: int,
        *,
        expected_head: str,
        expected_terminal_status: str,
        expected_comment_id: int,
        expected_command_kind: str,
        expected_test_result: str = "",
        cos_metadata: dict[str, Any] | None = None,
        markdown: str = "",
        expected_state: dict | None = None,
    ) -> bool:
        fresh_state = await self.proxy.read_hidden_state(repo, pr_number)
        if fresh_state is None:
            return False
        if expected_state is not None and fresh_state != expected_state:
            return False
        if fresh_state.get("head_sha", "") != expected_head:
            return False
        if fresh_state.get("status", "") != expected_terminal_status:
            return False
        cmd = fresh_state.get("command", {})
        if not isinstance(cmd, dict):
            return False
        if cmd.get("comment_id", 0) != expected_comment_id:
            return False
        if cmd.get("kind", "") != expected_command_kind:
            return False
        if cmd.get("phase", "") != "completed":
            return False
        if expected_test_result and fresh_state.get("test_result", "") != expected_test_result:
            return False

        # T4: expected_comment_id must be a valid positive integer (not bool)
        if isinstance(expected_comment_id, bool) or not isinstance(expected_comment_id, int):
            return False
        if expected_comment_id <= 0:
            return False

        # Read-only commands may have advanced the cursor after finalization.
        # A full expected_state snapshot still guards every field during rebind.
        cursor_val = int(fresh_state.get("last_processed_comment_id", 0) or 0)
        if cursor_val < expected_comment_id or (expected_state is None and cursor_val != expected_comment_id):
            return False

        # T4: command.args.result must match expected_test_result
        if expected_test_result:
            cmd_args = cmd.get("args", {})
            if not isinstance(cmd_args, dict):
                cmd_args = {}
            if cmd_args.get("result", "") != expected_test_result:
                return False

        metadata = cos_metadata or {}
        object_key = str(metadata.get("object_key", "") or "")
        sha256_val = str(metadata.get("sha256", "") or "")
        size_val = metadata.get("size", 0)

        if not object_key:
            return False

        # Strict object_key layout validation
        try:
            from .cos_client import CosClient
            CosClient.validate_object_key(
                repo, pr_number, expected_head, object_key,
            )
        except Exception:
            return False

        # SHA256 must be 64-char lowercase hex
        if not sha256_val or not re.fullmatch(r"[0-9a-f]{64}", sha256_val):
            return False

        # Size must be int (not bool) in range 1..10MiB
        if not (isinstance(size_val, int) and not isinstance(size_val, bool)
                and 1 <= size_val <= 10485760):
            return False

        # Existing COS conflict check — do not overwrite different evidence
        existing_cos = fresh_state.get("cos", {}) or {}
        existing_key = str(existing_cos.get("object_key", "") or "")
        if existing_key:
            if existing_key != object_key:
                return False
            if existing_cos.get("sha256", "") != sha256_val:
                return False
            existing_size = existing_cos.get("size", 0)
            if not (isinstance(existing_size, int) and not isinstance(existing_size, bool)
                    and existing_size == size_val):
                return False

        expected_terminal_state = copy.deepcopy(fresh_state)
        fresh_state = copy.deepcopy(fresh_state)
        fresh_state["cos"] = {
            "object_key": object_key,
            "sha256": sha256_val,
            "size": size_val,
        }
        if markdown:
            # Terminal rebind must NOT bypass the history-aware lifecycle writer:
            # a direct write_hidden_state would replace the visible lifecycle and
            # drop the existing visible History (Test recorded, deployments, ...).
            # event=None: refresh terminal rendering + state.cos only — the
            # history-preserving writer carries existing events over verbatim.
            await self._preflight_archive_for_event(repo, pr_number, markdown)
            return await self._write_lifecycle_with_history(
                repo, pr_number, fresh_state, markdown, event=None,
                expected_terminal_state=expected_terminal_state,
            )
        return False  # No lifecycle write was performed.

    def _resolve_component_runtime(
        self,
        drivers: list[dict],
        component: dict,
    ) -> dict[str, str] | None:
        """Resolve the exact Agent Core runtime id for one component.

        Perception: runtime id must be EXACT perception.
        ActuCore: runtime id must be EXACT actucore.
        Driver: exact 1-to-1 match on image repository from Agent Core catalog
        entry image metadata.  running_image is never used for
        resolution — the deploy state is the authoritative reference.

        No fallback, no substring, no fuzzy matching.
        """
        target = str(component.get("target", "") or "")
        if target in {"perception", "actucore"}:
            exact = [
                d for d in drivers
                if isinstance(d, dict)
                and str(d.get("id", "") or "") == target
            ]
            if len(exact) != 1:
                return None
            runtime_id = str(exact[0].get("id") or "")
            if not runtime_id:
                return None
            return {
                "runtime_id": runtime_id,
                "runtime_repo": _image_repository(
                    str(exact[0].get("image", "") or "")
                ),
            }

        if target != "driver":
            return None

        want_repo = _image_repository(str(component.get("image_ref", "") or ""))
        if not want_repo:
            return None

        matches: list[dict] = []
        for driver in drivers:
            if not isinstance(driver, dict):
                continue
            if str(driver.get("category", "") or "").strip() != "driver":
                continue
            # Agent Core entry must have image repository metadata
            driver_image = str(driver.get("image", "") or "").strip()
            if not driver_image:
                continue
            runtime_repo = _image_repository(driver_image)
            if not runtime_repo or runtime_repo != want_repo:
                continue
            matches.append(driver)

        if len(matches) == 1:
            runtime_id = str(matches[0].get("id") or "")
            if not runtime_id:
                return None
            return {
                "runtime_id": runtime_id,
                "runtime_repo": want_repo,
            }

        return None

    # ── Command handlers ──

    @staticmethod
    def _command_pr_gate_error(pr_data: dict, command: str) -> str:
        """Explain why a lifecycle command cannot run for this PR state."""
        state = str(pr_data.get("state", "unknown") or "unknown").casefold()
        if state != "open" or pr_data.get("merged"):
            return "这个 PR 已经关闭或合并，部署命令不再适用。"
        if pr_data.get("draft"):
            return "这个 PR 还是草稿，部署命令暂时不可用。"
        return ""

    async def _restore_interrupted_approval_preflight(
        self, repo: str, pr_number: int, *, reason: str, topic: str,
        require_stale: bool, expected_comment_id: int | None = None,
    ) -> bool:
        """Return an approval to its source state when no deploy POST could have started."""
        try:
            pr = await self.proxy.get_pr(repo, pr_number)
            state = await self.proxy.read_hidden_state(repo, pr_number)
        except Exception:
            return False
        if (not isinstance(pr, dict) or pr.get("state") != "open"
                or pr.get("merged") or pr.get("draft")
                or not isinstance(state, dict)
                or pr.get("head", {}).get("sha") != state.get("head_sha")):
            return False
        command = state.get("command", {})
        args = command.get("args", {}) if isinstance(command, dict) else {}
        if (state.get("status") not in {
                    "deploying", "deploy-ready", "deploy-requested",
                }
                or not isinstance(command, dict)
                or command.get("kind") != "approve_deploy"
                or command.get("phase") != "completed"
                or (expected_comment_id is not None
                    and command.get("comment_id") != expected_comment_id)
                or not isinstance(args, dict)
                or args.get("preflight_pending") is not True):
            return False
        if require_stale:
            try:
                timeout = max(900.0, float(self.config.total_timeout) * 3.0)
                started_at = float(args.get("preflight_started_at"))
            except (TypeError, ValueError, OverflowError):
                return False
            if started_at <= 0 or time.time() - started_at < timeout:
                return False

        restored = copy.deepcopy(state)
        restored["status"] = self._approval_retry_status(restored)
        clean_args = dict(args)
        for key in (
            "preflight_pending", "preflight_started_at", "node_id",
            "node_host", "pending_component_ids",
        ):
            clean_args.pop(key, None)
        restored["command"] = {
            "comment_id": command.get("comment_id", 0),
            "kind": "approve_deploy",
            "phase": "completed",
            "args": clean_args,
        }
        deployed_ids = _component_id_set(restored.get("deployments", []))
        remaining = [
            component for component in restored.get("components", [])
            if isinstance(component, dict)
            and component.get("component_id") not in deployed_ids
        ]
        try:
            groups = (
                self._runtime_redeploy_machine_groups(restored, remaining, repo)
                if restored.get("runtime_redeploy") else
                self._get_machine_groups_for_components(remaining, repo)
            )
        except Exception:
            groups = []
        next_step = "请按 PR Summary 中当前显示的机器命令重新审批。"
        markdown = await self._approval_retry_markdown(
            repo, pr_number, restored, groups,
            test_only=self._is_test_only_pr(pr),
            deployments=self._enrich_deployments_for_render(
                restored.get("deployments", []), repo,
            ),
            gate_note=[reason, next_step],
        )
        written = await self._write_lifecycle_with_history(
            repo, pr_number, restored, markdown,
            event={
                "event": "Approval preflight interrupted before deployment",
                "timestamp": comments_mod.beijing_now_str(),
            },
            expected_lifecycle_state=state,
        )
        if not written:
            return False
        await self._project_status_best_effort(repo, pr_number, restored["status"])
        comment_id = int(command.get("comment_id", 0) or 0)
        if comment_id > 0:
            # The unified failure reply states the reason once and takes the
            # current correct operation from lifecycle guidance; the machine
            # commands only belong to the rendered Summary (gate_note).
            await self._post_command_reply(
                repo, pr_number, comment_id, reason,
                topic=topic, error=True,
            )
        return True

    async def _recover_request_deploy_write(
        self, repo: str, pr_number: int, comment_id: int, *,
        expected_head: str, expected_author_id: str,
        original_state: dict, expected_state: dict,
        expected_round_id: str,
    ) -> tuple[str, dict | None]:
        """Classify an uncertain request_deploy lifecycle write by GitHub readback."""
        try:
            pr = await self.proxy.get_pr(repo, pr_number)
            persisted_state = await self.proxy.read_hidden_state(repo, pr_number)
            if (not isinstance(pr, dict)
                    or pr.get("number") != pr_number
                    or pr.get("state") != "open"
                    or pr.get("merged") or pr.get("draft")):
                return "unknown", None
            base = pr.get("base", {})
            base_repo = base.get("repo", {}) if isinstance(base, dict) else {}
            if (not isinstance(base_repo, dict)
                    or not isinstance(base_repo.get("full_name"), str)
                    or base_repo["full_name"].casefold() != repo.casefold()):
                return "unknown", None
            pr_head = (pr.get("head", {}).get("sha", "")
                       if isinstance(pr.get("head"), dict) else "")
            if not isinstance(pr_head, str) or not re.fullmatch(r"[0-9a-f]{40}", pr_head):
                return "unknown", None
            pr_user = pr.get("user", {})
            pr_author_id = str(pr_user.get("id") or "") if isinstance(pr_user, dict) else ""
            if not pr_author_id or pr_author_id != expected_author_id:
                return "unknown", None
            request_comment = await self._revalidate_request_deploy_comment(
                repo, pr_number, comment_id, expected_author_id,
            )
            if request_comment is None:
                return "unknown", None
            if pr_head != expected_head:
                return "head_changed", None
            if not isinstance(persisted_state, dict):
                return "unknown", None

            command = persisted_state.get("command", {})
            committed = (
                persisted_state.get("status") == "deploy-requested"
                and persisted_state.get("head_sha") == expected_head
                and isinstance(command, dict)
                and command.get("comment_id") == comment_id
                and command.get("kind") == "request_deploy"
                and command.get("phase") == "completed"
                and round_id_for_state(persisted_state) == expected_round_id
                and persisted_state.get("last_processed_comment_id", 0) >= comment_id
                and isinstance(expected_state, dict)
                and expected_state.get("status") == "deploy-requested"
                and expected_state.get("head_sha") == expected_head
                and expected_state.get("command", {}).get("comment_id") == comment_id
                and expected_state.get("command", {}).get("kind") == "request_deploy"
                and expected_state.get("command", {}).get("phase") == "completed"
                and round_id_for_state(expected_state) == expected_round_id
                and expected_state.get("last_processed_comment_id") == comment_id
            )
            if committed:
                actual = copy.deepcopy(persisted_state)
                expected = copy.deepcopy(expected_state)
                # The lifecycle writer fills this archive pointer while
                # preparing the round replacement; all request state must
                # otherwise match the state this command constructed.
                actual.pop("round_archive", None)
                expected.pop("round_archive", None)
                actual.pop("last_processed_comment_id", None)
                expected.pop("last_processed_comment_id", None)
                if actual == expected:
                    return "committed", copy.deepcopy(persisted_state)
            if persisted_state == original_state:
                return "not_written", None
            return "unknown", None
        except Exception as exc:
            logger.warning(
                "request_deploy write recovery %s#%s comment_id=%s failed: %s",
                repo, pr_number, comment_id, type(exc).__name__,
            )
            return "unknown", None

    async def _ensure_request_deploy_notice(
        self, repo: str, pr_number: int, comment_id: int,
    ) -> bool:
        """Confirm a persisted request_deploy and recover its idempotent owner notice."""
        try:
            pr = await self.proxy.get_pr(repo, pr_number)
            state = await self.proxy.read_hidden_state(repo, pr_number)
        except Exception as exc:
            logger.warning(
                "request_deploy notice context %s#%s unavailable: %s",
                repo, pr_number, type(exc).__name__,
            )
            return False
        if not isinstance(pr, dict):
            return False
        if (pr.get("state") != "open" or pr.get("merged") or pr.get("draft")):
            return True
        base = pr.get("base", {})
        base_repo = base.get("repo", {}) if isinstance(base, dict) else {}
        head_data = pr.get("head", {})
        head_sha = head_data.get("sha", "") if isinstance(head_data, dict) else ""
        if (pr.get("number") != pr_number
                or not isinstance(base_repo, dict)
                or not isinstance(base_repo.get("full_name"), str)
                or base_repo["full_name"].casefold() != repo.casefold()
                or not isinstance(head_sha, str)
                or not re.fullmatch(r"[0-9a-f]{40}", head_sha)):
            return True
        if not isinstance(state, dict):
            return False
        command = state.get("command", {})
        if (state.get("status") != "deploy-requested"
                or state.get("head_sha") != head_sha
                or not isinstance(command, dict)
                or command.get("comment_id") != comment_id
                or command.get("kind") != "request_deploy"
                or command.get("phase") != "completed"
                or round_id_for_state(state) != make_round_id(head_sha, comment_id)
                or state.get("last_processed_comment_id", 0) < comment_id):
            # A later lifecycle transition superseded the request. There is
            # no pending request notice to recover in that state.
            if (state.get("head_sha") == head_sha
                    and state.get("last_processed_comment_id", 0) < comment_id):
                return False
            return True

        pr_user = pr.get("user", {})
        pr_author_id = str(pr_user.get("id") or "") if isinstance(pr_user, dict) else ""
        if not pr_author_id:
            return True
        try:
            origin = await self.proxy.get_comment(repo, comment_id)
        except Exception as exc:
            logger.warning(
                "request_deploy notice origin %s#%s comment_id=%s unavailable: %s",
                repo, pr_number, comment_id, type(exc).__name__,
            )
            return False
        if not isinstance(origin, dict):
            return True
        user = origin.get("user", {})
        created_at = origin.get("created_at")
        body = origin.get("body", "")
        if (origin.get("id") != comment_id
                or not isinstance(user, dict)
                or str(user.get("id") or "") != pr_author_id
                or self.proxy.is_bot_comment(origin)
                or not isinstance(created_at, str)
                or origin.get("updated_at") != created_at
                or origin.get("url") != (
                    f"{self.config.github_api_url.rstrip('/')}/repos/{repo}/issues/comments/{comment_id}"
                )
                or origin.get("issue_url") != (
                    f"{self.config.github_api_url.rstrip('/')}/repos/{repo}/issues/{pr_number}"
                )
                or not isinstance(body, str)):
            return True
        from .commands import parse_command
        parsed = parse_command(body)
        if not parsed or parsed.kind != "request_deploy":
            return True

        components = state.get("components", [])
        test_only = self._is_test_only_pr(pr)
        runtime_bindings = state.get("runtime_redeploy", [])
        is_runtime_redeploy = isinstance(runtime_bindings, list) and bool(runtime_bindings)
        if is_runtime_redeploy:
            pending_ids = self._runtime_redeploy_pending_ids(state)
            drift_components = [
                component for component in components
                if isinstance(component, dict)
                and component.get("component_id") in pending_ids
            ]
            candidate_groups = self._get_machine_groups_for_components(
                drift_components, repo,
            )
            machine_groups = []
            for binding in runtime_bindings:
                if not isinstance(binding, dict):
                    continue
                try:
                    binding_ip = str(ipaddress.ip_address(binding.get("ip", "")))
                except (TypeError, ValueError):
                    binding_ip = ""
                binding_ids = set(binding.get("component_ids", []))
                binding_components = [
                    component for component in drift_components
                    if component.get("component_id") in binding_ids
                ]
                try:
                    binding_machine = self.policy.get_machine(
                        str(binding.get("machine", "") or ""), repo=repo,
                    )
                except Exception:
                    binding_machine = None
                endpoint_bound = bool(
                    binding_machine is not None and binding_ip
                    and binding_ip in {
                        item["ip"] for item in self._policy_machine_endpoints(
                            binding_machine, repo,
                        )
                    }
                    and self._endpoint_allowed_for_repository(
                        repo, binding_machine, binding_ip,
                        components=binding_components,
                    )
                )
                group = next((item for item in candidate_groups
                              if endpoint_bound
                              and item.get("alias") == binding.get("machine")
                              and binding_ids.issubset(set(item.get("component_ids", [])))),
                             None)
                if group is not None:
                    machine_groups.append({
                        **group, "component_ids": sorted(binding_ids),
                        "required_component_ids": sorted(binding_ids),
                        "verification_endpoints": [binding_ip],
                    })
            command_lines = await self._machine_notice_lines(
                machine_groups, repo, mention_owners=True,
                test_only=test_only, components=components, pr=pr,
            )
            next_step = (
                [
                    "请以下机器负责人直接执行对应审批命令；`/request_deploy` 仍是可选的申请操作。",
                    *command_lines,
                ]
                if command_lines else self._machine_blocking_summary(candidate_groups)
            )
            if command_lines and test_only:
                next_step.append("测试 PR 仅提醒 @Haohao-end。")
            topic = "runtime-redeploy-request-created"
            message = "\n".join([
                "镜像与当前批准版本不一致，已经为本轮创建了重新部署申请。",
                *next_step,
            ])
        else:
            machine_groups = self._get_machine_groups_for_components(
                components, repo,
            )
            command_lines = await self._machine_notice_lines(
                machine_groups, repo, mention_owners=True,
                test_only=test_only, components=components, pr=pr,
            )
            next_step = (
                [
                    "请以下机器负责人直接执行对应审批命令，部署完成后即可开始测试。",
                    *command_lines,
                ]
                if command_lines else self._machine_blocking_summary(machine_groups)
            )
            if command_lines and test_only:
                next_step.append("测试 PR 仅提醒 @Haohao-end。")
            topic = "deployment-requested-next-approver"
            message = "\n".join([
                "部署审批申请已经生效。",
                *next_step,
            ])
        if test_only:
            message = message.replace("@", "＠").replace(
                "＠Haohao-end", "@Haohao-end",
            )
        return await self._post_bound_notice(
            repo, pr_number, head_sha=head_sha,
            round_id=round_id_for_state(state), comment_id=comment_id,
            topic=topic, expected_command_kind="request_deploy",
            message=message, result="accepted",
        )

    async def handle_request_deploy(
        self, repo: str, pr_number: int, comment_id: int,
    ) -> bool:
        try:
            pr_data = await self.proxy.get_pr(repo, pr_number)
            pr_gate_error = self._command_pr_gate_error(pr_data, "/request_deploy")
            if pr_gate_error:
                await self._post_error(
                    repo, pr_number, pr_gate_error, comment_id=comment_id,
                )
                return True
            state = await self.proxy.read_hidden_state(repo, pr_number)
            comment_author_id, comment_author_login = await self.proxy.comment_identity(
                repo, comment_id
            )
            if not comment_author_id:
                await self._post_error(
                    repo, pr_number,
                    "无法确认这条命令的发送者，因此没有执行。",
                    comment_id=comment_id,
                )
                return True

            if state is None:
                await self._post_error(
                    repo, pr_number,
                    "当前 PR 还没有可用的部署进度信息，这次没有创建部署申请。",
                    comment_id=comment_id,
                )
                return True
            pr_head = pr_data.get("head", {}).get("sha", "")
            if not isinstance(pr_head, str) or not re.fullmatch(r"[0-9a-f]{40}", pr_head):
                await self._post_error(repo, pr_number, "无法确认 PR 的最新提交，这次没有执行。", comment_id=comment_id)
                return True
            if pr_head != state.get("head_sha", ""):
                await self._supersede_head_drift(
                    repo, pr_number, state, pr_head, comment_id,
                    command_kind="request_deploy",
                )
                return True
            _current_status = state.get("status", "")
            runtime_redeploy_request = False
            if _current_status == "deploy-ready":
                if comment_id <= state.get("last_processed_comment_id", 0):
                    return True
            elif _current_status in {"testing", "succeeded", "failed", "deploy-requested"}:
                if comment_id <= state.get("last_processed_comment_id", 0):
                    persisted_command = state.get("command", {})
                    if (_current_status == "deploy-requested"
                            and isinstance(persisted_command, dict)
                            and persisted_command.get("comment_id") == comment_id
                            and persisted_command.get("kind") == "request_deploy"):
                        return await self._ensure_request_deploy_notice(
                            repo, pr_number, comment_id,
                        )
                    return True
                if state.get("runtime_redeploy"):
                    await self._post_command_reply(
                        repo, pr_number, comment_id,
                        "镜像与批准版本不一致，本轮重新部署申请已经创建，"
                        "不需要再次申请。",
                        topic="runtime-redeploy-request-already-pending",
                    )
                    return True
                confirmed_drift = self._confirmed_runtime_drift(state)
                if confirmed_drift:
                    runtime_redeploy_request = True
                else:
                    checks = state.get("runtime_checks", [])
                    unreadable = self._runtime_unreadable_lines(checks)
                    if unreadable:
                        message = (
                            "目前无法确认机器的运行状态，这次没有创建重新部署申请。"
                        )
                        topic = "runtime-redeploy-request-state-unavailable"
                    elif (_current_status in {"testing", "succeeded", "failed"}
                          and checks
                          and all(isinstance(check, dict)
                                  and check.get("status") == "match"
                                  for check in checks)):
                        message = "机器上已经在运行本轮批准的镜像，不需要重新部署。"
                        topic = "runtime-redeploy-request-already-matches"
                    elif _current_status == "deploy-requested":
                        message = (
                            "本轮部署申请仍然有效，没有需要重新申请的镜像差异。"
                        )
                        topic = "request-deploy-already-processed"
                    else:
                        message = (
                            "目前没有确认到需要重新部署的镜像差异，这次没有创建申请。"
                        )
                        topic = "runtime-redeploy-request-no-confirmed-drift"
                    await self._post_command_reply(
                        repo, pr_number, comment_id, message, topic=topic,
                    )
                    return True
            elif _current_status in ("deploying",):
                logger.warning(
                    "STALE_COMMAND_IGNORED kind=request_deploy comment_id=%s current_status=%s",
                    comment_id, _current_status,
                )
                await self._post_command_reply(
                    repo, pr_number, comment_id,
                    "部署正在进行，这次没有重复创建部署申请。",
                    topic="request-deploy-already-processed",
                )
                return True
            else:
                await self._post_command_not_ready(
                    repo, pr_number, _current_status,
                    "当前阶段还不能申请部署。",
                    comment_id=comment_id,
                )
                return True
            pr_user = pr_data.get("user", {})
            pr_author_id = str(pr_user.get("id") or "") if isinstance(pr_user, dict) else ""
            if not pr_author_id:
                await self._post_error(
                    repo, pr_number,
                    "无法确认 PR 作者身份，这次没有执行。",
                    comment_id=comment_id,
                )
                return True
            if comment_author_id != pr_author_id:
                await self._post_error(
                    repo, pr_number,
                    "只有 PR 作者可以申请部署。",
                    comment_id=comment_id,
                )
                return True

            async def persist_request_deploy(
                write_operation, *, original_state: dict,
                expected_state: dict,
            ) -> tuple[str, dict | None]:
                write_error = None
                try:
                    written = await write_operation
                except Exception as exc:
                    write_error = exc
                    written = False
                if written is True:
                    return "committed", copy.deepcopy(expected_state)
                outcome, recovered_state = await self._recover_request_deploy_write(
                    repo, pr_number, comment_id,
                    expected_head=pr_head,
                    expected_author_id=pr_author_id,
                    original_state=original_state,
                    expected_state=expected_state,
                    expected_round_id=round_id_for_state(expected_state),
                )
                if outcome == "unknown":
                    uncertain = DeployOutcomeUncertain(
                        "request_deploy lifecycle write outcome could not be confirmed"
                    )
                    if write_error is not None:
                        raise uncertain from write_error
                    raise uncertain
                return outcome, recovered_state

            async def report_request_deploy_head_changed() -> bool:
                try:
                    current_pr = await self.proxy.get_pr(repo, pr_number)
                    current_state = await self.proxy.read_hidden_state(repo, pr_number)
                except Exception:
                    return False
                if (not isinstance(current_pr, dict)
                        or current_pr.get("state") != "open"
                        or current_pr.get("merged") or current_pr.get("draft")):
                    return False
                current_head = (current_pr.get("head", {}).get("sha", "")
                                if isinstance(current_pr.get("head"), dict) else "")
                if not isinstance(current_head, str) or not re.fullmatch(
                        r"[0-9a-f]{40}", current_head):
                    return False
                has_current_state = (
                    isinstance(current_state, dict)
                    and current_state.get("head_sha") == current_head
                )
                current_round = (
                    round_id_for_state(current_state) if has_current_state
                    else make_round_id(current_head, comment_id)
                )
                if has_current_state:
                    await self._post_command_reply(
                        repo, pr_number, comment_id,
                        "保存部署申请时 PR 出现了新的提交，旧申请没有用于当前代码。",
                        topic="request-deploy-write-head-changed", error=True,
                    )
                    return True
                return await self._post_bound_notice(
                    repo, pr_number, head_sha=current_head,
                    round_id=current_round, comment_id=comment_id,
                    topic="request-deploy-write-head-changed",
                    message=(
                        "这条命令没有执行：保存部署申请时 PR 出现了新的提交，"
                        "旧申请没有用于当前代码。\n\n"
                        "请等待当前提交的审核和构建结果，再按 PR Summary 操作。"
                    ),
                    allow_missing_state=True,
                )

            # Get build evidence from PR comments
            try:
                comments = await self.github.get_issue_comments(repo, pr_number)
                if not isinstance(comments, list):
                    comments = []
                persisted_build_id = state.get("review_evidence", {}).get("build_comment_id")
                if (comments and type(persisted_build_id) is int
                        and self._has_untrusted_newer_review_comment(
                            comments, persisted_build_id,
                        )):
                    await self._post_error(
                        repo, pr_number,
                        "当前出现了无法信任的新审核结果，这次没有创建部署申请。",
                        comment_id=comment_id,
                    )
                    return True
                evidence = await self._review_evidence_from_comments(repo, pr_number, pr_head, comments)
            except Exception as e:
                logger.warning(
                    "request_deploy comment evidence %s#%s: %s",
                    repo, pr_number, e,
                )
                evidence = None

            if evidence is None:
                await self._post_error(
                    repo, pr_number,
                    "当前提交还没有完成的审核结果，这次没有创建部署申请。",
                    comment_id=comment_id,
                )
                return True

            if not evidence.run_binding_valid:
                await self._post_error(
                    repo, pr_number,
                    "当前审核结果没有完整绑定构建来源，暂时不能据此部署。",
                    comment_id=comment_id,
                )
                return True
            # Convert evidence builds to BuildInfo
            builds = self._review_build_infos(repo, evidence)

            components = await self._build_component_snapshot(
                repo, pr_number, pr_head, builds,
            )
            if components is None:
                await self._post_error(
                    repo, pr_number,
                    "无法确认本次构建包含哪些组件，这次没有创建部署申请。",
                    comment_id=comment_id,
                )
                return True
            if not components:
                await self._post_error(
                    repo, pr_number,
                    "当前提交没有可部署的构建产物，这次没有创建部署申请。",
                    comment_id=comment_id,
                )
                return True

            # Resolve evidence commit prefix to full SHA
            resolved_head = await self._resolve_review_evidence_for_head(
                repo, pr_head, evidence, pr_number=pr_number,
            )
            if resolved_head is None:
                await self._post_error(
                    repo, pr_number,
                    "审核结果对应的提交与当前最新提交不一致，这次没有创建部署申请。",
                    comment_id=comment_id,
                )
                return True

            # Use the same canonical snapshot as reconcile and recovery.
            review_evidence_data = self._review_evidence_snapshot(
                evidence, resolved_head,
            )

            if runtime_redeploy_request:
                persisted_evidence = state.get("review_evidence", {})
                persisted_components = state.get("components", [])
                if (self._review_evidence_identity(review_evidence_data)
                        != self._review_evidence_identity(persisted_evidence)
                        or self._canonical_component_snapshot(components)
                        != self._canonical_component_snapshot(persisted_components)):
                    await self._post_error(
                        repo, pr_number,
                        "当前提交的审核或镜像结果已经变化，这次没有创建重新部署申请。",
                        comment_id=comment_id,
                    )
                    return True

                await self._reconcile_runtime_image_checks(
                    repo, pr_number, state, pr_data, force=True,
                )
                fresh_pr = await self.proxy.get_pr(repo, pr_number)
                fresh_state = await self.proxy.read_hidden_state(repo, pr_number)
                if (not isinstance(fresh_pr, dict)
                        or fresh_pr.get("state") != "open"
                        or fresh_pr.get("merged") or fresh_pr.get("draft")
                        or fresh_pr.get("head", {}).get("sha") != pr_head
                        or not isinstance(fresh_state, dict)
                        or fresh_state.get("head_sha") != pr_head
                        or fresh_state.get("status") != _current_status):
                    await self._post_command_reply(
                        repo, pr_number, comment_id,
                        "PR 或部署进度在确认期间发生了变化，这次没有创建重新部署申请。",
                        topic="runtime-redeploy-request-context-changed",
                    )
                    return True
                if not await self._fresh_review_evidence_matches_state(
                        repo, pr_number, pr_head,
                        fresh_state.get("review_evidence", {}),
                        expected_components=fresh_state.get("components", [])):
                    await self._post_command_reply(
                        repo, pr_number, comment_id,
                        "当前提交的审核结果无法重新确认，这次没有创建重新部署申请。",
                        topic="runtime-redeploy-request-review-invalid",
                    )
                    return True
                if not self._confirmed_runtime_drift(fresh_state):
                    fresh_checks = fresh_state.get("runtime_checks", [])
                    current_statuses = {
                        check.get("status") for check in fresh_checks
                        if isinstance(check, dict)
                    }
                    if current_statuses and current_statuses <= {"match"}:
                        message = "重新检查确认机器上已经在运行本轮批准的镜像，不需要重新部署。"
                        topic = "runtime-redeploy-request-already-matches"
                    else:
                        message = (
                            "重新检查仍然无法确认机器上的运行镜像，"
                            "这次没有创建重新部署申请。"
                        )
                        topic = "runtime-redeploy-request-state-unavailable"
                    await self._post_command_reply(
                        repo, pr_number, comment_id, message, topic=topic,
                    )
                    return True

                working_state = self._new_runtime_redeploy_round(
                    fresh_state, comment_id=comment_id,
                    command_kind="request_deploy",
                )
                drift_ids = self._runtime_redeploy_pending_ids(working_state)
                drift_components = [
                    component for component in working_state.get("components", [])
                    if component.get("component_id") in drift_ids
                ]
                candidate_groups = self._get_machine_groups_for_components(
                    drift_components, repo,
                )
                machine_groups = []
                for binding in working_state.get("runtime_redeploy", []):
                    if not isinstance(binding, dict):
                        continue
                    try:
                        binding_ip = str(ipaddress.ip_address(binding.get("ip", "")))
                    except (TypeError, ValueError):
                        binding_ip = ""
                    binding_ids = set(binding.get("component_ids", []))
                    binding_components = [
                        component for component in working_state.get("components", [])
                        if isinstance(component, dict)
                        and component.get("component_id") in binding_ids
                    ]
                    try:
                        binding_machine = self.policy.get_machine(
                            str(binding.get("machine", "") or ""), repo=repo,
                        )
                    except Exception:
                        binding_machine = None
                    endpoint_bound = bool(
                        binding_machine is not None and binding_ip
                        and binding_ip in {
                            item["ip"] for item in self._policy_machine_endpoints(
                                binding_machine, repo,
                            )
                        }
                        and self._endpoint_allowed_for_repository(
                            repo, binding_machine, binding_ip,
                            components=binding_components,
                        )
                    )
                    group = next((item for item in candidate_groups
                                  if endpoint_bound
                                  and item.get("alias") == binding.get("machine")
                                  and binding_ids.issubset(set(item.get("component_ids", [])))),
                                 None)
                    if group is None:
                        await self._post_command_reply(
                            repo, pr_number, comment_id,
                            "原来登记的机器已经不能部署这次需要重新部署的组件，这次没有创建重新部署申请。",
                            topic="runtime-redeploy-request-machine-incompatible",
                        )
                        return True
                    machine_groups.append({
                        **group, "component_ids": sorted(binding_ids),
                        "required_component_ids": sorted(binding_ids),
                        "verification_endpoints": [binding_ip],
                    })
                if not machine_groups:
                    await self._post_command_reply(
                        repo, pr_number, comment_id,
                        "目前没有可以部署这些组件的机器，这次没有创建重新部署申请。",
                        topic="runtime-redeploy-request-no-compatible-machine",
                    )
                    return True
                fresh_request_comment = await self._revalidate_request_deploy_comment(
                    repo, pr_number, comment_id, pr_author_id,
                )
                if fresh_request_comment is None:
                    await self._post_command_reply(
                        repo, pr_number, comment_id,
                        "这条部署申请已经失效，需要 PR 作者重新发送。",
                        topic="runtime-redeploy-request-comment-invalid",
                    )
                    return True
                request_markdown = await self._deploy_requested_markdown(
                    repo, pr_number, pr_head,
                    working_state.get("components", []), machine_groups,
                    test_only=self._is_test_only_pr(fresh_pr),
                    deployments=self._enrich_deployments_for_render(
                        working_state.get("deployments", []), repo,
                    ),
                )

                async def guard_drift_request_authorization() -> bool:
                    fresh_comment = await self._revalidate_request_deploy_comment(
                        repo, pr_number, comment_id, pr_author_id,
                    )
                    fresh_request_pr = await self.proxy.get_pr(repo, pr_number)
                    if not (
                        fresh_comment is not None
                        and isinstance(fresh_request_pr, dict)
                        and fresh_request_pr.get("state") == "open"
                        and not fresh_request_pr.get("merged")
                        and not fresh_request_pr.get("draft")
                        and fresh_request_pr.get("head", {}).get("sha") == pr_head
                    ):
                        return False
                    return await self._fresh_review_evidence_matches_state(
                        repo, pr_number, pr_head,
                        fresh_state.get("review_evidence", {}),
                        expected_components=fresh_state.get("components", []),
                    )

                expected_working_state = copy.deepcopy(working_state)
                write_outcome, recovered_state = await persist_request_deploy(
                    self._write_lifecycle_with_history(
                        repo, pr_number, working_state, request_markdown,
                        event={
                            "event": "Runtime image drift redeployment requested",
                            "lifecycle": f"`{_current_status}` → `deploy-requested`",
                            "timestamp": comments_mod.beijing_now_str(),
                        },
                        expected_lifecycle_state=fresh_state,
                        write_guard=guard_drift_request_authorization,
                        archive_reason="Confirmed runtime image drift redeployment request",
                    ),
                    original_state=fresh_state,
                    expected_state=expected_working_state,
                )
                if write_outcome == "not_written":
                    return False
                if write_outcome == "head_changed":
                    return await report_request_deploy_head_changed()
                working_state = recovered_state or working_state
                await self._project_status_best_effort(repo, pr_number, "deploy-requested")
                return await self._ensure_request_deploy_notice(
                    repo, pr_number, comment_id,
                )

            # A ready lifecycle is the developer-visible review snapshot. If
            # the latest trusted run changed before this command was handled,
            # consume this request without silently treating the new findings
            # as already reviewed. Reconciliation will publish the new result;
            # direct approval can then proceed from the refreshed deploy-ready state.
            if _current_status == "deploy-ready":
                persisted_evidence = state.get("review_evidence", {})
                persisted_components = state.get("components", [])
                if (self._review_evidence_identity(review_evidence_data)
                        != self._review_evidence_identity(persisted_evidence)
                        or (persisted_components and
                            self._canonical_component_snapshot(components)
                            != self._canonical_component_snapshot(persisted_components))):
                    await self._post_error(
                        repo, pr_number,
                        "当前提交的审核结果在部署就绪之后发生了变化，这次没有创建部署申请。",
                        comment_id=comment_id,
                    )
                    return True

            # Preserve the original round before replacing the active snapshot.
            previous_state = copy.deepcopy(state)
            preserved_deployments = (
                state.get("deployments", []) if _current_status == "deploy-ready" else []
            )
            preserved_deployed_ids = _component_id_set(preserved_deployments)
            remaining_request_components = [
                component for component in components
                if component.get("component_id") not in preserved_deployed_ids
            ]
            machine_groups = self._get_machine_groups_for_components(
                remaining_request_components, repo,
            )
            state = self._init_hidden_state(
                head_sha=pr_head,
                status="deploy-requested",
                review_evidence=review_evidence_data,
                components=components,
                deployments=preserved_deployments,
            )
            state["round_id"] = make_round_id(pr_head, comment_id)
            state["round_started_at"] = utc_now()
            state["command"] = {
                "comment_id": comment_id,
                "kind": "request_deploy",
                "phase": "completed",
                "args": {},
            }
            state["last_processed_comment_id"] = comment_id

            async def guard_request_deploy_authorization() -> bool:
                fresh_comment = await self._revalidate_request_deploy_comment(
                    repo, pr_number, comment_id, pr_author_id,
                )
                fresh_pr = await self.proxy.get_pr(repo, pr_number)
                fresh_user = fresh_pr.get("user", {}) if isinstance(fresh_pr, dict) else {}
                return bool(
                    fresh_comment is not None
                    and isinstance(fresh_pr, dict)
                    and fresh_pr.get("state") == "open"
                    and not fresh_pr.get("merged")
                    and not fresh_pr.get("draft")
                    and fresh_pr.get("head", {}).get("sha") == pr_head
                    and isinstance(fresh_user, dict)
                    and str(fresh_user.get("id") or "") == pr_author_id
                )

            # Validate state before persisting
            self._validate_hidden_state(state)

            markdown = await self._deploy_requested_markdown(
                repo, pr_number, pr_head, components, machine_groups,
                test_only=self._is_test_only_pr(pr_data),
            )
            event = {
                "event": "Deployment requested",
                "lifecycle": "`deploy-ready` \u2192 `deploy-requested`",
                "timestamp": comments_mod.beijing_now_str(),
            }
            expected_request_state = copy.deepcopy(state)
            write_outcome, recovered_state = await persist_request_deploy(
                self._write_lifecycle_with_history(
                    repo, pr_number, state, markdown, event=event,
                    expected_lifecycle_state=previous_state,
                    write_guard=guard_request_deploy_authorization,
                    archive_reason="New deployment request",
                ),
                original_state=previous_state,
                expected_state=expected_request_state,
            )
            if write_outcome == "not_written":
                return False
            if write_outcome == "head_changed":
                return await report_request_deploy_head_changed()
            state = recovered_state or state
            await self._project_status_best_effort(repo, pr_number, "deploy-requested")
            return await self._ensure_request_deploy_notice(
                repo, pr_number, comment_id,
            )

        except Exception as e:
            logger.error(
                "handle_request_deploy %s#%s: %s", repo, pr_number, e,
            )
            raise

    async def _prepare_runtime_redeploy_approval(
        self, repo: str, pr_number: int, comment_id: int,
        machine_selector: str, actor: str, state: dict, pr_data: dict,
    ) -> tuple[dict, dict, bool, bool, bool]:
        """Refresh and bind a direct drift reapproval to one current repo machine."""
        if comment_id <= state.get("last_processed_comment_id", 0):
            return state, state, False, False, True
        if not machine_selector:
            drift_checks = self._confirmed_runtime_drift(state)
            component_map = {
                component.get("component_id"): component
                for component in state.get("components", [])
                if isinstance(component, dict)
            }
            mismatch_components_by_binding: dict[tuple[str, str], set[str]] = {}
            for check in drift_checks:
                alias = check.get("machine")
                checked_ip = self._canonical_primary_ipv4(check.get("ip", ""))
                component_id = check.get("component_id")
                if (not isinstance(alias, str) or not alias
                        or not checked_ip
                        or not isinstance(component_id, str) or not component_id):
                    continue
                mismatch_components_by_binding.setdefault(
                    (alias, checked_ip), set(),
                ).add(component_id)
            drift_component_ids = {
                component_id
                for component_ids in mismatch_components_by_binding.values()
                for component_id in component_ids
            }
            drift_components = [component_map[component_id]
                                for component_id in drift_component_ids
                                if component_id in component_map]
            try:
                policy_status = self.policy.repo_policy_status(repo)
                if (not isinstance(policy_status, dict)
                        or policy_status.get("authorized") is not True
                        or policy_status.get("machines_configured") is not True):
                    await self._post_command_reply(
                        repo, pr_number, comment_id,
                        "当前仓库还没有可用的机器配置，因此无法重新审批，这次没有发送部署请求。",
                        topic="runtime-redeploy-policy-unconfigured",
                    )
                    return state, state, False, False, True
                groups = self._get_machine_groups_for_components(
                    drift_components, repo,
                ) if drift_components else []
            except Exception as exc:
                logger.warning("runtime redeploy machine selection unavailable repo=%s reason=%s",
                               repo, type(exc).__name__)
                await self._post_command_reply(
                    repo, pr_number, comment_id,
                    "目前无法确认仓库的机器配置，因此不能安全选择重新部署机器，这次没有发送部署请求。",
                    topic="runtime-redeploy-machine-selection-unavailable",
                )
                return state, state, False, False, True
            valid_bindings: dict[tuple[str, str], tuple[dict, dict]] = {}
            if drift_component_ids and len(drift_components) == len(drift_component_ids):
                for (alias, checked_ip), component_ids in mismatch_components_by_binding.items():
                    binding_components = [
                        component_map[component_id]
                        for component_id in component_ids
                        if component_id in component_map
                    ]
                    if len(binding_components) != len(component_ids):
                        continue
                    group = next((
                        item for item in groups
                        if isinstance(item, dict)
                        and item.get("alias") == alias
                        and item.get("approval_available") is True
                        and item.get("repo_authorized") is True
                        and item.get("identity_confirmed") is True
                        and component_ids.issubset(
                            set(item.get("component_ids", []))
                        )
                    ), None)
                    if group is None:
                        continue
                    try:
                        candidate_machine = self.policy.get_machine(alias, repo=repo)
                        endpoint_rows = self._policy_machine_endpoints(
                            candidate_machine, repo,
                        ) if candidate_machine is not None else []
                    except Exception:
                        candidate_machine = None
                        endpoint_rows = []
                    if candidate_machine is None:
                        continue
                    if (checked_ip not in {
                            item.get("ip") for item in endpoint_rows
                            if isinstance(item, dict)
                    } or not self._endpoint_allowed_for_repository(
                            repo, candidate_machine, checked_ip,
                            components=binding_components,
                    )):
                        continue
                    verified_endpoints = await self._agent_core_verified_endpoints(
                        repo, candidate_machine, binding_components,
                        endpoints=[checked_ip],
                    )
                    verified_endpoint = next((item for item in verified_endpoints
                                               if isinstance(item, dict)
                                               and item.get("ip") == checked_ip
                                               and component_ids.issubset(set(
                                                   item.get("component_ids", []),
                                               ))), None)
                    if verified_endpoint is not None:
                        valid_bindings[(alias, checked_ip)] = (
                            group, verified_endpoint,
                        )
            if len(valid_bindings) == 1:
                _binding, (_selected_group, selected_endpoint) = next(
                    iter(valid_bindings.items()),
                )
                machine_selector = str(selected_endpoint.get("ip", "") or "")
            elif len(valid_bindings) > 1:
                commands = sorted({
                    f"/approve_deploy machine={checked_ip}"
                    for _alias, checked_ip in valid_bindings
                })
                message = "多个已确认镜像差异绑定可用，请明确指定实际检查 IP。"
                if commands:
                    message += "\n" + "\n".join(f"`{command}`" for command in commands)
                topic = "runtime-redeploy-multiple-compatible-machines"
                await self._post_command_reply(
                    repo, pr_number, comment_id, message, topic=topic,
                )
                return state, state, False, False, True
            else:
                message = (
                    "目前没有找到与已确认镜像差异机器、实际检查 IP 和组件完全对应的有效绑定，"
                    "这次没有发送部署请求。"
                )
                topic = "runtime-redeploy-no-confirmed-machine"
                await self._post_command_reply(
                    repo, pr_number, comment_id, message, topic=topic,
                )
                return state, state, False, False, True
        try:
            policy_status = self.policy.repo_policy_status(repo)
            if (not isinstance(policy_status, dict)
                    or policy_status.get("authorized") is not True
                    or policy_status.get("machines_configured") is not True):
                await self._post_command_reply(
                    repo, pr_number, comment_id,
                    "当前仓库还没有可用的机器配置，因此无法重新审批，这次没有发送部署请求。",
                    topic="runtime-redeploy-policy-unconfigured",
                )
                return state, state, False, False, True
            machines = self.policy.get_machines(repo=repo)
            machine_map = {item.alias: item for item in machines}
            machine, requested_endpoint = self._resolve_policy_machine_selector(
                machine_selector, repo,
            )
            requested_endpoint = str(requested_endpoint or "")
        except PolicyError:
            await self._post_command_reply(
                repo, pr_number, comment_id,
                "找不到你填写的机器，这次没有发送部署请求。",
                topic="runtime-redeploy-machine-not-found",
            )
            return state, state, False, False, True
        except Exception as exc:
            logger.warning("runtime redeploy policy lookup failed repo=%s reason=%s",
                           repo, type(exc).__name__)
            await self._post_command_reply(
                repo, pr_number, comment_id,
                "目前无法确认仓库的机器配置，因此不能确认审批目标，这次没有发送部署请求。",
                topic="runtime-redeploy-policy-unavailable",
            )
            return state, state, False, False, True

        try:
            current_ip = ipaddress.ip_address(machine.node_host)
        except (TypeError, ValueError):
            current_ip = None
        machine_ip = str(current_ip) if current_ip is not None and current_ip.version == 4 else ""
        permitted_selector = self._machine_command_selector(machine.alias, repo)
        requested_endpoint = self._canonical_primary_ipv4(machine_selector)
        endpoint_rows = self._policy_machine_endpoints(machine, repo)
        confirmed_endpoints = {item["ip"] for item in endpoint_rows}
        selector_is_alias = machine_selector == machine.alias
        if (not confirmed_endpoints
                or (not selector_is_alias
                    and requested_endpoint not in confirmed_endpoints)):
            await self._post_command_reply(
                repo, pr_number, comment_id,
                "重新部署审批必须使用当前仓库已确认的实际机器 IP，这次没有发送部署请求。"
                "请按 PR Summary 中当前可用的 IP 命令操作。",
                topic="runtime-redeploy-requires-ip",
            )
            return state, state, False, False, True
        allowed_endpoints = [
            item["ip"] for item in endpoint_rows
            if self._endpoint_allowed_for_repository(
                repo, machine, item["ip"], components=drift_components,
            )
        ]
        if requested_endpoint:
            selected_endpoint = (
                requested_endpoint if requested_endpoint in allowed_endpoints else ""
            )
        else:
            drift_ips = sorted({
                self._canonical_primary_ipv4(check.get("ip", ""))
                for check in self._confirmed_runtime_drift(state)
                if check.get("machine") == machine.alias
                and self._canonical_primary_ipv4(check.get("ip", ""))
                in allowed_endpoints
            })
            if len(drift_ips) == 1:
                selected_endpoint = drift_ips[0]
            elif len(drift_ips) > 1:
                verified_commands = await self._runtime_drift_command_lines(state, repo)
                machine_drift_commands = {
                    f"/approve_deploy machine={ip}" for ip in drift_ips
                }
                verified_commands = [
                    command for command in verified_commands
                    if command in machine_drift_commands
                ]
                suffix = (
                    "\n" + "\n".join(f"`{line}`" for line in verified_commands)
                    if verified_commands else ""
                )
                await self._post_command_reply(
                    repo, pr_number, comment_id,
                    "这台机器有多个地址需要重新部署，请明确指定实际检查 IP。"
                    + suffix,
                    topic="runtime-redeploy-requires-machine-ip",
                )
                return state, state, False, False, True
            elif machine_ip in allowed_endpoints:
                selected_endpoint = machine_ip
            elif len(allowed_endpoints) == 1:
                selected_endpoint = allowed_endpoints[0]
            else:
                selected_endpoint = ""
        if not selected_endpoint:
            await self._post_command_reply(
                repo, pr_number, comment_id,
                "无法确认这次重新部署对应的安全机器 IP，这次没有发送部署请求。"
                "请按 PR Summary 中当前可用的 IP 命令操作。",
                topic="runtime-redeploy-endpoint-unconfirmed",
            )
            return state, state, False, False, True

        requested_machine_binding = (
            machine.alias,
            str(getattr(machine, "node_id", "") or "").strip(),
            machine_ip,
        )
        await self._reconcile_runtime_image_checks(
            repo, pr_number, state, pr_data, force=True,
            machine_filter=(machine.alias, selected_endpoint),
        )
        fresh_pr = await self.proxy.get_pr(repo, pr_number)
        fresh_state = await self.proxy.read_hidden_state(repo, pr_number)
        if (not isinstance(fresh_pr, dict) or fresh_pr.get("state") != "open"
                or fresh_pr.get("merged") or fresh_pr.get("draft")
                or fresh_pr.get("head", {}).get("sha") != state.get("head_sha")
                or not isinstance(fresh_state, dict)
                or fresh_state.get("head_sha") != state.get("head_sha")):
            await self._post_command_reply(
                repo, pr_number, comment_id,
                "PR 有了新提交或当前不再可部署，之前的审批已不适用，这次没有发送部署请求。",
                topic="runtime-redeploy-head-changed",
            )
            return state, state, False, False, True

        fresh_status = fresh_state.get("status")
        fresh_command = fresh_state.get("command", {})
        if (fresh_status not in {"deploy-ready", "deploy-requested", "testing", "succeeded", "failed"}
                or not isinstance(fresh_command, dict)
                or fresh_command.get("phase") in {"executing", "uncertain"}):
            await self._post_command_reply(
                repo, pr_number, comment_id,
                "部署已经开始或结果还在确认中，这次没有重复提交部署。",
                topic="runtime-redeploy-deployment-in-progress",
            )
            return fresh_state, fresh_state, False, False, True

        try:
            fresh_policy_status = self.policy.repo_policy_status(repo)
            fresh_machines = self.policy.get_machines(repo=repo)
            policy_still_authorized = (
                isinstance(fresh_policy_status, dict)
                and fresh_policy_status.get("authorized") is True
                and fresh_policy_status.get("machines_configured") is True
            )
            fresh_machine_matches = (
                [item for item in fresh_machines
                 if getattr(item, "alias", None) == machine.alias]
                if isinstance(fresh_machines, list) else []
            )
            fresh_machine = (
                fresh_machine_matches[0]
                if len(fresh_machine_matches) == 1 else None
            )
            fresh_ip = self._canonical_primary_ipv4(
                getattr(fresh_machine, "node_host", ""),
            )
            fresh_node_id = str(
                getattr(fresh_machine, "node_id", "") or "",
            ).strip()
            _, fresh_identity_matches = self._machine_identity_matches(
                machine.alias, fresh_machine, None, fresh_machines, repo=repo,
            )
            fresh_selector = self._machine_command_selector(machine.alias, repo)
        except Exception as exc:
            logger.warning(
                "runtime redeploy policy recheck failed repo=%s machine=%s reason=%s",
                repo, machine.alias, type(exc).__name__,
            )
            policy_still_authorized = False
            fresh_machine_matches = []
            fresh_machine = None
            fresh_ip = ""
            fresh_node_id = ""
            fresh_identity_matches = False
            fresh_selector = ""

        machine_binding_unchanged = bool(
            policy_still_authorized
            and len(fresh_machine_matches) == 1
            and fresh_machine is not None
            and fresh_identity_matches
            and fresh_ip == requested_machine_binding[2]
            and fresh_node_id == requested_machine_binding[1]
            and fresh_selector == permitted_selector
            and selected_endpoint in {
                item["ip"] for item in self._policy_machine_endpoints(
                    fresh_machine, repo,
                )
            }
            and self._endpoint_allowed_for_repository(
                repo, fresh_machine, selected_endpoint,
                policy_machines=fresh_machines,
            )
        )
        if not machine_binding_unchanged:
            if not policy_still_authorized:
                reason = "当前仓库的机器授权已经变化或无法确认"
                topic = "runtime-redeploy-policy-changed"
            elif fresh_machine is None:
                reason = "指定的机器已经不在当前仓库的机器清单中"
                topic = "runtime-redeploy-machine-removed"
            else:
                reason = "这台机器的登记信息已经变化"
                topic = "runtime-redeploy-machine-identity-changed"
            await self._post_command_reply(
                repo, pr_number, comment_id,
                f"{reason}，这次没有发送部署请求。",
                topic=topic,
            )
            return fresh_state, fresh_state, False, False, True

        current_checks = [check for check in fresh_state.get("runtime_checks", [])
                          if isinstance(check, dict)
                          and check.get("machine") == machine.alias
                          and check.get("ip") == selected_endpoint]
        current_drift = self._runtime_drift_checks_for_machine(
            fresh_state, machine.alias, selected_endpoint,
        )
        current_pending_ids = self._runtime_redeploy_ids_for_machine(
            fresh_state, machine.alias, selected_endpoint,
        )
        current_drift_ids = {
            check.get("component_id") for check in current_drift
            if isinstance(check.get("component_id"), str)
        }
        unbound_drift_ids = current_drift_ids - current_pending_ids
        if current_drift_ids:
            component_map = {
                component.get("component_id"): component
                for component in fresh_state.get("components", [])
                if isinstance(component, dict)
                and isinstance(component.get("component_id"), str)
            }
            drift_components = [component_map[component_id]
                                for component_id in current_drift_ids
                                if component_id in component_map]
            if len(drift_components) != len(current_drift_ids):
                await self._post_command_reply(
                    repo, pr_number, comment_id,
                    "最新运行状态里包含了无法识别的组件，因此无法确认部署范围，这次没有发送部署请求。",
                    topic="runtime-redeploy-component-binding-invalid",
                )
                return fresh_state, fresh_state, False, False, True
            try:
                compatible_ids = set(self._get_component_ids_for_machine(
                    machine.alias, drift_components, repo,
                ))
            except Exception as exc:
                logger.warning(
                    "runtime redeploy compatibility check failed repo=%s machine=%s reason=%s",
                    repo, machine.alias, type(exc).__name__,
                )
                compatible_ids = set()
            incompatible_ids = current_drift_ids - compatible_ids
            if incompatible_ids:
                await self._post_command_reply(
                    repo, pr_number, comment_id,
                    "这台机器已经不能部署这次需要重新部署的组件，这次没有发送部署请求。",
                    topic="runtime-redeploy-component-incompatible",
                )
                return fresh_state, fresh_state, False, False, True
        if not current_drift and not current_pending_ids:
            if current_checks and all(check.get("status") == "match" for check in current_checks):
                message = "重新检查确认机器上已经在运行本轮批准的镜像，不需要重新部署。"
                topic = "runtime-redeploy-already-matches"
            elif any(check.get("status") == "identity_changed" for check in current_checks):
                message = (
                    "机器的登记信息已经变化，暂时无法确认当前运行镜像，"
                    "这次没有发送部署请求。"
                )
                topic = "runtime-redeploy-identity-changed"
            elif any(check.get("status") == "not_running" for check in current_checks):
                message = (
                    "目标组件当前没有运行，暂时无法确认运行镜像，"
                    "这次没有发送部署请求。"
                )
                topic = "runtime-redeploy-not-running"
            elif any(check.get("status") == "unavailable" for check in current_checks):
                message = "目前无法连接机器确认运行镜像，这次没有发送部署请求。"
                topic = "runtime-redeploy-unavailable"
            else:
                message = "目前还没有确认到需要重新部署的镜像差异，这次没有发送部署请求。"
                topic = "runtime-redeploy-no-drift"
            await self._post_command_reply(
                repo, pr_number, comment_id, message, topic=topic,
            )
            return fresh_state, fresh_state, False, False, True

        if not current_drift and current_pending_ids:
            if current_checks and all(
                    check.get("status") == "match" for check in current_checks):
                message = "重新检查确认机器上已经在运行本轮批准的镜像，不需要重新部署。"
                topic = "runtime-redeploy-already-target"
            elif any(check.get("status") in {"unavailable", "identity_changed"}
                     for check in current_checks):
                message = "目前无法确认机器的运行状态，这次没有发送部署请求。"
                topic = "runtime-redeploy-pending-state-unavailable"
            elif any(check.get("status") == "not_running" for check in current_checks):
                message = "目标组件当前没有运行，暂时无法执行重新部署，这次没有发送部署请求。"
                topic = "runtime-redeploy-pending-not-running"
            else:
                message = "目前还没有确认到需要重新部署的镜像差异，这次没有发送部署请求。"
                topic = "runtime-redeploy-pending-state-unconfirmed"
            await self._post_command_reply(
                repo, pr_number, comment_id, message, topic=topic,
            )
            return fresh_state, fresh_state, False, False, True

        current_drift_ids = {
            check.get("component_id") for check in current_drift
            if isinstance(check.get("component_id"), str)
            and check.get("component_id")
        }
        component_map = {
            component.get("component_id"): component
            for component in fresh_state.get("components", [])
            if isinstance(component, dict)
            and isinstance(component.get("component_id"), str)
        }
        drift_components = [
            component_map[component_id]
            for component_id in current_drift_ids
            if component_id in component_map
        ]
        compatible_group = None
        if drift_components and len(drift_components) == len(current_drift_ids):
            try:
                candidate_groups = self._get_machine_groups_for_components(
                    drift_components, repo,
                )
                compatible_group = next((
                    group for group in candidate_groups
                    if group.get("alias") == machine.alias
                    and group.get("repo_authorized") is True
                    and group.get("identity_confirmed") is True
                    and group.get("approval_available") is True
                    and selected_endpoint in {
                        item["ip"] for item in self._policy_machine_endpoints(
                            fresh_machine, repo,
                        )
                    }
                    and self._endpoint_allowed_for_repository(
                        repo, fresh_machine, selected_endpoint,
                        components=drift_components,
                        policy_machines=fresh_machines,
                    )
                    and current_drift_ids.issubset(
                        set(group.get("component_ids", [])),
                    )
                ), None)
            except Exception as exc:
                logger.warning(
                    "runtime redeploy compatibility recheck failed repo=%s machine=%s reason=%s",
                    repo, machine.alias, type(exc).__name__,
                )
        if compatible_group is None:
            await self._post_command_reply(
                repo, pr_number, comment_id,
                "这台机器目前不能部署这次需要重新部署的组件，这次没有发送部署请求。",
                topic="runtime-redeploy-machine-incompatible",
            )
            return fresh_state, fresh_state, False, False, True

        if not await self._fresh_review_evidence_matches_state(
                repo, pr_number, fresh_state.get("head_sha", ""),
                fresh_state.get("review_evidence", {}),
                expected_components=fresh_state.get("components", [])):
            await self._post_command_reply(
                repo, pr_number, comment_id,
                "当前提交的审核结果已经变化或无法确认，这次没有发送部署请求。",
                topic="runtime-redeploy-review-evidence-invalid",
            )
            return fresh_state, fresh_state, False, False, True

        expected_state = copy.deepcopy(fresh_state)
        pending_bindings = {
            (item.get("machine"), item.get("ip"), component_id)
            for item in fresh_state.get("runtime_redeploy", [])
            if isinstance(item, dict)
            for component_id in item.get("component_ids", [])
            if isinstance(component_id, str)
        }
        current_mismatch_bindings = {
            (check.get("machine"), check.get("ip"), check.get("component_id"))
            for check in self._confirmed_runtime_drift(fresh_state)
            if all(isinstance(check.get(field), str) and check.get(field)
                   for field in ("machine", "ip", "component_id"))
        }
        has_unbound_mismatch = bool(current_mismatch_bindings - pending_bindings)
        if has_unbound_mismatch or (current_pending_ids and fresh_status == "failed"):
            working_state = self._new_runtime_redeploy_round(
                fresh_state, comment_id=comment_id,
                command_kind="approve_deploy", actor=actor,
                machine=machine.alias,
            )
            working_state.setdefault("command", {}).setdefault("args", {})[
                "node_host"
            ] = selected_endpoint
            self._validate_hidden_state(working_state)
            return working_state, expected_state, True, True, False

        if current_pending_ids and not unbound_drift_ids:
            working_state = copy.deepcopy(fresh_state)
            command = dict(working_state.get("command", {}))
            command.update({
                "comment_id": comment_id, "kind": "approve_deploy",
                "phase": "completed",
                "args": {
                    "machine": machine.alias, "actor": actor,
                    "node_host": selected_endpoint,
                },
            })
            working_state["command"] = command
            working_state["last_processed_comment_id"] = comment_id
            self._validate_hidden_state(working_state)
            return working_state, expected_state, True, False, False

        working_state = self._new_runtime_redeploy_round(
            fresh_state, comment_id=comment_id, command_kind="approve_deploy",
            actor=actor, machine=machine.alias,
        )
        working_state.setdefault("command", {}).setdefault("args", {})[
            "node_host"
        ] = selected_endpoint
        self._validate_hidden_state(working_state)
        return working_state, expected_state, True, True, False

    async def handle_approve_deploy(
        self, repo: str, pr_number: int, comment_id: int,
        machine_alias: str, actor: str, actor_id: str,
    ) -> bool:
        try:
            pr_data = await self.proxy.get_pr(repo, pr_number)
            pr_gate_error = self._command_pr_gate_error(pr_data, "/approve_deploy")
            if pr_gate_error:
                await self._post_error(
                    repo, pr_number, pr_gate_error, comment_id=comment_id,
                )
                return True
            state = await self.proxy.read_hidden_state(repo, pr_number)
            if state is None:
                await self._post_error(
                    repo, pr_number,
                    "当前 PR 还没有可用的部署进度信息，因此没有执行部署审批。",
                    comment_id=comment_id,
                )
                return True

            pr_head = pr_data.get("head", {}).get("sha", "")
            if not isinstance(pr_head, str) or not re.fullmatch(r"[0-9a-f]{40}", pr_head):
                await self._post_error(
                    repo, pr_number,
                    "无法确认 PR 的最新提交，这次没有执行部署审批。",
                    comment_id=comment_id,
                )
                return True
            if pr_head != state.get("head_sha", ""):
                await self._supersede_head_drift(
                    repo, pr_number, state, pr_head, comment_id,
                )
                return True
            initial_lifecycle_state = copy.deepcopy(state)

            existing_command = state.get("command", {})
            existing_args = (
                existing_command.get("args", {})
                if isinstance(existing_command, dict) else {}
            )
            if (isinstance(existing_command, dict)
                    and existing_command.get("kind") == "approve_deploy"
                    and existing_command.get("phase") in {"executing", "uncertain"}):
                await self._post_command_reply(
                    repo, pr_number, comment_id,
                    "部署请求正在执行或结果仍在确认，这次没有重复提交部署。",
                    topic="deployment-already-in-progress",
                )
                return True
            if (isinstance(existing_command, dict)
                    and existing_command.get("kind") == "approve_deploy"
                    and existing_command.get("phase") == "completed"
                    and isinstance(existing_args, dict)
                    and existing_args.get("preflight_pending") is True):
                stale_preflight_restored = await self._restore_interrupted_approval_preflight(
                        repo, pr_number,
                        reason=(
                            "上一次审批在部署前检查阶段中断，当时没有发送部署请求，"
                            "这次也没有重复发送。"
                        ),
                        topic="approval-preflight-retry-required",
                        require_stale=True,
                        expected_comment_id=int(existing_command.get("comment_id", 0) or 0),
                )
                if stale_preflight_restored:
                    if existing_command.get("comment_id") != comment_id:
                        await self._post_command_reply(
                            repo, pr_number, comment_id,
                            "上一次审批在部署前检查阶段中断，本次审批没有执行，也没有发送部署 POST。",
                            topic="deployment-preflight-interrupted",
                        )
                    return True
                await self._post_command_reply(
                    repo, pr_number, comment_id,
                    "上一次审批仍在检查部署条件，这次没有重复提交；请等待 PR Summary 更新。",
                    topic="deployment-already-in-progress",
                )
                return True

            _current_status = state.get("status", "")
            deployment_request_submitted = _current_status == "deploy-requested"
            redeploy_mode = False
            new_redeploy_round = False
            runtime_drift_checks = self._confirmed_runtime_drift(state)
            pending_redeploy = state.get("runtime_redeploy", [])
            if not isinstance(pending_redeploy, list):
                pending_redeploy = []
            if _current_status == "deploy-ready":
                if comment_id <= state.get("last_processed_comment_id", 0):
                    return True
                if (not state.get("review_evidence") or not state.get("components")
                        or not await self._fresh_review_evidence_matches_state(
                            repo, pr_number, pr_head, state.get("review_evidence", {}),
                            expected_components=state.get("components", []),
                        )):
                    await self._post_error(
                        repo, pr_number,
                        "当前提交的审核或构建结果还不完整或已经变化，这次没有执行部署审批。",
                        comment_id=comment_id,
                    )
                    return True
            if (_current_status in {"testing", "succeeded", "failed"}
                    or _current_status in {"deploy-ready", "deploy-requested"}
                    and (runtime_drift_checks or pending_redeploy)):
                (state, initial_lifecycle_state, redeploy_mode,
                 new_redeploy_round, handled) = await self._prepare_runtime_redeploy_approval(
                    repo, pr_number, comment_id, machine_alias, actor,
                    state, pr_data,
                )
                if handled:
                    return True
                _current_status = state.get("status", "")
                if redeploy_mode:
                    redeploy_args = state.get("command", {}).get("args", {})
                    selected_redeploy_ip = self._canonical_primary_ipv4(
                        redeploy_args.get("node_host", "")
                        if isinstance(redeploy_args, dict) else "",
                    )
                    if selected_redeploy_ip:
                        machine_alias = selected_redeploy_ip

            if _current_status == "deploying":
                phase = state.get("command", {}).get("phase")
                command_args = state.get("command", {}).get("args", {})
                if (phase == "completed" and isinstance(command_args, dict)
                        and command_args.get("preflight_pending") is True
                        and await self._restore_interrupted_approval_preflight(
                            repo, pr_number,
                            reason=("上一次审批在部署前检查阶段中断，当时没有发送部署请求，这次也没有重复发送。"),
                            topic="approval-preflight-retry-required",
                            require_stale=True,
                        )):
                    return True
                if phase == "executing":
                    await self._handle_uncertain_if_needed(repo, pr_number, state)
                elif phase == "uncertain":
                    await self._recover_uncertain_deployment_tick(
                        repo, pr_number, state, pr_data,
                    )
                if (phase == "completed" and isinstance(command_args, dict)
                        and command_args.get("preflight_pending") is True):
                    in_progress_message = (
                        "上一个审批还在部署前检查中，当时没有发送部署请求，这次没有重复提交。"
                    )
                else:
                    in_progress_message = (
                        "部署正在进行或结果还在确认中，这次没有重复提交部署。"
                    )
                await self._post_command_reply(
                    repo, pr_number, comment_id,
                    in_progress_message,
                    topic="deployment-already-in-progress",
                )
                return True

            if _current_status in {"deploy-ready", "deploy-requested"}:
                pass  # normal path continues below
            elif _current_status in ("testing", "succeeded", "failed"):
                logger.warning(
                    "STALE_COMMAND_IGNORED kind=approve_deploy comment_id=%s current_status=%s",
                    comment_id, _current_status,
                )
                await self._post_command_reply(
                    repo, pr_number, comment_id,
                    "本轮部署已经结束，这次审批没有执行。",
                    topic="approve-deploy-already-processed",
                )
                return True
            else:
                await self._post_command_not_ready(
                    repo, pr_number, _current_status,
                    "当前阶段还不能执行部署审批。",
                    comment_id=comment_id,
                )
                return True

            # Check PR is still valid
            pr_state = pr_data.get("state", "")
            pr_merged = pr_data.get("merged", False)
            if pr_state != "open" or pr_merged:
                await self._post_error(
                    repo, pr_number,
                    "这个 PR 已经关闭或合并，部署命令不再适用。",
                    comment_id=comment_id,
                )
                return True

            if pr_data.get("draft") is True:
                await self._post_error(
                    repo, pr_number,
                    "这个 PR 还是草稿，部署命令暂时不可用。",
                    comment_id=comment_id,
                )
                return True

            phase = state.get("command", {}).get("phase")
            if phase == "executing":
                await self._handle_uncertain_if_needed(repo, pr_number, state)
                return True
            if phase == "uncertain":
                await self._refresh_uncertain_state(repo, pr_number, state)
                # Recovery is read-only with respect to Agent Core. A later
                # approval may deploy only components proven never attempted.
                return True

            # Resolve machine selector (alias or IPv4) to canonical MachineInfo
            machine_selector = machine_alias
            if not machine_alias:
                remaining_for_selection = [
                    component for component in state.get("components", [])
                    if component.get("component_id") not in _component_id_set(
                        state.get("deployments", []),
                    )
                ]
                groups = await self._machine_groups_verify_endpoints(
                    self._get_machine_groups_for_components(
                        remaining_for_selection, repo,
                    ),
                    repo,
                    remaining_for_selection,
                )
                remaining_ids = {
                    component.get("component_id") for component in remaining_for_selection
                    if isinstance(component, dict)
                }
                full_groups = [
                    group for group in groups
                    if remaining_ids and remaining_ids.issubset(set(group.get("component_ids", [])))
                ]
                if len(full_groups) == 1:
                    options = full_groups
                else:
                    options = groups
                if len(options) != 1 or not full_groups:
                    # Let the unified guidance block carry the exact machine
                    # commands; this reply states only why the bare command
                    # cannot be executed.
                    explanation = (
                        "有多台机器都能部署剩余组件，请在命令中明确指定一台。"
                        if len(full_groups) > 1 else
                        "没有单台机器覆盖全部剩余组件，需要分批审批。"
                    )
                    await self._post_command_reply(
                        repo, pr_number, comment_id, explanation,
                        topic="approve-deploy-machine-selection",
                    )
                    return True
                machine_alias = str(options[0].get("command_selector", "") or "")

            try:
                machine, requested_endpoint = self._resolve_policy_machine_selector(
                    machine_alias, repo,
                )
                requested_endpoint = str(requested_endpoint or "")
            except PolicyError:
                # Keep the reply to the unified two-block shape: why it failed
                # plus the current correct operation taken from lifecycle
                # guidance. Do not append machine diagnostics or a second
                # command list here.
                await self._post_error(
                    repo, pr_number,
                    "找不到你填写的机器，这次没有执行部署审批。",
                    comment_id=comment_id,
                )
                return True

            # Preserve the ORIGINAL selector (IPv4 or alias) from the comment
            # for exact revalidation. Canonical alias is used for state/persistence.
            # Retain the selector from the original comment (empty for automatic selection).
            # Use canonical alias for all state persistence
            machine_alias = machine.alias
            approved_machine_binding = (
                machine.alias, machine.node_id, machine.node_host,
            )
            approved_primary_ip = self._canonical_primary_ipv4(machine.node_host)

            # V49: dynamic machine identity drives endpoint selection. The
            # confirmed endpoint list comes from the current Policy Feishu
            # snapshot for this repository, and only Agent Core-verified
            # addresses are executable. Explicitly selected endpoints take
            # priority; otherwise the registered primary IP is used first.
            approved_machine_identity = self._policy_machine_identity(machine, repo)
            requested_ip = self._canonical_primary_ipv4(requested_endpoint)
            try:
                policy_endpoints = self._policy_machine_endpoints(machine, repo)
            except Exception:
                policy_endpoints = []
            policy_machines = []
            try:
                policy_machines = self.policy.get_machines(repo=repo) or []
            except Exception:
                policy_machines = []
            if (requested_ip
                    and requested_ip in {item["ip"] for item in policy_endpoints}
                    and self._endpoint_allowed_for_repository(
                        repo, machine, requested_ip,
                        policy_machines=policy_machines,
                    )):
                confirmed_endpoints = [
                    requested_ip,
                    *{item["ip"] for item in policy_endpoints if item["ip"] != requested_ip},
                ]
            else:
                confirmed_endpoints = [item["ip"] for item in policy_endpoints]

            # Check permissions async
            await self._check_approval_permissions(
                machine, actor, repo,
            )

            pending_drift_ids = self._runtime_redeploy_pending_ids(state)
            if (runtime_drift_checks and not pending_drift_ids
                    and not redeploy_mode):
                await self._post_command_reply(
                    repo, pr_number, comment_id,
                    "当前还有已部署组件的运行镜像与批准版本不一致，"
                    "这台机器的审批没有执行，需要先重新部署这些镜像。",
                    topic="runtime-redeploy-required-before-other-machine",
                )
                return True

            # Determine which component_ids are assigned to this machine group
            components = state.get("components", [])
            existing_deployments = state.get("deployments", [])
            existing_deployed = _component_id_set(existing_deployments)

            # Determined from ALL undeployed components — not from compatible IDs.
            undeployed_components = [
                c for c in components
                if c.get("component_id") not in existing_deployed
            ]
            if not undeployed_components:
                await self._post_error(
                    repo, pr_number,
                    "这台机器没有剩余需要部署的组件，这次审批没有执行。",
                    comment_id=comment_id,
                )
                return True


            compatible_remaining_ids = set(
                self._get_component_ids_for_machine(
                    machine_alias, undeployed_components, repo,
                )
            )

            # Multi-machine partial coverage: select only compatible, undeployed components.
            selected_components = [
                c for c in undeployed_components
                if c.get("component_id", "") in compatible_remaining_ids
            ]
            if pending_drift_ids:
                machine_drift_ids = self._runtime_redeploy_ids_for_machine(
                    state, machine.alias, requested_ip or machine.node_host,
                )
                # A runtime redeploy round is bound only to components whose
                # latest read-only check confirmed MISMATCH. Do not fold other
                # undeployed components into this approval.
                selected_components = [
                    component for component in undeployed_components
                    if component.get("component_id", "") in compatible_remaining_ids
                    and component.get("component_id", "") in machine_drift_ids
                    and component.get("component_id", "") in pending_drift_ids
                ]

            if not selected_components:
                # Selected machine covers zero remaining components.
                if not await self._machine_is_deployable(machine, repo):
                    selection_problem = (
                        "这台机器目前无法连接或没有部署访问权限，因此不能部署剩余组件。"
                    )
                else:
                    selection_problem = (
                        "这台机器不能部署本次需要部署的剩余组件。"
                    )
                # A rejected machine choice must not consume this command or
                # alter the lifecycle. The unified guidance block reports the
                # current compatible machine commands; this reply only explains
                # why the chosen machine cannot be used.
                await self._post_command_reply(
                    repo, pr_number, comment_id,
                    selection_problem,
                    topic="approve-deploy-incompatible-machine",
                )
                return True


            # Record the source approval while retaining deploy-ready or
            # deploy-requested until the first deployment POST is actually sent.
            preflight_source_status = (
                "deploy-requested" if deployment_request_submitted else "deploy-ready"
            )
            state["status"] = preflight_source_status
            state["command"] = {
                "comment_id": comment_id,
                "kind": "approve_deploy",
                "phase": "completed",
                "args": {
                    "machine": machine_alias,
                    "actor": actor,
                    "deployment_request_submitted": deployment_request_submitted,
                    "preflight_pending": True,
                    "preflight_started_at": time.time(),
                },
            }
            state["last_processed_comment_id"] = max(
                int(state.get("last_processed_comment_id", 0) or 0), comment_id,
            )
            candidate_errors: list[Exception] = []
            core = None
            preflight = None
            selected_endpoint = ""
            selected_core_key = None
            preflight_reason = ""
            endpoint_failures: list[dict[str, str]] = []
            try:
                preflight_written = await self._write_lifecycle_with_history(
                    repo, pr_number, state,
                    await self._deployment_progress_markdown(
                        repo, pr_number, state, machine, selected_components,
                        "审批已收到，正在检查部署条件",
                        test_only=self._is_test_only_pr(pr_data),
                    ), event=None,
                    expected_lifecycle_state=initial_lifecycle_state,
                )
                if not preflight_written:
                    return False
                initial_lifecycle_state = copy.deepcopy(state)
                # A legal approval is accepted as soon as the durable preflight
                # reservation is written. Keep the public label in deploying
                # while the controller checks endpoints; a no-POST failure
                # restores the source label below.
                await self._project_status_best_effort(
                    repo, pr_number, "deploying",
                )
                checking_notice = await self._post_bound_notice(
                    repo, pr_number, head_sha=pr_head,
                    round_id=round_id_for_state(state), comment_id=comment_id,
                    topic="approval-preflight-started",
                    expected_command_kind="approve_deploy",
                    message="审批已收到，正在检查部署条件。",
                )
                if not checking_notice:
                    return False
                if not confirmed_endpoints:
                    if not self._machine_identity_is_confirmed(approved_machine_identity):
                        candidate_errors.append(DeployControllerError(
                            "current Feishu device identity is not confirmed"
                        ))
                    else:
                        candidate_errors.append(DeployControllerError(
                            "no Policy-confirmed Agent Core endpoint is available"
                        ))
                for endpoint in confirmed_endpoints:
                    endpoint_stage = "identity"
                    try:
                        if (not self._machine_identity_is_confirmed(
                                    approved_machine_identity,
                                )
                                or not self._machine_endpoint_has_unambiguous_identity(
                                    machine, endpoint, repo, approved_machine_identity,
                                )):
                            raise DeployControllerError(
                                "machine endpoint identity is not confirmed"
                            )
                        endpoint_stage = "authentication"
                        candidate_core = await self._core_for_machine_endpoint(
                            machine, endpoint, repo,
                        )
                        endpoint_stage = "runtime-preflight"
                        candidate_preflight = await self._preflight_running_images(
                            candidate_core, selected_components,
                        )
                        for item in candidate_preflight:
                            component = item.get("component", {})
                            if (component.get("target") != "core"
                                    and item.get("runtime_repo") != _image_repository(
                                        str(component.get("image_ref", "") or ""))):
                                raise DeployControllerError(
                                    "Driver runtime image repository does not match the approved target repository"
                                )
                        endpoint_pr = await self.proxy.get_pr(repo, pr_number)
                        if (not isinstance(endpoint_pr, dict)
                                or endpoint_pr.get("state") != "open"
                                or endpoint_pr.get("merged") or endpoint_pr.get("draft")
                                or (endpoint_pr.get("head") or {}).get("sha") != pr_head):
                            raise PolicyError(
                                "PR HEAD changed during deployment preflight"
                            )
                        await self._check_approval_permissions(machine, actor, repo)
                        current_machine = self.policy.get_machine(machine_alias, repo=repo)
                        if (current_machine is None
                                or (current_machine.alias, current_machine.node_id,
                                    current_machine.node_host) != approved_machine_binding
                                or not self._machine_endpoint_has_unambiguous_identity(
                                    current_machine, endpoint, repo,
                                    approved_machine_identity,
                                )):
                            raise PolicyError(
                                "machine identity or endpoint changed during deployment preflight"
                            )
                        core = candidate_core
                        preflight = candidate_preflight
                        selected_endpoint = endpoint
                        state["command"].setdefault("args", {})["node_host"] = endpoint
                        selected_core_key = (
                            repo.casefold(), machine_alias if endpoint ==
                            self._canonical_primary_ipv4(machine.node_host)
                            else f"{machine_alias}@{endpoint}"
                        )
                        self._record_agent_core_health(repo, machine, "available")
                        break
                    except (PolicyError, GitHubError):
                        raise
                    except (AgentCoreError, DeployControllerError, TimeoutError, OSError) as endpoint_error:
                        candidate_errors.append(endpoint_error)
                        endpoint_failures.append({
                            "ip": endpoint,
                            "stage": endpoint_stage,
                            "reason": type(endpoint_error).__name__,
                            "connectivity": self._agent_core_failure_is_connectivity(
                                endpoint_error,
                            ),
                        })
                        self._record_agent_core_health(repo, machine, "unavailable")
                        continue
                if preflight is None or core is None:
                    preflight_reason = self._preflight_failure_reason(candidate_errors)
                    raise DeployControllerError(preflight_reason)
            except (
                AgentCoreError, DeployControllerError, PolicyError, GitHubError,
                TimeoutError, OSError,
            ) as exc:
                # No deploy POST is possible in this block. Restore the source
                # lifecycle and explain which actual gate failed.
                if exc not in candidate_errors:
                    candidate_errors.append(exc)
                fresh = await self.proxy.read_hidden_state(repo, pr_number)
                if fresh != state:
                    return False
                if redeploy_mode:
                    for failed_ip in sorted({
                            item.get("ip") for item in endpoint_failures
                            if isinstance(item.get("ip"), str)
                    }):
                        self._mark_runtime_checks_unavailable(
                            state, machine, selected_components,
                            endpoint_ip=failed_ip,
                        )
                state["status"] = preflight_source_status
                state["command"] = {
                    "comment_id": comment_id, "kind": "approve_deploy", "phase": "completed",
                    "args": {
                        "machine": machine_alias, "actor": actor,
                        "deployment_request_submitted": deployment_request_submitted,
                    },
                }
                state["last_processed_comment_id"] = comment_id
                reason = preflight_reason or self._preflight_failure_reason(candidate_errors)
                markdown = await self._deployment_progress_markdown(
                    repo, pr_number, state, machine, selected_components,
                    f"部署预检失败：{reason} 本次没有开始部署，也没有发送部署 POST。请根据当前 Summary 再操作。",
                    test_only=self._is_test_only_pr(pr_data),
                )
                preflight_failure_written = await self._write_lifecycle_with_history(
                    repo, pr_number, state, markdown,
                    event={"event": "Deployment preflight failed", "machine": machine_alias,
                           "ip": selected_endpoint or self._runtime_display_identity(machine_alias, repo)[0],
                           "reason": reason,
                           "timestamp": comments_mod.beijing_now_str()},
                    expected_lifecycle_state=fresh,
                )
                if not preflight_failure_written:
                    return False
                await self._project_status_best_effort(repo, pr_number, state["status"])
                offline = bool(endpoint_failures) and all(
                    item.get("stage") == "authentication"
                    and item.get("connectivity") is True
                    for item in endpoint_failures
                )
                if offline:
                    failed_ips = list(dict.fromkeys(
                        item["ip"] for item in endpoint_failures if item.get("ip")
                    ))
                    required_ids = {
                        item.get("component_id") for item in selected_components
                        if isinstance(item, dict) and item.get("component_id")
                    }
                    available_endpoints = await self._agent_core_verified_endpoints(
                        repo, machine, selected_components,
                        endpoints=[ip for ip in confirmed_endpoints
                                   if ip not in failed_ips],
                    )
                    available_ips = list(dict.fromkeys(
                        str(item.get("ip")) for item in available_endpoints
                        if required_ids.issubset(set(item.get("component_ids", [])))
                    ))
                    retry_candidates = ([requested_ip] if requested_ip else [])
                    retry_candidates.extend(
                        ip for ip in confirmed_endpoints if ip != requested_ip
                    )
                    retry_endpoint = next((ip for ip in retry_candidates
                        if ip in confirmed_endpoints
                        and self._endpoint_allowed_for_repository(
                            repo, machine, ip, components=selected_components,
                        )), "")
                    offline_message = (
                        "机器当前无法连接，可能未开机或网络不可达。"
                        "本次未发送部署请求。\n"
                        f"实际失败 IP：{', '.join(f'`{ip}`' for ip in failed_ips) or '未确认'}。\n"
                        f"其他已验证可用 IP：{', '.join(f'`{ip}`' for ip in available_ips) or '无'}。"
                    )
                    if retry_endpoint:
                        offline_message += (
                            f"\n机器恢复后可重新审批："
                            f"`/approve_deploy machine={retry_endpoint}`。"
                        )
                    await self._post_command_reply(
                        repo, pr_number, comment_id, offline_message,
                        topic="machine-offline-approval-preflight",
                    )
                else:
                    await self._post_command_reply(
                        repo, pr_number, comment_id,
                        f"部署预检失败：{reason} 本次没有开始部署，也没有发送部署 POST。",
                        topic="deployment-preflight-check-failed",
                    )
                return True
            for item in preflight:
                item["component"]["runtime_id"] = item["runtime_id"]
            approve_attempt = {
                "comment_id": comment_id,
                "actor": actor,
                "machine": machine_alias,
                "preflight": [
                    {
                        "component_id": item["component"].get("component_id", ""),
                        "runtime_id": item["runtime_id"],
                        "running_image": item["running_image"],
                    }
                    for item in preflight
                ],
                "outcome": "",
                "health": [],
            }

            # Fresh PR re-read before unsafe POST
            fresh_pr = await self.proxy.get_pr(repo, pr_number)
            fresh_state = fresh_pr.get("state", "")
            fresh_merged = fresh_pr.get("merged", False)
            fresh_head = fresh_pr.get("head", {}).get("sha", "")
            if fresh_state != "open" or fresh_merged or fresh_pr.get("draft") is True or fresh_head != state.get("head_sha", ""):
                if fresh_pr.get("draft") is True:
                    await self._post_error(
                        repo, pr_number,
                        "这个 PR 还是草稿，部署命令暂时不可用。",
                        comment_id=comment_id,
                    )
                await self._invalidate_review_required(
                    repo,
                    pr_number,
                    state,
                    fresh_head or state.get("head_sha", ""),
                    comment_id,
                    "部署前再次检查时 PR 已经变化，旧的部署准备不再适用。",
                )
                return True

            # Fresh exact approval comment re-validation
            validated_comment = await self._revalidate_approve_comment(
                repo, comment_id, actor_id, machine_selector,
            )
            if validated_comment is None:
                state["status"] = self._approval_retry_status(state)
                state["command"] = {
                    "comment_id": comment_id,
                    "kind": "approve_deploy",
                    "phase": "completed",
                    "args": {
                        "machine": machine_alias, "actor": actor,
                        "deployment_request_submitted": deployment_request_submitted,
                    },
                }
                state["last_processed_comment_id"] = comment_id
                approve_attempt["outcome"] = "approval_revoked"
                self._record_approve_attempt(state, approve_attempt)
                markdown = await self._deployment_progress_markdown(
                    repo, pr_number, state, machine, selected_components,
                    "审批命令已被删除或修改，本次部署没有发送，需要重新审批。",
                    test_only=self._is_test_only_pr(pr_data),
                )
                event = {
                    "event": "Approval revoked",
                    "machine": machine_alias,
                    "timestamp": comments_mod.beijing_now_str(),
                }
                revoked_written = await self._write_lifecycle_with_history(
                    repo, pr_number, state, markdown, event=event,
                    expected_lifecycle_state=initial_lifecycle_state,
                )
                if not revoked_written:
                    return False
                await self._project_status_best_effort(repo, pr_number, state["status"])
                return True

            # Fresh actor permission re-check
            await self._check_approval_permissions(
                machine, actor, repo,
            )

            # Final fresh PR read — authoritative gate after approval+permission revalidation
            final_pr = await self.proxy.get_pr(repo, pr_number)
            final_state = final_pr.get("state", "")
            final_merged = final_pr.get("merged", False)
            final_head = final_pr.get("head", {}).get("sha", "")

            if final_state != "open" or final_merged or final_pr.get("draft") is True:
                if final_pr.get("draft") is True:
                    await self._post_error(
                        repo, pr_number,
                        "这个 PR 还是草稿，部署命令暂时不可用。",
                        comment_id=comment_id,
                    )
                await self._invalidate_review_required(
                    repo,
                    pr_number,
                    state,
                    final_head or state.get("head_sha", ""),
                    comment_id,
                    "审批复核后 PR 状态发生变化，旧的部署准备不再适用。",
                )
                return True

            if final_head != state.get("head_sha", ""):
                await self._invalidate_review_required(
                    repo,
                    pr_number,
                    state,
                    final_head,
                    comment_id,
                    "审批复核后 PR 出现了新的提交，旧的部署准备不再适用。",
                )
                return True

            # Capture frozen component + deployment snapshots before hidden state validation
            expected_component_snapshot = self._canonical_component_snapshot(
                state.get("components", []),
            )
            expected_deployments = list(state.get("deployments", []))

            # Fresh hidden state re-read before unsafe POST
            validated_state = await self._revalidate_hidden_state(
                repo, pr_number, final_head,
                state.get("review_evidence", {}),
                expected_status=preflight_source_status,
                expected_component_snapshot=expected_component_snapshot,
                expected_deployments=expected_deployments,
            )
            if validated_state is None:
                await self._invalidate_review_required(
                    repo, pr_number, state, final_head, comment_id,
                    "Hidden state changed after final pre-deploy validation.",
                )
                return True


            # Fresh review evidence revalidation before unsafe POST
            if not await self._fresh_review_evidence_matches_state(
                repo, pr_number, final_head,
                state.get("review_evidence", {}),
                expected_components=state.get("components", []),
            ):
                await self._invalidate_review_required(
                    repo, pr_number, state, final_head, comment_id,
                    "Review evidence changed after approval.",
                )
                return True

            # Non-core components deploy first; core restarts Agent Core and
            # therefore remains last. Track only the component whose POST may
            # be in flight, not every component selected for this approval.
            ordered_components = self._order_components_for_deploy(selected_components)

            # Reserve visible history capacity before marking the command as
            # in flight. Archive writes are safe, but an archive failure must
            # not leave a false deploying state for a POST that never started.
            prospective = await self._approval_retry_markdown(
                repo, pr_number, state,
                self._get_machine_groups_for_components(state.get("components", []), repo),
                test_only=self._is_test_only_pr(pr_data),
                deployments=state.get("deployments", []),
                display_status=preflight_source_status,
            )
            deploy_reservation = {
                "event": "Machine `<alias>` deployed",
                "machine": "<alias>",
                "ip": "<ip>",
                "timestamp": comments_mod.beijing_now_str(),
            }
            await self._preflight_archive_for_event(
                repo, pr_number, prospective,
                reserved_event=deploy_reservation,
            )

            # Keep the durable command in the completed preflight phase until
            # the exact component has passed every final read-only gate. The
            # executing phase is written immediately before a possible POST.
            persisted_lifecycle_state = copy.deepcopy(validated_state)
            round_id = round_id_for_state(state)
            deployment_started_notice_posted = False

            new_deployments = []
            deploy_error = None
            failed_component_id = ""
            failed_component_target = ""
            deploy_outcome_uncertain = False
            deploy_preflight_unavailable = False
            runtime_unconfirmed_components = []
            runtime_unconfirmed_status = "unavailable"
            runtime_preflight_message = ""
            # Sequential per-component deploy; POST success followed by
            # post-deploy runtime verification before recording as deployed.
            for comp in ordered_components:
                image_ref = comp["image_ref"]
                runtime_id = str(comp.get("runtime_id") or "")
                component_id = comp.get("component_id", "")
                comp_target = comp.get("target", "")
                failed_component_id = str(component_id)
                failed_component_target = str(comp_target)
                if not runtime_id:
                    deploy_error = f"missing runtime id for {comp_target}"
                    break

                # Persist verified earlier components and narrow restart
                # recovery to the next POST that may actually be attempted.
                state["deployments"] = list(existing_deployments) + list(new_deployments)
                if redeploy_mode and new_deployments:
                    self._record_redeployed_runtime_matches(
                        state, machine, new_deployments, approve_attempt["health"],
                    )
                state["status"] = preflight_source_status
                state["command"] = {
                    "comment_id": comment_id,
                    "kind": "approve_deploy",
                    "phase": "completed",
                    "args": {
                        "machine": machine_alias,
                        "actor": actor,
                        "node_id": machine.node_id,
                        "node_host": selected_endpoint,
                        "deployment_request_submitted": deployment_request_submitted,
                        "pending_component_ids": [component_id],
                        "preflight_pending": True,
                        "preflight_started_at": time.time(),
                    },
                }
                pending_written = await self._write_lifecycle_with_history(
                    repo, pr_number, state,
                    await self._deployment_progress_markdown(
                        repo, pr_number, state, machine, [comp],
                        "预检已通过，正在准备部署请求",
                        test_only=self._is_test_only_pr(pr_data),
                    ), event=None,
                    expected_lifecycle_state=persisted_lifecycle_state,
                )
                if not pending_written:
                    return False
                persisted_lifecycle_state = copy.deepcopy(state)

                async def mark_component_executing() -> bool:
                    nonlocal persisted_lifecycle_state
                    state["status"] = preflight_source_status
                    state["command"] = {
                        "comment_id": comment_id,
                        "kind": "approve_deploy",
                        "phase": "executing",
                        "args": {
                            "machine": machine_alias,
                            "actor": actor,
                            "node_id": machine.node_id,
                            "node_host": selected_endpoint,
                            "deployment_request_submitted": deployment_request_submitted,
                            "pending_component_ids": [component_id],
                            "execution_started_at": time.time(),
                        },
                    }
                    executing_written = await self._write_lifecycle_with_history(
                        repo, pr_number, state,
                        await self._deployment_progress_markdown(
                            repo, pr_number, state, machine, [comp],
                            "部署条件已通过，正在准备发送部署请求",
                            # This reservation precedes the unsafe POST. It only
                            # says the request is being prepared, not that deploy
                            # has started.
                            test_only=self._is_test_only_pr(pr_data),
                        ), event=None,
                        expected_lifecycle_state=persisted_lifecycle_state,
                    )
                    if not executing_written:
                        return False
                    persisted_lifecycle_state = copy.deepcopy(state)
                    return True

                # Machine policy refreshes independently of the controller.
                # Recheck endpoint, compatibility, ownership, and the cached
                # connection binding immediately before each possible POST.
                try:
                    current_machine = self.policy.get_machine(machine_alias, repo=repo)
                except Exception as exc:
                    return await self._block_machine_policy_change(
                        repo, pr_number, persisted_lifecycle_state,
                        persisted_lifecycle_state, comment_id, machine_alias, actor,
                        f"Current machine policy could not be verified ({type(exc).__name__}).",
                    )
                if current_machine is None:
                    return await self._block_machine_policy_change(
                        repo, pr_number, persisted_lifecycle_state,
                        persisted_lifecycle_state, comment_id, machine_alias, actor,
                        "The approved machine is no longer present in this repository's current policy.",
                    )
                if (current_machine.alias, current_machine.node_id, current_machine.node_host) != approved_machine_binding:
                    return await self._block_machine_policy_change(
                        repo, pr_number, persisted_lifecycle_state,
                        persisted_lifecycle_state, comment_id, machine_alias, actor,
                        "The machine alias now points to a different node ID or IP than the one that passed preflight.",
                    )
                if not await self._machine_is_deployable(
                        current_machine, repo, [comp], endpoints=[selected_endpoint]):
                    return await self._block_machine_policy_change(
                        repo, pr_number, persisted_lifecycle_state,
                        persisted_lifecycle_state, comment_id, machine_alias, actor,
                        "The current repository policy no longer confirms this physical machine identity or Agent Core readiness.",
                    )
                try:
                    current_compatible_ids = set(self._get_component_ids_for_machine(
                        machine_alias, [comp], repo,
                    ))
                except Exception as exc:
                    return await self._block_machine_policy_change(
                        repo, pr_number, persisted_lifecycle_state,
                        persisted_lifecycle_state, comment_id, machine_alias, actor,
                        f"Current machine compatibility could not be verified ({type(exc).__name__}).",
                    )
                if component_id not in current_compatible_ids:
                    return await self._block_machine_policy_change(
                        repo, pr_number, persisted_lifecycle_state,
                        persisted_lifecycle_state, comment_id, machine_alias, actor,
                        "The current machine policy no longer adapts to this component's target, platform, variant, or driver path.",
                    )
                try:
                    await self._check_approval_permissions(current_machine, actor, repo)
                except PolicyError as exc:
                    return await self._block_machine_policy_change(
                        repo, pr_number, persisted_lifecycle_state,
                        persisted_lifecycle_state, comment_id, machine_alias, actor,
                        f"Approval authority could not be revalidated ({str(exc)}).",
                    )
                try:
                    machine_after_permission = self.policy.get_machine(machine_alias, repo=repo)
                except Exception as exc:
                    return await self._block_machine_policy_change(
                        repo, pr_number, persisted_lifecycle_state,
                        persisted_lifecycle_state, comment_id, machine_alias, actor,
                        f"Machine policy changed while approval authority was checked ({type(exc).__name__}).",
                    )
                if (machine_after_permission is None
                        or (machine_after_permission.alias,
                            machine_after_permission.node_id,
                            machine_after_permission.node_host) != approved_machine_binding
                        or not await self._machine_is_deployable(
                            machine_after_permission, repo, [comp],
                            endpoints=[selected_endpoint],
                        )
                        or tuple(sorted(str(owner).casefold() for owner in
                                        (machine_after_permission.owners or [])))
                        != tuple(sorted(str(owner).casefold() for owner in
                                        (current_machine.owners or [])))):
                    return await self._block_machine_policy_change(
                        repo, pr_number, persisted_lifecycle_state,
                        persisted_lifecycle_state, comment_id, machine_alias, actor,
                        "Machine ownership or endpoint policy changed during final authorization; submit a new approval.",
                    )
                current_core_key = selected_core_key or (repo.casefold(), machine_alias)
                if (not self._machine_endpoint_has_unambiguous_identity(
                            machine_after_permission, selected_endpoint, repo,
                            approved_machine_identity,
                        )
                        or self._core_clients.get(current_core_key) is not core
                        or self._core_client_fingerprints.get(current_core_key)
                        != self._endpoint_connection_fingerprint(
                            machine_after_permission, selected_endpoint,
                        )):
                    return await self._block_machine_policy_change(
                        repo, pr_number, persisted_lifecycle_state,
                        persisted_lifecycle_state, comment_id, machine_alias, actor,
                        "The Agent Core target or configured credential changed after preflight; review the current configuration and submit a new approval.",
                    )
                machine = machine_after_permission
                node_id = machine.node_id

                async def announce_post_sent(*, uncertain: bool = False) -> bool:
                    nonlocal persisted_lifecycle_state, deployment_started_notice_posted
                    state["status"] = "deploying"
                    started_written = await self._write_lifecycle_with_history(
                        repo, pr_number, state,
                        await self._deployment_progress_markdown(
                            repo, pr_number, state, machine, [comp],
                            "部署 POST 已发送，正在确认运行镜像",
                            test_only=self._is_test_only_pr(pr_data),
                        ), event=None,
                        expected_lifecycle_state=persisted_lifecycle_state,
                    )
                    if not started_written:
                        return False
                    persisted_lifecycle_state = copy.deepcopy(state)
                    await self._project_status_best_effort(repo, pr_number, "deploying")
                    if not deployment_started_notice_posted:
                        target_image = str(comp.get("image_ref", "") or "未知")
                        deployment_started_notice_posted = await self._post_bound_notice(
                            repo, pr_number, head_sha=pr_head, round_id=round_id,
                            comment_id=comment_id,
                            topic=("deployment-post-uncertain" if uncertain else "deployment-started"),
                            expected_command_kind="approve_deploy",
                            message=(
                                f"部署请求已发送但响应未确认：机器 `{machine.alias}`，"
                                f"已验证 IP `{selected_endpoint}`，目标镜像 `{target_image}`。"
                                "正在核对结果，请勿重复审批。"
                                if uncertain else
                                f"部署已经开始：机器 `{machine.alias}`，使用已验证 IP `{selected_endpoint}`；"
                                f"目标镜像 `{target_image}`。无需重复审批。"
                            ),
                        )
                    return True

                # Recheck the PR, exact approval comment, permissions, and the
                # current policy binding immediately before each possible POST.
                try:
                    execution_pr = await self.proxy.get_pr(repo, pr_number)
                except Exception as exc:
                    logger.warning("final deployment PR check unavailable %s#%s", repo, pr_number)
                    restored = await self._restore_interrupted_approval_preflight(
                        repo, pr_number,
                        reason="暂时无法确认 PR 的当前状态，这次没有发送部署请求。",
                        topic="deployment-pr-check-unavailable",
                        require_stale=False,
                        expected_comment_id=comment_id,
                    )
                    if restored:
                        return True
                    await self._post_command_reply(
                        repo, pr_number, comment_id,
                        "暂时无法确认 PR 的当前状态，这次没有发送部署请求。",
                        topic="deployment-pr-check-unavailable",
                    )
                    return True
                execution_head = execution_pr.get("head") if isinstance(execution_pr, dict) else None
                if (not isinstance(execution_pr, dict)
                        or execution_pr.get("state") != "open"
                        or execution_pr.get("merged")
                        or execution_pr.get("draft") is True):
                    reason = (
                        "这个 PR 还是草稿，部署命令暂时不可用，这次没有发送部署请求。"
                        if isinstance(execution_pr, dict) and execution_pr.get("draft") is True else
                        "这个 PR 已经关闭或合并，部署命令不再适用，这次没有发送部署请求。"
                    )
                    await self._post_command_reply(
                        repo, pr_number, comment_id,
                        reason,
                        topic="deployment-pr-no-longer-open",
                    )
                    return True
                if (not isinstance(execution_head, dict)
                        or execution_head.get("sha") != pr_head):
                    if isinstance(execution_head, dict) and execution_head.get("sha"):
                        await self._invalidate_review_required(
                            repo, pr_number, state, execution_head["sha"], comment_id,
                            "最终部署检查时 PR 出现了新的提交，旧的部署准备不再适用。",
                        )
                    else:
                        await self._post_command_reply(
                            repo, pr_number, comment_id,
                            "暂时无法确认 PR 的最新提交，这次没有发送部署请求。",
                            topic="deployment-head-check-unavailable",
                        )
                    return True
                if await self._revalidate_approve_comment(
                    repo, comment_id, actor_id, machine_selector,
                ) is None:
                    return await self._block_machine_policy_change(
                        repo, pr_number, persisted_lifecycle_state,
                        persisted_lifecycle_state, comment_id, machine_alias, actor,
                        "最终授权后审批命令发生了改变，本次部署没有发送，需要重新审批。",
                    )
                try:
                    await self._check_approval_permissions(machine, actor, repo)
                except PolicyError as exc:
                    return await self._block_machine_policy_change(
                        repo, pr_number, persisted_lifecycle_state,
                        persisted_lifecycle_state, comment_id, machine_alias, actor,
                        f"Approval authority changed before the deploy POST ({exc}); no deploy POST was sent.",
                    )
                try:
                    final_machine = self.policy.get_machine(machine_alias, repo=repo)
                except Exception as exc:
                    return await self._block_machine_policy_change(
                        repo, pr_number, persisted_lifecycle_state,
                        persisted_lifecycle_state, comment_id, machine_alias, actor,
                        f"Current machine policy could not be verified immediately before deployment ({type(exc).__name__}).",
                    )
                if (final_machine is None
                        or (final_machine.alias, final_machine.node_id,
                            final_machine.node_host) != approved_machine_binding
                        or not await self._machine_is_deployable(
                            final_machine, repo, [comp], endpoints=[selected_endpoint],
                        )
                        or tuple(sorted(str(owner).casefold() for owner in
                                        (final_machine.owners or [])))
                        != tuple(sorted(str(owner).casefold() for owner in
                                        (machine.owners or [])))
                        or not self._machine_endpoint_has_unambiguous_identity(
                            final_machine, selected_endpoint, repo,
                            approved_machine_identity,
                        )
                        or self._core_clients.get(current_core_key) is not core
                        or self._core_client_fingerprints.get(current_core_key)
                        != self._endpoint_connection_fingerprint(
                            final_machine, selected_endpoint,
                        )):
                    return await self._block_machine_policy_change(
                        repo, pr_number, persisted_lifecycle_state,
                        persisted_lifecycle_state, comment_id, machine_alias, actor,
                        "Machine endpoint, ownership, or credentials changed during final deployment checks; no deploy POST was sent.",
                    )
                machine = final_machine
                node_id = machine.node_id

                if redeploy_mode:
                    try:
                        final_runtime = await self._preflight_running_images(core, [comp])
                        if len(final_runtime) != 1:
                            raise DeployControllerError("runtime preflight result is incomplete")
                        observed = final_runtime[0]
                    except Exception as exc:
                        deploy_preflight_unavailable = True
                        runtime_unconfirmed_components.append(comp)
                        deploy_error = f"cannot confirm runtime image before redeployment ({type(exc).__name__})"
                        break
                    if str(observed.get("runtime_id", "") or "") != runtime_id:
                        deploy_preflight_unavailable = True
                        runtime_unconfirmed_components.append(comp)
                        runtime_unconfirmed_status = "identity_changed"
                        runtime_preflight_message = (
                            "运行时身份在最终只读检查中发生变化，无法确认审批目标。"
                        )
                        deploy_error = "runtime identity changed; ZERO deploy POST"
                        break
                    if comp_target == "core":
                        actual_image = str(observed.get("running_image", "") or "")
                        try:
                            validate_image_ref(actual_image)
                            runtime_known = True
                        except ValueError:
                            runtime_known = False
                        already_target = observed.get("already_target") is True
                        if not runtime_known:
                            deploy_preflight_unavailable = True
                            runtime_unconfirmed_components.append(comp)
                            deploy_error = "cannot compare the complete Core image reference; ZERO deploy POST"
                            break
                    else:
                        runtime_status = str(observed.get("status", "") or "").casefold()
                        actual_image = str(observed.get("running_image", "") or "")
                        if not runtime_status:
                            deploy_preflight_unavailable = True
                            runtime_unconfirmed_components.append(comp)
                            deploy_error = "machine status is unavailable; ZERO deploy POST"
                            break
                        if runtime_status.casefold() in {
                                "deploying", "updating", "starting", "restarting", "stopping"}:
                            deploy_preflight_unavailable = True
                            runtime_unconfirmed_components.append(comp)
                            deploy_error = "deployment is already in progress; ZERO deploy POST"
                            break
                        if runtime_status == "running":
                            if not actual_image:
                                deploy_preflight_unavailable = True
                                runtime_unconfirmed_components.append(comp)
                                deploy_error = "running image is unavailable; ZERO deploy POST"
                                break
                            try:
                                validate_image_ref(actual_image)
                            except ValueError:
                                deploy_preflight_unavailable = True
                                runtime_unconfirmed_components.append(comp)
                                deploy_error = "running image reference is invalid; ZERO deploy POST"
                                break
                            already_target = actual_image == image_ref
                        elif runtime_status in {"stopped", "exited", "not_running", "failed"}:
                            deploy_preflight_unavailable = True
                            runtime_unconfirmed_components.append(comp)
                            runtime_unconfirmed_status = "not_running"
                            runtime_preflight_message = (
                                "目标运行时当前未运行，无法确认镜像漂移。"
                            )
                            deploy_error = "target runtime is not running; ZERO deploy POST"
                            break
                        else:
                            deploy_preflight_unavailable = True
                            runtime_unconfirmed_components.append(comp)
                            deploy_error = "machine state cannot be confirmed; ZERO deploy POST"
                            break
                    if already_target:
                        if comp_target == "core":
                            approve_attempt["health"].append({
                                "component_id": component_id, "runtime_id": "core",
                                "current_tag": actual_image,
                                "target_tag": image_ref,
                                "verified": True, "already_target": True,
                            })
                        else:
                            approve_attempt["health"].append({
                                "component_id": component_id, "runtime_id": runtime_id,
                                "status": "running", "running_image": image_ref,
                                "target_image": image_ref, "verified": True,
                            })
                        new_deployments.append({
                            "machine": machine_alias, "ip": selected_endpoint,
                            "component_ids": [component_id], "phase": "deployed",
                        })
                        state["deployments"] = list(existing_deployments) + list(new_deployments)
                        self._record_redeployed_runtime_matches(
                            state, machine, new_deployments, approve_attempt["health"],
                        )
                        state["command"] = {
                            "comment_id": comment_id,
                            "kind": "approve_deploy",
                            "phase": "completed",
                            "args": {
                                "machine": machine_alias,
                                "actor": actor,
                                "node_id": machine.node_id,
                                "node_host": selected_endpoint,
                                "deployment_request_submitted": deployment_request_submitted,
                                "pending_component_ids": [component_id],
                                "preflight_pending": True,
                                "preflight_started_at": time.time(),
                            },
                        }
                        remaining_after_adoption = [
                            component for component in state.get("components", [])
                            if component.get("component_id", "")
                            not in _component_id_set(state["deployments"])
                        ]
                        remaining_groups_after_adoption = (
                            self._runtime_redeploy_machine_groups(
                                state, remaining_after_adoption, repo,
                            )
                            if state.get("runtime_redeploy") else
                            self._get_machine_groups_for_components(
                                remaining_after_adoption, repo,
                            )
                        )
                        adopted_markdown = await self._approval_retry_markdown(
                            repo, pr_number, state, remaining_groups_after_adoption,
                            display_status=preflight_source_status,
                            test_only=self._is_test_only_pr(pr_data),
                            gate_note=[
                                "这台机器上已经在运行本轮批准的镜像，这次没有发送部署 POST。",
                                "请继续审批剩余组件；全部确认后即可开始测试。",
                            ],
                            deployments=self._enrich_deployments_for_render(
                                state["deployments"], repo,
                            ),
                        )
                        adopted_written = await self._write_lifecycle_with_history(
                            repo, pr_number, state, adopted_markdown,
                            expected_lifecycle_state=persisted_lifecycle_state,
                        )
                        if not adopted_written:
                            return False
                        persisted_lifecycle_state = copy.deepcopy(state)
                        continue
                # Route core through self-update path; non-core via existing path
                if comp_target == "core":
                    # Core has no automated case; runtime_id is always "core"
                    # Use unified idempotent entry point
                    try:
                        verified, health_evidence, post_performed = (
                            await self._deploy_or_adopt_core_component(
                                core, node_id, component_id, image_ref,
                                before_post=mark_component_executing,
                                after_post=announce_post_sent,
                            )
                        )
                    except DeployOutcomeUncertain as e:
                        deploy_outcome_uncertain = True
                        deploy_error = str(e)
                        break
                    except DeployPreflightUnavailable as e:
                        deploy_preflight_unavailable = True
                        runtime_unconfirmed_components.append(comp)
                        deploy_error = str(e)
                        break
                    except DeployControllerError as e:
                        deploy_error = str(e)
                        break

                    if health_evidence.get("error") == (
                            "deploy lifecycle write was not confirmed before POST"):
                        return False
                    approve_attempt["health"].append(health_evidence)
                    if not verified:
                        deploy_outcome_uncertain = True
                        deploy_error = (
                            f"post-deploy verify timeout for core: "
                            f"target image not observed running"
                        )
                        break

                    # Deploy success verified (or adopted as already deployed): record deployment
                    new_deployments.append({
                        "machine": machine_alias,
                        "ip": selected_endpoint,
                        "component_ids": [component_id],
                        "phase": "deployed",
                    })
                else:
                    if not await mark_component_executing():
                        return False
                    try:
                        await self._deploy_component(
                            core, node_id, image_ref, runtime_id,
                            after_post=announce_post_sent,
                        )
                    except DeployOutcomeUncertain as e:
                        deploy_outcome_uncertain = True
                        deploy_error = str(e)
                        break
                    except DeployControllerError as e:
                        deploy_error = str(e)
                        break

                    verifying_written = await self._write_lifecycle_with_history(
                        repo, pr_number, state,
                        await self._deployment_progress_markdown(
                            repo, pr_number, state, machine, [comp], "正在确认目标镜像",
                            test_only=self._is_test_only_pr(pr_data),
                        ), event=None,
                        expected_lifecycle_state=persisted_lifecycle_state,
                    )
                    if not verifying_written:
                        return False
                    persisted_lifecycle_state = copy.deepcopy(state)
                    # Post-deploy verification: confirm target image is actually running
                    verified, health_evidence = await self._verify_deployed_runtime(
                        core, node_id, component_id, runtime_id, image_ref,
                    )
                    approve_attempt["health"].append(health_evidence)
                    if not verified:
                        deploy_outcome_uncertain = True
                        deploy_error = (
                            f"post-deploy verify timeout for {comp_target!r}: "
                            f"target image not observed running"
                        )
                        break

                    # Deploy success verified: record deployment
                    new_deployments.append({
                        "machine": machine_alias,
                        "ip": selected_endpoint,
                        "component_ids": [component_id],
                        "phase": "deployed",
                    })

            if deploy_preflight_unavailable:
                state["deployments"] = list(existing_deployments) + list(new_deployments)
                if redeploy_mode:
                    self._record_redeployed_runtime_matches(
                        state, machine, new_deployments, approve_attempt["health"],
                    )
                    if runtime_unconfirmed_components:
                        self._mark_runtime_checks_unavailable(
                            state, machine, runtime_unconfirmed_components,
                            status=runtime_unconfirmed_status,
                            endpoint_ip=selected_endpoint,
                        )
                state["status"] = self._approval_retry_status(state)
                state["command"] = {
                    "comment_id": comment_id,
                    "kind": "approve_deploy",
                    "phase": "completed",
                    "args": {
                        "machine": machine_alias, "actor": actor,
                        "deployment_request_submitted": deployment_request_submitted,
                    },
                }
                state["last_processed_comment_id"] = comment_id
                approve_attempt["outcome"] = "preflight_unavailable"
                self._record_approve_attempt(state, approve_attempt)
                remaining_components = [
                    c for c in state.get("components", [])
                    if c.get("component_id", "")
                    not in _component_id_set(state["deployments"])
                ]
                remaining_groups = (
                    self._runtime_redeploy_machine_groups(
                        state, remaining_components, repo,
                    )
                    if state.get("runtime_redeploy") else
                    self._get_machine_groups_for_components(remaining_components, repo)
                )
                markdown = await self._approval_retry_markdown(
                    repo, pr_number, state, remaining_groups,
                    test_only=self._is_test_only_pr(pr_data),
                    gate_note=[
                        (runtime_preflight_message
                         or "目前无法确认机器上的运行状态。"),
                        "剩余组件没有部署，这次没有发送部署请求。",
                        "请在机器恢复后按当前 PR Summary 重新审批。",
                    ],
                    deployments=self._enrich_deployments_for_render(state["deployments"], repo),
                )
                deferred_written = await self._write_lifecycle_with_history(
                    repo, pr_number, state, markdown,
                    event={"event": "Deploy preflight deferred: zero POST for remaining component",
                           "machine": machine_alias, "timestamp": comments_mod.beijing_now_str()},
                    expected_lifecycle_state=persisted_lifecycle_state,
                )
                if not deferred_written:
                    return False
                if new_deployments:
                    state = await self._reconcile_runtime_image_checks(
                        repo, pr_number, state, pr_data, force=True,
                        machine_filter=(
                            machine_alias,
                            selected_endpoint,
                        ),
                    )
                await self._project_status_best_effort(repo, pr_number, state["status"])
                await self._post_command_reply(
                    repo, pr_number, comment_id,
                    (runtime_preflight_message
                     or "目前无法确认机器上的运行状态。")
                    + " 剩余组件没有部署，这次没有发送部署请求。",
                    topic="deployment-preflight-failed",
                )
                return True

            if deploy_outcome_uncertain:
                state["deployments"] = list(existing_deployments) + list(new_deployments)
                if redeploy_mode:
                    self._record_redeployed_runtime_matches(
                        state, machine, new_deployments, approve_attempt["health"],
                    )
                state["status"] = "deploying"
                previous_command = state.get("command", {})
                previous_args = (
                    previous_command.get("args", {})
                    if isinstance(previous_command, dict) else {}
                )
                uncertain_args = {
                    "machine": machine_alias,
                    "actor": actor,
                    "node_id": node_id,
                    "node_host": selected_endpoint,
                    "deployment_request_submitted": deployment_request_submitted,
                    "pending_component_ids": [component_id],
                }
                if (isinstance(previous_args, dict)
                        and "execution_started_at" in previous_args):
                    uncertain_args["execution_started_at"] = previous_args[
                        "execution_started_at"
                    ]
                uncertain_command = {
                    "comment_id": comment_id,
                    "kind": "approve_deploy",
                    "phase": "uncertain",
                    "args": uncertain_args,
                }
                self._ensure_uncertain_since(uncertain_command)
                state["command"] = uncertain_command
                state["last_processed_comment_id"] = comment_id
                approve_attempt["outcome"] = "uncertain"
                self._record_approve_attempt(state, approve_attempt)
                markdown = await self._approval_retry_markdown(
                    repo, pr_number, state,
                    self._get_machine_groups_for_components([
                        c for c in state.get("components", [])
                        if c.get("component_id", "") not in _component_id_set(state["deployments"])
                    ], repo),
                    test_only=self._is_test_only_pr(pr_data),
                    gate_note=[
                        "已经尝试发送部署请求，但结果还没有确认。",
                        "控制器会持续只读检查目标状态，不会重复提交部署。",
                        "在确认实际运行状态之前，请保持等待。",
                    ],
                    deployments=self._enrich_deployments_for_render(state["deployments"], repo),
                    display_status="deploying",
                )
                event = {
                    "event": "Deploy outcome uncertain",
                    "result": "uncertain",
                    "machine": machine_alias,
                    "timestamp": comments_mod.beijing_now_str(),
                }
                uncertain_written = await self._write_lifecycle_with_history(
                    repo, pr_number, state, markdown, event=event,
                    expected_lifecycle_state=persisted_lifecycle_state,
                )
                if not uncertain_written:
                    return False
                await self._project_status_best_effort(repo, pr_number, "deploying")
                await self._post_command_reply(
                    repo, pr_number, comment_id,
                    "部署请求已经发出，但还没有确认结果。",
                    topic="deployment-outcome-uncertain", error=True,
                )
                return True

            if deploy_error is not None:
                state["deployments"] = list(existing_deployments) + list(new_deployments)
                if redeploy_mode:
                    self._record_redeployed_runtime_matches(
                        state, machine, new_deployments, approve_attempt["health"],
                    )
                # Deploy failed - persist terminal state FIRST, then upload evidence
                state["status"] = "failed"
                state["command"] = {
                    "comment_id": comment_id,
                    "kind": "approve_deploy",
                    "phase": "completed",
                    "args": {
                        "machine": machine_alias, "actor": actor,
                        "deployment_request_submitted": deployment_request_submitted,
                    },
                }
                state["last_processed_comment_id"] = comment_id

                failure_component = (
                    failed_component_target or failed_component_id
                    if failed_component_id else "组件"
                )
                failure_detail = (
                    f"机器 `{machine_alias}`（IP `{machine.node_host}`）上的 {failure_component} "
                    f"没有完成部署。"
                )
                markdown = comments_mod.failed_comment(
                    repo, pr_number, pr_head, error=failure_detail,
                    failed_stage="deployment",
                )
                approve_attempt["outcome"] = "failed"
                self._record_approve_attempt(state, approve_attempt)
                event = {
                    "event": "Deploy failed",
                    "result": "failed",
                    "machine": machine_alias,
                    "timestamp": comments_mod.beijing_now_str(),
                }
                failed_written = await self._write_lifecycle_with_history(
                    repo, pr_number, state, markdown, event=event,
                    expected_lifecycle_state=persisted_lifecycle_state,
                )
                if not failed_written:
                    return False
                if new_deployments:
                    state = await self._reconcile_runtime_image_checks(
                        repo, pr_number, state, pr_data, force=True,
                        machine_filter=(
                            machine_alias,
                            selected_endpoint,
                        ),
                    )
                await self._project_status_best_effort(repo, pr_number, "failed")
                await self._post_command_reply(
                    repo, pr_number, comment_id,
                    f"机器上的 {failure_component} 没有部署成功。",
                    topic="deployment-failed", error=True,
                )

                # One-shot runtime log snapshot for failed path
                runtime_logs = await self._snapshot_terminal_runtime_logs(
                    repo,
                    state.get("components", []),
                    state.get("deployments", []),
                )

                # Best-effort evidence upload after failed
                try:
                    cos_metadata = await self._upload_evidence(
                        repo, pr_number, pr_head, state, "fail",
                        deploy_error=deploy_error,
                        runtime_logs=runtime_logs,
                    )
                except Exception as e:
                    logger.warning(
                        "failed deploy evidence upload %s#%s: %s",
                        repo, pr_number, e,
                    )
                    return True

                if cos_metadata.get("object_key"):
                    # Step 1: rebind terminal state with COS metadata FIRST
                    rebound = await self._rebind_terminal_cos_if_current(
                        repo,
                        pr_number,
                        expected_head=pr_head,
                        expected_terminal_status="failed",
                        expected_comment_id=comment_id,
                        expected_command_kind="approve_deploy",
                        cos_metadata=cos_metadata,
                        markdown=comments_mod.failed_comment(
                            repo, pr_number, pr_head,
                            error=failure_detail,
                            cos_object_key=str(cos_metadata.get("object_key", "") or ""),
                            cos_bundle_sha256=str(cos_metadata.get("sha256", "") or ""),
                            cos_bundle_size=int(cos_metadata.get("size", 0) or 0),
                            failed_stage="deployment",
                        ),
                    )
                    if not rebound:
                        return False
                    # Step 2: generate presigned URL AFTER successful rebind
                    cos_download_url = ""
                    try:
                        cos_download_url = self.cos.generate_evidence_download_url(
                            cos_metadata["object_key"],
                        )
                    except Exception:
                        logger.warning(
                            "COS_EVIDENCE_PRESIGN=FAILED repo=%s pr=%s",
                            repo, pr_number,
                        )
                    # Step 3: rebind final comment with download URL
                    rebound = await self._rebind_terminal_cos_if_current(
                        repo,
                        pr_number,
                        expected_head=pr_head,
                        expected_terminal_status="failed",
                        expected_comment_id=comment_id,
                        expected_command_kind="approve_deploy",
                        cos_metadata=cos_metadata,
                        markdown=comments_mod.failed_comment(
                            repo, pr_number, pr_head,
                            error=failure_detail,
                            cos_object_key=str(cos_metadata.get("object_key", "") or ""),
                            cos_bundle_sha256=str(cos_metadata.get("sha256", "") or ""),
                            cos_bundle_size=int(cos_metadata.get("size", 0) or 0),
                            cos_download_url=cos_download_url,
                            failed_stage="deployment",
                        ),
                    )
                    if not rebound:
                        return False
                return True

            # Merge into existing deployments
            state["deployments"] = list(existing_deployments) + list(new_deployments)
            if redeploy_mode:
                self._record_redeployed_runtime_matches(
                    state, machine, new_deployments, approve_attempt["health"],
                )

            state["command"] = {
                "comment_id": comment_id,
                "kind": "approve_deploy",
                "phase": "completed",
                "args": {
                    "machine": machine_alias, "actor": actor,
                    "deployment_request_submitted": deployment_request_submitted,
                },
            }
            state["last_processed_comment_id"] = comment_id
            approve_attempt["outcome"] = "deployed"
            self._record_approve_attempt(state, approve_attempt)
            # Persist this machine's log task atomically with its verified
            # deployed fact, before testing projection or other evidence reads.
            deployment_logs = state.setdefault("deployment_logs", {})
            prior_log = deployment_logs.get(machine_alias)
            if not (isinstance(prior_log, dict)
                    and prior_log.get("head_sha") == pr_head
                    and prior_log.get("round_id") == round_id_for_state(state)
                    and prior_log.get("status") == "ready"):
                deployment_logs[machine_alias] = {
                    "head_sha": pr_head, "round_id": round_id_for_state(state),
                    "status": "pending", "collected_at": "",
                    "object_key": "", "sha256": "", "size": 0,
                }

            # Check completion: all required components durably deployed -> testing.
            all_component_ids = {c.get("component_id", "") for c in components}
            deployed_component_ids = set()
            for dep in state["deployments"]:
                if dep.get("phase") == "deployed":
                    for cid in dep.get("component_ids", []):
                        deployed_component_ids.add(cid)

            if deployed_component_ids != all_component_ids:
                # Partial coverage achieved; more machines needed.
                state["status"] = self._approval_retry_status(state)
                remaining = [
                    c for c in components
                    if c.get("component_id", "") not in deployed_component_ids
                ]
                remaining_groups = (
                    self._runtime_redeploy_machine_groups(state, remaining, repo)
                    if state.get("runtime_redeploy") else
                    self._get_machine_groups_for_components(remaining, repo)
                )
                markdown = await self._approval_retry_markdown(
                    repo, pr_number, state,
                    remaining_groups,
                    test_only=self._is_test_only_pr(pr_data),
                    gate_note=[
                        "这台机器已部署它负责的组件，但还有剩余组件需要其他机器审批。",
                        "请按 PR Summary 中当前显示的机器命令继续审批。",
                    ],
                    deployments=self._enrich_deployments_for_render(state["deployments"], repo),
                )
                deploy_event = {
                    "event": f"Machine `{machine_alias}` deployed",
                    "machine": machine_alias,
                    "ip": self._runtime_display_identity(machine_alias, repo)[0],
                    "timestamp": comments_mod.beijing_now_str(),
                }
                partial_written = await self._write_lifecycle_with_history(
                    repo, pr_number, state, markdown, event=deploy_event,
                    expected_lifecycle_state=persisted_lifecycle_state,
                )
                if not partial_written:
                    return False
                await self._save_deployed_machine_log(repo, pr_number, state, machine_alias)
                if new_deployments:
                    state = await self._reconcile_runtime_image_checks(
                        repo, pr_number, state, pr_data, force=True,
                        machine_filter=(
                            machine_alias,
                            selected_endpoint,
                        ),
                    )
                await self._project_status_best_effort(repo, pr_number, state["status"])
                notice_lines = await self._machine_notice_lines(
                    remaining_groups, repo, mention_owners=False,
                    test_only=self._is_test_only_pr(pr_data),
                    components=remaining,
                )
                await self._post_bound_notice(
                    repo, pr_number, head_sha=pr_head,
                    round_id=round_id_for_state(state), comment_id=comment_id,
                    topic="partial-deployment-next-approver",
                    expected_command_kind="approve_deploy",
                    result="accepted",
                    message="\n".join([
                        "这台机器负责的组件已经部署完成，剩余组件还需要其他机器审批。",
                        *(
                            ["请按下面的命令继续审批：", *notice_lines]
                            if notice_lines else
                            self._machine_blocking_summary(remaining_groups)
                        ),
                    ]),
                )
                return True

            # All components deployed -> durable testing state FIRST
            state["status"] = "testing"
            state.pop("acceptance_request", None)

            # Build testing markdown WITHOUT advisory case result
            testing_markdown = comments_mod.testing(
                repo, pr_number, pr_head, case_result="",
                deployments=self._enrich_deployments_for_render(state.get("deployments", []), repo),
                components=state.get("components", []),
                deployments_complete=(bool(all_component_ids)
                                      and all_component_ids.issubset(deployed_component_ids)),
            )
            # The LAST machine also gets its own per-machine history event,
            # mirroring the partial-coverage path, so every successful machine
            # appears exactly once in the visible History (newest-first).
            last_machine_event = {
                "event": f"Machine `{machine_alias}` deployed",
                "machine": machine_alias,
                "ip": self._runtime_display_identity(machine_alias, repo)[0],
                "timestamp": comments_mod.beijing_now_str(),
            }
            event_all = {
                "event": "All components deployed",
                "lifecycle": "`deploy-requested` \u2192 `testing`",
                "timestamp": comments_mod.beijing_now_str(),
            }
            # Atomic: write BOTH "All components deployed" and "Machine deployed"
            # in a single hidden-state/comment write so a crash cannot leave
            # incomplete History.  Newest-first: All components, then Machine.
            testing_written = await self._write_lifecycle_with_history(
                repo, pr_number, state, testing_markdown,
                events=[event_all, last_machine_event],
                expected_lifecycle_state=persisted_lifecycle_state,
            )
            if not testing_written:
                return False
            # Project status label "testing" SECOND
            await self._save_deployed_machine_log(repo, pr_number, state, machine_alias)
            if new_deployments:
                state = await self._reconcile_runtime_image_checks(
                    repo, pr_number, state, pr_data, force=True,
                    machine_filter=(
                        machine_alias,
                        selected_endpoint,
                    ),
                )
            await self._project_status_best_effort(repo, pr_number, "testing")
            upload_url = await self._current_testing_upload_url(
                repo, pr_number, head_sha=pr_head,
                round_id=round_id_for_state(state),
                approval_comment_id=comment_id,
            )
            upload_message = (
                f"可选上传测试视频或图片，方便验收人了解实际效果：[打开固定上传页面](<{upload_url}>)。"
                if upload_url else
                "测试视频或图片上传完全可选；公共上传入口暂时不可用时不影响测试和验收，"
                "恢复后 PR Summary 会出现同一个固定链接。"
            )
            await self._post_bound_notice(
                repo, pr_number, head_sha=pr_head,
                round_id=round_id_for_state(state), comment_id=comment_id,
                topic="deployment-complete-testing-next",
                expected_command_kind="approve_deploy",
                result="accepted",
                message=(f"部署已完成，现在可以开始测试。\n\n"
                         f"{upload_message}\n\n"
                         "测试完成后，请发送 `/request_acceptance` 提交验收。"),
            )

            return True

        except PolicyError as e:
            logger.warning(
                "handle_approve_deploy final authorization blocked %s#%s: %s",
                repo, pr_number, type(e).__name__,
            )
            restored = await self._restore_interrupted_approval_preflight(
                repo, pr_number,
                reason=(
                    "部署前的最终权限检查没有通过，当时没有发送部署请求，"
                    "这次审批也没有执行。"
                ),
                topic="approval-preflight-authorization-blocked",
                require_stale=False,
                expected_comment_id=comment_id,
            )
            if restored:
                return True
            await self._post_error(
                repo, pr_number,
                "部署前的最终权限检查没有通过，这次审批没有执行。",
                comment_id=comment_id,
            )
            return True
        except Exception as e:
            restored = await self._restore_interrupted_approval_preflight(
                repo, pr_number,
                reason=(
                    "部署前的最终检查没有通过，当时没有发送部署请求，"
                    "这次审批也没有执行。"
                ),
                topic="approval-preflight-validation-failed",
                require_stale=False,
                expected_comment_id=comment_id,
            )
            if restored:
                return True
            logger.error(
                "handle_approve_deploy %s#%s: %s",
                repo, pr_number, e,
            )
            raise

    def _all_required_components_deployed(self, state: dict, repo: str) -> bool:
        """Validate every required component has a trusted deployment record."""
        components = state.get("components")
        deployments = state.get("deployments")
        if (not isinstance(components, list) or not components
                or not isinstance(deployments, list)):
            return False
        seen = set()
        for component in components:
            if not isinstance(component, dict):
                return False
            cid = component.get("component_id")
            target = component.get("target")
            runtime_id = component.get("runtime_id")
            image_ref = component.get("image_ref")
            if (not isinstance(cid, str) or not cid or cid in seen
                    or not _is_supported_target(target)
                    or not isinstance(runtime_id, str) or not runtime_id
                    or not isinstance(image_ref, str) or not image_ref):
                return False
            seen.add(cid)
            if target == "core" and runtime_id != "core":
                return False
            records = [dep for dep in deployments if isinstance(dep, dict)
                       and dep.get("phase") == "deployed"
                       and isinstance(dep.get("component_ids"), list)
                       and cid in dep.get("component_ids", [])]
            if len(records) != 1:
                return False
            alias = records[0].get("machine")
            if not isinstance(alias, str) or not alias or self.policy.get_machine(alias, repo=repo) is None:
                return False
        return True

    async def _restart_record_test_comment_is_current(
        self, repo: str, state: dict, expected_comment: dict, *, consumed: bool = False,
    ) -> bool:
        """Recheck unedited comment provenance and current authority, fail closed."""
        if (not self.config.auth_valid or repo not in self.config.active_repos
                or repo not in self.config.github_repos):
            return False
        cid = expected_comment.get("id")
        user = expected_comment.get("user", {})
        if not isinstance(user, dict):
            return False
        uid, login = user.get("id"), user.get("login")
        if (not isinstance(cid, int) or isinstance(cid, bool) or cid <= 0
                or (not consumed and cid <= state.get("last_processed_comment_id", 0))
                or (consumed and (cid != state.get("command", {}).get("comment_id")
                                  or cid > state.get("last_processed_comment_id", 0)))
                or not isinstance(uid, int) or isinstance(uid, bool) or uid <= 0
                or not isinstance(login, str) or not login
                or self.proxy.is_bot_comment(expected_comment)
                or not isinstance(expected_comment.get("body"), str)
                or not isinstance(expected_comment.get("created_at"), str)
                or not expected_comment.get("created_at")
                or expected_comment.get("updated_at") != expected_comment.get("created_at")):
            return False
        from .commands import parse_command
        parsed = parse_command(expected_comment.get("body", ""))
        try:
            await self._check_record_test_permissions(
                repo, login, state, actor_id=uid, comment_id=cid,
                result=parsed.result,
            )
        except PolicyError:
            return False
        fresh_comment = await self.proxy.get_comment(repo, cid)
        if not isinstance(fresh_comment, dict):
            return False
        fresh_user = fresh_comment.get("user", {})
        if not isinstance(fresh_user, dict):
            return False
        # Compare API identity, not response shape (pin/reactions may differ).
        # Bind both snapshots to the explicitly requested repository and ID.
        comment_url = f"{self.config.github_api_url.rstrip('/')}/repos/{repo}/issues/comments/{cid}"
        for comment in (expected_comment, fresh_comment):
            app = comment.get("performed_via_github_app")
            if app is not None and (
                not isinstance(app, dict)
                or not isinstance(app.get("id"), int) or isinstance(app.get("id"), bool)
                or app["id"] <= 0
            ):
                return False
        return (type(fresh_comment.get("id")) is int and fresh_comment["id"] == cid
                and expected_comment.get("url") == comment_url
                and fresh_comment.get("url") == comment_url
                and fresh_comment.get("body") == expected_comment["body"]
                and type(fresh_user.get("id")) is int and fresh_user["id"] == uid
                and fresh_user.get("login") == login
                and fresh_user.get("type") == user.get("type")
                and fresh_comment.get("created_at") == expected_comment["created_at"]
                and fresh_comment.get("updated_at") == expected_comment["updated_at"]
                and (fresh_comment.get("performed_via_github_app") or {}).get("id")
                == (expected_comment.get("performed_via_github_app") or {}).get("id")
                and not self.proxy.is_bot_comment(fresh_comment)
                and self.config.auth_valid
                and repo in self.config.active_repos and repo in self.config.github_repos)

    async def resume_record_test(
        self, repo: str, pr_number: int, expected_state: dict, expected_comment: dict,
    ) -> bool:
        """Resume the business verdict only; never dispatch deployment commands."""
        from .commands import parse_command

        cmd = parse_command(expected_comment.get("body", ""))
        if (cmd.kind != "record_test" or cmd.result not in ("pass", "fail")
                or expected_state.get("status") != "testing"
                or not self._all_required_components_deployed(expected_state, repo)
                or not await self._restart_record_test_comment_is_current(
                    repo, expected_state, expected_comment)):
            return False
        pr = await self.proxy.get_pr(repo, pr_number)
        if (pr.get("state") != "open" or pr.get("merged") or pr.get("draft")
                or pr.get("head", {}).get("sha") != expected_state.get("head_sha")):
            return False
        user = expected_comment["user"]
        handled = await self.handle_record_test(
            repo, pr_number, expected_comment["id"], cmd.result, cmd.summary,
            user["login"], str(user["id"]),
            _recovery_state=expected_state, _recovery_comment=expected_comment,
        )
        if not handled:
            return False
        # Policy/not-ready responses are handled commands in normal operation,
        # but never authorize advancing a startup baseline over unfinished work.
        fresh = await self.proxy.read_hidden_state(repo, pr_number)
        return (isinstance(fresh, dict)
                and fresh.get("head_sha") == expected_state.get("head_sha")
                and fresh.get("status") == ("succeeded" if cmd.result == "pass" else "failed")
                and fresh.get("command", {}).get("kind") == "record_test"
                and fresh.get("command", {}).get("comment_id") == expected_comment["id"]
                and fresh.get("command", {}).get("phase") == "completed"
                and fresh.get("last_processed_comment_id") == expected_comment["id"])

    async def _revalidate_record_test_state(
        self, repo: str, pr_number: int, original: dict, result: str,
        expected_comment: dict | None = None,
    ) -> dict | None:
        """Fresh-read GitHub after awaits before publishing the result."""
        pr_data = await self.proxy.get_pr(repo, pr_number)
        if inspect.isawaitable(pr_data):
            pr_data = await pr_data
        fresh = await self.proxy.read_hidden_state(repo, pr_number)
        if (not isinstance(pr_data, dict) or not isinstance(fresh, dict)
                or pr_data.get("state") != "open" or pr_data.get("merged")
                or pr_data.get("draft")):
            return None
        pr_head = pr_data.get("head", {}).get("sha", "")
        if (not isinstance(pr_head, str) or not re.fullmatch(r"[0-9a-f]{40}", pr_head)
                or pr_head != original.get("head_sha", "")):
            return None
        if (fresh.get("status") != "testing" or not isinstance(fresh.get("command"), dict)
                or fresh.get("command", {}).get("phase") != "completed"
                or fresh.get("command") != original.get("command")):
            return None
        if int(fresh.get("last_processed_comment_id", 0) or 0) != original.get("last_processed_comment_id", 0):
            return None
        if (fresh.get("head_sha") != original.get("head_sha")
                or fresh.get("cos") != original.get("cos")):
            return None
        if not self._all_required_components_deployed(fresh, repo):
            return None
        if result == "pass":
            for key in (
                "head_sha", "components", "deployments", "case_results", "review_evidence",
                "approve_attempts", "approve_attempts_total", "approve_attempts_truncated",
            ):
                if fresh.get(key) != original.get(key):
                    return None
        if expected_comment is not None:
            if (pr_head != original.get("head_sha")
                    or fresh != original
                    or not await self._restart_record_test_comment_is_current(
                        repo, fresh, expected_comment)):
                return None
        return copy.deepcopy(fresh)

    @staticmethod
    def _valid_cos_metadata(repo: str, pr_number: int, head_sha: str, metadata: dict) -> bool:
        try:
            CosClient.validate_object_key(repo, pr_number, head_sha, metadata.get("object_key", ""))
            size = metadata.get("size")
            return (isinstance(metadata.get("sha256"), str)
                    and re.fullmatch(r"[0-9a-f]{64}", metadata["sha256"]) is not None
                    and isinstance(size, int) and not isinstance(size, bool)
                    and 1 <= size <= 10485760)
        except (ValueError, TypeError, AttributeError):
            return False

    async def _terminal_cos_context_is_current(
        self, repo: str, pr_number: int, state: dict, comment: dict,
    ) -> bool:
        if not await self._restart_record_test_comment_is_current(
            repo, state, comment, consumed=True,
        ):
            return False
        pr = await self.proxy.get_pr(repo, pr_number)
        fresh = await self.proxy.read_hidden_state(repo, pr_number)
        return (fresh == state and pr.get("state") == "open" and not pr.get("merged")
                and not pr.get("draft")
                and pr.get("head", {}).get("sha") == state.get("head_sha")
                and self.config.auth_valid and repo in self.config.active_repos
                and repo in self.config.github_repos)

    async def _retry_terminal_cos(
        self, repo: str, pr_number: int, state: dict, *, refresh_url: bool = False,
    ) -> None:
        """Best-effort evidence maintenance in the existing serial watcher.

        Missing metadata is the durable restart signal. Retry timing is local:
        five attempts per command/process, 60s exponential backoff capped at
        900s. No business fields/events/labels are changed by this path.
        """
        try:
            state = copy.deepcopy(state)
            status = state.get("status")
            cmd = state.get("command", {})
            result = state.get("test_result")
            cid = cmd.get("comment_id")
            head = state.get("head_sha", "")
            if (status not in ("succeeded", "failed") or result not in ("pass", "fail")
                    or status != ("succeeded" if result == "pass" else "failed")
                    or cmd.get("kind") != "record_test" or cmd.get("phase") != "completed"
                    or not isinstance(cid, int) or isinstance(cid, bool) or cid <= 0
                    or state.get("last_processed_comment_id", 0) < cid):
                return
            metadata = state.get("cos", {}) or {}
            if self._valid_cos_metadata(repo, pr_number, head, metadata) and not refresh_url:
                return
            key = (repo, pr_number, head, cid)
            attempts, next_attempt = self._cos_retries.get(key, (0, 0.0))
            now = time.monotonic()
            if attempts >= 5 or now < next_attempt:
                return
            self._cos_retries[key] = (attempts + 1, now + min(60 * 2 ** attempts, 900))

            # Old terminal states lacking the original command/deployment
            # evidence remain readable; they never authorize invented evidence.
            args = cmd.get("args", {})
            if (args.get("result") != result or not args.get("actor")
                    or not isinstance(args.get("summary"), str)
                    or not state.get("components") or not state.get("deployments")
                    or not state.get("review_evidence")
                    or not self._all_required_components_deployed(state, repo)):
                logger.warning("COS retry lacks original evidence %s#%s", repo, pr_number)
                return
            comment = await self.proxy.get_comment(repo, cid)
            if not isinstance(comment, dict):
                return
            from .commands import parse_command
            parsed = parse_command(comment.get("body", ""))
            if (parsed.kind != "record_test" or parsed.result != result
                    or parsed.summary != args["summary"]
                    or comment.get("user", {}).get("login") != args["actor"]
                    or not await self._terminal_cos_context_is_current(repo, pr_number, state, comment)):
                return

            # A stable date keeps uncertain PUTs on the same key across retries
            # and restarts. This candidate key is never published as metadata.
            object_key = metadata.get("object_key") or self.cos.build_object_key(
                repo, pr_number, head,
                now=datetime.fromisoformat(comment["created_at"].replace("Z", "+00:00")),
            )
            runtime_logs = await self._snapshot_terminal_runtime_logs(
                repo,
                state.get("components", []), state.get("deployments", []),
            )
            if not await self._terminal_cos_context_is_current(repo, pr_number, state, comment):
                return
            uploaded = await self._upload_evidence(
                repo, pr_number, head, state, result, args["summary"],
                runtime_logs=runtime_logs, object_key=object_key,
            )
            if not self._valid_cos_metadata(repo, pr_number, head, uploaded):
                logger.warning("COS retry not verified %s#%s attempt=%s", repo, pr_number, attempts + 1)
                return
            if not await self._terminal_cos_context_is_current(repo, pr_number, state, comment):
                return
            # Existing references are immutable even when they are incomplete.
            if metadata.get("object_key") and metadata != uploaded:
                logger.warning("COS retry metadata conflict %s#%s", repo, pr_number)
                return
            try:
                download_url = self.cos.generate_evidence_download_url(uploaded["object_key"])
            except Exception:
                download_url = ""
                logger.warning("COS_EVIDENCE_PRESIGN=FAILED repo=%s pr=%s", repo, pr_number)
            render_kwargs = {
                "cos_object_key": uploaded["object_key"],
                "cos_bundle_sha256": uploaded["sha256"],
                "cos_bundle_size": uploaded["size"],
                "cos_download_url": download_url,
            }
            if result == "pass":
                markdown = comments_mod.succeeded_comment(
                    repo, pr_number, head,
                    deployments=self._enrich_deployments_for_render(state["deployments"], repo),
                    components=state["components"], **render_kwargs,
                )
            else:
                markdown = comments_mod.failed_comment(
                    repo, pr_number, head, failed_stage="acceptance",
                    **render_kwargs,
                )
            if await self._rebind_terminal_cos_if_current(
                repo, pr_number, expected_head=head, expected_terminal_status=status,
                expected_comment_id=cid, expected_command_kind="record_test",
                expected_test_result=result, cos_metadata=uploaded, markdown=markdown,
                expected_state=state,
            ):
                self._cos_retries.pop(key, None)
        except Exception as exc:
            # No exception from optional persistence may strand a consumed
            # record_test or prevent subsequent GitHub command processing.
            logger.warning("COS retry failed %s#%s exception=%s", repo, pr_number, type(exc).__name__)

    async def handle_request_acceptance(
        self, repo: str, pr_number: int, comment_id: int,
        actor: str, actor_id: str,
    ) -> bool:
        """Persist a current-round independent acceptance request from a deployed owner."""
        try:
            pr = await self.proxy.get_pr(repo, pr_number)
            if (not isinstance(pr, dict) or pr.get("state") != "open"
                    or pr.get("merged") or pr.get("draft")):
                await self._post_error(
                    repo, pr_number,
                    "这个 PR 已经关闭、合并或还是草稿，验收命令暂时不可用。",
                    comment_id=comment_id,
                )
                return True
            state = await self.proxy.read_hidden_state(repo, pr_number)
            if not isinstance(state, dict):
                await self._post_error(
                    repo, pr_number,
                    "当前还没有可验收的部署结果，这次验收申请没有提交。",
                    comment_id=comment_id,
                )
                return True
            state = copy.deepcopy(state)
            head = pr.get("head", {}).get("sha", "")
            round_id = round_id_for_state(state)
            if isinstance(head, str) and re.fullmatch(r"[0-9a-f]{40}", head) and head != state.get("head_sha"):
                await self._supersede_head_drift(
                    repo, pr_number, state, head, comment_id,
                    command_kind="request_acceptance",
                )
                return True
            if (state.get("status") != "testing" or state.get("head_sha") != head
                    or not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40}", head)
                    or not self._all_required_components_deployed(state, repo)):
                await self._post_command_not_ready(
                    repo, pr_number, state.get("status", "unknown"),
                    "本轮部署还没有全部完成，因此还不能提交验收。",
                    comment_id=comment_id,
                )
                return True
            try:
                owner_id = int(actor_id)
            except (TypeError, ValueError):
                owner_id = 0
            if (owner_id <= 0 or not isinstance(actor, str)
                    or not self._is_deployed_machine_owner(actor, state, repo)):
                await self._post_error(
                    repo, pr_number,
                    "只有本轮实际部署机器的负责人可以提交验收。",
                    comment_id=comment_id,
                )
                return True
            if type(comment_id) is not int or comment_id <= state.get("last_processed_comment_id", 0):
                return True
            comment = await self.proxy.get_comment(repo, comment_id)
            from .commands import parse_command
            parsed = parse_command(comment.get("body", "") if isinstance(comment, dict) else "")
            user = comment.get("user", {}) if isinstance(comment, dict) else {}
            api_base = self.config.github_api_url.rstrip("/")
            expected_comment_url = f"{api_base}/repos/{repo}/issues/comments/{comment_id}"
            expected_issue_url = f"{api_base}/repos/{repo}/issues/{pr_number}"
            if (not isinstance(comment, dict) or comment.get("id") != comment_id
                    or not isinstance(user, dict)
                    or parsed.kind != "request_acceptance"
                    or user.get("login") != actor or str(user.get("id")) != str(owner_id)
                    or type(user.get("id")) is not int or user["id"] <= 0
                    or comment.get("url") != expected_comment_url
                    or comment.get("issue_url") != expected_issue_url
                    or self.proxy.is_bot_comment(comment)
                    or not isinstance(comment.get("created_at"), str)
                    or comment.get("updated_at") != comment.get("created_at")):
                return False

            evidence_url = ""

            existing = state.get("acceptance_request")
            refresh_pending_request = (
                isinstance(existing, dict) and existing.get("status") == "pending"
                and existing.get("head_sha") == head and existing.get("round_id") == round_id
            )

            original = copy.deepcopy(state)
            if not refresh_pending_request:
                state["acceptance_request"] = {
                    "head_sha": head,
                    "round_id": round_id,
                    "status": "pending",
                    "requested_by": actor,
                    "requested_by_id": owner_id,
                    "comment_id": comment_id,
                    "requested_at": comment["created_at"],
                }

            reviewers_configured, eligible_reviewers = self._eligible_acceptance_reviewers(
                repo, pr,
            )

            state["command"] = {
                "comment_id": comment_id,
                "kind": "request_acceptance",
                "phase": "completed",
                "args": {"actor": actor, "round_id": round_id},
            }
            state["last_processed_comment_id"] = comment_id
            markdown = comments_mod.testing(
                repo, pr_number, head,
                deployments=self._enrich_deployments_for_render(state.get("deployments", []), repo),
                components=state.get("components", []),
                deployments_complete=True,
                acceptance_pending=True,
                acceptance_reviewers_configured=reviewers_configured,
                acceptance_reviewers=eligible_reviewers,
                evidence_url=evidence_url,
            )
            is_test_pr = self._is_test_only_pr(pr)
            if is_test_pr:
                pr_user = pr.get("user", {}) if isinstance(pr, dict) else {}
                pr_author = (pr_user.get("login") or "").strip() if isinstance(pr_user, dict) else ""
                reviewer_guidance = self._acceptance_reviewer_guidance(
                    repo, pr, reviewers_configured, eligible_reviewers,
                )
                if eligible_reviewers:
                    record_test_instruction = (
                        f"测试阶段请由 @{eligible_reviewers[0]} 执行 `/record_test result=pass` 或 `/record_test result=fail`。"
                    )
                else:
                    test_account_display = f"当前测试账号 {pr_author}" if pr_author else "当前 PR 作者"
                    record_test_instruction = (
                        f"{test_account_display} 未在当前仓库验收名单中，没有验收权限。测试阶段不提醒其他账号。"
                    )
                notice = "\n\n".join((reviewer_guidance, record_test_instruction))
                if eligible_reviewers:
                    markdown = markdown.rstrip() + "\n\n" + notice
                else:
                    no_reviewer_messages = (
                        "当前仓库没有可用的验收人，暂时无法验收。请联系仓库管理员配置验收账号。",
                        "当前没有可用的验收人，暂时无法验收。请联系仓库管理员检查验收账号。",
                        "当前仓库还没有可用的验收账号，暂时无法验收。请联系仓库维护者配置验收账号。",
                        "当前没有可用的验收账号，暂时无法验收。请联系仓库维护者检查验收账号。",
                    )
                    for message in no_reviewer_messages:
                        if message in markdown:
                            markdown = markdown.replace(message, notice, 1)
                            break
                    else:
                        markdown = markdown.rstrip() + "\n\n" + notice
            else:
                record_test_instruction = (
                    "请由验收账号执行 `/record_test result=pass` 或 `/record_test result=fail`。"
                    if reviewers_configured else
                    "配置有效的验收账号后，验收人才能执行 `/record_test result=pass` 或 `/record_test result=fail`。"
                )
            event = None
            if not refresh_pending_request:
                event = {
                    "event": "Independent acceptance requested",
                    "lifecycle": "`testing` · 测试完成 · 待独立验收",
                    "machine": next((d.get("machine", "") for d in state.get("deployments", [])
                                     if isinstance(d, dict) and d.get("phase") == "deployed"), ""),
                    "timestamp": comments_mod.beijing_now_str(),
                }
                await self._preflight_archive_for_event(repo, pr_number, markdown, reserved_event=event)
            written = await self._write_lifecycle_with_history(
                repo, pr_number, state, markdown, event=event,
                expected_acceptance_state=original,
                expected_acceptance_comment=comment,
            )
            if not written:
                return False
            try:
                await self.proxy.project_status_label(repo, pr_number, "acceptance-required")
            except Exception as exc:
                logger.warning("acceptance label projection %s#%s exception=%s",
                               repo, pr_number, type(exc).__name__)
            reviewer_notice = self._acceptance_reviewer_guidance(
                repo, pr, reviewers_configured, eligible_reviewers,
            )
            if is_test_pr:
                pr_user = pr.get("user", {}) if isinstance(pr, dict) else {}
                pr_author = (pr_user.get("login") or "").strip() if isinstance(pr_user, dict) else ""
                if eligible_reviewers:
                    next_action = (
                        f"请 @{eligible_reviewers[0]} 检查本轮证据和实际部署效果，确认是否符合 PR 需求、"
                        "是否存在阻塞问题，然后执行 `/record_test result=pass` 或 "
                        "`/record_test result=fail`。"
                    )
                else:
                    test_account_display = f"当前测试账号 {pr_author}" if pr_author else "当前 PR 作者"
                    next_action = (
                        f"{test_account_display} 没有验收权限，不能执行 `/record_test`。"
                        "请联系仓库维护者将测试账号加入验收名单后重试。"
                    )
            else:
                next_action = (
                    "请验收人 " + " ".join(f"@{r}" for r in eligible_reviewers) + " 检查本轮证据和实际部署效果，确认是否符合 PR 需求、"
                    "是否存在阻塞问题，然后执行 `/record_test result=pass` 或 "
                    "`/record_test result=fail`。"
                    if (reviewers_configured and eligible_reviewers) else
                    ("请验收人检查本轮证据和实际部署效果，确认是否符合 PR 需求、"
                     "是否存在阻塞问题，然后执行 `/record_test result=pass` 或 "
                     "`/record_test result=fail`。"
                     if reviewers_configured else
                     "当前仓库还没有可用的验收账号，请联系仓库维护者配置；"
                     "配置后验收人即可执行 `/record_test result=pass` 或 "
                     "`/record_test result=fail`。")
                )
            evidence_location = (
                f"本轮测试视频或图片（可选）：[打开固定上传页面](<{evidence_url}>)，"
                "也可在 PR Summary 的测试证据区域查看。"
                if evidence_url else
                "本轮测试视频或图片为可选上传；请查看 PR Summary 的测试证据区域，"
                "公共上传入口恢复后会出现同一个固定链接。"
            )
            await self._post_bound_notice(
                repo, pr_number, head_sha=head, round_id=round_id,
                comment_id=comment_id, topic="acceptance-requested",
                expected_command_kind="request_acceptance",
                result="accepted",
                message=self._format_user_reply(
                    "\n\n".join((
                        "验收申请已经提交，本轮测试的验收现在开始。",
                        reviewer_notice,
                        evidence_location,
                    )),
                    next_action,
                ),
            )
            return True
        except PolicyError as exc:
            await self._post_error(repo, pr_number, str(exc), comment_id=comment_id)
            return True
        except Exception as exc:
            logger.error("handle_request_acceptance %s#%s: %s",
                         repo, pr_number, type(exc).__name__)
            raise

    async def handle_record_test(
        self, repo: str, pr_number: int, comment_id: int,
        result: str, summary: str, actor: str, actor_id: str,
        *, _recovery_state: dict | None = None, _recovery_comment: dict | None = None,
    ) -> bool:
        try:
            pr_data = await self.proxy.get_pr(repo, pr_number)
            pr_gate_error = self._command_pr_gate_error(pr_data, "/record_test")
            if pr_gate_error:
                await self._post_error(
                    repo, pr_number, pr_gate_error, comment_id=comment_id,
                )
                return True
            state = await self.proxy.read_hidden_state(repo, pr_number)
            if _recovery_state is not None and state != _recovery_state:
                return False
            if state is None:
                await self._post_error(
                    repo, pr_number,
                    "当前 PR 还没有可用的部署进度信息，这次测试结果没有记录。",
                    comment_id=comment_id,
                )
                return True

            # Freeze the accepted bindings before permissions/logging awaits.
            state = copy.deepcopy(state)
            pr_head = pr_data.get("head", {}).get("sha", "")
            if not isinstance(pr_head, str) or not re.fullmatch(r"[0-9a-f]{40}", pr_head):
                await self._post_error(
                    repo, pr_number,
                    "无法确认 PR 的最新提交，这次测试结果没有记录。",
                    comment_id=comment_id,
                )
                return True
            if pr_head != state.get("head_sha", ""):
                if _recovery_comment is not None:
                    return False
                await self._supersede_head_drift(
                    repo, pr_number, state, pr_head, comment_id,
                    command_kind="record_test",
                )
                return True

            _current_status = state.get("status", "")
            if _current_status == "testing":
                pass  # normal path continues below
            elif _current_status in ("succeeded", "failed"):
                terminal_command = state.get("command", {})
                if (terminal_command.get("kind") == "record_test"
                        and terminal_command.get("comment_id") == comment_id
                        and terminal_command.get("phase") == "completed"
                        and _current_status == ("succeeded" if result == "pass" else "failed")
                        and state.get("test_result") == result
                        and terminal_command.get("args", {}).get("result") == result):
                    if not self._all_required_components_deployed(state, repo):
                        return False
                    await self._check_record_test_permissions(
                        repo, actor, state, actor_id=actor_id,
                        comment_id=comment_id, result=result,
                    )
                    await self._retry_terminal_cos(repo, pr_number, state, refresh_url=True)
                    return True
                logger.warning(
                    "STALE_COMMAND_IGNORED kind=record_test comment_id=%s current_status=%s",
                    comment_id, _current_status,
                )
                await self._post_command_reply(
                    repo, pr_number, comment_id,
                    (
                        "本轮验收结果已经记录通过，这次命令没有重复处理。"
                        if _current_status == "succeeded" else
                        "本轮验收结果已经记录为未通过，这次命令没有重复处理。"
                    ),
                    topic="record-test-already-processed",
                )
                return True
            else:
                if _current_status in {"review-required", "reviewing"}:
                    not_ready_message = (
                        "当前提交的审核和构建结果还没有完成，因此暂时不能记录验收结果。"
                    )
                elif _current_status == "deploy-ready":
                    not_ready_message = (
                        "当前提交还没有完成部署，因此暂时不能记录验收结果。"
                    )
                elif _current_status == "deploy-requested":
                    not_ready_message = (
                        "当前正在等待机器部署，因此暂时不能记录验收结果。"
                    )
                elif _current_status == "deploying":
                    not_ready_message = (
                        "部署正在进行，因此暂时不能记录验收结果。"
                    )
                else:
                    not_ready_message = (
                        "当前阶段还不能记录验收结果。"
                    )
                await self._post_command_not_ready(
                    repo, pr_number, _current_status,
                    not_ready_message,
                    comment_id=comment_id,
                )
                return True

            # Check PR is still valid
            pr_state = pr_data.get("state", "")
            pr_merged = pr_data.get("merged", False)
            if pr_state != "open" or pr_merged or pr_data.get("draft"):
                await self._post_error(
                    repo, pr_number,
                    "这个 PR 已经关闭、合并或还是草稿，验收命令暂时不可用。",
                    comment_id=comment_id,
                )
                return True

            # Check all components are deployed before accepting record_test
            components = state.get("components", [])
            deployed_component_ids = set()
            for dep in state.get("deployments", []):
                if dep.get("phase") == "deployed":
                    for cid in dep.get("component_ids", []):
                        deployed_component_ids.add(cid)
            all_component_ids = {c.get("component_id", "") for c in components}
            if (not all_component_ids or not all_component_ids.issubset(deployed_component_ids)
                    or not self._all_required_components_deployed(state, repo)):
                await self._post_error(
                    repo, pr_number,
                    "本轮组件还没有全部部署完成，因此暂时不能记录验收结果。",
                    comment_id=comment_id,
                )
                return True

            await self._check_record_test_permissions(
                repo, actor, state, actor_id=actor_id,
                comment_id=comment_id, result=result,
            )

            original_state = copy.deepcopy(state)
            if _recovery_comment is None:
                _recovery_comment = await self.proxy.get_comment(repo, comment_id)
            if not isinstance(_recovery_comment, dict):
                return False
            from .commands import parse_command
            accepted = parse_command(_recovery_comment.get("body", ""))
            user = _recovery_comment.get("user", {})
            if (accepted.kind != "record_test" or accepted.result != result
                    or accepted.summary != summary or _recovery_comment.get("id") != comment_id
                    or user.get("login") != actor or str(user.get("id")) != actor_id
                    or not await self._restart_record_test_comment_is_current(
                        repo, state, _recovery_comment)):
                return False
            fresh_state = await self._revalidate_record_test_state(
                repo, pr_number, original_state, result,
                expected_comment=_recovery_comment,
            )
            if fresh_state is None:
                return False
            state = fresh_state
            # COS is independent of the business verdict. Retain any published
            # metadata, but expose it only when its existing binding is valid.
            metadata = state.get("cos", {}) or {}
            render_cos = metadata if self._valid_cos_metadata(repo, pr_number, pr_head, metadata) else {}

            # Persist the business verdict before any COS or runtime-log request.
            state["status"] = "succeeded" if result == "pass" else "failed"
            state["test_result"] = "pass" if result == "pass" else "fail"
            state["command"] = {
                "comment_id": comment_id,
                "kind": "record_test",
                "phase": "completed",
                "args": {"result": result, "summary": summary, "actor": actor},
            }
            state["last_processed_comment_id"] = comment_id
            acceptance_request = copy.deepcopy(state.get("acceptance_request", {}))
            acceptance_request.update({
                "status": "completed",
                "accepted_by": actor,
                "accepted_by_id": int(actor_id),
                "acceptance_comment_id": comment_id,
                "accepted_at": utc_now(),
                "result": result,
                "summary": summary,
            })
            state["acceptance_request"] = acceptance_request

            # Write the terminal visible lifecycle comment
            if result == "pass":
                enriched = self._enrich_deployments_for_render(
                    state.get("deployments", []), repo,
                )
                terminal_markdown = comments_mod.succeeded_comment(
                    repo, pr_number, pr_head,
                    deployments=enriched,
                    components=state.get("components", []),
                    cos_object_key=str(render_cos.get("object_key", "") or ""),
                    cos_bundle_sha256=str(render_cos.get("sha256", "") or ""),
                    cos_bundle_size=int(render_cos.get("size", 0) or 0),
                )
                event = {
                    "event": "Test recorded",
                    "lifecycle": "`testing` \u2192 `succeeded`",
                    "result": "pass",
                    "timestamp": comments_mod.beijing_now_str(),
                }
            else:
                terminal_markdown = comments_mod.failed_comment(
                    repo, pr_number, pr_head,
                    cos_object_key=str(render_cos.get("object_key", "") or ""),
                    cos_bundle_sha256=str(render_cos.get("sha256", "") or ""),
                    cos_bundle_size=int(render_cos.get("size", 0) or 0),
                    failed_stage="acceptance",
                )
                event = {
                    "event": "Test recorded",
                    "lifecycle": "`testing` \u2192 `failed`",
                    "result": "fail",
                    "timestamp": comments_mod.beijing_now_str(),
                }

            await self._preflight_archive_for_event(
                repo, pr_number, terminal_markdown, reserved_event=event,
            )
            terminal_written = await self._write_lifecycle_with_history(
                repo, pr_number, state, terminal_markdown, event=event,
                expected_record_test_state=original_state,
                expected_record_test_comment=_recovery_comment,
            )
            if not terminal_written:
                return False
            try:
                await self.proxy.project_status_label(repo, pr_number, state["status"])
            except Exception as exc:
                logger.warning("record_test label projection %s#%s exception=%s",
                               repo, pr_number, type(exc).__name__)
            next_step = (
                "本轮验收已通过，可以按仓库正常的 PR 流程继续审阅和合并。"
                if result == "pass" else
                "本轮验收未通过。请先修复问题并更新 PR，等新的审核和构建完成后再重新部署和验收。"
            )
            await self._post_bound_notice(
                repo, pr_number, head_sha=pr_head,
                round_id=round_id_for_state(state), comment_id=comment_id,
                topic="test-result-recorded", expected_command_kind="record_test",
                result="accepted",
                message=(
                    f"验收结果已经记录：{'通过' if result == 'pass' else '未通过'}。\n\n"
                    f"{next_step}"
                ),
            )
            # Failures are logged/backed off internally and cannot undo or block
            # consumption of this durably completed business command.
            await self._retry_terminal_cos(repo, pr_number, state)
            return True



        except PolicyError as e:
            await self._post_error(repo, pr_number, str(e), comment_id=comment_id)
            return True
        except Exception as e:
            logger.error(
                "handle_record_test %s#%s: %s",
                repo, pr_number, e,
            )
            raise

    async def handle_evidence_link(
        self, repo: str, pr_number: int, comment_id: int, actor: str, actor_id: str,
    ) -> bool:
        """Consume deprecated requests without creating or returning a link."""
        await self._post_command_reply(
            repo, pr_number, comment_id,
            "下载链接命令已经停用，这次没有生成链接。",
            topic="evidence-link-deprecated",
        )
        return True

    _DEPLOY_STATUS_LEADS = {
        "review-required": "当前提交还没有完成审核和构建。",
        "reviewing": "当前提交正在审核和构建。",
        "deploy-ready": "当前提交已通过审核和构建，可以开始部署审批。",
        "deploy-requested": "部署审批已经提交，正在等待机器执行。",
        "deploying": "本轮部署正在进行。",
        "testing": "本轮部署已经完成，可以开始测试。",
        "acceptance-required": "本轮测试已经完成，正在等待验收。",
        "succeeded": "本轮验收已经通过。",
        "failed": "本轮没有通过，需要修复后重新开始。",
    }

    async def handle_deploy_status(
        self, repo: str, pr_number: int, comment_id: int,
    ) -> bool:
        try:
            state = await self.proxy.read_hidden_state(repo, pr_number)
            if state is None:
                await self._post_error(
                    repo, pr_number,
                    "当前 PR 还没有可用的部署进度信息。",
                    comment_id=comment_id,
                )
                return True

            status = state.get("status", "review-required")
            lead = self._DEPLOY_STATUS_LEADS.get(
                status if isinstance(status, str) else "",
                "当前还没有可确认的部署结果。",
            )
            if status == "testing" and self._acceptance_request_is_pending(state):
                lead = "本轮测试已经完成，正在等待验收。"
            cos_state = state.get("cos", {})
            cos_object_key = (
                str(cos_state.get("object_key", "") or "")
                if status in ("succeeded", "failed")
                else ""
            )
            if cos_object_key:
                try:
                    cos_download_url = self.cos.generate_evidence_download_url(
                        cos_object_key,
                    )
                except Exception:
                    cos_download_url = ""
                if cos_download_url:
                    lead += (
                        "\n\n本轮测试证据：[打开证据下载页面]"
                        f"(<{cos_download_url}>)。"
                    )
            await self._post_command_reply(
                repo, pr_number, comment_id, lead, topic="deploy-status",
            )
            return True
        except Exception as e:
            logger.error(
                "handle_deploy_status %s#%s: %s", repo, pr_number, e,
            )
            raise

    async def handle_deploy_help(
        self, repo: str, pr_number: int, comment_id: int,
        topic: str = "",
    ) -> bool:
        try:
            markdown = comments_mod.deploy_help_text(topic)
            await self._post_command_reply(
                repo, pr_number, comment_id, markdown, topic="deploy-help",
            )
            return True
        except Exception as e:
            logger.error(
                "handle_deploy_help %s#%s: %s", repo, pr_number, e,
            )
            raise

    # ── Build helpers ──


    def _get_component_ids_for_machine(
        self, machine_alias: str, components: list[dict], repo: str,
    ) -> list[str]:
        """Return only the same physical, authorized, compatible set shown to users."""
        group = next((item for item in self._get_machine_groups_for_components(
            components, repo,
        ) if item.get("alias") == machine_alias), None)
        return list(group.get("component_ids", [])) if group else []

    @staticmethod
    def _inventory_field(machine, *names, default=None):
        for name in names:
            if isinstance(machine, dict) and name in machine:
                return machine[name]
            value = getattr(machine, name, None)
            if value is not None:
                return value
        return default

    @staticmethod
    def _canonical_primary_ipv4(value) -> str:
        if not isinstance(value, str) or not value.strip():
            return ""
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError:
            return ""
        return str(address) if address.version == 4 else ""

    @staticmethod
    def _explicit_feishu_number_from_alias(alias: str) -> str:
        """Read only an explicit leading device number encoded in a legacy alias."""
        if not isinstance(alias, str):
            return ""
        match = re.fullmatch(
            r"(?i)(?:rm75[-_ ]*)?([0-9]{3})(?:$|[^0-9].*)",
            alias.strip(),
        )
        return match.group(1).zfill(3) if match else ""

    def _physical_machine_inventory(self) -> list[dict]:
        """Read the physical inventory without using either repository policy."""
        try:
            from agents.deploy_approval.machine_inventory import get_machine_inventory
            value = get_machine_inventory()
        except Exception as exc:
            logger.warning("physical machine inventory unavailable reason=%s",
                           type(exc).__name__)
            return []

        if isinstance(value, dict):
            records = next((value[key] for key in ("machines", "inventory", "items")
                            if isinstance(value.get(key), (list, tuple, dict))), None)
            if records is None:
                records = value
        else:
            records = self._inventory_field(value, "machines", "inventory", "items")
            if records is None:
                records = value
        if isinstance(records, dict):
            rows = []
            for key, item in records.items():
                if isinstance(item, dict):
                    row = dict(item)
                    row.setdefault("alias", key)
                    rows.append(row)
                else:
                    rows.append(item)
        elif isinstance(records, (list, tuple)):
            rows = list(records)
        else:
            return []

        inventory = []
        for item in rows:
            alias = self._inventory_field(item, "alias", "name", default="")
            primary_ip = self._inventory_field(
                item, "primary_ip", "primary_ip_address", default="",
            )
            owners = self._inventory_field(item, "owners", default=[])
            if isinstance(owners, str):
                owners = [owners]
            if not isinstance(owners, (list, tuple, set)):
                owners = []
            alias = alias.strip() if isinstance(alias, str) else ""
            primary_ip = self._canonical_primary_ipv4(primary_ip)
            inventory.append({
                "alias": alias,
                "primary_ip": primary_ip,
                "owners": list(owners),
                "owner_status": self._inventory_field(
                    item, "owner_status", default="pending",
                ),
                "owner_source": self._inventory_field(
                    item, "owner_source", default="pending",
                ),
                "node_id": str(self._inventory_field(item, "node_id", default="") or ""),
                "platform_status": self._inventory_field(
                    item, "platform_status", default=None,
                ),
                "platform": self._inventory_field(item, "platform", default=""),
                "platforms": self._inventory_field(item, "platforms", default=[]),
                "platform_verified": self._inventory_field(
                    item, "platform_verified", default=None,
                ),
                "driver_path": self._inventory_field(
                    item, "driver_path", default=None,
                ),
                "driver_path_verified": self._inventory_field(
                    item, "driver_path_verified", default=False,
                ),
                "raw": item,
            })
        return inventory

    def _machine_identity_matches(
        self, alias: str, policy_machine, inventory: list[dict] | None = None,
        policy_machines: list | None = None, *, repo: str = "",
    ) -> tuple[dict | None, bool]:
        """Match a machine alias against the current Policy Feishu identity only.

        Physical device identity comes from the Policy's live Feishu snapshot,
        never from stale static inventory, and there is no fuzzy name/model
        inference against historical records.
        """
        if not isinstance(alias, str) or not alias or policy_machine is None:
            return None, False
        identity = self._policy_machine_identity(policy_machine, repo) if repo else None
        if not isinstance(identity, dict):
            return None, False
        # Policy may wrap the snapshot under "identity" or "machine" for
        # legacy consumers; unwrap it here once.
        identity_source = identity.get("identity", identity.get("machine", identity))
        if not isinstance(identity_source, dict):
            return None, False
        policy_alias = getattr(policy_machine, "alias", "")
        policy_node_id = str(getattr(policy_machine, "node_id", "") or "").strip()
        if (not identity_source.get("number") or not identity_source.get("brand")
                or not identity_source.get("model")
                or policy_alias != alias or not policy_node_id):
            return None, False
        alias_number = self._explicit_feishu_number_from_alias(alias)
        identity_number = str(identity_source.get("number", "")).strip().zfill(3)
        if alias_number and alias_number != identity_number:
            logger.warning(
                "SECURITY machine alias device number conflicts with Feishu identity "
                "repo=%s alias=%s alias_number=%s feishu_number=%s",
                repo, alias, alias_number, identity_number,
            )
            return None, False
        endpoints = self._policy_machine_endpoints(policy_machine, repo) if repo else []
        endpoint_ips = {item["ip"] for item in endpoints}
        addresses = identity_source.get("addresses")
        if not isinstance(addresses, list):
            return None, False
        ambiguous_ips = {
            endpoint for item in addresses if isinstance(item, dict)
            if str(item.get("ambiguous", "false")).casefold() == "true"
            if (endpoint := self._canonical_primary_ipv4(item.get("ip")))
        }
        feishu_ips = {
            endpoint for item in addresses if isinstance(item, dict)
            if str(item.get("ambiguous", "false")).casefold() != "true"
            if (endpoint := self._canonical_primary_ipv4(item.get("ip")))
        }
        # Policy must expose the complete current Feishu address set for this
        # physical machine. Ambiguous addresses remain visible in the inventory
        # but cannot block its independent, unambiguous addresses.
        if not endpoint_ips or endpoint_ips - ambiguous_ips != feishu_ips:
            return None, False
        peers = (
            policy_machines if isinstance(policy_machines, list)
            else [policy_machine]
        )
        physical_identity_key = self._physical_machine_identity_key(identity_source)
        same_physical_identity_count = 0
        for peer in peers:
            try:
                peer_identity = self._policy_machine_identity(peer, repo)
            except Exception:
                continue
            peer_source = (
                peer_identity.get("identity", peer_identity.get("machine", peer_identity))
                if isinstance(peer_identity, dict) else peer_identity
            )
            if (isinstance(peer_source, dict)
                    and self._physical_machine_identity_key(peer_source)
                    == physical_identity_key):
                same_physical_identity_count += 1
        policy_unambiguous = bool(
            sum(getattr(item, "alias", None) == alias for item in peers) == 1
            and sum(
                str(getattr(item, "node_id", "") or "").strip() == policy_node_id
                for item in peers
            ) == 1
            and same_physical_identity_count == 1
        )
        return identity_source, policy_unambiguous

    @staticmethod
    def _normalized_identity_text(value) -> str:
        return " ".join(value.split()).casefold() if isinstance(value, str) else ""

    def _endpoint_allowed_for_repository(
        self, repo: str, machine, endpoint: str,
        components: list[dict] | None = None,
        policy_machines: list | None = None,
    ) -> bool:
        """Bind an endpoint and requested Driver path to the current physical identity."""
        if not isinstance(repo, str) or not repo or machine is None:
            return False
        endpoint = self._canonical_primary_ipv4(endpoint)
        alias = str(getattr(machine, "alias", "") or "")
        if not endpoint or not alias:
            return False
        try:
            status = self.policy.repo_policy_status(repo)
            machines = (policy_machines if isinstance(policy_machines, list)
                        else self.policy.get_machines(repo=repo))
        except Exception:
            return False
        if (not isinstance(status, dict) or status.get("authorized") is not True
                or status.get("machines_configured") is not True
                or not isinstance(machines, list)):
            return False
        matches = [item for item in machines
                   if getattr(item, "alias", None) == alias]
        if len(matches) != 1:
            return False
        current = matches[0]
        if (str(getattr(current, "node_id", "") or "")
                != str(getattr(machine, "node_id", "") or "")):
            return False
        endpoints = self._policy_machine_endpoints(current, repo)
        if endpoint not in {item["ip"] for item in endpoints}:
            return False
        if any(
            endpoint == self._canonical_primary_ipv4(
                getattr(other, "node_host", ""),
            ) or endpoint in {
                item["ip"] for item in self._policy_machine_endpoints(other, repo)
            }
            for other in machines if other is not current
        ):
            return False

        identity = self._policy_machine_identity(current, repo)
        identity_source = (
            identity.get("identity", identity.get("machine", identity))
            if isinstance(identity, dict) else None
        )
        identity_addresses = identity.get("addresses") if isinstance(identity, dict) else None
        if identity_source is not None:
            identity_addresses = identity_source.get("addresses")
        if (not isinstance(identity, dict) or not isinstance(identity_source, dict)
                or identity.get("stale", identity_source.get("stale")) is not False):
            return False
        inventory, identity_matches = self._machine_identity_matches(
            alias, current, None, machines, repo=repo,
        )
        if not identity_matches or not isinstance(inventory, dict):
            return False
        if isinstance(identity_addresses, list):
            confirmed_ips = {
                self._canonical_primary_ipv4(item.get("ip"))
                for item in identity_addresses if isinstance(item, dict)
                and str(item.get("ambiguous", "false")).casefold() != "true"
            }
            if endpoint not in confirmed_ips:
                return False
        else:
            return False

        requested_components = components if isinstance(components, list) else []
        driver_components = [
            component for component in requested_components
            if isinstance(component, dict) and component.get("target") == "driver"
        ]
        if driver_components:
            physical_rows = [
                item for item in self._physical_machine_inventory()
                if item.get("alias") == alias
            ]
            if len(physical_rows) != 1:
                return False
            physical = physical_rows[0]
            physical_path = physical.get("driver_path")
            verified_path = physical.get("driver_path_verified") is True
            physical_raw = physical.get("raw")
            physical_number = self._inventory_field(
                physical_raw, "number", "feishu_number", default="",
            )
            if (not isinstance(physical_number, str)
                    or not physical_number.strip()
                    or physical_number.strip() != str(identity_source.get("number", "")).strip()):
                return False
            policy_paths = getattr(current, "driver_paths", []) or []
            for component in driver_components:
                component_path = component.get("driver_path")
                if (not verified_path or not isinstance(physical_path, str)
                        or not isinstance(component_path, str)
                        or component_path != physical_path
                        or component_path not in policy_paths):
                    return False
        return True

    def _record_agent_core_health(self, repo: str, machine, status: str) -> None:
        alias = str(getattr(machine, "alias", "") or "")
        if not alias:
            return
        self._agent_core_health[(repo.casefold(), alias)] = (
            time.monotonic(), self._machine_connection_fingerprint(machine), status,
        )

    def _agent_core_status_for_machine(self, repo: str, machine) -> str:
        if machine is None:
            return "unknown"
        if (self._agent_core_factory is None
                and not self._agent_core_token(str(getattr(machine, "alias", "") or ""))):
            return "credential_missing"
        if (not str(getattr(machine, "node_id", "") or "").strip()
                or not self._canonical_primary_ipv4(
                    getattr(machine, "node_host", ""),
                )):
            return "unknown"
        key = (repo.casefold(), str(getattr(machine, "alias", "") or ""))
        entry = self._agent_core_health.get(key)
        if not entry:
            return "unknown"
        checked_at, fingerprint, status = entry
        if (fingerprint != self._machine_connection_fingerprint(machine)
                or time.monotonic() - checked_at >= RUNTIME_IMAGE_CHECK_INTERVAL_SECONDS):
            return "unknown"
        return status if status in {
            "available", "unavailable", "credential_missing",
        } else "unknown"

    async def _machine_is_deployable(
        self, machine, repo: str | None = None,
        components: list[dict] | None = None,
        endpoints: list[str] | None = None,
    ) -> bool:
        if machine is None or not isinstance(repo, str) or not repo:
            return False
        alias = str(getattr(machine, "alias", "") or "")
        try:
            policy_status = self.policy.repo_policy_status(repo)
            machines = self.policy.get_machines(repo=repo)
            current_machine = self.policy.get_machine(alias, repo=repo)
        except Exception:
            return False
        if (not isinstance(policy_status, dict)
                or policy_status.get("authorized") is not True
                or policy_status.get("machines_configured") is not True
                or current_machine is None
                or not isinstance(machines, list)
                or sum(getattr(item, "alias", None) == alias for item in machines) != 1
                or self._machine_connection_fingerprint(current_machine)
                != self._machine_connection_fingerprint(machine)):
            return False
        _, identity_matches = self._machine_identity_matches(
            alias, current_machine, [], machines, repo=repo,
        )
        if not identity_matches:
            return False
        machine = current_machine
        required = components if isinstance(components, list) else []
        verified = await self._agent_core_verified_endpoints(
            repo, machine, required, endpoints=endpoints,
        )
        if required:
            required_ids = {
                item.get("component_id") for item in required
                if isinstance(item, dict) and isinstance(item.get("component_id"), str)
            }
            return bool(required_ids and any(
                required_ids.issubset(set(item.get("component_ids", [])))
                for item in verified
            ))
        return bool(verified)

    # ── Codex C verified-endpoint contract (V49) ──

    async def _agent_core_verified_endpoints(
        self, repo: str, machine, components: list[dict] | None = None,
        *, endpoints: list[str] | None = None,
        endpoint_diagnostics: list[dict] | None = None,
    ) -> list[dict[str, object]]:
        """Authenticate and read each candidate endpoint's actual runtimes."""
        alias = str(getattr(machine, "alias", "") or "")
        identity = self._policy_machine_identity(machine, repo)
        if not alias or not self._machine_identity_is_confirmed(identity):
            return []
        requested_components = [
            item for item in (components if isinstance(components, list) else [])
            if isinstance(item, dict)
        ]
        component_signature = hashlib.sha256(json.dumps(
            [{key: item.get(key) for key in (
                "component_id", "target", "driver_path", "variant", "image_ref",
            )} for item in requested_components],
            sort_keys=True, separators=(",", ":"), default=str,
        ).encode("utf-8")).hexdigest()
        try:
            policy_status = self.policy.repo_policy_status(repo)
            policy_machines = self.policy.get_machines(repo=repo)
        except Exception:
            return []
        if (not isinstance(policy_status, dict)
                or policy_status.get("authorized") is not True
                or policy_status.get("machines_configured") is not True
                or not isinstance(policy_machines, list)):
            return []
        policy_matches = [item for item in policy_machines
                          if getattr(item, "alias", None) == alias]
        if (len(policy_matches) != 1
                or self._machine_connection_fingerprint(policy_matches[0])
                != self._machine_connection_fingerprint(machine)
                or getattr(policy_matches[0], "feishu_snapshot_generation", 0)
                != getattr(machine, "feishu_snapshot_generation", 0)):
            return []
        current_machine = policy_matches[0]
        identity = self._policy_machine_identity(current_machine, repo)
        if not self._machine_identity_is_confirmed(identity):
            return []
        policy_version = hashlib.sha256(json.dumps({
            key: policy_status.get(key) for key in (
                "source_sha", "local_sha256", "machines_status",
                "machines_configured", "authorized",
            )
        }, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
        identity_digest = hashlib.sha256(json.dumps(
            self._physical_machine_identity_key(identity),
            sort_keys=True, separators=(",", ":"), default=str,
        ).encode()).hexdigest()
        generation = getattr(current_machine, "feishu_snapshot_generation", 0)
        credential_fingerprint = (
            self._credential_fingerprint(self._agent_core_token(alias))
            or ("injected-factory" if self._agent_core_factory is not None else "")
        )
        if not credential_fingerprint:
            return []
        allowed_ips = {
            self._canonical_primary_ipv4(value)
            for value in (endpoints or [])
            if self._canonical_primary_ipv4(value)
        } if endpoints is not None else None
        candidates = self._policy_machine_endpoints(current_machine, repo)
        if allowed_ips is not None:
            candidates = [item for item in candidates if item["ip"] in allowed_ips]
        verified: list[dict[str, object]] = []

        def record_endpoint_diagnostic(
            item: dict, *, status: str, reason: str, component_id: str = "",
            reachable: bool | None = None,
        ) -> dict:
            if not isinstance(endpoint_diagnostics, list):
                return {}
            diagnostic = {
                "ip": item.get("ip", ""),
                "label": item.get("label", ""),
                "status": status,
                "reason": reason,
            }
            if component_id:
                diagnostic["component_id"] = component_id
            if reachable is not None:
                diagnostic["reachable"] = reachable
            endpoint_diagnostics.append(diagnostic)
            return diagnostic

        def failure_reason(exc: Exception) -> str:
            status_code = getattr(exc, "status_code", None)
            if type(status_code) is int:
                if status_code in {401, 403}:
                    return f"Agent Core 鉴权失败（HTTP {status_code}）"
                return f"Agent Core 请求失败（HTTP {status_code}）"
            name = type(exc).__name__
            folded = name.casefold()
            if "timeout" in folded or "deadline" in folded:
                return "Agent Core 连接超时"
            if "connect" in folded or "network" in folded or "socket" in folded:
                return "Agent Core 网络连接失败"
            return f"Agent Core 请求失败（{name}）"

        now = time.monotonic()
        # Expired entries are discarded so cache growth stays bounded.
        for key, (checked_at, _value) in list(self._agent_core_verified_endpoints_cache.items()):
            if now - checked_at >= AGENT_CORE_ENDPOINT_CACHE_TTL_SECONDS:
                self._agent_core_verified_endpoints_cache.pop(key, None)
        for item in candidates:
            endpoint_ip = item["ip"]
            if not self._endpoint_allowed_for_repository(
                    repo, current_machine, endpoint_ip,
                    components=requested_components,
                    policy_machines=policy_machines,
            ):
                record_endpoint_diagnostic(
                    item, status="incompatible",
                    reason="该地址未通过当前仓库的机器身份或组件兼容检查。",
                )
                continue
            cache_key = (
                repo.casefold(), alias, identity_digest, endpoint_ip,
                credential_fingerprint, generation, policy_version,
                component_signature,
            )
            cached = self._agent_core_verified_endpoints_cache.get(cache_key)
            if (cached is not None
                    and now - cached[0] < AGENT_CORE_ENDPOINT_CACHE_TTL_SECONDS):
                for diagnostic in cached[1].get("_endpoint_diagnostics", []):
                    if isinstance(endpoint_diagnostics, list) and isinstance(diagnostic, dict):
                        endpoint_diagnostics.append(copy.deepcopy(diagnostic))
                if cached[1].get("_verification_failed") is True:
                    continue
                verified.append(copy.deepcopy(cached[1]))
                continue
            try:
                core = await self._core_for_machine_endpoint(
                    current_machine, endpoint_ip, repo,
                )
                drivers = await core.list_drivers()
                if not isinstance(drivers, list):
                    diagnostic = record_endpoint_diagnostic(
                        item, status="unavailable",
                        reason="Agent Core 未返回可读取的运行时列表。",
                    )
                    self._agent_core_verified_endpoints_cache[cache_key] = (
                        time.monotonic(), {
                            "ip": endpoint_ip, "label": item.get("label", ""),
                            "component_ids": [], "_verification_failed": True,
                            "_endpoint_diagnostics": [diagnostic] if diagnostic else [],
                        },
                    )
                    continue
                supported_ids: list[str] = []
                runtime_failures: list[tuple[str, str]] = []
                if requested_components:
                    for component in requested_components:
                        component_id = component.get("component_id")
                        if not isinstance(component_id, str) or not component_id:
                            continue
                        target = str(component.get("target", "") or "")
                        try:
                            if target == "core":
                                runtime = await core.core_update_check()
                                runtime_ok = bool(
                                    isinstance(runtime, dict)
                                    and isinstance(runtime.get("current_tag"), str)
                                    and runtime.get("current_tag", "").strip()
                                )
                            else:
                                runtime_binding = self._resolve_component_runtime(
                                    drivers, component,
                                )
                                if not isinstance(runtime_binding, dict):
                                    runtime_ok = False
                                else:
                                    runtime = await core.driver_status(
                                        runtime_binding["runtime_id"],
                                    )
                                    runtime_ok = bool(
                                        isinstance(runtime, dict)
                                        and ((isinstance(runtime.get("running_image"), str)
                                              and runtime.get("running_image", "").strip())
                                             or (isinstance(runtime.get("status"), str)
                                                 and runtime.get("status", "").strip()))
                                    )
                            if runtime_ok:
                                supported_ids.append(component_id)
                            else:
                                component_label = (
                                    str(component.get("driver_path") or "")
                                    if target == "driver" else target
                                ) or "组件"
                                runtime_failures.append((
                                    component_label, "未发现兼容的运行时",
                                ))
                        except Exception as exc:
                            component_label = (
                                str(component.get("driver_path") or "")
                                if target == "driver" else target
                            ) or "组件"
                            runtime_failures.append((component_label, type(exc).__name__))
                            logger.info(
                                "Agent Core runtime probe failed repo=%s machine=%s ip=%s component=%s reason=%s",
                                repo, alias, endpoint_ip, component_id,
                                type(exc).__name__,
                            )
                else:
                    # /api/drivers is an authenticated, read-only runtime catalog
                    # request and is required even when callers have no component.
                    supported_ids = []

                latest_machines = self.policy.get_machines(repo=repo)
                latest_matches = [entry for entry in latest_machines
                                  if getattr(entry, "alias", None) == alias] \
                    if isinstance(latest_machines, list) else []
                if (len(latest_matches) != 1
                        or self._machine_connection_fingerprint(latest_matches[0])
                        != self._machine_connection_fingerprint(current_machine)
                        or getattr(latest_matches[0], "feishu_snapshot_generation", 0)
                        != generation
                        or self._policy_machine_identity(latest_matches[0], repo) != identity
                        or not self._endpoint_allowed_for_repository(
                            repo, latest_matches[0], endpoint_ip,
                            components=requested_components,
                            policy_machines=latest_machines,
                        )):
                    record_endpoint_diagnostic(
                        item, status="incompatible",
                        reason="运行时检查期间仓库授权或机器身份绑定发生变化。",
                    )
                    continue
                # Runtime catalog reachability is enough only for generic
                # availability. Deploy commands require at least one exact
                # compatible runtime for the requested component set.
                if requested_components and not supported_ids:
                    details = "; ".join(
                        f"{label} 检查失败（{reason}）"
                        for label, reason in runtime_failures
                    )
                    diagnostic = record_endpoint_diagnostic(
                        item, status="incompatible",
                        reason=(
                            "Agent Core 未确认该地址兼容本次所需组件运行时。"
                            + (f" {details}" if details else "")
                        ),
                    )
                    self._agent_core_verified_endpoints_cache[cache_key] = (
                        time.monotonic(), {
                            "ip": endpoint_ip, "label": item.get("label", ""),
                            "component_ids": [], "_verification_failed": True,
                            "_endpoint_diagnostics": [diagnostic] if diagnostic else [],
                        },
                    )
                    continue
                result: dict[str, object] = {
                    "ip": endpoint_ip,
                    "label": item.get("label", ""),
                    "component_ids": supported_ids,
                }
                self._agent_core_verified_endpoints_cache[cache_key] = (
                    time.monotonic(), copy.deepcopy(result),
                )
                verified.append(result)
                if runtime_failures:
                    for component_label, reason in runtime_failures:
                        record_endpoint_diagnostic(
                            item, status="incompatible",
                            reason=f"{component_label} 运行时检查失败（{reason}）。",
                        )
                    result["_endpoint_diagnostics"] = [
                        copy.deepcopy(diagnostic)
                        for diagnostic in (endpoint_diagnostics or [])
                        if isinstance(diagnostic, dict)
                        and diagnostic.get("ip") == endpoint_ip
                    ]
                    self._agent_core_verified_endpoints_cache[cache_key] = (
                        time.monotonic(), copy.deepcopy(result),
                    )
            except Exception as exc:
                diagnostic = record_endpoint_diagnostic(
                    item, status="unavailable", reason=failure_reason(exc),
                )
                self._agent_core_verified_endpoints_cache[cache_key] = (
                    time.monotonic(), {
                        "ip": endpoint_ip, "label": item.get("label", ""),
                        "component_ids": [], "_verification_failed": True,
                        "_endpoint_diagnostics": [diagnostic] if diagnostic else [],
                    },
                )
                logger.info(
                    "Agent Core endpoint verification failed repo=%s machine=%s ip=%s reason=%s",
                    repo, alias, endpoint_ip, type(exc).__name__,
                )
        return verified

    async def _machine_groups_verify_endpoints(
        self, groups: list[dict], repo: str, components: list[dict] | None = None,
    ) -> list[dict]:
        """Restrict command generation to live, runtime-verified endpoints."""
        result = []
        for group in (groups if isinstance(groups, list) else []):
            if not isinstance(group, dict):
                continue
            group = dict(group)
            original_component_ids = group.get("component_ids", [])
            group["verified_endpoints"] = []
            group["endpoint_diagnostics"] = list(
                group.get("endpoint_diagnostics", [])
                if isinstance(group.get("endpoint_diagnostics"), list) else []
            )
            group["approval_available"] = False
            group["command_selector"] = ""
            group["ip_command_safe"] = False
            alias = str(group.get("alias", "") or "")
            required_ids = {
                value for value in group.get(
                    "required_component_ids", group.get("component_ids", []),
                ) if isinstance(value, str) and value
            } if isinstance(group.get(
                "required_component_ids", group.get("component_ids", []),
            ), (list, tuple, set)) else set()
            group["required_component_ids"] = sorted(required_ids)
            group["component_ids"] = []
            if not alias or not required_ids:
                result.append(group)
                continue

            reasons = {
                str(value or "").strip().upper()
                for value in group.get("blocking_reasons", [])
                if isinstance(value, str)
            } if isinstance(group.get("blocking_reasons"), (list, tuple, set)) else set()
            compatible_ids = {
                value for value in group.get(
                    "compatible_component_ids", original_component_ids,
                ) if isinstance(value, str) and value
            } if isinstance(group.get(
                "compatible_component_ids", original_component_ids,
            ), (list, tuple, set)) else set()
            owner_rows = group.get("owners", [])
            has_owner = bool(self._runtime_transition_owner_labels(
                owner_rows if isinstance(owner_rows, list) else []
            ))
            core_only_reasons = {"AGENT_CORE_UNKNOWN", "AGENT_CORE_UNAVAILABLE"}
            probe_blocking_reasons = {
                "MACHINE_NOT_AUTHORIZED", "REPOSITORY_POLICY_MISSING",
                "MACHINE_IDENTITY_MISMATCH", "FEISHU_DEVICE_REPOSITORY_CONFLICT",
                "OWNER_NOT_CONFIGURED", "AGENT_CORE_CREDENTIAL_MISSING",
            }
            can_probe = bool(
                group.get("repo_authorized") is True
                and group.get("identity_confirmed") is True
                and has_owner
                and required_ids.issubset(compatible_ids)
                and not (reasons & probe_blocking_reasons)
            )
            requested = [item for item in (components or [])
                         if isinstance(item, dict)
                         and item.get("component_id") in required_ids]
            if (not can_probe or len({
                    item.get("component_id") for item in requested
                    if isinstance(item.get("component_id"), str)
                }) != len(required_ids)):
                result.append(group)
                continue
            machine = None
            try:
                machine = self.policy.get_machine(alias, repo=repo)
            except Exception:
                machine = None
            if machine is None:
                group["blocking_reasons"] = list(dict.fromkeys(
                    [*group.get("blocking_reasons", []), "MACHINE_IDENTITY_MISMATCH"]
                ))
                result.append(group)
                continue
            endpoint_diagnostics: list[dict] = []
            verification_endpoints = group.get("verification_endpoints")
            if verification_endpoints is not None:
                verification_endpoints = sorted({
                    self._canonical_primary_ipv4(value)
                    for value in verification_endpoints
                    if self._canonical_primary_ipv4(value)
                }) if isinstance(verification_endpoints, (list, tuple, set)) else []
            verified = await self._agent_core_verified_endpoints(
                repo, machine, requested,
                endpoints=verification_endpoints,
                endpoint_diagnostics=endpoint_diagnostics,
            )
            full_endpoints = [
                endpoint for endpoint in verified
                if isinstance(endpoint, dict)
                and required_ids.issubset(set(endpoint.get("component_ids", [])))
            ]
            group["endpoint_diagnostics"].extend(endpoint_diagnostics)
            group["endpoint_diagnostics"] = list({
                (item.get("ip"), item.get("status"), item.get("reason"),
                 item.get("component_id")): item
                for item in group["endpoint_diagnostics"]
                if isinstance(item, dict)
            }.values())
            group["verified_endpoints"] = full_endpoints
            group["component_ids"] = sorted(required_ids) if full_endpoints else []
            group["approval_available"] = bool(full_endpoints)
            group["command_selector"] = (
                self._canonical_primary_ipv4(full_endpoints[0].get("ip", ""))
                if full_endpoints else ""
            )
            group["ip_command_safe"] = bool(group["command_selector"])
            if full_endpoints:
                group["agent_core_status"] = "available"
                group["blocking_reasons"] = [
                    value for value in group.get("blocking_reasons", [])
                    if value not in core_only_reasons
                ]
            elif any(
                    item.get("status") == "unavailable"
                    for item in endpoint_diagnostics if isinstance(item, dict)):
                group["agent_core_status"] = "unavailable"
            elif endpoint_diagnostics:
                # The endpoint responded, but none proved the full component
                # set on that one address. Keep this diagnostic address-local.
                group["agent_core_status"] = "available"
            result.append(group)
        return result

    def _get_machine_groups_for_components(
        self, components: list[dict], repo: str,
    ) -> list[dict]:
        """Diagnose every physical machine against repo authorization and PR components.

        ``component_ids`` contains only components that are currently safe to
        approve on that machine. ``compatible_component_ids`` keeps the
        compatibility result separate from repository authorization.
        """
        inventory = self._physical_machine_inventory()
        display_by_alias: dict[str, dict] = {}
        for physical in inventory:
            alias = str(physical.get("alias", "") or "")
            if alias and alias not in display_by_alias:
                display_by_alias[alias] = physical

        try:
            policy_status = self.policy.repo_policy_status(repo)
            policy_access_authorized = (
                isinstance(policy_status, dict)
                and policy_status.get("authorized") is True
            )
            policy_configured = (
                policy_access_authorized
                and policy_status.get("machines_configured") is True
            )
            authorized_machines = self.policy.get_machines(repo=repo) if policy_configured else []
            if not isinstance(authorized_machines, list):
                policy_configured = False
                authorized_machines = []
        except Exception as exc:
            logger.warning("repository machine policy unavailable repo=%s reason=%s",
                           repo, type(exc).__name__)
            policy_access_authorized = False
            policy_configured = False
            authorized_machines = []
        authorized_by_alias: dict[str, list] = {}
        policy_aliases_by_ip: dict[str, list[str]] = {}
        for machine in authorized_machines:
            machine_alias = str(getattr(machine, "alias", "") or "")
            if machine_alias:
                authorized_by_alias.setdefault(machine_alias, []).append(machine)
            machine_ip = self._canonical_primary_ipv4(
                getattr(machine, "node_host", ""),
            )
            if machine_ip and machine_alias:
                policy_aliases_by_ip.setdefault(machine_ip, []).append(machine_alias)
        groups = []
        # The official repository policy is the authorization source, so every
        # authorized alias must be evaluated even when the descriptive physical
        # inventory has no matching record. Such a machine stays blocked with an
        # explicit identity reason instead of silently disappearing.
        inventory_aliases = set(display_by_alias)
        entries: list[tuple[dict | None, str]] = [
            (item, alias) for alias, item in display_by_alias.items()
        ]
        for machine in authorized_machines:
            policy_only_alias = str(getattr(machine, "alias", "") or "")
            if policy_only_alias and policy_only_alias not in inventory_aliases:
                entries.append((None, policy_only_alias))
        for physical, alias in entries:
            physical = physical or {}
            policy_matches = authorized_by_alias.get(alias, [])
            policy_machine = policy_matches[0] if len(policy_matches) == 1 else None
            node_id = str(getattr(policy_machine, "node_id", "") or "")
            node_host = self._canonical_primary_ipv4(
                getattr(policy_machine, "node_host", ""),
            )
            _, identity_matches = self._machine_identity_matches(
                alias, policy_machine, None, authorized_machines, repo=repo,
            )
            confirmed_endpoint_set = None
            if (policy_machine is not None
                    and callable(getattr(self.policy, "machine_identity", None))):
                try:
                    policy_identity = self._policy_machine_identity(
                        policy_machine, repo,
                    )
                    confirmed_endpoints = self._policy_machine_endpoints(
                        policy_machine, repo,
                    )
                    confirmed_endpoint_set = {
                        item["ip"] for item in confirmed_endpoints
                    }
                    identity_matches = (
                        self._machine_identity_is_confirmed(policy_identity)
                        and any(
                            self._endpoint_allowed_for_repository(
                                repo, policy_machine, item["ip"],
                                policy_machines=authorized_machines,
                            )
                            and self._machine_endpoint_has_unambiguous_identity(
                                policy_machine, item["ip"], repo, policy_identity,
                            )
                            for item in confirmed_endpoints
                        )
                    )
                except Exception:
                    identity_matches = False
            # Only the current repository policy may supply an authorization IP.
            primary_ip = self._canonical_primary_ipv4(
                str(getattr(policy_machine, "node_host", "") or "")
            ) if policy_machine is not None else ""
            endpoint_allowed = bool(
                policy_machine is not None and confirmed_endpoint_set
                and any(self._endpoint_allowed_for_repository(
                    repo, policy_machine, endpoint_ip,
                    policy_machines=authorized_machines,
                ) for endpoint_ip in confirmed_endpoint_set)
            )
            repo_authorized = bool(
                policy_configured and policy_machine is not None
                and node_id and identity_matches
                and endpoint_allowed
                and len(policy_matches) == 1
            )
            if not policy_configured:
                repo_authorized = False

            policy_owners = list(getattr(policy_machine, "owners", []) or []) \
                if policy_configured and policy_machine is not None else []
            valid_policy_owners = sorted({
                owner.strip() for owner in policy_owners
                if isinstance(owner, str) and _LOGIN_RE.fullmatch(owner.strip())
                and not owner.strip().casefold().endswith("[bot]")
            }, key=str.casefold)

            agent_core_status = (
                self._agent_core_status_for_machine(repo, policy_machine)
                if repo_authorized else "unknown"
            )
            reasons: list[str] = []
            if not policy_access_authorized:
                reasons.append("MACHINE_NOT_AUTHORIZED")
            elif not policy_configured:
                reasons.append("REPOSITORY_POLICY_MISSING")
            elif len(policy_matches) > 1:
                reasons.append("MACHINE_IDENTITY_MISMATCH")
            elif policy_machine is not None and not identity_matches:
                reasons.append("MACHINE_IDENTITY_MISMATCH")
            elif policy_machine is not None and not endpoint_allowed:
                reasons.append("FEISHU_DEVICE_REPOSITORY_CONFLICT")
            elif not repo_authorized:
                reasons.append("MACHINE_NOT_AUTHORIZED")
            if repo_authorized and not valid_policy_owners:
                reasons.append("OWNER_NOT_CONFIGURED")
            if agent_core_status == "credential_missing":
                reasons.append("AGENT_CORE_CREDENTIAL_MISSING")
            elif agent_core_status == "unavailable":
                reasons.append("AGENT_CORE_UNAVAILABLE")
            elif repo_authorized and agent_core_status == "unknown":
                reasons.append("AGENT_CORE_UNKNOWN")

            compatible_ids: list[str] = []
            target_ids: list[str] = []
            variant_ids: list[str] = []
            driver_path_ids: list[str] = []
            platform_values = list(getattr(policy_machine, "platforms", []) or [])
            variants = list(getattr(policy_machine, "variants", []) or [])
            driver_paths = list(getattr(policy_machine, "driver_paths", []) or [])
            targets = list(getattr(policy_machine, "targets", []) or [])
            platform_verified = bool(policy_machine is not None and platform_values)
            if (policy_configured and policy_machine is not None and components
                    and any(not comp.get("resolved_platform")
                            for comp in components if isinstance(comp, dict))):
                platform_verified = False

            platform_mismatch = False
            variant_mismatch = False
            driver_path_mismatch = False
            target_mismatch = False
            if policy_configured and repo_authorized:
                for comp in components:
                    if not isinstance(comp, dict):
                        continue
                    component_id = comp.get("component_id", "")
                    target = comp.get("target", "")
                    if not isinstance(component_id, str) or not component_id:
                        continue
                    if target not in targets:
                        target_mismatch = True
                        continue
                    target_ids.append(component_id)
                    comp_platform = comp.get("resolved_platform", "")
                    platform_ok = True
                    if not comp_platform:
                        platform_ok = False
                    elif not platform_values or comp_platform not in platform_values:
                        platform_mismatch = True
                        platform_ok = False

                    comp_variant = comp.get("variant", "")
                    variant_ok = True
                    if (target not in ("core", "driver") and variants
                            and (not comp_variant or comp_variant not in variants)):
                        variant_mismatch = True
                        variant_ok = False
                    else:
                        variant_ids.append(component_id)

                    driver_path_ok = True
                    if (target == "driver"
                            and (not comp.get("driver_path") or not driver_paths
                                 or comp.get("driver_path") not in driver_paths)):
                        driver_path_mismatch = True
                        driver_path_ok = False
                    else:
                        driver_path_ids.append(component_id)

                    if platform_ok and variant_ok and driver_path_ok:
                        compatible_ids.append(component_id)
            elif components:
                target_mismatch = False

            if target_mismatch:
                reasons.append("TARGET_UNSUPPORTED")
            if platform_mismatch:
                reasons.append("PLATFORM_MISMATCH")
            if not platform_verified:
                reasons.append("PLATFORM_UNVERIFIED")
            if variant_mismatch:
                reasons.append("VARIANT_MISMATCH")
            if driver_path_mismatch:
                reasons.append("DRIVER_PATH_MISMATCH")

            primary_ip_ambiguous = bool(
                primary_ip and (
                    len(policy_aliases_by_ip.get(primary_ip, [])) > 1
                )
            ) or bool(
                node_host and len(policy_aliases_by_ip.get(node_host, [])) > 1
            )
            if primary_ip_ambiguous:
                reasons.append("PRIMARY_IP_AMBIGUOUS")
            ip_command_safe = bool(
                repo_authorized and primary_ip and not primary_ip_ambiguous and node_host == primary_ip
                and len(policy_aliases_by_ip.get(node_host, [])) == 1
                and (confirmed_endpoint_set is None or node_host in confirmed_endpoint_set)
            )
            # A previous probe failure on one address must not reject a
            # different, repository-authorized address. The selected endpoint
            # is checked again by Agent Core during deployment preflight.
            core_ready = agent_core_status != "credential_missing" and bool(
                repo_authorized and policy_machine and node_id and node_host
            )
            approval_available = bool(
                repo_authorized and valid_policy_owners and core_ready
                and platform_verified and compatible_ids
            )
            command_selector = primary_ip if ip_command_safe else ""
            # The legacy ``ip`` field is consumed by command templates. Empty it
            # whenever a literal primary IP cannot be resolved to this exact
            # repository binding; diagnostics retain the true primary_ip.
            groups.append({
                "alias": alias,
                "node_id": node_id,
                "primary_ip": primary_ip,
                "node_host": str(getattr(policy_machine, "node_host", "") or ""),
                "ip": primary_ip if ip_command_safe else "",
                "owners": valid_policy_owners,
                "repo_authorized": repo_authorized,
                "identity_confirmed": repo_authorized and identity_matches,
                "identity_status": (
                    "verified" if repo_authorized and identity_matches else
                    "mismatch" if policy_machine is not None or len(policy_matches) > 1 else
                    "unknown"
                ),
                "agent_core_status": agent_core_status,
                "platform_status": (
                    "unverified" if not platform_verified else
                    "incompatible" if platform_mismatch else
                    "compatible" if policy_machine is not None else "not_applicable"
                ),
                "target_compatible": bool(target_ids),
                "variant_compatible": bool(variant_ids),
                "driver_path_compatible": bool(driver_path_ids),
                "approval_available": approval_available,
                "blocking_reasons": list(dict.fromkeys(reasons)),
                "target_component_ids": target_ids,
                "variant_component_ids": variant_ids,
                "driver_path_component_ids": driver_path_ids,
                "compatible_component_ids": compatible_ids,
                "component_ids": compatible_ids if approval_available else [],
                # A machine may be assigned only a subset of the PR's
                # components. Verify that assigned set on one endpoint; the
                # caller separately requires full PR coverage for bare approve.
                "required_component_ids": list(compatible_ids),
                "ip_command_safe": ip_command_safe,
                "command_selector": command_selector,
            })
        return groups

    def _runtime_redeploy_machine_groups(
        self, state: dict, components: list[dict], repo: str,
    ) -> list[dict]:
        """Return only currently confirmed drift bindings for a redeploy round."""
        bindings = state.get("runtime_redeploy", []) if isinstance(state, dict) else []
        if not isinstance(bindings, list) or not bindings:
            return []
        component_ids = {
            item.get("component_id") for item in components
            if isinstance(item, dict) and isinstance(item.get("component_id"), str)
        }
        confirmed = {
            (check.get("machine"), check.get("ip"), check.get("component_id"))
            for check in state.get("runtime_checks", [])
            if isinstance(check, dict)
            and check.get("status") == "mismatch"
        }
        candidates = self._get_machine_groups_for_components(components, repo)
        result = []
        for binding in bindings:
            if not isinstance(binding, dict):
                continue
            alias, ip_value = binding.get("machine"), binding.get("ip")
            drift_ids = {
                component_id for component_id in binding.get("component_ids", [])
                if component_id in component_ids
                and (alias, ip_value, component_id) in confirmed
            }
            if not drift_ids:
                continue
            current_machine = None
            try:
                current_machine = self.policy.get_machine(alias, repo=repo)
            except Exception:
                pass
            drift_ip = self._canonical_primary_ipv4(ip_value)
            endpoint_bound = bool(
                current_machine is not None and drift_ip
                and drift_ip in {
                    item["ip"] for item in self._policy_machine_endpoints(
                        current_machine, repo,
                    )
                }
                and self._endpoint_allowed_for_repository(
                    repo, current_machine, drift_ip, components=components,
                )
            )
            match = next((group for group in candidates
                          if endpoint_bound and group.get("alias") == alias
                          and drift_ids.issubset(set(group.get("component_ids", [])))),
                         None)
            if match is not None:
                result.append({
                    **match, "component_ids": sorted(drift_ids),
                    "required_component_ids": sorted(drift_ids),
                    "verification_endpoints": [drift_ip],
                })
        return result

    def _machine_command_selector(self, alias: str, repo: str) -> str:
        """Return an exact IP selector, or alias only for an ambiguous verified IP."""
        if not isinstance(alias, str) or not alias:
            return ""
        try:
            policy_status = self.policy.repo_policy_status(repo)
            if (not isinstance(policy_status, dict)
                    or policy_status.get("authorized") is not True
                    or policy_status.get("machines_configured") is not True):
                return ""
            machines = self.policy.get_machines(repo=repo)
            if not isinstance(machines, list):
                return ""
            matches = [item for item in machines
                       if getattr(item, "alias", "") == alias]
        except Exception:
            return ""
        if len(matches) != 1:
            return ""
        machine = matches[0]
        if re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", alias) is None:
            return ""
        _, identity_matches = self._machine_identity_matches(
            alias, machine, None, machines, repo=repo,
        )
        if not identity_matches:
            return ""
        endpoints = self._policy_machine_endpoints(machine, repo)
        primary_ip = self._canonical_primary_ipv4(
            getattr(machine, "node_host", ""),
        )
        deployable_ips = [item["ip"] for item in endpoints]
        if (primary_ip and primary_ip in deployable_ips
                and sum(primary_ip in {
                    endpoint["ip"] for endpoint in self._policy_machine_endpoints(
                        item, repo,
                    )
                } for item in machines) == 1):
            return primary_ip
        # Approval commands always name the exact IP that passed Agent Core
        # authentication and runtime compatibility checks.
        return ""

    def _runtime_display_identity(self, alias: str, repo: str) -> tuple[str, str, list[str]]:
        primary_ip = ""
        owners: list[str] = []
        try:
            policy_status = self.policy.repo_policy_status(repo)
            machines = self.policy.get_machines(repo=repo)
            machine = self.policy.get_machine(alias, repo=repo)
        except Exception:
            policy_status, machines, machine = None, [], None
        if (isinstance(policy_status, dict)
                and policy_status.get("authorized") is True
                and policy_status.get("machines_configured") is True
                and isinstance(machines, list)
                and sum(getattr(item, "alias", None) == alias for item in machines) == 1
                and machine is not None):
            _, identity_matches = self._machine_identity_matches(
                alias, machine, None, machines, repo=repo,
            )
            if identity_matches:
                primary_ip = self._canonical_primary_ipv4(
                    getattr(machine, "node_host", ""),
                )
                owners = list(getattr(machine, "owners", []) or [])
        else:
            machine = None
        return primary_ip, self._machine_command_selector(alias, repo), owners

    def _machine_command_uses_primary_ip(self, alias: str, repo: str) -> bool:
        primary_ip, selector, _ = self._runtime_display_identity(alias, repo)
        if not primary_ip or selector != primary_ip:
            return False
        try:
            machine = self.policy.get_machine(alias, repo=repo)
        except Exception:
            return False
        return (
            machine is not None
            and self._canonical_primary_ipv4(getattr(machine, "node_host", "")) == primary_ip
        )

    def _machine_ip_command_selector(self, alias: str, repo: str) -> str:
        """Return a selector for display only when it is the verified primary IPv4."""
        selector = self._machine_command_selector(alias, repo)
        canonical_ip = self._canonical_primary_ipv4(selector)
        if (not canonical_ip or selector != canonical_ip
                or not self._machine_command_uses_primary_ip(alias, repo)):
            return ""
        return canonical_ip

    async def _runtime_owner_guidance(
        self, checks: list[dict], components: list[dict],
        repo: str, pr_data: dict | None, lifecycle_status: str = "",
    ) -> list[str]:
        test_only = pr_data is None or self._is_test_only_pr(pr_data)
        component_by_id = {
            item.get("component_id"): item for item in components
            if isinstance(item, dict) and isinstance(item.get("component_id"), str)
        }
        by_machine: dict[str, list[dict]] = {}
        for check in checks:
            if isinstance(check, dict) and isinstance(check.get("machine"), str):
                by_machine.setdefault(check["machine"], []).append(check)
        lines = ["机器负责人和可用的直接操作："]
        for alias, machine_checks in sorted(by_machine.items(), key=lambda item: item[0].casefold()):
            primary_ip, selector, owners = self._runtime_display_identity(alias, repo)
            mismatch_ids = {
                item.get("component_id") for item in machine_checks
                if item.get("status") == "mismatch"
                and isinstance(item.get("component_id"), str)
            }
            mismatch_components = [component_by_id[item] for item in mismatch_ids
                                   if item in component_by_id]
            selectors: list[str] = []
            if mismatch_ids:
                current_machine = None
                try:
                    current_machine = self.policy.get_machine(alias, repo=repo)
                except Exception:
                    pass
                if current_machine is not None:
                    for endpoint_ip in sorted({
                            self._canonical_primary_ipv4(check.get("ip", ""))
                            for check in machine_checks
                            if check.get("status") == "mismatch"
                            and self._canonical_primary_ipv4(check.get("ip", ""))}):
                        endpoint_ids = {
                            check.get("component_id") for check in machine_checks
                            if check.get("status") == "mismatch"
                            and self._canonical_primary_ipv4(check.get("ip", "")) == endpoint_ip
                            and isinstance(check.get("component_id"), str)
                        }
                        endpoint_components = [component_by_id[item]
                                               for item in endpoint_ids
                                               if item in component_by_id]
                        if (not endpoint_ids or len(endpoint_components) != len(endpoint_ids)
                                or endpoint_ip not in {
                                    item["ip"] for item in self._policy_machine_endpoints(
                                        current_machine, repo,
                                    )
                                } or not self._endpoint_allowed_for_repository(
                                    repo, current_machine, endpoint_ip,
                                    components=endpoint_components,
                                )):
                            continue
                        verified = await self._agent_core_verified_endpoints(
                            repo, current_machine, endpoint_components,
                            endpoints=[endpoint_ip],
                        )
                        endpoint_verified_ids = set().union(*(
                            set(item.get("component_ids", []))
                            for item in verified if isinstance(item, dict)
                        )) if verified else set()
                        eligible_group = next((group for group in
                            self._get_machine_groups_for_components(endpoint_components, repo)
                            if group.get("alias") == alias
                            and group.get("approval_available") is True
                            and endpoint_ids.issubset(set(group.get("component_ids", [])))), None)
                        if (eligible_group is not None
                                and endpoint_ids.issubset(endpoint_verified_ids)):
                            selectors.append(endpoint_ip)
                            owners = list(eligible_group.get("owners", []) or owners)
            valid_owners = sorted({
                owner.strip() for owner in owners
                if isinstance(owner, str) and _LOGIN_RE.fullmatch(owner.strip())
                and not owner.strip().casefold().endswith("[bot]")
            }, key=str.casefold)
            if test_only:
                valid_owners = []
            # Lifecycle summaries are informational. Only an explicit
            # /request_deploy command sends Owner mentions.
            owner_labels = valid_owners
            owner_text = " ".join(owner_labels) if owner_labels else "负责人待配置"
            statuses = {item.get("status") for item in machine_checks}
            if lifecycle_status == "deploying":
                result = "正在部署，请等待结果"
            elif statuses and statuses <= {"match"}:
                result = "运行镜像与批准版本一致，无需重新部署"
            elif "mismatch" in statuses:
                result = "运行镜像与批准版本不一致，需要重新部署"
            else:
                result = "暂时无法确认运行镜像，因此不能判断是否需要重新部署"
            line = f"- 机器 `{alias}`（主 IP：`{primary_ip or '未记录'}`），负责人：{owner_text}；{result}"
            if "mismatch" in statuses:
                if selectors:
                    commands = "、".join(
                        f"`/approve_deploy machine={selector}`"
                        for selector in sorted(set(selectors))
                    )
                    line += f"；直接重新审批：{commands}；`/request_deploy` 可选，不是前提"
                else:
                    line += "；当前无法确认安全的审批命令，请等待状态检查恢复"
            lines.append(line)
            for check in machine_checks:
                component = component_by_id.get(check.get("component_id"))
                if (not isinstance(component, dict)
                        or component.get("target") != "core"):
                    continue
                target_image = str(check.get("target_image", "") or
                                   component.get("image_ref", "") or "")
                observed_image = self._runtime_observed_image_for_display(
                    check, component,
                )
                image_status = (
                    "运行镜像与批准版本一致"
                    if check.get("status") == "match" else
                    "运行镜像与批准版本不一致，需要重新部署"
                    if check.get("status") == "mismatch" else
                    "暂时无法确认运行镜像"
                )
                lines.append(
                    f"  - Core 组件 `{check.get('component_id', '')}`："
                    f"批准镜像 `{target_image or '未读取'}`；"
                    f"实际运行镜像 `{observed_image or '未读取'}`；{image_status}"
                )
        return lines if len(lines) > 1 else []

    async def _add_runtime_owner_guidance(
        self, markdown: str, checks: list[dict], components: list[dict],
        repo: str, pr_data: dict | None, lifecycle_status: str = "",
    ) -> str:
        lines = await self._runtime_owner_guidance(
            checks, components, repo, pr_data, lifecycle_status,
        )
        if not lines or "<!-- deploy-approval-runtime-checks:end -->" not in markdown:
            return markdown
        marker = "<!-- deploy-approval-runtime-checks:end -->"
        return markdown.replace(marker, "\n" + "\n".join(lines) + "\n" + marker, 1)

    async def _render_runtime_checks_for_display(
        self, markdown: str, checks: list[dict], components: list[dict],
        repo: str, lifecycle_status: str, pr_data: dict | None,
    ) -> str:
        test_only = pr_data is None or self._is_test_only_pr(pr_data)
        if pr_data is None:
            pr_data = {"title": "[TEST ONLY]"}
        component_by_id = {
            item.get("component_id"): item for item in components
            if isinstance(item, dict) and isinstance(item.get("component_id"), str)
        }
        checks_by_alias: dict[str, list[dict]] = {}
        for check in checks:
            if isinstance(check, dict) and isinstance(check.get("machine"), str):
                checks_by_alias.setdefault(check["machine"], []).append(check)

        try:
            policy_status = self.policy.repo_policy_status(repo)
        except Exception as exc:
            logger.warning(
                "runtime display repository policy unavailable repo=%s reason=%s",
                repo, type(exc).__name__,
            )
            policy_status = None
        repository_authorized = (
            isinstance(policy_status, dict)
            and policy_status.get("authorized") is True
            and policy_status.get("machines_configured") is True
        )
        try:
            policy_machines = (
                self.policy.get_machines(repo=repo) if repository_authorized else []
            )
            if not isinstance(policy_machines, list):
                policy_machines = []
        except Exception as exc:
            logger.warning(
                "runtime display machine policy unavailable repo=%s reason=%s",
                repo, type(exc).__name__,
            )
            policy_machines = []

        identities: dict[str, tuple[str, list[str], bool, str]] = {}
        diagnostics = []
        for alias, machine_checks in checks_by_alias.items():
            primary_ip, selector, owners = self._runtime_display_identity(alias, repo)
            machine_repository_authorized = (
                repository_authorized
                and sum(getattr(item, "alias", None) == alias for item in policy_machines) == 1
            )
            owners = sorted({
                owner.strip() for owner in owners
                if isinstance(owner, str) and _LOGIN_RE.fullmatch(owner.strip())
                and not owner.strip().casefold().endswith("[bot]")
            }, key=str.casefold)
            machine_identity_confirmed = bool(primary_ip)
            safe_selector = ""

            identities[alias] = (
                primary_ip if machine_identity_confirmed else "",
                owners if machine_identity_confirmed and machine_repository_authorized else [],
                machine_identity_confirmed,
                safe_selector,
            )
            diagnostics.append({
                "alias": alias,
                "primary_ip": primary_ip if machine_identity_confirmed else "",
                # Per-check node_host carries the actually queried address;
                # do not force every secondary address back to the primary.
                "node_host": "",
                "owners": owners if machine_identity_confirmed and machine_repository_authorized else [],
                "duplicate_ip": False,
                "repository_authorized": machine_repository_authorized,
                "identity_confirmed": machine_identity_confirmed,
            })

        display_checks = []
        for check in checks:
            if not isinstance(check, dict):
                continue
            item = copy.deepcopy(check)
            alias = str(item.get("machine", "") or "")
            component = component_by_id.get(item.get("component_id"))
            item["observed_image"] = self._runtime_observed_image_for_display(
                item, component,
            )
            primary_ip, owners, machine_identity_confirmed, safe_selector = identities.get(
                alias, ("", [], False, ""),
            )
            item["owners"] = owners if owners else ["负责人待配置"]
            check_ip = self._canonical_primary_ipv4(item.get("ip", ""))
            current_machine = next((machine for machine in policy_machines
                                    if getattr(machine, "alias", None) == alias), None)
            endpoint_current = bool(
                machine_identity_confirmed and current_machine is not None
                and check_ip in {
                    endpoint["ip"] for endpoint in self._policy_machine_endpoints(
                        current_machine, repo,
                    )
                }
            )
            item["primary_ip"] = check_ip if endpoint_current else ""
            item["node_host"] = check_ip if endpoint_current else ""
            item["ip"] = check_ip if endpoint_current else ""
            selector = ""
            component_compatible = False
            if (endpoint_current and item.get("status") == "mismatch"
                    and isinstance(component, dict)
                    and self._endpoint_allowed_for_repository(
                        repo, current_machine, check_ip, components=[component],
                        policy_machines=policy_machines,
                    )):
                eligible = next((group for group in self._get_machine_groups_for_components(
                    [component], repo,
                ) if group.get("alias") == alias
                    and group.get("approval_available") is True
                    and component.get("component_id") in set(group.get("component_ids", []))),
                    None)
                if eligible is not None:
                    verified = await self._agent_core_verified_endpoints(
                        repo, current_machine, [component], endpoints=[check_ip],
                    )
                    component_id = component.get("component_id")
                    if any(
                        isinstance(endpoint, dict)
                        and endpoint.get("ip") == check_ip
                        and component_id in set(endpoint.get("component_ids", []))
                        for endpoint in verified
                    ):
                        selector = check_ip
                        component_compatible = True
            item["command_selector"] = selector
            item["approval_available"] = bool(selector)
            item["component_compatible"] = component_compatible
            item["repository_authorized"] = machine_repository_authorized
            item["identity_confirmed"] = endpoint_current
            item["duplicate_ip"] = not endpoint_current
            display_checks.append(item)
        updated = comments_mod.update_runtime_image_checks(
            markdown, display_checks, components,
            lifecycle_status=lifecycle_status,
            machine_diagnostics=diagnostics,
            machine_inventory=self._physical_machine_inventory(),
            test_only=test_only,
        )
        unverified_aliases = {
            alias for alias, values in identities.items() if not values[2]
        }
        unverified_owner_aliases = {
            alias for alias, values in identities.items() if not values[1]
        }
        if unverified_aliases or unverified_owner_aliases:
            start_marker = "<!-- deploy-approval-runtime-checks:start -->"
            end_marker = "<!-- deploy-approval-runtime-checks:end -->"
            start = updated.find(start_marker)
            end = updated.find(end_marker, start + len(start_marker)) if start >= 0 else -1
            if start >= 0 and end >= 0:
                block = updated[start:end + len(end_marker)]
                lines = block.splitlines()
                for index, line in enumerate(lines):
                    for alias in unverified_aliases | unverified_owner_aliases:
                        alias_cell = f"`{comments_mod._escape(alias)}`"
                        if line.startswith(f"| {alias_cell} |"):
                            cells = line.split("|")
                            if len(cells) >= 5:
                                if alias in unverified_aliases:
                                    cells[2] = " `主 IP 未确认` "
                                if alias in unverified_owner_aliases:
                                    cells[3] = " 负责人待配置 "
                                lines[index] = "|".join(cells)
                            break
                updated = updated[:start] + "\n".join(lines) + updated[end + len(end_marker):]
        return await self._add_runtime_owner_guidance(
            updated, display_checks, components, repo, pr_data, lifecycle_status,
        )

    def _enrich_deployments_for_render(
        self, deployments: list[dict], repo: str, *, historical: bool = False,
        historical_machine_groups: list[dict] | None = None,
    ) -> list[dict]:
        """Keep the IP recorded for the actual deployment endpoint."""
        enriched: list[dict] = []
        for dep in deployments:
            if not isinstance(dep, dict):
                enriched.append(dep)
                continue
            machine_alias = dep.get("machine", "")
            ip = dep.get("ip", "")
            if historical:
                ip = "历史主 IP 未记录"
            else:
                ip = self._canonical_primary_ipv4(ip) or (
                    "实际部署 IP 未记录"
                )
            enriched.append({
                **dep,
                "ip": ip,
            })
        return enriched

    @staticmethod
    def _current_core_image(update_info: dict | None) -> str:
        """Return a validated full Core image reference, never a tag guess."""
        if not isinstance(update_info, dict):
            return ""
        for field in ("current_image", "running_image"):
            value = update_info.get(field)
            if not isinstance(value, str) or not value:
                continue
            try:
                return validate_image_ref(value)
            except ValueError:
                continue
        return ""

    @staticmethod
    def _preflight_failure_reason(errors: list[Exception]) -> str:
        text = " ".join(str(error).casefold() for error in errors)
        if any(isinstance(error, GitHubRateLimitError) for error in errors):
            return "GitHub 请求受到限流，当前无法确认 PR 状态；本次部署没有开始。"
        if any(isinstance(error, GitHubTransientError) for error in errors):
            return "GitHub 请求暂时超时或不可用，无法确认 PR 状态；本次部署没有开始。"
        if "github" in text and any(token in text for token in ("timeout", "timed out", "temporarily unavailable")):
            return "GitHub 请求暂时超时，无法确认 PR 状态；本次部署没有开始。"
        if "head changed" in text or "pr head changed" in text:
            return "检查期间 PR HEAD 已变化，原审核和镜像不再适用于当前提交。"
        if any(token in text for token in ("permission", "not authorized", "approval authority")):
            return "当前审批权限已失效，无法确认最终授权。"
        if any(token in text for token in ("identity", "endpoint changed")):
            return "当前设备身份或已确认 IP 集合发生变化，无法确认部署目标。"
        if any(token in text for token in ("duplicate runtime_id", "cannot uniquely resolve", "no driver id")):
            return "Agent Core 返回的 Driver 无法与批准组件唯一匹配，或多个组件指向同一 Runtime ID。"
        if "repository" in text and any(token in text for token in ("image", "runtime", "driver")):
            return "Driver 的运行镜像仓库与批准的目标镜像仓库不一致。"
        if any(token in text for token in ("list_drivers", "driver_status", "driver catalog")):
            return "Agent Core 已连接，但无法读取 Driver 列表或运行状态。"
        if any(token in text for token in ("token", "unauthorized", "401", "forbidden", "authentication", "auth")):
            return "Agent Core 鉴权失败，当前机器凭据无法验证该设备。"
        if any(token in text for token in ("timed out", "timeout", "connect", "unreachable", "network", "no route")):
            return "同一设备的已确认 IP 均无法连接到 Agent Core。"
        return "同一设备的所有已确认 IP 均未通过部署预检。"

    @staticmethod
    def _agent_core_failure_is_connectivity(exc: Exception) -> bool:
        if isinstance(exc, (TimeoutError, OSError)):
            return True
        if not isinstance(exc, AgentCoreError):
            return False
        message = str(exc).casefold()
        return any(marker in message for marker in (
            "connecterror", "connection refused", "connection reset",
            "connection timed out", "connect timeout", "read timeout",
            "timed out", "no route to host", "network is unreachable",
            "temporary failure in name resolution", "name or service not known",
            "nodename nor servname", "network is down",
        ))

    async def _preflight_running_images(
        self,
        core: AgentCoreClient,
        components: list[dict],
    ) -> list[dict]:
        """Read running_image for every selected component before any deploy POST.

        Also validates that no two selected components resolve to the same
        runtime_id — duplicates would cause double-deploy of the same runtime.

        Core components use /api/system/update-check instead of driver Status.
        list_drivers() is only called when there are non-core components.
        """
        deadline = time.monotonic() + float(self.config.total_timeout)

        def remaining_probe_time() -> float:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise asyncio.TimeoutError
            return remaining

        has_non_core = any(c.get("target") != "core" for c in components)
        if has_non_core:
            drivers = await asyncio.wait_for(
                core.list_drivers(), timeout=remaining_probe_time(),
            )
            if not isinstance(drivers, list):
                raise DeployControllerError("Agent Core list_drivers returned an invalid payload")
        else:
            drivers = []

        cached_statuses: dict[str, dict] = {}
        preflight: list[dict] = []
        seen_runtime_ids: dict[str, str] = {}  # runtime_id -> component_id
        for component in components:
            comp_target = component.get("target", "")
            if comp_target == "core":
                # Core update-check must expose the complete running image.
                # current_tag alone cannot prove this round's approved image.
                try:
                    update_info = await asyncio.wait_for(
                        core.core_update_check(), timeout=remaining_probe_time(),
                    )
                except AgentCoreError as e:
                    raise DeployControllerError(
                        f"core preflight update-check failed: {e}"
                    ) from e
                current_image = self._current_core_image(update_info)
                target_image = str(component.get("image_ref", "") or "")
                if not current_image:
                    raise DeployControllerError(
                        "core full running image is unavailable; refusing unsafe approval"
                    )
                try:
                    validate_image_ref(target_image)
                except ValueError as exc:
                    raise DeployControllerError(
                        "core approved image reference is invalid"
                    ) from exc
                runtime_id = "core"
                if runtime_id in seen_runtime_ids:
                    raise DeployControllerError(
                        f"duplicate runtime_id {runtime_id!r} for components "
                        f"{seen_runtime_ids[runtime_id]!r} and "
                        f"{component.get('component_id', '')!r} "
                        f"— refusing to deploy the same runtime twice"
                    )
                seen_runtime_ids[runtime_id] = component.get("component_id", "")
                already_target = current_image == target_image
                preflight.append({
                    "component": component,
                    "runtime_id": runtime_id,
                    "running_image": current_image,
                    "current_tag": current_image,
                    "target_tag": target_image,
                    "status": str(update_info.get("status", "") or ""),
                    "already_target": already_target,
                    "runtime_repo": "",
                })
                continue

            resolved = self._resolve_component_runtime(drivers, component)
            if resolved is None:
                target = component.get("target", "")
                raise DeployControllerError(
                    f"cannot uniquely resolve runtime for component target {target!r}"
                )
            runtime_id = str(resolved.get("runtime_id") or "")
            if not runtime_id:
                raise DeployControllerError(
                    f"runtime for component target {component.get('target', '')!r} has no driver id"
                )
            # Fail on duplicate runtime_id in the same approval group
            if runtime_id in seen_runtime_ids:
                raise DeployControllerError(
                    f"duplicate runtime_id {runtime_id!r} for components "
                    f"{seen_runtime_ids[runtime_id]!r} and {component.get('component_id', '')!r} "
                    f"— refusing to deploy the same runtime twice"
                )
            seen_runtime_ids[runtime_id] = component.get("component_id", "")
            if runtime_id not in cached_statuses:
                status = await asyncio.wait_for(
                    core.driver_status(runtime_id),
                    timeout=remaining_probe_time(),
                )
                if not isinstance(status, dict):
                    raise DeployControllerError(
                        f"Agent Core driver_status for {runtime_id} returned invalid data"
                    )
                cached_statuses[runtime_id] = status
            running_image = str(cached_statuses[runtime_id].get("running_image", "") or "")
            preflight.append({
                "component": component,
                "runtime_id": runtime_id,
                "running_image": running_image,
                "status": str(cached_statuses[runtime_id].get("status", "") or ""),
                "runtime_repo": resolved.get("runtime_repo", ""),
            })
        return preflight

    async def _verify_deployed_runtime(
        self,
        core,
        node_id: str,
        component_id: str,
        runtime_id: str,
        target_image_ref: str,
    ) -> tuple[bool, dict]:
        """Make one short observation; an unconfirmed POST remains uncertain."""
        last_status = ""
        last_running_image = ""
        last_error: str | None = None
        try:
            status_data = await asyncio.wait_for(
                core.driver_status(runtime_id),
                timeout=min(float(self.config.total_timeout),
                            AGENT_CORE_STATUS_PROBE_TIMEOUT_SECONDS),
            )
            if isinstance(status_data, dict):
                status_val = status_data.get("status", "")
                running_image = status_data.get("running_image", "")
                last_status = status_val if isinstance(status_val, str) else ""
                last_running_image = running_image if isinstance(running_image, str) else ""
                if last_status == "running" and last_running_image == target_image_ref:
                    return True, {
                        "component_id": component_id,
                        "runtime_id": runtime_id,
                        "status": "running",
                        "running_image": target_image_ref,
                        "target_image": target_image_ref,
                        "verified": True,
                    }
                last_error = "target image not yet observed running"
            else:
                last_error = "invalid runtime status response"
        except (AgentCoreError, asyncio.TimeoutError) as exc:
            last_error = type(exc).__name__

        result: dict[str, Any] = {
            "component_id": component_id,
            "runtime_id": runtime_id,
            "status": last_status,
            "running_image": last_running_image,
            "target_image": target_image_ref,
            "verified": False,
        }
        result["error"] = last_error or "runtime status unavailable"
        return False, result

    async def _snapshot_terminal_runtime_logs(
        self, repo: str, components: list[dict], deployments: list[dict],
    ) -> dict[str, str]:
        """Snapshot terminal runtime logs for deployed components.

        Executed AFTER durable terminal lifecycle state has been written.
        Never used as a health gate; never changes lifecycle status.
        Returns dict[source_key: log_text] where source_key is
        "machine_alias/runtime_id" for each distinct deployed runtime.
        """
        result: dict[str, str] = {}
        seen: set[tuple[str, str]] = set()
        for dep in deployments:
            if dep.get("phase") != "deployed":
                continue
            machine_alias = dep.get("machine", "")
            for cid in dep.get("component_ids", []):
                comp = next(
                    (c for c in components if c.get("component_id", "") == cid),
                    None,
                )
                if comp is None:
                    continue
                runtime_id = str(comp.get("runtime_id") or "")
                comp_target = comp.get("target", "")
                # Core has no driver_status endpoint; never fabricate runtime text.
                if comp_target == "core":
                    continue
                if not runtime_id:
                    continue
                seen_key = (machine_alias, runtime_id)
                if seen_key in seen:
                    continue
                seen.add(seen_key)
                source_key = f"{machine_alias}/{runtime_id}"
                machine = self.policy.get_machine(machine_alias, repo=repo)
                if machine is None:
                    result[source_key] = "[RUNTIME_LOG_SNAPSHOT_UNAVAILABLE]"
                    continue
                try:
                    core = await self._core_for_node(machine.node_id, repo)
                    status = await core.driver_status(runtime_id)
                    logs = status.get("logs", "") if isinstance(status, dict) else ""
                    if isinstance(logs, str) and logs:
                        result[source_key] = logs
                    else:
                        result[source_key] = "[RUNTIME_LOG_SNAPSHOT_UNAVAILABLE]"
                except NameError:
                    raise
                except Exception:
                    result[source_key] = "[RUNTIME_LOG_SNAPSHOT_UNAVAILABLE]"
        return result

    async def _save_deployed_machine_log(self, repo: str, pr_number: int,
                                        state: dict, machine_alias: str) -> None:
        """Persist and best-effort upload logs for this newly verified machine."""
        try:
            head = state.get("head_sha", "")
            round_id = round_id_for_state(state)
            deployments = [d for d in state.get("deployments", [])
                           if d.get("phase") == "deployed" and d.get("machine") == machine_alias]
            if not deployments:
                return
            current = await self.proxy.read_hidden_state(repo, pr_number)
            if not isinstance(current, dict) or current.get("head_sha") != head or round_id_for_state(current) != round_id:
                return
            deployments = [d for d in current.get("deployments", [])
                           if d.get("phase") == "deployed" and d.get("machine") == machine_alias]
            if not deployments:
                return
            logs = current.get("deployment_logs", {})
            prior = logs.get(machine_alias) if isinstance(logs, dict) else None
            if isinstance(prior, dict) and (prior.get("head_sha"), prior.get("round_id")) == (head, round_id):
                if prior.get("status") != "pending":
                    return
                task = copy.deepcopy(prior)
            else:
                task = {"head_sha": head, "round_id": round_id, "status": "pending",
                        "collected_at": "",
                        "object_key": "", "sha256": "", "size": 0}
                if not await self._write_machine_log_state(repo, pr_number, current, machine_alias, task):
                    return
            # The pending CAS is durable; refresh its exact result before any
            # log collection or subsequent state transition.
            state = await self.proxy.read_hidden_state(repo, pr_number)
            if (not isinstance(state, dict) or state.get("head_sha") != head
                    or round_id_for_state(state) != round_id
                    or state.get("deployment_logs", {}).get(machine_alias) != task
                    or not any(d.get("phase") == "deployed" and d.get("machine") == machine_alias
                               for d in state.get("deployments", []))):
                return
            if task.get("collected_at"):
                object_key = self.cos.build_object_key(
                    repo, pr_number, head, machine_alias=machine_alias, round_id=round_id,
                    now=datetime.fromisoformat(task["collected_at"].replace("Z", "+00:00")),
                )
                try:
                    existing_bytes = await self.cos.download_evidence_archive(object_key, 10 * 1024 * 1024)
                except Exception as exc:
                    existing_bytes = None
                    cause = exc
                    while cause is not None:
                        getter = getattr(cause, "get_status_code", None)
                        try:
                            status = getter() if callable(getter) else None
                        except Exception:
                            status = None
                        if status == 404:
                            break
                        cause = getattr(cause, "__cause__", None)
                    else:
                        if self.cos._fake and str(exc) == "fake COS object not found":
                            cause = None
                        else:
                            # A failed read is not evidence that the object is
                            # absent. Keep the fixed task pending without recapture.
                            return
                if existing_bytes is not None:
                    existing_sha = hashlib.sha256(existing_bytes).hexdigest()
                    identity_error = CosClient._validate_evidence_identity(
                        object_key, existing_bytes, expected_sha256=existing_sha,
                        expected_size=len(existing_bytes), repo=repo, pr_number=pr_number,
                        head_sha=head, expected_result="deployed", machine_alias=machine_alias,
                        round_id=round_id,
                    )
                    if identity_error is None:
                        ready = copy.deepcopy(task)
                        ready.update(status="ready", object_key=object_key,
                                     sha256=existing_sha, size=len(existing_bytes))
                        if await self._write_machine_log_state(repo, pr_number, state, machine_alias, ready):
                            return
                        return
                    # A key occupied by different or unverifiable content is
                    # immutable. Never attempt a replacement upload.
                    return
                if existing_bytes is None and task.get("collected_at"):
                    # A confirmed 404 permits a fresh collection only after
                    # clearing the former collection identity via CAS.
                    task = copy.deepcopy(task)
                    task["collected_at"] = ""
                    if not await self._write_machine_log_state(repo, pr_number, state, machine_alias, task):
                        return
                    state = await self.proxy.read_hidden_state(repo, pr_number)
                    if (not isinstance(state, dict) or state.get("head_sha") != head
                            or round_id_for_state(state) != round_id
                            or state.get("deployment_logs", {}).get(machine_alias) != task):
                        return
            all_logs = await asyncio.wait_for(
                self._snapshot_terminal_runtime_logs(
                    repo, state.get("components", []), deployments,
                ),
                timeout=20,
            )
            machine_logs = {k: v for k, v in all_logs.items() if k.startswith(machine_alias + "/")}
            machine_logs = {k: v for k, v in machine_logs.items()
                            if isinstance(v, str) and v.strip()
                            and "SNAPSHOT_UNAVAILABLE" not in v}
            if not task.get("collected_at"):
                task = copy.deepcopy(task)
                task["collected_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                if not await self._write_machine_log_state(repo, pr_number, state, machine_alias, task):
                    return
                state = await self.proxy.read_hidden_state(repo, pr_number)
                if (not isinstance(state, dict) or state.get("head_sha") != head
                        or round_id_for_state(state) != round_id
                        or state.get("deployment_logs", {}).get(machine_alias) != task):
                    return
            object_key = self.cos.build_object_key(
                repo, pr_number, head, machine_alias=machine_alias, round_id=round_id,
                now=datetime.fromisoformat(task["collected_at"].replace("Z", "+00:00")),
            )
            pr_now = await self.proxy.get_pr(repo, pr_number)
            state_now = await self.proxy.read_hidden_state(repo, pr_number)
            if (not isinstance(pr_now, dict) or pr_now.get("state") != "open"
                    or pr_now.get("merged") or pr_now.get("draft")
                    or pr_now.get("head", {}).get("sha") != head
                    or state_now != state or not self.config.auth_valid
                    or repo not in self.config.active_repos or repo not in self.config.github_repos):
                return
            meta = await asyncio.wait_for(
                self._upload_evidence(repo, pr_number, head, state, "deployed",
                                      runtime_logs=machine_logs, object_key=object_key,
                                      machine_alias=machine_alias, round_id=round_id,
                                      collected_at=task["collected_at"]),
                timeout=20,
            )
            if (not meta or meta.get("object_key") != object_key
                    or not isinstance(meta.get("sha256"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", meta["sha256"])
                    or type(meta.get("size")) is not int or meta["size"] <= 0):
                unavailable = copy.deepcopy(task)
                unavailable["status"] = "unavailable"
                await self._write_machine_log_state(repo, pr_number, state, machine_alias, unavailable)
                return
            ready = copy.deepcopy(task)
            ready.update(status="ready", object_key=meta["object_key"],
                         sha256=meta["sha256"], size=meta["size"])
            await self._write_machine_log_state(repo, pr_number, state, machine_alias, ready)
        except Exception:
            logger.warning("machine deployment log save failed %s#%s machine=%s", repo, pr_number, machine_alias)

    async def _write_machine_log_state(self, repo: str, pr_number: int, expected: dict,
                                       machine_alias: str, task: dict) -> bool:
        """CAS one machine-log transition into the existing trusted Lifecycle comment."""
        try:
            pr = await self.proxy.get_pr(repo, pr_number)
            comment = await self.proxy.find_trusted_lifecycle_comment(repo, pr_number)
            fresh = await self.proxy.read_hidden_state(repo, pr_number)
            if (not isinstance(pr, dict) or pr.get("state") != "open" or pr.get("merged")
                    or pr.get("draft") or pr.get("head", {}).get("sha") != expected.get("head_sha")
                    or fresh != expected or not self.config.auth_valid
                    or repo not in self.config.active_repos or repo not in self.config.github_repos
                    or not isinstance(comment, dict)):
                return False
            dep_exists = any(isinstance(d, dict) and d.get("phase") == "deployed"
                             and d.get("machine") == machine_alias for d in fresh.get("deployments", []))
            if not dep_exists or task.get("head_sha") != fresh.get("head_sha") \
                    or task.get("round_id") != round_id_for_state(fresh):
                return False
            new_state = copy.deepcopy(fresh)
            new_state.setdefault("deployment_logs", {})[machine_alias] = copy.deepcopy(task)
            from .github_state_proxy import HIDDEN_STATE_MARKER
            visible = comment.get("body", "").split(HIDDEN_STATE_MARKER, 1)[0].rstrip()
            written = await self.proxy.write_hidden_state(
                repo, pr_number, visible, new_state,
                expected_comment=(comment.get("id"), comment.get("body")),
            )
            if not isinstance(written, dict):
                return False
            after = await self.proxy.read_hidden_state(repo, pr_number)
            return after == new_state
        except Exception:
            return False

    async def _check_approval_permissions(
        self, machine, actor: str, repo: str,
    ) -> None:
        """Check if actor is authorized to approve deploy on this machine.

        Authorized if:
        1. actor is in machine owners list, OR
        2. actor has write/maintain/admin GitHub collaborator permission.

        Fail closed on permission lookup error.
        """
        actor_lower = actor.strip().lower() if actor else ""
        owners_lower = [o.lower() for o in (machine.owners or [])]
        if actor_lower in owners_lower:
            return
        next_step = "\n\n请让这台机器配置的负责人按 PR Summary 中当前可用的 IP 审批命令操作。"

        # Fresh collaborator permission check
        try:
            permission = await self.proxy.collaborator_permission(repo, actor)
        except Exception:
            raise PolicyError(
                "暂时无法确认当前账号的仓库权限，因此没有执行这次审批。" + next_step
            )

        if not Policy.collaborator_can_approve(permission):
            raise PolicyError(
                "当前账号既不是这台机器的负责人，也没有足够的仓库权限（需要写入、维护或管理员权限）。"
                + next_step
            )

    def _is_deployed_machine_owner(self, actor: str, state: dict, repo: str) -> bool:
        actor_lower = actor.strip().casefold() if isinstance(actor, str) else ""
        if not actor_lower:
            return False
        for dep in state.get("deployments", []):
            if not isinstance(dep, dict) or dep.get("phase") != "deployed":
                continue
            machine = self.policy.get_machine(dep.get("machine", ""), repo=repo)
            if machine and any(
                isinstance(owner, str) and owner.casefold() == actor_lower
                for owner in (machine.owners or [])
            ):
                return True
        return False

    async def _check_record_test_permissions(
        self, repo: str, actor: str, state: dict, *, actor_id=None,
        comment_id=None, result="",
    ) -> None:
        """Authorize a configured allowlisted GitHub user for this round."""
        reviewers = self.policy.reviewers_for_repo(repo)
        valid_reviewers = {
            reviewer.strip().casefold()
            for reviewer in reviewers if isinstance(reviewer, str)
            and _LOGIN_RE.fullmatch(reviewer.strip())
            and not reviewer.strip().casefold().endswith("[bot]")
        } if isinstance(reviewers, list) else set()
        if not valid_reviewers:
            raise PolicyError(
                f"当前仓库 `{repo}` 还没有配置可用的验收账号，已拒绝记录测试结果。"
                "请联系仓库维护者在默认分支的验收名单中配置。"
            )
        actor_lower = actor.strip().casefold() if isinstance(actor, str) else ""
        if not actor_lower or actor_lower not in valid_reviewers:
            raise PolicyError(
                f"只有当前仓库 `{repo}` 验收名单中的账号可以执行 `/record_test`。"
            )
        request = state.get("acceptance_request")
        try:
            expected_round = round_id_for_state(state)
        except Exception:
            expected_round = ""
        if (not isinstance(request, dict)
                or request.get("head_sha") != state.get("head_sha")
                or request.get("round_id") != expected_round):
            raise PolicyError("本轮尚无有效的验收请求。")
        try:
            numeric_actor_id = int(actor_id)
        except (TypeError, ValueError):
            numeric_actor_id = 0
        if numeric_actor_id <= 0 or type(comment_id) is not int or comment_id <= 0:
            raise PolicyError("无法验证验收人的 GitHub 评论身份。")
        if request.get("status") == "pending":
            if state.get("status") != "testing":
                raise PolicyError("当前轮次尚未处于可记录验收结果的 testing 状态。")
            return
        if (request.get("status") == "completed"
                and request.get("accepted_by_id") == numeric_actor_id
                and request.get("acceptance_comment_id") == comment_id
                and request.get("accepted_by", "").casefold() == actor_lower
                and request.get("result") == result
                and state.get("status") == ("succeeded" if result == "pass" else "failed")):
            return
        raise PolicyError("本轮验收请求已完成或不再有效。")

    async def _deploy_component(
        self, core: AgentCoreClient, node_id: str,
        image_ref: str, runtime_id: str, after_post=None,
    ) -> dict:
        """Deploy a single component to a machine via Agent Core."""
        try:
            result = await core.deploy_driver(runtime_id, image_ref)
            if after_post is not None and not await after_post():
                raise DeployOutcomeUncertain(
                    "deploy POST was sent but the deployment-start state could not be confirmed"
                )
            return {"result": result}
        except AgentCoreDeployOutcomeUncertain as e:
            if after_post is not None:
                await after_post(uncertain=True)
            raise DeployOutcomeUncertain(
                f"Deploy outcome uncertain for {runtime_id} on node {node_id}: {e}"
            ) from e
        except AgentCoreError as e:
            raise DeployControllerError(
                f"Deploy failed for {runtime_id} on node {node_id}: {e}"
            )

    async def _deploy_core_component(
        self,
        core: AgentCoreClient,
        node_id: str,
        image_ref: str,
    ) -> dict:
        """Deploy core via Agent Core self-update POST /api/system/update.

        Must be called AFTER all non-core components have been deployed,
        because core update restarts Agent Core and would interrupt further
        API calls.

        Returns {"result": data_dict} on UPDATE_ACCEPTED.
        Raises DeployOutcomeUncertain on transport uncertainty.
        Raises DeployControllerError on confirmed failure.
        """
        try:
            result = await core.update_core(image_ref)
            return {"result": result}
        except AgentCoreDeployOutcomeUncertain as e:
            raise DeployOutcomeUncertain(
                f"Core deploy outcome uncertain for node {node_id}: {e}"
            ) from e
        except AgentCoreError as e:
            raise DeployControllerError(
                f"Core deploy failed for node {node_id}: {e}"
            )

    async def _verify_core_update(
        self,
        core: AgentCoreClient,
        component_id: str,
        target_image_ref: str,
    ) -> tuple[bool, dict]:
        """Make one short update-check; confirm only the exact full image ref."""
        try:
            validate_image_ref(target_image_ref)
        except ValueError:
            return False, {
                "component_id": component_id,
                "runtime_id": "core",
                "current_tag": "",
                "target_tag": target_image_ref,
                "verified": False,
                "error": "core approved image reference is invalid",
            }

        last_current_image = ""
        last_error: str | None = None
        try:
            update_info = await asyncio.wait_for(
                core.core_update_check(),
                timeout=min(float(self.config.total_timeout),
                            AGENT_CORE_STATUS_PROBE_TIMEOUT_SECONDS),
            )
            last_current_image = self._current_core_image(update_info)
            if last_current_image and last_current_image == target_image_ref:
                return True, {
                    "component_id": component_id,
                    "runtime_id": "core",
                    "current_tag": last_current_image,
                    "target_tag": target_image_ref,
                    "verified": True,
                }
            last_error = "complete target core image not yet observed"
        except (AgentCoreError, asyncio.TimeoutError) as exc:
            last_error = type(exc).__name__

        result: dict[str, Any] = {
            "component_id": component_id,
            "runtime_id": "core",
            "current_tag": last_current_image,
            "target_tag": target_image_ref,
            "verified": False,
        }
        result["error"] = last_error or "core update status unavailable"
        return False, result

    @staticmethod
    def _order_components_for_deploy(components: list[dict]) -> list[dict]:
        """Order components so non-core deploy first, core last.

        Preserves relative order within each group.
        """
        non_core = [c for c in components if c.get("target") != "core"]
        core_comp = [c for c in components if c.get("target") == "core"]
        return non_core + core_comp


    async def _deploy_or_adopt_core_component(
        self,
        core: AgentCoreClient,
        node_id: str,
        component_id: str,
        image_ref: str,
        before_post=None,
        after_post=None,
    ) -> tuple[bool, dict, bool]:
        """Deploy core via self-update, or adopt if already at target.

        Returns (verified, health_evidence, post_performed).

        This is the single entry point for core deployment in
        handle_approve_deploy — it implements the idempotent
        "already-target → zero POST" protection.
        """
        try:
            validate_image_ref(image_ref)
        except ValueError:
            raise DeployControllerError(
                "core image reference is invalid — refusing unsafe POST"
            )

        # Step 1: fresh already-target check
        try:
            update_info = await asyncio.wait_for(
                core.core_update_check(),
                timeout=float(self.config.total_timeout),
            )
        except (AgentCoreError, asyncio.TimeoutError) as e:
            raise DeployPreflightUnavailable(
                f"core already-target check failed: {e}"
            ) from e

        current_image = self._current_core_image(update_info)
        if not current_image:
            raise DeployPreflightUnavailable(
                "core full running image is unavailable; no deploy POST was sent"
            )

        # Step 2: if already at target, adopt without POST
        if current_image == image_ref:
            return True, {
                "component_id": component_id,
                "runtime_id": "core",
                "current_tag": current_image,
                "target_tag": image_ref,
                "verified": True,
                "already_target": True,
            }, False

        # Step 3: perform the unsafe POST then verify
        if before_post is not None:
            reservation_confirmed = await before_post()
            if not reservation_confirmed:
                return False, {
                    "component_id": component_id,
                    "runtime_id": "core",
                    "verified": False,
                    "error": "deploy lifecycle write was not confirmed before POST",
                }, False
        try:
            await self._deploy_core_component(core, node_id, image_ref)
        except DeployOutcomeUncertain:
            if after_post is not None:
                await after_post(uncertain=True)
            raise
        if after_post is not None and not await after_post():
            raise DeployOutcomeUncertain(
                "core deploy POST was sent but the deployment-start state could not be confirmed"
            )
        verified, health_evidence = await self._verify_core_update(
            core, component_id, image_ref,
        )
        if verified:
            health_evidence["already_target"] = False
        return verified, health_evidence, True
    async def _run_automated_case(
        self, repo: str, pr_number: int, head_sha: str,
        components: list[dict],
        deployments: list[dict],
    ) -> dict[str, str]:
        """Run automated cases per component.

        Returns dict of component_id -> result ("pass", "fail", "n/a").
        Only runs after all components are deployed.

        For each component, binds to the actual deployed machine.
        Uses the explicit deployments list from the caller.
        """
        if not deployments:
            deployments = []
        results: dict[str, str] = {}
        for comp in components:
            cid = comp.get("component_id", "")
            if not cid:
                continue
            target = comp.get("target", "")
            variant = comp.get("variant", "")
            image_ref = comp.get("image_ref", "")

            # Find the deployment record for this component
            deployment_record = None
            for dep in deployments:
                if dep.get("phase") == "deployed" and cid in dep.get("component_ids", []):
                    deployment_record = dep
                    break

            if deployment_record is None:
                results[cid] = "fail"
                continue

            machine_alias = deployment_record.get("machine", "")
            machine = self.policy.get_machine(machine_alias, repo=repo)
            if machine is None:
                results[cid] = "fail"
                continue

            node_id = machine.node_id

            # Select case for this component before network access
            runner = self._get_case_runner()
            try:
                case_id = runner.select_case(target, variant, node_id)
            except Exception as e:
                logger.warning("case select %s: %s", cid, e)
                results[cid] = "fail"
                continue
            if case_id is None:
                results[cid] = "n/a"
                continue

            # Resolve core client (only for components with cases)
            try:
                core = await self._core_for_node(node_id, repo)
            except Exception as e:
                logger.warning("case core resolve %s: %s", cid, e)
                results[cid] = "fail"
                continue

            # Use deploy-pinned runtime_id from the component, never re-resolve
            # from list_drivers(). The runtime_id was pinned during approve_deploy
            # preflight and is the authoritative binding.
            driver_id = str(comp.get("runtime_id") or "")
            if not driver_id:
                logger.warning(
                    "case component %s has no pinned runtime_id; "
                    "deploy must have set runtime_id during preflight",
                    cid,
                )
                results[cid] = "fail"
                continue

            # Run case with actual binding
            deployment_dict = {
                "component_id": cid,
                "target": target,
                "variant": variant,
                "driver_path": comp.get("driver_path", ""),
                "runtime_id": driver_id,
                "node_id": node_id,
                "node_host": selected_endpoint,
                "image_ref": image_ref,
                "machine_alias": machine_alias,
                "_core": core,
                "_driver_id": driver_id,
            }
            try:
                case_result = await runner.run_case(case_id, deployment_dict)
                passed = case_result.get("passed", False)
                results[cid] = "pass" if passed else "fail"
            except Exception as e:
                logger.warning(
                    "case %s for %s: %s", case_id, cid, e,
                )
                results[cid] = "fail"

        return results

    # _get_current_state removed - state is passed explicitly

    async def _upload_evidence(
        self, repo: str, pr_number: int, head_sha: str,
        state: dict, result: str, summary: str = "",
        deploy_error: str = "",
        runtime_logs: dict | None = None,
        object_key: str = "",
        machine_alias: str = "",
        round_id: str = "",
        collected_at: str = "",
    ) -> dict:
        """Upload COS evidence bundle. Returns metadata dict.

        Builds evidence in memory, uploads to COS, returns metadata.
        Failure does not raise.
        """
        try:
            # Retries keep the originally published key, including its date.
            # ensure_evidence_archive verifies/reuses it without replacing bytes.
            object_key = object_key or (state.get("cos", {}) or {}).get("object_key") or self.cos.build_object_key(
                repo, pr_number, head_sha, machine_alias=machine_alias, round_id=round_id,
                now=(datetime.fromisoformat(collected_at.replace("Z", "+00:00")) if collected_at else None),
            )
            CosClient.validate_object_key(
                repo, pr_number, head_sha, object_key,
                machine_alias=machine_alias, round_id=round_id,
            )
            archive_bytes = b""
            sha256 = ""
            size = 0

            # Build evidence bundle
            try:
                builder = EvidenceBuilder(self.config)
                archive_bytes, sha256, size = await builder.build_evidence(
                    repo=repo,
                    pr_number=pr_number,
                    head_sha=head_sha,
                    state=state,
                    result=result,
                    summary=summary,
                    deploy_error=deploy_error,
                    runtime_logs=runtime_logs,
                    machine_alias=machine_alias, round_id=round_id, collected_at=collected_at,
                )
            except Exception as e:
                logger.warning(
                    "evidence build %s#%s: %s", repo, pr_number, e,
                )

            if archive_bytes:
                return await self.cos.ensure_evidence_archive(
                    object_key=object_key,
                    archive_bytes=archive_bytes,
                    repo=repo,
                    pr_number=pr_number,
                    head_sha=head_sha,
                    result=result,
                    machine_alias=machine_alias, round_id=round_id,
                )
            return {"object_key": "", "sha256": "", "size": 0}
        except Exception as e:
            logger.warning(
                "evidence upload %s#%s: %s", repo, pr_number, e,
            )
            return {"object_key": "", "sha256": "", "size": 0}

    async def _ensure_history_archive(
        self, repo: str, pr_number: int, existing_comments: list[dict],
        *, extra_text: str,
    ) -> dict:
        """Reuse the identical trusted archive after an uncertain GitHub write."""
        prefix = f"{HISTORY_ARCHIVE_MARKER_PREFIX}{repo}:{pr_number}:"
        for comment in existing_comments:
            body = comment.get("body", "")
            if not isinstance(body, str) or prefix not in body or not self.proxy.is_bot_comment(comment):
                continue
            page = body.split(prefix, 1)[1].split(" -->", 1)[0]
            if not re.fullmatch(r"[1-9][0-9]*", page):
                continue
            if body == _build_archive_body(repo, pr_number, int(page), [], extra_text=extra_text):
                return {"page": int(page), "url": comment.get("html_url", "")}
        page = _next_history_archive_page(existing_comments, repo, pr_number)
        body = _build_archive_body(repo, pr_number, page, [], extra_text=extra_text)
        comment = await self.proxy.post_issue_comment(repo, pr_number, body)
        if not isinstance(comment, dict) or not comment.get("id"):
            raise GitHubStateProxyError("History archive write was not confirmed")
        # The archive must be visible as a trusted comment before the caller
        # removes its events from the lifecycle document.
        readback = await self.proxy.get_issue_comments(repo, pr_number)
        confirmed = next((row for row in readback if isinstance(row, dict)
                         and row.get("id") == comment.get("id")
                         and row.get("body") == body
                         and self.proxy.is_bot_comment(row)), None)
        if confirmed is None:
            raise GitHubStateProxyError("History archive readback failed")
        return {"page": page, "url": confirmed.get("html_url", comment.get("html_url", ""))}

    async def _preflight_archive_for_event(
        self,
        repo: str,
        pr_number: int,
        prospective_visible: str,
        reserved_event: dict | None = None,
    ) -> None:
        """Pre-flight visible lifecycle capacity and create archive if needed.

        Computes the REAL prospective visible body:
          prospective_renderer_output
          + existing generated history events
          + reserved/new event (if any)
          + archive links
        and measures its UTF-8 bytes.

        Must be called BEFORE any unsafe side effect (Agent Core deploy POST).
        If archive creation fails, raise to prevent the unsafe action.
        If prospective body exceeds 48 KiB and there is no archivables history,
        raise explicitly (fail closed).
        """
        from .github_state_proxy import (
            _parse_visible_history,
            _build_history_block,
            _insert_history_into_visible,
            VISIBLE_HISTORY_START_MARKER,
            VISIBLE_HISTORY_END_MARKER,
        )

        # 1. Fresh-read current lifecycle comment
        comment = await self.proxy.find_trusted_lifecycle_comment(repo, pr_number)
        if comment is None:
            # No existing lifecycle comment: compute prospective body size.
            # Build real prospective visible: base + reserved_event
            from .github_state_proxy import (
                _build_history_block,
                _insert_history_into_visible,
            )
            if reserved_event is not None:
                prospective_with_history = _insert_history_into_visible(
                    prospective_visible, reserved_event,
                )
            else:
                prospective_with_history = prospective_visible
            body_bytes = _count_visible_bytes(prospective_with_history)
            if body_bytes <= _MAX_VISIBLE_LIFECYCLE_BYTES:
                # Under budget: no archive needed, caller will create lifecycle comment
                return
            else:
                # Over budget with no existing comment to archive into: fail closed
                raise GitHubStateProxyError(
                    "preflight archive: visible lifecycle exceeds 48 KiB "
                    "soft limit and no trusted lifecycle comment exists to host archives"
                )

        current_body = comment.get("body", "")
        if not isinstance(current_body, str):
            raise GitHubStateProxyError(
                "preflight archive: comment body is not a string"
            )

        # Keep raw events: parsing/re-rendering would discard historical fields.
        from .github_state_proxy import HIDDEN_STATE_MARKER
        hidden_idx = current_body.find(HIDDEN_STATE_MARKER)
        if hidden_idx < 0:
            raise GitHubStateProxyError("preflight archive: cannot find hidden state marker")
        existing_visible_part = current_body[:hidden_idx].rstrip()
        h_start = existing_visible_part.find(VISIBLE_HISTORY_START_MARKER)
        h_end = existing_visible_part.find(VISIBLE_HISTORY_END_MARKER)
        raw_events = []
        tail = ""
        if h_start >= 0 or h_end >= 0:
            if (h_start < 0 or h_end <= h_start
                    or existing_visible_part.count(VISIBLE_HISTORY_START_MARKER) != 1
                    or existing_visible_part.count(VISIBLE_HISTORY_END_MARKER) != 1):
                raise GitHubStateProxyError("preflight archive: malformed History markers")
            content = existing_visible_part[h_start + len(VISIBLE_HISTORY_START_MARKER):h_end]
            parts = content.split(HISTORY_EVENT_DELIMITER)
            raw_events = [part + HISTORY_EVENT_DELIMITER for part in parts[:-1]]
            tail = parts[-1]
            if tail.strip():
                raw_events.append(tail)
                tail = ""
        legacy_history = None
        if h_start < 0 and h_end < 0:
            legacy_history = re.search(r"(?ms)^### History[ \t]*\n.*?(?=^### |\Z)", existing_visible_part)
            if legacy_history:
                raw_events = [legacy_history.group(0).partition("\n")[2]]
        old_archives = re.search(r"(?ms)^### Archived history[ \t]*\n.*?(?=^### |\Z)", existing_visible_part)
        archive_links_text = old_archives.group(0) if old_archives else ""
        reserved_inner = ""
        if reserved_event is not None:
            reserved_inner = _build_history_block([reserved_event])[
                len(VISIBLE_HISTORY_START_MARKER):-len(VISIBLE_HISTORY_END_MARKER)
            ]

        def prospective_size(kept_events: list[str]) -> int:
            return _count_visible_bytes(
                prospective_visible.rstrip() + "\n\n### History\n\n"
                + VISIBLE_HISTORY_START_MARKER + reserved_inner
                + "".join(kept_events) + tail + VISIBLE_HISTORY_END_MARKER
                + "\n\n" + archive_links_text
            )

        # 4. Count real prospective visible bytes
        body_bytes = prospective_size(raw_events)
        if body_bytes <= _MAX_VISIBLE_LIFECYCLE_BYTES:
            return

        # 5. Need to archive oldest events
        if not raw_events:
            raise GitHubStateProxyError(
                "preflight archive: visible lifecycle exceeds 48 KiB "
                "soft limit and no history events available to archive"
            )

        # 6. Truncate oldest events to fit
        kept = list(raw_events)
        archived = []
        while kept and prospective_size(kept) > _MAX_VISIBLE_LIFECYCLE_BYTES - 2048:
            archived.insert(0, kept.pop())
        if prospective_size(kept) > _MAX_VISIBLE_LIFECYCLE_BYTES - 2048:
            raise GitHubStateProxyError("preflight archive: prospective lifecycle cannot fit after archival")

        if not archived:
            raise GitHubStateProxyError(
                "preflight archive: unable to fit visible lifecycle even "
                "after attempting to archive oldest events"
            )

        # 7. Create archive comment
        existing_comments = await self.proxy.get_issue_comments(repo, pr_number)
        archive = await self._ensure_history_archive(
            repo, pr_number, existing_comments,
            extra_text=("Archived oldest history events to preserve main lifecycle capacity.\n\n"
                        + VISIBLE_HISTORY_START_MARKER + "".join(archived) + tail
                        + VISIBLE_HISTORY_END_MARKER),
        )

        # 8. Rewrite the SAME lifecycle comment to remove archived events
        new_history_block = (VISIBLE_HISTORY_START_MARKER + "".join(kept) + tail
                             + VISIBLE_HISTORY_END_MARKER)

        # Reconstruct visible with shrunk history
        h_start = existing_visible_part.find(VISIBLE_HISTORY_START_MARKER)
        h_end = existing_visible_part.find(VISIBLE_HISTORY_END_MARKER)
        if h_start >= 0 and h_end >= 0:
            before_hist = existing_visible_part[:h_start]
            after_hist = existing_visible_part[h_end + len(VISIBLE_HISTORY_END_MARKER):]
            new_visible = before_hist + new_history_block + after_hist
        elif legacy_history is not None:
            new_visible = (existing_visible_part[:legacy_history.start()]
                           + "### History\n\n" + new_history_block + "\n\n"
                           + existing_visible_part[legacy_history.end():])
        else:
            new_visible = existing_visible_part.rstrip() + "\n\n" + new_history_block + "\n"

        # Publish the new archive reference atomically with removal from main.
        archive_line = comments_mod._archives_link_block([archive]).split("\n", 2)[2]
        old_links = re.search(r"(?ms)^### Archived history[ \t]*\n.*?(?=^### |\Z)", new_visible)
        if old_links:
            if str(archive["page"]) not in re.findall(r"History Archive Page ([0-9]+)", old_links.group(0)):
                new_visible = (new_visible[:old_links.end()].rstrip() + "\n" + archive_line
                               + "\n\n" + new_visible[old_links.end():])
        else:
            new_visible += "\n\n" + comments_mod._archives_link_block([archive])

        # 9. Verify the shrunk visible fits
        shrunk_bytes = _count_visible_bytes(new_visible)
        if shrunk_bytes > _MAX_VISIBLE_LIFECYCLE_BYTES:
            # Should not happen if truncation logic is correct, but guard anyway
            raise GitHubStateProxyError(
                "preflight archive: shrunk visible lifecycle still exceeds 48 KiB soft limit"
            )

        # 10. Parse fresh hidden state and write back
        fresh_state = _extract_hidden_state(current_body)
        if fresh_state is None:
            raise GitHubStateProxyError("preflight archive: cannot extract hidden state")
        fresh_state = _validate_hidden_state(fresh_state)

        final_body = _build_hidden_state_body(new_visible, fresh_state)
        comment_id = comment.get("id")
        fresh_comment = await self.proxy.find_trusted_lifecycle_comment(repo, pr_number)
        if (fresh_comment is None or fresh_comment.get("body") != current_body
                or fresh_comment.get("id") != comment_id):
            raise GitHubStateProxyError("preflight archive: lifecycle changed during archival")
        if not isinstance(comment_id, int) or isinstance(comment_id, bool) or comment_id <= 0:
            raise GitHubStateProxyError("preflight archive: invalid lifecycle comment id")
        written = await self.proxy.update_comment(repo, comment_id, final_body)
        if not isinstance(written, dict):
            raise GitHubStateProxyError("preflight archive: lifecycle write was not confirmed")
        confirmed = await self.proxy.find_trusted_lifecycle_comment(repo, pr_number)
        if (confirmed is None or confirmed.get("id") != comment_id
                or confirmed.get("body") != final_body):
            raise GitHubStateProxyError("preflight archive: lifecycle readback failed")

    @staticmethod
    def _set_lifecycle_summary_status(markdown: str, status: str) -> str:
        if status not in {"deploy-requested", "deploying"}:
            raise DeployControllerError(f"unsupported lifecycle display status {status!r}")
        target = f"**Status:** `{status}`"
        if target in markdown:
            return markdown
        alternate = "**Status:** `deploying`" if status == "deploy-requested" else "**Status:** `deploy-requested`"
        if markdown.count(alternate) != 1:
            raise DeployControllerError("lifecycle summary status marker is missing or ambiguous")
        return markdown.replace(alternate, target, 1)

    async def _deploy_requested_markdown(
        self, repo, pr_number, head_sha, components, machine_groups, *,
        display_status: str = "deploy-requested", test_only: bool = True, **kwargs,
    ) -> str:
        renderer = comments_mod.deploy_requested
        command_groups: list[dict] = []
        suppress_approval_commands = bool(
            kwargs.pop("_suppress_approval_commands", False)
        )
        if display_status == "deploy-requested" and not suppress_approval_commands:
            command_groups = await self._machine_groups_verify_endpoints(
                machine_groups if isinstance(machine_groups, list) else [],
                repo, components,
            )
        try:
            parameters = inspect.signature(renderer).parameters
            supports_display_status = (
                "display_status" in parameters
                or any(item.kind == inspect.Parameter.VAR_KEYWORD
                       for item in parameters.values())
            )
        except (TypeError, ValueError):
            supports_display_status = False
            parameters = {}
        render_kwargs = dict(kwargs)
        machine_context = self._machine_comment_context(
            components, command_groups, repo, test_only=test_only,
        )
        for key, value in machine_context.items():
            render_kwargs.setdefault(key, value)
        accepts_kwargs = any(
            item.kind == inspect.Parameter.VAR_KEYWORD
            for item in parameters.values()
        )
        render_kwargs = {
            key: value for key, value in render_kwargs.items()
            if accepts_kwargs or key in parameters
        }
        if supports_display_status:
            markdown = renderer(
                repo, pr_number, head_sha, components, command_groups,
                display_status=display_status, **render_kwargs,
            )
        else:
            render_kwargs.pop("display_status", None)
            markdown = renderer(repo, pr_number, head_sha, components, command_groups,
                                **render_kwargs)
            markdown = self._set_lifecycle_summary_status(markdown, display_status)
        return markdown

    def _machine_comment_context(
        self, components: list[dict], machine_groups: list[dict], repo: str,
        *, test_only: bool,
    ) -> dict:
        """Project service diagnostics into the compatible lifecycle renderer API."""
        inventory = self._physical_machine_inventory()
        current_groups = self._get_machine_groups_for_components(components, repo)
        selected_by_alias = {
            str(group.get("alias")): group for group in machine_groups or []
            if isinstance(group, dict) and isinstance(group.get("alias"), str)
        }
        policy_aliases_by_ip: dict[str, list[str]] = {}
        policy_status = {}
        policy_machines = []
        try:
            status = self.policy.repo_policy_status(repo)
            if isinstance(status, dict):
                policy_status = dict(status)
            if (policy_status.get("authorized") is True
                    and policy_status.get("machines_configured") is True):
                policy_machines = self.policy.get_machines(repo=repo)
                if not isinstance(policy_machines, list):
                    policy_machines = []
                for machine in policy_machines:
                    machine_ip = self._canonical_primary_ipv4(
                        getattr(machine, "node_host", ""),
                    )
                    machine_alias = str(getattr(machine, "alias", "") or "")
                    if machine_ip and machine_alias:
                        policy_aliases_by_ip.setdefault(machine_ip, []).append(machine_alias)
        except Exception:
            policy_status = {}
            policy_machines = []
            policy_aliases_by_ip = {}

        policy_by_alias: dict[str, list] = {}
        for machine in policy_machines:
            alias = str(getattr(machine, "alias", "") or "")
            if alias:
                policy_by_alias.setdefault(alias, []).append(machine)

        # Keep the inventory's physical description, but overwrite identity,
        # owner, and platform fields from current repository policy only.
        inventory_rows = []
        for item in inventory:
            alias = str(item.get("alias", "") or "")
            raw = item.get("raw")
            row = {
                key: raw[key] for key in ("number", "brand", "model")
                if isinstance(raw, dict) and key in raw
            }
            matching = policy_by_alias.get(alias, [])
            machine = matching[0] if len(matching) == 1 else None
            _, identity_confirmed = self._machine_identity_matches(
                alias, machine, None, policy_machines, repo=repo,
            ) if machine is not None else (None, False)
            if identity_confirmed and policy_status.get("authorized") is True:
                row.update({
                    "primary_ip": self._canonical_primary_ipv4(
                        getattr(machine, "node_host", ""),
                    ),
                    "node_id": str(getattr(machine, "node_id", "") or ""),
                    "owners": list(getattr(machine, "owners", []) or []),
                    "owner_status": "verified",
                    "owner_source": "machines.yaml",
                    "platform": list(getattr(machine, "platforms", []) or []),
                    "platforms": list(getattr(machine, "platforms", []) or []),
                    "platform_status": "verified",
                    "platform_verified": True,
                })
            else:
                row.update({
                    "primary_ip": "", "node_id": "", "owners": [],
                    "owner_status": "pending", "owner_source": "pending",
                    "platform": [], "platforms": [],
                    "platform_status": "unverified", "platform_verified": False,
                })
            row["alias"] = alias
            inventory_rows.append(row)

        diagnostics = []
        for group in current_groups:
            alias = group.get("alias", "")
            selected = selected_by_alias.get(alias)
            policy_machine = None
            matching_policy = [machine for machine in policy_machines
                               if getattr(machine, "alias", "") == alias]
            if len(matching_policy) == 1:
                policy_machine = matching_policy[0]
            core_configured = bool(
                policy_machine is not None
                and (self._agent_core_factory is not None
                     or self._agent_core_token(alias))
            )
            agent_core_status = str(group.get("agent_core_status", "unknown"))
            agent_core_available = (
                True if agent_core_status == "available" else
                False if agent_core_status in {"credential_missing", "unavailable"} else
                None
            )
            reasons = []
            for reason in group.get("blocking_reasons", []):
                reasons.append({
                    "REPOSITORY_POLICY_MISSING": "当前仓库还没有可用的机器配置。",
                    "MACHINE_NOT_AUTHORIZED": "当前仓库 main 未授权这台机器。",
                    "OWNER_NOT_CONFIGURED": "当前仓库机器负责人待配置。",
                    "MACHINE_IDENTITY_MISMATCH": "当前仓库机器策略中的 alias、node_id 或主 IP 缺失或重复。",
                    "AGENT_CORE_CREDENTIAL_MISSING": "Agent Core 凭证未配置。",
                    "AGENT_CORE_UNAVAILABLE": "Agent Core 当前无法连接。",
                    "AGENT_CORE_UNKNOWN": "Agent Core 尚未确认；审批时会先执行只读预检。",
                    "PLATFORM_UNVERIFIED": "机器平台未确认。",
                    "PLATFORM_MISMATCH": "机器平台与当前构建不匹配。",
                    "TARGET_UNSUPPORTED": "机器不支持当前构建目标。",
                    "VARIANT_MISMATCH": "当前构建 variant 与机器配置不匹配。",
                    "DRIVER_PATH_MISMATCH": "当前构建 driver_path 与机器配置不匹配。",
                    "PRIMARY_IP_AMBIGUOUS": "主 IP 有重复，无法显示安全的机器审批命令。",
                }.get(reason, str(reason)))
            ip = group.get("primary_ip", "")
            ip_conflicts = list(policy_aliases_by_ip.get(ip, [])) if ip else []
            policy_owners = list(group.get("owners", []))
            policy_platforms = list(getattr(policy_machine, "platforms", []) or []) \
                if policy_machine is not None else []
            authorized = group.get("repo_authorized") is True
            diagnostics.append({
                "alias": alias,
                "primary_ip": ip,
                "ip": ip,
                "owners": policy_owners if authorized and policy_owners else ["负责人待配置"],
                "physical_owners": [],
                "owner_status": "verified" if authorized and policy_owners else "pending",
                "owner_source": "machines.yaml" if authorized and policy_owners else "pending",
                "policy_owners": policy_owners,
                "repository_authorized": authorized,
                "identity_confirmed": group.get("identity_confirmed") is True,
                "identity_status": group.get("identity_status", "mismatch"),
                "agent_core_credentials_configured": core_configured,
                "agent_core_credentials_available": agent_core_available,
                "agent_core_status": agent_core_status,
                "platform_confirmed": group.get("platform_status") in {
                    "compatible", "incompatible",
                },
                "platform": policy_platforms if authorized else [],
                "component_compatible": bool(group.get("compatible_component_ids")),
                "component_ids": list(group.get("compatible_component_ids", [])),
                "safe_to_approve": bool(
                    selected and selected.get("approval_available") is True
                    and selected.get("command_selector")
                    and selected.get("component_ids")
                ),
                "duplicate_ip": "PRIMARY_IP_AMBIGUOUS" in group.get("blocking_reasons", []),
                "ip_conflicts": list(dict.fromkeys(ip_conflicts)),
                "reasons": reasons,
            })

        try:
            machines = policy_machines
            policy_status["authorized_machines"] = [
                getattr(machine, "alias", "") for machine in machines
                if isinstance(getattr(machine, "alias", ""), str)
                and getattr(machine, "alias", "")
            ]
            policy_status["authorized_machine_count"] = len(
                policy_status["authorized_machines"],
            )
            policy_status["test_only"] = bool(test_only)
            configured_reviewers = []
            if policy_status.get("reviewers_configured") is True:
                try:
                    configured_reviewers = self.policy.reviewers_for_repo(repo)
                except Exception as exc:
                    logger.warning("acceptance reviewer list unavailable repo=%s reason=%s",
                                   repo, type(exc).__name__)
            seen_reviewers = set()
            policy_status["reviewers"] = []
            for reviewer in configured_reviewers if isinstance(configured_reviewers, list) else []:
                if (not isinstance(reviewer, str)
                        or not _LOGIN_RE.fullmatch(reviewer.strip())
                        or reviewer.strip().casefold().endswith("[bot]")):
                    continue
                key = reviewer.strip().casefold()
                if key not in seen_reviewers:
                    seen_reviewers.add(key)
                    policy_status["reviewers"].append(reviewer.strip())
        except Exception as exc:
            logger.warning("machine comment policy unavailable repo=%s reason=%s",
                           repo, type(exc).__name__)
            policy_status = {
                "authorized": False, "machines_configured": False,
                "reviewers_configured": False, "missing_files": [],
                "authorized_machines": [], "authorized_machine_count": None,
                "test_only": bool(test_only),
            }
        return {
            "machine_inventory": inventory_rows,
            "machine_diagnostics": diagnostics,
            "repository_policy_status": policy_status,
        }

    async def _deployment_progress_markdown(
        self, repo, pr_number, state, machine, components, phase, *, test_only: bool = True,
    ):
        command = state.get("command", {}) if isinstance(state, dict) else {}
        command_args = command.get("args", {}) if isinstance(command, dict) else {}
        display_ip = self._canonical_primary_ipv4(
            command_args.get("node_host", "") if isinstance(command_args, dict) else "",
        ) or self._runtime_display_identity(machine.alias, repo)[0] or "未记录"
        deployed = _component_id_set(state.get("deployments", []))
        remaining = [c for c in state.get("components", []) if c.get("component_id") not in deployed]
        targets = ", ".join(str(c.get("component_id", "")) for c in components)
        # Progress is presentation-only: hidden deployment rows retain their
        # canonical deployed schema until a POST has been verified.
        display_deployments = list(state.get("deployments", [])) + [{
            "machine": machine.alias,
            "ip": display_ip,
            "component_ids": [c.get("component_id", "") for c in components],
            "phase": ("preflight" if str(phase).startswith(
                ("审批已收到", "部署前检查", "预检已通过", "部署条件已通过"))
                else "deploying"),
            "timestamp": comments_mod.beijing_now_str(),
        }]
        display_status = (
            "deploying" if state.get("status") == "deploying"
            else self._approval_retry_status(state)
        )
        return await self._approval_retry_markdown(
            repo, pr_number, state,
            self._get_machine_groups_for_components(remaining, repo),
            test_only=test_only,
            deployments=self._enrich_deployments_for_render(display_deployments, repo),
            gate_note=[
                f"{phase}：机器 `{machine.alias}`（实际验证 IP：`{display_ip}`），"
                f"组件：{targets}。"
            ],
            display_status=display_status,
        )

    @staticmethod
    def _deployment_request_was_submitted(state: dict) -> bool:
        """Read persisted request provenance, with a status-based legacy fallback."""
        command = state.get("command", {}) if isinstance(state, dict) else {}
        args = command.get("args", {}) if isinstance(command, dict) else {}
        submitted = args.get("deployment_request_submitted") if isinstance(args, dict) else None
        if type(submitted) is bool:
            return submitted
        return isinstance(state, dict) and state.get("status") in {
            "deploy-requested", "deploying",
        }

    @classmethod
    def _approval_retry_status(cls, state: dict) -> str:
        return "deploy-requested" if cls._deployment_request_was_submitted(state) else "deploy-ready"

    def _ip_command_machine_groups(self, groups: list[dict]) -> list[dict]:
        """Keep groups with a verified IP selector or an exact safe alias."""
        result = []
        for group in (groups if isinstance(groups, list) else []):
            if not isinstance(group, dict) or group.get("approval_available") is not True:
                continue
            primary_ip = self._canonical_primary_ipv4(group.get("primary_ip", ""))
            node_host = self._canonical_primary_ipv4(group.get("node_host", ""))
            raw_selector = str(group.get("command_selector", "") or "")
            selector = self._canonical_primary_ipv4(raw_selector)
            alias = str(group.get("alias", "") or "")
            if ((primary_ip and primary_ip == node_host == selector
                 and group.get("ip_command_safe") is True)
                    or (raw_selector == alias
                        and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", alias))):
                result.append(group)
        return result

    def _require_explicit_ip_for_multiple_full_machines(
        self, markdown: str, all_groups: list[dict], components: list[dict],
    ) -> str:
        component_ids = {
            component.get("component_id") for component in components
            if isinstance(component, dict) and isinstance(component.get("component_id"), str)
        }
        full_groups = [
            group for group in all_groups if isinstance(group, dict)
            and group.get("approval_available") is True and component_ids
            and component_ids.issubset(set(group.get("component_ids", [])))
        ]
        if len(full_groups) <= 1:
            return markdown
        lines = markdown.splitlines()
        for group in self._ip_command_machine_groups(full_groups):
            alias = str(group.get("alias", "") or "")
            primary_ip = self._canonical_primary_ipv4(group.get("primary_ip", ""))
            if (not alias or not primary_ip
                    or group.get("ip_command_safe") is not True):
                continue
            row_prefix = f"- `{alias}`（{primary_ip}）"
            for index, line in enumerate(lines):
                if not line.startswith(row_prefix):
                    continue
                command_index = next((offset for offset in range(index + 1, min(index + 4, len(lines)))
                                      if lines[offset] == "  `/approve_deploy`"), None)
                if command_index is not None:
                    lines[command_index] = f"  `/approve_deploy machine={primary_ip}`"
                break
        return "\n".join(lines)

    def _deploy_ready_retry_markdown(
        self, repo: str, pr_number: int, state: dict, remaining: list[dict],
        machine_groups: list[dict], *, gate_note: list[str] | None = None,
    ) -> str:
        builds = [
            BuildInfo(
                target=str(component.get("target", "") or ""),
                driver_path=str(component.get("driver_path", "") or ""),
                variant=str(component.get("variant", "") or ""),
                success=True,
                image_tag=str(component.get("review_image_tag", "") or ""),
                deployable=True,
                component_id=str(component.get("component_id", "") or ""),
            )
            for component in remaining if isinstance(component, dict)
        ]
        markdown = comments_mod.deploy_ready(
            repo, pr_number, state.get("head_sha", ""), builds,
            review_evidence=state.get("review_evidence", {}),
            machine_groups=machine_groups,
            components=remaining,
        )
        markdown = self._require_explicit_ip_for_multiple_full_machines(
            markdown, machine_groups, remaining,
        )
        deployed_ids = sorted(_component_id_set(state.get("deployments", [])))
        progress_lines = []
        if deployed_ids:
            deployed_labels = self._component_summary_labels(
                deployed_ids, state.get("components", []),
            )
            progress_lines.append(
                f"已确认成功部署的组件：{deployed_labels}；这些组件的部署记录已保留，不会重复部署。"
            )
        progress_lines.extend(gate_note or [])
        if progress_lines:
            markdown += "\n\n### Deployment progress\n\n" + "\n".join(progress_lines)
        return markdown

    async def _approval_retry_markdown(
        self, repo: str, pr_number: int, state: dict, machine_groups: list[dict], *,
        display_status: str | None = None, test_only: bool = True,
        gate_note: list[str] | None = None, deployments: list[dict] | None = None,
    ) -> str:
        status = display_status or self._approval_retry_status(state)
        deployed_ids = _component_id_set(state.get("deployments", []))
        remaining = [
            component for component in state.get("components", [])
            if isinstance(component, dict)
            and component.get("component_id") not in deployed_ids
        ]
        progress_notes = list(gate_note or [])
        command = state.get("command", {}) if isinstance(state, dict) else {}
        command_args = command.get("args", {}) if isinstance(command, dict) else {}
        command_pending = (
            isinstance(command_args, dict)
            and command_args.get("preflight_pending") is True
        ) or (isinstance(command, dict)
              and command.get("phase") in {"executing", "uncertain"})
        verified_groups = (
            await self._machine_groups_verify_endpoints(
                machine_groups, repo, remaining,
            )
            if status == "deploy-ready" and not command_pending else []
        )
        if status == "deploy-ready":
            return self._deploy_ready_retry_markdown(
                repo, pr_number, state, remaining, verified_groups,
                gate_note=progress_notes,
            )
        markdown = await self._deploy_requested_markdown(
            repo, pr_number, state.get("head_sha", ""),
            state.get("components", []), machine_groups,
            display_status=status, test_only=test_only,
            gate_note=progress_notes, deployments=deployments,
            _suppress_approval_commands=command_pending,
        )
        if status == "deploying" and not self._deployment_request_was_submitted(state):
            markdown = self._mark_request_step_not_submitted(markdown)
        return markdown

    @staticmethod
    def _mark_request_step_not_submitted(markdown: str) -> str:
        return markdown.replace(
            "- [x] 3. Request deployment",
            "- [ ] 3. Request deployment (optional; direct approval; no request submitted)",
            1,
        )

    async def _archive_round(self, repo, pr_number, state, reason):
        async with self._evidence_lock:
            return await self._archive_round_unlocked(repo, pr_number, state, reason)

    async def _archive_round_unlocked(self, repo, pr_number, state, reason):
        rid = round_id_for_state(state)
        records = await self.proxy.read_evidence_records(repo, pr_number)
        attachments = [{"kind": r["kind"], "key": r["key"],
                        "data": copy.deepcopy(r["data"]), "sha256": r["sha256"]}
                       for r in records if r["kind"] in ("operation", "attachment")
                       and r["data"].get("round_id") == rid]
        snapshot = archive_snapshot(repo, pr_number, state, utc_now(), reason)
        snapshot["attachment_records"] = attachments
        # Archive identity is the round snapshot and its evidence, not the
        # wall-clock time of an attempt to archive it. A retry after an
        # uncertain lifecycle write must resolve to the same immutable record.
        identity_snapshot = copy.deepcopy(snapshot)
        identity_snapshot.pop("ended_at", None)
        identity_snapshot.pop("archived_at", None)
        content = {"snapshot": identity_snapshot["snapshot"], "attachment_records": attachments}
        import json
        key = hashlib.sha256(json.dumps(content, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        existing = next((r for r in records if r["kind"] == "round" and r["key"] == key), None)
        if existing is None:
            # Reuse records made by the previous timestamp-based key scheme
            # when they already contain this same snapshot and attachment set.
            existing = next((r for r in records if r["kind"] == "round"
                             and r["data"].get("round_id") == rid
                             and r["data"].get("reason") == reason
                             and r["data"].get("attachment_records") == attachments
                             and {k: v for k, v in r["data"].get("snapshot", {}).items()
                                  if k not in {"ended_at", "archived_at"}}
                             == identity_snapshot.get("snapshot")), None)
        record = existing or await self.proxy.write_evidence_record(repo, pr_number, "round", key, snapshot)
        if not isinstance(record, dict) or not isinstance(record.get("sha256"), str):
            raise GitHubStateProxyError("Round archive write was not confirmed")
        # Do not let Lifecycle point at an archive until its immutable evidence
        # record is observable through the public reader with the same digest.
        verified = await self.proxy.read_evidence_records(repo, pr_number)
        readback = next((r for r in verified if r["kind"] == "round"
                         and r["key"] == record.get("key", key)
                         and r.get("sha256") == record["sha256"]), None)
        if (readback is None or readback["data"].get("round_id") != rid
                or readback["data"].get("attachment_records") != attachments):
            raise GitHubStateProxyError("Round archive readback failed")
        result = {"round_id": rid, "sha256": record["sha256"]}
        if type(record.get("comment_id")) is int and isinstance(record.get("url"), str):
            result.update(comment_id=record["comment_id"], url=record["url"])
        return result

    @staticmethod
    def _replace_markdown_section(markdown, heading, content, next_heading):
        """Replace one heading-delimited lifecycle section idempotently."""
        heading_re = re.compile(r"(?m)^" + re.escape(heading) + r"[ \t]*$")
        matches = list(heading_re.finditer(markdown))
        if len(matches) != 1:
            return markdown
        content_start = matches[0].end()
        next_match = None
        if isinstance(next_heading, str) and next_heading:
            next_re = re.compile(r"(?m)^" + re.escape(next_heading) + r"[ \t]*$")
            next_match = next_re.search(markdown, content_start)
            if next_match is None:
                return markdown
        end = next_match.start() if next_match is not None else len(markdown)
        replacement = markdown[:content_start] + "\n\n" + content.rstrip()
        if end < len(markdown):
            return replacement + "\n\n" + markdown[end:]
        if markdown.endswith(("\n", "\r")):
            replacement += "\n"
        return replacement

    @staticmethod
    def _unwrap_history_details(history_content: str) -> str:
        """Remove one generated outer History wrapper without touching its body."""
        if not isinstance(history_content, str):
            return ""
        opening = re.match(r"\A\s*<details\b[^>]*>", history_content, re.IGNORECASE)
        if opening is None:
            return history_content
        summary_open = re.match(
            r"\s*<summary\b[^>]*>", history_content[opening.end():], re.IGNORECASE,
        )
        if summary_open is None:
            return history_content
        summary_start = opening.end() + summary_open.end()
        summary_close = re.search(r"</summary\s*>", history_content[summary_start:], re.IGNORECASE)
        if summary_close is None:
            return history_content
        summary_end = summary_start + summary_close.start()
        title = history_content[summary_start:summary_end].strip()
        if title.casefold() != "history · 历史事件":
            return history_content
        body_start = summary_start + summary_close.end()
        outer_close = re.search(r"</details\s*>\s*\Z", history_content, re.IGNORECASE)
        if outer_close is None or outer_close.start() < body_start:
            return history_content
        return history_content[body_start:outer_close.start()]

    @staticmethod
    def _fold_history_content(history_content: str) -> str:
        """Normalize only the outer History block; preserve nested event markup."""
        if not isinstance(history_content, str) or not history_content.strip():
            return ""
        content = history_content
        while True:
            unwrapped = DeployController._unwrap_history_details(content)
            if unwrapped == content:
                break
            content = unwrapped
        header = "<details>\n<summary>History · 历史事件</summary>"
        if content and not content.startswith("\n"):
            header += "\n\n"
        closing_separator = "" if not content or content.endswith("\n") else "\n"
        return (
            header + content + closing_separator + "</details>"
        )

    @staticmethod
    def _extract_visible_history(visible):
        """Remove recognized History sections for safe repositioning verbatim."""
        if not isinstance(visible, str):
            return visible, ""
        history_start = VISIBLE_HISTORY_START_MARKER
        history_end = VISIBLE_HISTORY_END_MARKER
        if visible.count(history_start) != visible.count(history_end):
            raise GitHubStateProxyError("Malformed visible History markers")
        history_spans = []
        if history_start in visible:
            cursor = 0
            while True:
                start = visible.find(history_start, cursor)
                end_before_start = visible.find(history_end, cursor)
                if start < 0 and end_before_start < 0:
                    break
                if end_before_start >= 0 and (start < 0 or end_before_start < start):
                    raise GitHubStateProxyError("Malformed visible History markers")
                end = visible.find(history_end, start + len(history_start))
                if end < 0 or visible.find(history_start, start + len(history_start), end) >= 0:
                    raise GitHubStateProxyError("Malformed visible History markers")
                history_spans.append((start, end + len(history_end)))
                cursor = end + len(history_end)

        heading_re = re.compile(
            r"(?mi)^(#{2,6})[ \t]+(?:历史记录|history|archived history)[ \t]*$",
        )
        heading_matches = list(heading_re.finditer(visible))
        all_heading_matches = list(re.finditer(r"(?m)^(#{1,6})[ \t]+", visible))
        for heading in heading_matches:
            level = len(heading.group(1))
            end = len(visible)
            for following in all_heading_matches:
                if following.start() > heading.start() and len(following.group(1)) <= level:
                    end = min(end, following.start())
                    break
            projection_start = visible.find("<!-- evidence-projection:start -->", heading.end())
            if projection_start >= 0:
                end = min(end, projection_start)
            history_spans.append((heading.start(), end))

        if not history_spans:
            return visible, ""
        history_spans.sort()
        merged = []
        for start, end in history_spans:
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        pieces = []
        cursor = 0
        history_blocks = []
        for start, end in merged:
            pieces.append(visible[cursor:start])
            block = visible[start:end]
            block = re.sub(r"\A[ \t]*#{2,6}[ \t]+(?:history|历史记录)[ \t]*\r?\n+",
                           "", block, count=1, flags=re.IGNORECASE)
            if block.strip():
                # Collapse any pre-existing generated marker pair before
                # joining sections so the final Summary contains one marker
                # pair and one History details block, never nested wrappers.
                block = block.replace(history_start, "").replace(history_end, "")
                block = DeployController._unwrap_history_details(block)
                if block.strip():
                    history_blocks.append(block)
            cursor = end
        pieces.append(visible[cursor:])
        if not history_blocks:
            return "".join(pieces), ""
        history_content = "\n\n".join(history_blocks)
        history_content = DeployController._fold_history_content(history_content)
        if not history_content.endswith("\n"):
            history_content += "\n"
        history = (
            VISIBLE_HISTORY_START_MARKER + "\n" + history_content
            + VISIBLE_HISTORY_END_MARKER
        )
        return "".join(pieces), history

    @classmethod
    def _strip_legacy_evidence_blocks(cls, visible):
        """Remove duplicate evidence presentation before History is isolated.

        Operate on the whole visible body first so obsolete evidence nested
        under a legacy History heading cannot be copied into the preserved
        History block. Only presentation rows are removed; archive links and
        lifecycle prose remain intact.
        """
        if not isinstance(visible, str):
            return visible
        projection_start = "<!-- evidence-projection:start -->"
        projection_end = "<!-- evidence-projection:end -->"
        starts, ends = visible.count(projection_start), visible.count(projection_end)
        if starts != ends:
            raise GitHubStateProxyError("Malformed evidence projection")
        if starts:
            cleaned = []
            cursor = 0
            for _ in range(starts):
                start = visible.find(projection_start, cursor)
                end_before_start = visible.find(projection_end, cursor)
                if start < 0 or end_before_start >= 0 and end_before_start < start:
                    raise GitHubStateProxyError("Malformed evidence projection")
                end = visible.find(projection_end, start + len(projection_start))
                if start < 0 or end < 0 or visible.find(projection_start, start + len(projection_start), end) >= 0:
                    raise GitHubStateProxyError("Malformed evidence projection")
                cleaned.append(visible[cursor:start])
                cursor = end + len(projection_end)
            cleaned.append(visible[cursor:])
            visible = "".join(cleaned)

        lines = visible.splitlines(keepends=True)
        result = []
        index = 0
        heading_re = re.compile(
            r"^(#{2,6})[ \t]+(?:\*\*)?(?:测试附件|附件)(?:\*\*)?[ \t]*#*[ \t]*(?:\r?\n)?$",
        )
        legacy_link_re = re.compile(
            r"\[(?:查看测试附件|打开附件页|上传或查看附件|查看 COS 证据与历史|上传到 COS)\]"
            r"\((?:<[^>]*>|[^)]*)\)"
        )
        cos_link_re = re.compile(
            r"\[[^\]]*\]\((?:<)?https://[^<>\s)]*\.cos\.[^<>\s)]*\.myqcloud\.com/[^<>\s)]*(?:>)?\)",
            re.IGNORECASE,
        )
        cos_url_re = re.compile(
            r"https?://[^\s<>()\]]*\.cos\.[^\s<>()\]]*\.myqcloud\.com/[^\s<>()\]]*",
            re.IGNORECASE,
        )
        cos_download_field_re = re.compile(
            r'''(?i)\bcos_download_url\b[ \t]*[:=][ \t]*(?:"[^"]*"|'[^']*'|[^|,}\s]+)'''
        )
        metadata_value_re = re.compile(
            r"[\"']?(?:object_key|sha256|size|cos_object_key|cos_bundle_sha256|cos_bundle_size|cos_download_url|cos)"
            r"[\"']?[ \t]*[:=][ \t]*(\"[^\"]*\"|'[^']*'|[0-9]+|null|None)",
            re.IGNORECASE,
        )
        empty_metadata_assignment_re = re.compile(
            r"(?i)(?:\*{1,2}cos(?:_object_key|_bundle_sha256|_bundle_size)?\*{1,2}"
            r"|[\"']?cos(?:_object_key|_bundle_sha256|_bundle_size)?[\"']?)"
            r"[ \t]*[:：=][ \t]*(?:[|·*_`-]*)(?:\r?\n)?$",
        )
        while index < len(lines):
            heading = heading_re.match(lines[index])
            if heading:
                index += 1
                # Remove the old heading and its immediate Markdown table,
                # while retaining following History prose/events.
                while index < len(lines) and not lines[index].strip():
                    index += 1
                if index < len(lines) and lines[index].lstrip().startswith("|"):
                    while index < len(lines) and lines[index].lstrip().startswith("|"):
                        index += 1
                continue
            line = lines[index]
            legacy_link = legacy_link_re.search(line)
            cos_link = cos_link_re.search(line)
            cos_url = cos_url_re.search(line)
            metadata_values = metadata_value_re.findall(line)
            empty_cos_metadata = (
                bool(metadata_values) and all(
                    value.strip("\\\"' ").lower() in {"", "0", "null", "none"}
                    for value in metadata_values
                ) and bool(re.search(r"(?i)cos|object_key|sha256", line))
            ) or bool(empty_metadata_assignment_re.search(line))
            old_cos_download_row = (
                bool(re.search(r"(?i)\b(?:COS[ \t]+下载|下载[ \t]+COS|verified[ \t]+COS[ \t]+download)\b", line))
                and (".cos." in line.lower() or "cos_download_url" in line.lower())
            )
            if cos_download_field_re.search(line):
                line = cos_download_field_re.sub("COS 下载链接已省略", line)
                cos_link = cos_link_re.search(line)
                cos_url = cos_url_re.search(line)
            if legacy_link or cos_link or cos_url or old_cos_download_row or empty_cos_metadata:
                remainder = line
                if legacy_link:
                    remainder = legacy_link_re.sub("", remainder)
                if cos_link:
                    remainder = cos_link_re.sub("", remainder)
                if cos_url:
                    remainder = cos_url_re.sub("", remainder)
                if old_cos_download_row and re.fullmatch(
                        r"[ \t|·:*_`-]*(?:COS[ \t]+)?(?:下载|Download(?:[ \t]+COS)?|"
                        r"下载已验证归档文件)[ \t:：|·*_`-]*\r?\n?",
                        remainder, re.IGNORECASE):
                    remainder = ""
                if empty_cos_metadata or not remainder.strip(" \t\r\n|·-*"):
                    index += 1
                    continue
                line = remainder
            result.append(line)
            index += 1
        visible = "".join(result).rstrip()
        return visible

    @staticmethod
    def _strip_legacy_lifecycle_display_fields(
        visible, *, remove_current_deployment=False,
    ):
        """Remove recognized top-level legacy display fields only."""
        if not isinstance(visible, str):
            return visible
        lines = visible.splitlines()
        result = []
        index = 0
        details_depth = 0
        code_fence = None
        deployment_heading = re.compile(r"^### Current Deployment[ \t]*$")
        table_rule = re.compile(r"^\s*\|(?:\s*:?-+:?\s*\|)+\s*$")
        last_event = re.compile(
            r"^\s*(?:\*\*)?Last lifecycle event:(?:\*\*)?(?:\s+.*)?$",
        )
        known_empty_deployment = {
            "Deployment records exist; details unavailable.",
            "No deployment has been performed yet.",
            "No deployment record is available for this round yet.",
            "Deployment completed; deployment records unavailable.",
        }

        def update_details_depth(line):
            nonlocal details_depth
            details_depth += len(re.findall(r"<details\b[^>]*>", line, re.IGNORECASE))
            details_depth -= len(re.findall(r"</details\s*>", line, re.IGNORECASE))
            details_depth = max(0, details_depth)

        while index < len(lines):
            fence_match = re.match(r"^\s*(`{3,}|~{3,})", lines[index])
            if code_fence is not None:
                result.append(lines[index])
                if (fence_match and fence_match.group(1)[0] == code_fence[0]
                        and len(fence_match.group(1)) >= code_fence[1]):
                    code_fence = None
                index += 1
                continue
            if fence_match:
                result.append(lines[index])
                code_fence = (fence_match.group(1)[0], len(fence_match.group(1)))
                index += 1
                continue
            if details_depth == 0 and last_event.fullmatch(lines[index]):
                index += 1
                continue
            if (remove_current_deployment and details_depth == 0
                    and deployment_heading.fullmatch(lines[index])):
                following = index + 1
                while following < len(lines) and not lines[following].strip():
                    following += 1
                end = None
                if following < len(lines) and lines[following].lstrip().startswith("|"):
                    cells = [cell.strip() for cell in lines[following].strip().strip("|").split("|")]
                    if (len(cells) >= 2 and cells[0].casefold() == "machine"
                            and cells[1].casefold() == "ip"
                            and following + 1 < len(lines)
                            and table_rule.fullmatch(lines[following + 1])):
                        end = following + 2
                        while end < len(lines) and lines[end].lstrip().startswith("|"):
                            end += 1
                elif (following < len(lines)
                      and lines[following].strip() in known_empty_deployment):
                    end = following + 1
                if end is None:
                    logger.warning(
                        "Unrecognized top-level Current Deployment section; preserving it",
                    )
                else:
                    index = end
                    while index < len(lines) and not lines[index].strip():
                        index += 1
                    if result and index < len(lines):
                        result.append("")
                    continue
            result.append(lines[index])
            update_details_depth(lines[index])
            index += 1
        return "\n".join(result).strip()

    async def _render_evidence_projection(self, repo, pr_number, state, visible):
        evidence_service = getattr(self, "evidence_service", None)
        schedule_backfill = getattr(
            evidence_service, "schedule_ready_notification_backfill", None,
        )
        if callable(schedule_backfill):
            # After a switch to the fixed public origin, announce attachments
            # that were verified while only an ephemeral tunnel existed.
            schedule_backfill(repo, pr_number)
        renderer = getattr(comments_mod, "render_evidence_section", None)
        if renderer is None:
            visible, history = self._extract_visible_history(visible)
            visible = self._strip_legacy_lifecycle_display_fields(visible)
            return visible.rstrip() + ("\n\n" + history if history else "")
        previous_visible = visible
        records = await self.proxy.read_evidence_records(repo, pr_number)
        archives = [r["data"] for r in records if r["kind"] == "round"]
        attachments = [r["data"] for r in records if r["kind"] == "attachment"]
        operation_candidates_by_identity = {}
        for record in records:
            if record.get("kind") != "operation" or not isinstance(record.get("data"), dict):
                continue
            operation = record["data"]
            identity = (
                operation.get("repo"), operation.get("pr_number"),
                operation.get("head_sha"), operation.get("round_id"),
                operation.get("attachment_id"),
            )
            if all(value is not None for value in identity):
                operation_candidates_by_identity.setdefault(identity, []).append(
                    (record.get("key", ""), operation),
                )

        operation_phase_rank = {
            "prepared": 10, "initializing": 20, "uploading": 30,
            "completing": 40, "verifying": 50, "processing": 60,
            "ready": 70, "invalid": 80, "deleted": 90,
        }

        def operation_candidate_rank(candidate):
            record_key, operation = candidate
            timestamp = float("-inf")
            for field in ("updated_at", "completed_at", "created_at"):
                value = operation.get(field)
                if not isinstance(value, str):
                    continue
                try:
                    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                except ValueError:
                    continue
                if parsed.tzinfo is None or parsed.utcoffset() is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                timestamp = parsed.timestamp()
                break
            # Deletion and invalidation are terminal. A persisted ready phase
            # outranks stale upload phases regardless of record iteration order.
            phase_rank = operation_phase_rank.get(operation.get("status"), 0)
            return phase_rank, timestamp, str(record_key)

        operation_records_by_identity = {
            identity: max(candidates, key=operation_candidate_rank)[1]
            for identity, candidates in operation_candidates_by_identity.items()
            if candidates
        }
        trusted_records_by_key = {
            (record.get("kind"), record.get("key")): record
            for record in records
            if isinstance(record, dict) and isinstance(record.get("key"), str)
        }
        latest_by_identity = {}
        deleted_by_identity = {}
        attachment_id_identities: dict[str, set[tuple[str, int, str, str, str]]] = {}

        def attachment_is_deleted(row):
            return bool(row.get("deleted_at")) or row.get("status") == "deleted"

        def operation_matches_attachment(row, operation):
            if (not isinstance(operation, dict)
                    or operation.get("status") != "ready"
                    or operation.get("deleted_at")
                    or operation.get("cos_content_verified") is not True):
                return False
            return all(
                operation.get(field) == row.get(field)
                for field in (
                    "repo", "pr_number", "head_sha", "round_id", "attachment_id",
                    "object_key", "filename", "size", "sha256",
                )
            )

        for row in attachments:
            attachment_id = row.get("attachment_id") if isinstance(row, dict) else None
            if isinstance(attachment_id, str):
                # read_evidence_records is chronologically ordered; this is
                # the same Latest rule used by EvidenceService.
                identity = (
                    row.get("repo"), row.get("pr_number"), row.get("head_sha"),
                    row.get("round_id"), attachment_id,
                )
                attachment_id_identities.setdefault(attachment_id, set()).add(identity)
                latest_by_identity[identity] = row
                if attachment_is_deleted(row):
                    # The download API treats an attachment ID as permanently
                    # deleted once a trusted tombstone exists for that identity.
                    deleted_by_identity[identity] = row
        current_round = round_id_for_state(state)
        current_rows = []
        for identity, row in latest_by_identity.items():
            record_repo, record_pr, head_sha, round_id, attachment_id = identity
            if ((record_repo, record_pr, head_sha, round_id)
                    != (repo, pr_number, state.get("head_sha"), current_round)):
                continue
            current_rows.append(deleted_by_identity.get(identity, row))

        def attachment_key_inputs(row):
            object_key = row.get("object_key")
            filename = row.get("filename")
            if not isinstance(filename, str) or not filename.strip():
                filename = (object_key.rsplit("/", 1)[-1]
                            if isinstance(object_key, str) else "")
            uploaded_at = None
            for field in ("created_at", "uploaded_at"):
                value = row.get(field)
                if not isinstance(value, str):
                    continue
                try:
                    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                except ValueError:
                    continue
                if parsed.tzinfo is not None and parsed.utcoffset() is not None:
                    uploaded_at = value
                    break
            display_uploaded_at = uploaded_at
            if uploaded_at is None and isinstance(object_key, str):
                parts = object_key.split("/")
                if len(parts) == 10 and parts[0] == "phanthymotus_pr":
                    try:
                        # This date-only fallback is used solely to verify the
                        # canonical object path; it is never exposed as upload time.
                        uploaded_at = datetime.fromisoformat(
                            parts[3] + "T00:00:00+08:00",
                        ).isoformat()
                    except ValueError:
                        pass
            return uploaded_at, filename, display_uploaded_at

        def verified_evidence_row(
            row, head_sha, round_id, *, operation=None,
            archived_invite_provenance=False,
        ):
            if not isinstance(row, dict):
                return False
            if (row.get("repo") != repo or type(row.get("pr_number")) is not int
                    or row.get("pr_number") != pr_number):
                return False
            invitation_upload = (
                row.get("upload_method") == "signed_invite"
                and row.get("upload_link_authorized") is True
                and row.get("actor_verified") is False
                and row.get("github_user_authenticated") is False
                and row.get("cos_content_verified") is True
            )
            archived_invitation_upload = (
                archived_invite_provenance
                and row.get("upload_method") == "signed_invite"
                and row.get("actor") == "shared-link"
            )
            invitation_upload = invitation_upload or archived_invitation_upload
            if row.get("upload_method") == "signed_invite" and not invitation_upload:
                return False
            if (row.get("head_sha") != head_sha
                    or row.get("round_id") != round_id
                    or not isinstance(head_sha, str)
                    or not isinstance(round_id, str)
                    or re.fullmatch(re.escape(head_sha) + r"-[0-9]+", round_id) is None
                    or not (row.get("actor_verified") is True or invitation_upload)):
                return False
            if row.get("status") == "text":
                source_id = row.get("source_comment_id")
                digest = row.get("sha256")
                return (type(source_id) is int and source_id > 0
                        and isinstance(digest, str)
                        and re.fullmatch(r"[0-9a-f]{64}", digest) is not None)
            if (row.get("status") != "ready" or row.get("deleted_at")
                    or type(row.get("size")) is not int
                    or not 1 <= row["size"] <= 512 * 1024 * 1024):
                return False
            digest = row.get("sha256")
            source_id = row.get("source_comment_id")
            if source_id is not None and (type(source_id) is not int or source_id <= 0):
                return False
            if (not isinstance(digest, str)
                    or re.fullmatch(r"[0-9a-f]{64}", digest) is None):
                return False
            if not operation_matches_attachment(row, operation):
                return False
            if (row.get("upload_method") == "signed_invite"
                    and not archived_invite_provenance
                    and row.get("cos_content_verified") is not True):
                return False
            uploaded_at, filename, _ = attachment_key_inputs(row)
            if not isinstance(uploaded_at, str) or not isinstance(filename, str) or not filename:
                return False
            try:
                from .evidence_store import build_attachment_key
                expected_key = build_attachment_key(
                    repo, pr_number, head_sha, round_id, row.get("attachment_id", ""),
                    uploaded_at, filename,
                )
            except (ValueError, TypeError, AttributeError):
                return False
            return row.get("object_key") == expected_key

        store = getattr(getattr(self, "evidence_service", None), "store", None)

        async def cos_object_is_verified(
            row, head_sha, round_id, operation, *,
            archived_invite_provenance=False,
        ):
            if not verified_evidence_row(
                    row, head_sha, round_id, operation=operation,
                    archived_invite_provenance=archived_invite_provenance):
                return row.get("status") == "text" and verified_evidence_row(
                    row, head_sha, round_id, operation=operation,
                )
            verify = getattr(store, "verify_summary_attachment", None)
            if callable(verify):
                try:
                    identity = await verify(
                        repo=repo, pr_number=pr_number, operation=operation,
                    )
                except Exception:
                    return False
            else:
                # Older store adapters can prove readiness only by issuing a
                # signed Summary URL, whose signer also reads back the object.
                sign = getattr(store, "sign_summary_attachment", None)
                if not callable(sign):
                    return False
                try:
                    signed = await sign(
                        repo=repo, pr_number=pr_number, operation=operation,
                    )
                except Exception:
                    return False
                if not isinstance(signed, dict):
                    return False
                identity = {
                    "key": signed.get("object_key"),
                    "head_sha": signed.get("head_sha"),
                    "round_id": signed.get("round_id"),
                    "attachment_id": signed.get("attachment_id"),
                    "size": signed.get("size"),
                    "sha256": signed.get("sha256"),
                }
            return (
                isinstance(identity, dict)
                and identity.get("key") == row.get("object_key")
                and identity.get("head_sha") == head_sha
                and identity.get("round_id") == round_id
                and identity.get("attachment_id") == row.get("attachment_id")
                and identity.get("size") == row.get("size")
                and identity.get("sha256") == row.get("sha256")
            )

        verified_current = set()
        for row in current_rows:
            identity = (
                repo, pr_number, row.get("head_sha"), row.get("round_id"),
                row.get("attachment_id"),
            )
            operation = operation_records_by_identity.get(identity)
            if await cos_object_is_verified(
                    row, state.get("head_sha"), current_round, operation):
                verified_current.add(identity)
        confirmed_current = bool(verified_current) or any(
            row.get("status") == "text"
            and verified_evidence_row(
                row, state.get("head_sha"), current_round,
                operation=operation_records_by_identity.get((
                    repo, pr_number, row.get("head_sha"), row.get("round_id"),
                    row.get("attachment_id"),
                )),
            )
            for row in current_rows
        )
        if state.get("status") == "testing":
            component_ids = {c.get("component_id") for c in state.get("components", [])
                             if isinstance(c, dict) and c.get("component_id")}
            deployed_ids = _component_id_set(state.get("deployments", []))
            deployments_complete = bool(component_ids) and component_ids.issubset(deployed_ids)
            workflow = comments_mod._workflow_lines(
                "testing", evidence_complete=confirmed_current,
                deployments_complete=deployments_complete,
                record_test_complete=(
                    state.get("test_result") in {"pass", "fail"}
                    and state.get("command", {}).get("kind") == "record_test"
                    and state.get("command", {}).get("phase") == "completed"
                    and state.get("command", {}).get("args", {}).get("result")
                    == state.get("test_result")
                ),
            )
            visible = self._replace_markdown_section(
                visible, "### Workflow", workflow, "### Next action",
            )
        # Presentation flags are deliberately ephemeral. Hidden state has a
        # strict schema and must never learn about browser feature config.
        render_state = copy.deepcopy(state)
        store = getattr(self.evidence_service, "store", None)
        try:
            pr = await self.proxy.get_pr(repo, pr_number)
        except Exception as exc:
            logger.warning("Evidence PR context unavailable %s#%s exception=%s",
                           repo, pr_number, type(exc).__name__)
            raise GitHubStateProxyError(
                "Evidence projection could not verify current PR context",
            ) from None
        if (not isinstance(pr, dict) or pr.get("state") not in {"open", "closed"}
                or pr.get("base", {}).get("repo", {}).get("full_name", "").lower() != repo.lower()
                or not isinstance(pr.get("head"), dict)
                or pr.get("head", {}).get("sha") != state.get("head_sha")):
            raise GitHubStateProxyError(
                "Evidence projection could not verify current PR head",
            )
        if state.get("status") == "testing":
            acceptance = state.get("acceptance_request")
            acceptance_pending = (
                isinstance(acceptance, dict)
                and acceptance.get("status") == "pending"
                and acceptance.get("head_sha") == state.get("head_sha")
                and acceptance.get("round_id") == current_round
            )
            reviewers_configured, eligible_reviewers = self._eligible_acceptance_reviewers(
                repo, pr,
            )
            fresh_testing = comments_mod.testing(
                repo, pr_number, state.get("head_sha", ""),
                deployments=self._enrich_deployments_for_render(
                    state.get("deployments", []), repo,
                ),
                components=state.get("components", []),
                evidence_complete=confirmed_current,
                deployments_complete=deployments_complete,
                acceptance_pending=acceptance_pending,
                acceptance_reviewers_configured=reviewers_configured,
                acceptance_reviewers=eligible_reviewers,
            )
            action_heading = re.search(r"(?m)^### Next action[ \t]*$", fresh_testing)
            if action_heading is not None:
                action_start = action_heading.end()
                next_template_heading = re.search(
                    r"(?m)^#{1,6}[ \t]+[^\r\n]+", fresh_testing[action_start:],
                )
                action_end = (action_start + next_template_heading.start()
                              if next_template_heading else len(fresh_testing))
                next_action = fresh_testing[action_start:action_end].strip()
                if acceptance_pending and self._is_test_only_pr(pr):
                    reviewer_guidance = self._acceptance_reviewer_guidance(
                        repo, pr, reviewers_configured, eligible_reviewers,
                    )
                    if reviewers_configured:
                        record_test_instruction = (
                            "当前仓库所有有效验收白名单成员仍可按原有权限输入 "
                            "`/record_test result=pass` 或 `/record_test result=fail`。"
                        )
                    else:
                        record_test_instruction = (
                            "配置当前仓库有效验收名单后，名单成员仍按原有规则获得 "
                            "`/record_test` 权限。"
                        )
                    if eligible_reviewers:
                        next_action = "\n\n".join((
                            next_action, reviewer_guidance, record_test_instruction,
                        ))
                    else:
                        upload_followup = next((
                            line for line in next_action.splitlines()
                            if line.startswith("如需补充测试视频或图片，可")
                        ), "")
                        next_action = "\n\n".join(
                            part for part in (
                                reviewer_guidance, record_test_instruction,
                                upload_followup,
                            ) if part
                        )
                elif acceptance_pending and not eligible_reviewers:
                    reviewer_guidance = self._acceptance_reviewer_guidance(
                        repo, pr, reviewers_configured, eligible_reviewers,
                    )
                    if reviewers_configured:
                        next_action = "\n\n".join((
                            reviewer_guidance,
                            "由当前仓库验收白名单中的获授权账号输入 `/record_test result=pass` 或 `/record_test result=fail`。",
                        ))
                    else:
                        next_action = "\n\n".join((
                            reviewer_guidance,
                            "配置有效的当前仓库验收账号后，获授权验收人才能输入 `/record_test result=pass` 或 `/record_test result=fail`。",
                        ))
                action_start = visible.find("### Next action")
                action_content_start = (action_start + len("### Next action")
                                        if action_start >= 0 else -1)
                next_heading = "### Current Deployment"
                if (action_content_start >= 0
                        and visible.find(next_heading, action_content_start) < 0):
                    candidates = [
                        match.start() + action_content_start
                        for match in re.finditer(
                            r"(?m)^#{1,6}[ \t]+[^\r\n]+",
                            visible[action_content_start:],
                        )
                    ]
                    candidates.extend(
                        position for marker in (
                            "<!-- evidence-projection:start -->",
                            VISIBLE_HISTORY_START_MARKER,
                        )
                        if (position := visible.find(marker, action_content_start)) >= 0
                    )
                    next_heading = (
                        visible[min(candidates):].splitlines()[0]
                        if candidates else None
                    )
                visible = self._replace_markdown_section(
                    visible, "### Next action", next_action, next_heading,
                )
        try:
            from .evidence_auth import readiness
            status = readiness(self.config, self.evidence_service)
            backend_ready = (status["EVIDENCE_BACKEND_READY"]
                             and callable(getattr(store, "dispatch", None)))
            browser_upload_ready = (
                backend_ready and status["PUBLIC_HTTPS_INGRESS_READY"]
                and state.get("status") == "testing"
                and pr.get("state") == "open" and not pr.get("merged")
                and not pr.get("draft")
            )
        except Exception:
            status = {"status": "EVIDENCE_BACKEND_PENDING",
                      "PUBLIC_HTTPS_INGRESS_READY": False}
            backend_ready = False
            browser_upload_ready = False
        has_evidence_history = any(
            isinstance(row, dict) and isinstance(row.get("head_sha"), str)
            and isinstance(row.get("round_id"), str)
            and re.fullmatch(re.escape(row["head_sha"]) + r"-[0-9]+", row["round_id"])
            for row in attachments
        ) or any(
            isinstance(archive.get("snapshot"), dict)
            and isinstance(archive["snapshot"].get("attachments"), list)
            and bool(archive["snapshot"]["attachments"])
            for archive in archives if isinstance(archive, dict)
        ) or any(
            isinstance(archive, dict)
            and isinstance(archive.get("attachment_records"), list)
            and any(
                isinstance(wrapper, dict)
                and wrapper.get("kind") == "attachment"
                and isinstance(wrapper.get("data"), dict)
                and wrapper["data"].get("repo") == repo
                and type(wrapper["data"].get("pr_number")) is int
                and wrapper["data"].get("pr_number") == pr_number
                and wrapper["data"].get("head_sha") == archive.get("head_sha")
                and wrapper["data"].get("round_id") == archive.get("round_id")
                for wrapper in archive["attachment_records"]
            )
            for archive in archives
        )
        attachment_access_allowed = (
            state.get("status") in {"testing", "succeeded", "failed"}
            or has_evidence_history
        )
        render_state.update(
            evidence_enabled=bool(backend_ready and attachment_access_allowed),
            browser_upload_ready=bool(browser_upload_ready),
            evidence_readiness=status,
            enabled=bool(backend_ready and attachment_access_allowed),
            pr_state=pr.get("state"),
            merged=bool(pr.get("merged")),
            attachments=current_rows,
        )
        round_numbers = trusted_round_numbers(records, state, repo, pr_number)
        if current_round not in round_numbers and state.get("status") in {"testing", "succeeded", "failed"}:
            if not archives:
                round_numbers[current_round] = 1
            else:
                max_archive_number = max(
                    (round_numbers.get(a.get("round_id"), 0) for a in archives if isinstance(a, dict)),
                    default=0,
                )
                if max_archive_number > 0:
                    round_numbers[current_round] = max_archive_number + 1
                else:
                    round_numbers[current_round] = len(archives) + 1
        verified_current_round = (
            state.get("status") in {"testing", "succeeded", "failed"}
            and current_round in round_numbers
        )
        if verified_current_round:
            # This display-only copy may use current authorized machine data
            # when a legacy current-round deployment row has no captured IP.
            render_state["deployments"] = self._enrich_deployments_for_render(
                state.get("deployments", []), repo,
            )
        if current_round in round_numbers:
            render_state["round_number"] = round_numbers[current_round]
        bundles = []
        seen_rounds = set()
        configured_public_base = getattr(self.config, "evidence_public_base_url", "")
        public_base_url = (configured_public_base
                           if is_stable_public_base_url(configured_public_base) else "")
        upload_public_base_url = (
            configured_public_base
            if is_evidence_ingress_url(configured_public_base) else ""
        )
        historical_cos_sign_budget = [24]
        from .evidence_auth import DOWNLOAD_PURPOSE, issue_capability

        # Reuse only long-lived COS URLs from the previous trusted lifecycle
        # projection. They are matched to their exact decoded object key and
        # checked for the configured HTTPS bucket host and COS signature fields.
        # Signed URLs remain ephemeral presentation data; they are never saved
        # into hidden state or evidence records.
        store = getattr(self.evidence_service, "store", None)
        cached_cos_urls = {}
        cached_cos_preview_urls = {}
        inferred_cos_download_urls = set()
        if backend_ready and store is not None:
            for match in re.finditer(r"<(?P<url>https://[^<>\s]+)>", previous_visible):
                candidate = match.group("url")
                try:
                    from urllib.parse import parse_qsl, unquote, urlsplit
                    parsed = urlsplit(candidate)
                    object_key = unquote(parsed.path.lstrip("/"))
                    q = dict(parse_qsl(parsed.query))
                    if q.get("response-content-disposition") == "inline":
                        cached_cos_preview_urls.setdefault(object_key, []).append(candidate)
                    else:
                        expiry = store.download_url_expiry(candidate, key=object_key)
                        if expiry is not None and expiry > cached_cos_urls.get(object_key, (0, ""))[0]:
                            cached_cos_urls[object_key] = (expiry, candidate)
                except (AttributeError, TypeError, ValueError):
                    continue

        async def stable_cos_url(
            object_key, filename, *, attachment_id=None, sign_budget=None,
            operation=None,
        ):
            """Return a verified long-lived Summary URL, or "".

            The projection channel is separate from browser downloads. For a
            ready attachment the caller supplies its persisted record, so the
            signer re-derives repo/PR/HEAD/round/attachment identity and
            re-verifies the COS content SHA256 before issuing a one-year URL
            that must pass ``download_url_expiry``. Lifecycle logs keep the
            narrower key-only path because they have no attachment identity.
            """
            if not backend_ready or store is None:
                return ""
            using_summary_signer = False
            if (operation is not None and attachment_id
                    and callable(getattr(store, "sign_summary_attachment", None))):
                sign = store.sign_summary_attachment
                using_summary_signer = True
            else:
                sign = getattr(store, "issue_projection_url", None)
            if not callable(sign):
                return ""
            cached = cached_cos_urls.get(object_key)
            now = int(time.time())
            if cached:
                checked_expiry = store.download_url_expiry(
                    cached[1], key=object_key, filename=filename,
                    attachment_id=attachment_id,
                )
                if checked_expiry is not None:
                    cached = (checked_expiry, cached[1])
                    cached_cos_urls[object_key] = cached
                    # Re-sign close to expiry so the Summary never shows a
                    # link that dies within its own projection window.
                    if checked_expiry - now > 30 * 24 * 60 * 60:
                        return cached[1]
                else:
                    cached = None
            if sign_budget is not None and sign_budget[0] <= 0:
                return cached[1] if cached and cached[0] > now else ""
            if sign_budget is not None:
                sign_budget[0] -= 1
            try:
                if using_summary_signer:
                    signed = await sign(
                        repo=repo, pr_number=pr_number, operation=operation,
                    )
                    candidate, expiry = signed["url"], signed["expires_at"]
                else:
                    candidate = await store._io(
                        sign, key=object_key, filename=filename,
                        attachment_id=attachment_id,
                    )
                    expiry = store.download_url_expiry(
                        candidate, key=object_key, filename=filename,
                        attachment_id=attachment_id,
                    )
                if expiry is not None and expiry > now:
                    cached_cos_urls[object_key] = (expiry, candidate)
                    return candidate
            except Exception as exc:
                logger.warning("COS evidence link refresh failed %s#%s exception=%s",
                               repo, pr_number, type(exc).__name__)
            # A transient signing failure must not erase a still-valid link,
            # including one inside the renewal window.
            if cached and cached[0] > now:
                return cached[1]
            return ""

        async def stable_cos_preview_url(
            object_key, filename, *, attachment_id, sign_budget=None,
            operation=None,
        ):
            """Return a validated long-lived inline media URL, or "".

            Images are inlined for direct display and videos for a clickable
            playback preview. Both are bound to the persisted attachment
            identity and checked by the same one-year projection window.
            """
            if not backend_ready or store is None:
                return ""
            text = str(filename or "")
            suffix = text.rsplit(".", 1)[-1].lower() if "." in text else ""
            if suffix not in {"png", "jpg", "jpeg", "gif", "webp", "mp4", "webm"}:
                return ""
            sign = getattr(store, "sign_summary_attachment", None)
            using_summary_signer = bool(operation is not None and callable(sign))
            if using_summary_signer:
                project, validate = sign, store.projection_inline_url_expiry
                images_only = False
            else:
                project = getattr(store, "issue_projection_preview_url", None)
                validate = getattr(store, "projection_preview_url_expiry", None)
                images_only = True
                if suffix not in {"png", "jpg", "jpeg", "gif", "webp"}:
                    return ""
            if not callable(project) or not callable(validate):
                return ""
            now = int(time.time())
            cached_candidates = cached_cos_preview_urls.get(object_key, [])
            for prev_url in cached_candidates:
                try:
                    checked_expiry = validate(
                        prev_url, key=object_key, filename=text,
                        attachment_id=attachment_id,
                    )
                except Exception:
                    checked_expiry = None
                if checked_expiry is not None and checked_expiry - now > 30 * 24 * 60 * 60:
                    return prev_url
            if sign_budget is not None and sign_budget[0] <= 0:
                return ""
            if sign_budget is not None:
                sign_budget[0] -= 1
            try:
                if using_summary_signer:
                    signed = await sign(
                        repo=repo, pr_number=pr_number, operation=operation,
                        inline=True,
                    )
                    candidate, expiry = signed["url"], signed["expires_at"]
                else:
                    candidate = await store._io(
                        project, key=object_key, filename=text,
                        attachment_id=attachment_id,
                    )
                    expiry = validate(
                        candidate, key=object_key, filename=text,
                        attachment_id=attachment_id,
                    )
            except Exception as exc:
                logger.warning("COS evidence preview refresh failed %s#%s exception=%s",
                               repo, pr_number, type(exc).__name__)
                return ""
            return candidate if expiry is not None and expiry > int(time.time()) else ""

        async def bind_download_capabilities(
            rows, head_sha, round_id, *, include_cos_urls=True,
            cos_sign_budget=None, legacy_signed_invite_identities=None,
        ):
            bound = []
            legacy_signed_invite_identities = legacy_signed_invite_identities or set()
            for row in rows:
                item = copy.deepcopy(row)
                for time_field in ("created_at", "uploaded_at"):
                    value = item.get(time_field)
                    if value is None:
                        continue
                    try:
                        parsed_time = datetime.fromisoformat(value.replace("Z", "+00:00"))
                    except (AttributeError, TypeError, ValueError):
                        item.pop(time_field, None)
                        continue
                    if parsed_time.tzinfo is None or parsed_time.utcoffset() is None:
                        item.pop(time_field, None)
                _, _, trusted_display_time = attachment_key_inputs(item)
                if trusted_display_time is None:
                    item.pop("created_at", None)
                    item.pop("uploaded_at", None)
                attachment_id = item.get("attachment_id")
                identity = (repo, pr_number, head_sha, round_id, attachment_id)
                operation = operation_records_by_identity.get(identity)
                valid_row = (
                    verified_evidence_row(
                        item, head_sha, round_id,
                        operation=operation,
                        archived_invite_provenance=(
                            identity in legacy_signed_invite_identities
                        ),
                    )
                    and item.get("head_sha") == head_sha
                    and item.get("round_id") == round_id
                    and item.get("status") == "ready"
                    and isinstance(item.get("sha256"), str)
                    and re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", "")) is not None
                )
                if valid_row:
                    valid_row = await cos_object_is_verified(
                        item, head_sha, round_id, operation,
                        archived_invite_provenance=(
                            identity in legacy_signed_invite_identities
                        ),
                    )
                if valid_row:
                    uploaded_at, filename, display_uploaded_at = attachment_key_inputs(item)
                    try:
                        from .evidence_store import build_attachment_key
                        expected_key = build_attachment_key(
                            repo, pr_number, head_sha, round_id, attachment_id,
                            uploaded_at, filename,
                        )
                    except (ValueError, TypeError, AttributeError):
                        valid_row = False
                    else:
                        valid_row = item.get("object_key") == expected_key
                        if valid_row:
                            if (not isinstance(item.get("filename"), str)
                                    or not item["filename"].strip()):
                                item["filename"] = filename
                            if display_uploaded_at is None:
                                # These fields are presentation timestamps; a
                                # path-derived date must never be presented as
                                # the real upload time.
                                item.pop("created_at", None)
                                item.pop("uploaded_at", None)
                item["cos_projection_verified"] = bool(valid_row)
                if valid_row:
                    # Render-only proof: the persisted ready records agreed
                    # and COS read-back matched the attachment SHA256.
                    item["cos_content_verified"] = True
                if (valid_row and isinstance(attachment_id, str)
                        and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", attachment_id)):
                    controller_download_compatible = False
                    created_at = item.get("created_at")
                    if (len(attachment_id_identities.get(attachment_id, set())) == 1
                            and isinstance(created_at, str)):
                        try:
                            created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                            if created.tzinfo is not None and created.utcoffset() is not None:
                                from .evidence_store import build_attachment_key
                                controller_download_compatible = (
                                    build_attachment_key(
                                        repo, pr_number, head_sha, round_id,
                                        attachment_id, created_at, filename,
                                    ) == expected_key
                                )
                        except (ValueError, TypeError, AttributeError):
                            controller_download_compatible = False
                    if controller_download_compatible:
                        item["download_capability"] = issue_capability(
                            self.config, repo, pr_number, head_sha, round_id,
                            purpose=DOWNLOAD_PURPOSE,
                            resource="attachment:" + attachment_id,
                        )
                    else:
                        # The Controller download API reconstructs object keys
                        # from created_at. For older records without that
                        # trusted timestamp, use the verified object key below.
                        item.pop("download_capability", None)
                    if include_cos_urls or not controller_download_compatible:
                        cos_url = await stable_cos_url(
                            expected_key, item.get("filename", ""),
                            attachment_id=attachment_id,
                            sign_budget=cos_sign_budget,
                            operation=operation,
                        )
                        if cos_url:
                            item["cos_download_url"] = cos_url
                            if not controller_download_compatible:
                                item["_projection_cos_fallback"] = True
                            if display_uploaded_at is None:
                                # The renderer needs a timestamp to reproduce
                                # the dated key. This render-only date is
                                # removed from the visible upload-time cell.
                                item["created_at"] = uploaded_at
                                item["_projection_date_only"] = True
                                inferred_cos_download_urls.add(cos_url)
                        else:
                            item.pop("cos_download_url", None)
                    else:
                        # Historical downloads resolve through the existing
                        # attachment-scoped API when clicked; do not sign every
                        # archived COS object on each Summary projection.
                        item.pop("cos_download_url", None)
                    # Temporary public ingress compatibility: when no stable
                    # Controller origin is available the Summary carries the
                    # validated COS link directly instead of dropping the
                    # already-verified attachment. Quick Tunnel URLs are never
                    # persisted here.
                    item.pop("cos_preview_url", None)
                    if (item.get("cos_download_url")
                            and not public_base_url):
                        preview_url = await stable_cos_preview_url(
                            expected_key, item.get("filename", ""),
                            attachment_id=attachment_id,
                            sign_budget=cos_sign_budget,
                            operation=operation,
                        )
                        if preview_url:
                            item["cos_preview_url"] = preview_url
                            inferred_cos_download_urls.add(preview_url)
                else:
                    item.pop("download_capability", None)
                    item.pop("cos_download_url", None)
                bound.append(item)
            return bound

        async def bind_log_url(target, head_sha, round_id):
            metadata = target.get("cos") if isinstance(target.get("cos"), dict) else {}
            if (not backend_ready or not isinstance(metadata, dict)
                    or not self._valid_cos_metadata(repo, pr_number, head_sha, metadata)):
                target.pop("cos_log_download_url", None)
                return
            object_key = metadata["object_key"]
            filename = object_key.rsplit("/", 1)[-1]
            # Lifecycle COS metadata is persisted only after the existing
            # upload verification. Reuse or sign a URL from that trusted record
            # without downloading historical logs again on every projection.
            url = await stable_cos_url(object_key, filename)
            if url:
                target["cos_log_download_url"] = url
            else:
                target.pop("cos_log_download_url", None)

        def remove_attachment_page_download_links(rendered):
            """Keep read-page links and inferred upload dates out of file rows."""
            if not isinstance(rendered, str):
                return rendered
            page_link = re.compile(
                r"\[([^\]]+)\]\(<https?://[^<>]*[?&]view=read(?:[&#][^<>]*)?>\)",
            )
            lines = []
            for line in rendered.split("\n"):
                if line.lstrip().startswith("|"):
                    if any(url in line for url in inferred_cos_download_urls):
                        cells = line.split("|")
                        if len(cells) >= 5:
                            cells[-2] = " 时间未记录 "
                            line = "|".join(cells)
                    line = page_link.sub(r"\1", line)
                lines.append(line)
            return "\n".join(lines)

        if backend_ready and attachment_access_allowed:
            render_state["capability"] = issue_capability(
                self.config, repo, pr_number, state["head_sha"], current_round,
                purpose=DOWNLOAD_PURPOSE, resource="page",
            )
            # The public upload entry is the permanent per-PR path; the upload
            # session itself is minted only when that page is opened and is
            # never stored in the Summary. No capability is projected here.
            render_state["log_capability"] = issue_capability(
                self.config, repo, pr_number, state["head_sha"], current_round,
                purpose=DOWNLOAD_PURPOSE, resource="log:" + current_round,
            )
        if backend_ready and attachment_access_allowed:
            current_rows = await bind_download_capabilities(current_rows, state["head_sha"], current_round)
            render_state["attachments"] = current_rows
            await bind_log_url(render_state, state["head_sha"], current_round)
            render_state["deployment_logs"] = self.evidence_service._trusted_deployment_logs(
                render_state, repo, pr_number, state["head_sha"], current_round,
            )
        trusted_archives = []
        testing_statuses = {"testing", "succeeded", "failed"}
        for archive in archives:
            if not isinstance(archive, dict):
                continue
            archive_round = archive.get("round_id")
            if not isinstance(archive_round, str):
                continue
            archive_head = archive.get("head_sha")
            snapshot_value = archive.get("snapshot")
            round_number = round_numbers.get(archive_round)
            if (type(round_number) is not int or round_number <= 0
                    or not isinstance(archive_head, str)
                    or not isinstance(snapshot_value, dict)
                    or snapshot_value.get("head_sha") != archive_head
                    or snapshot_value.get("status") not in testing_statuses
                    or archive_round == current_round):
                continue
            try:
                snapshot_round = round_id_for_state(snapshot_value)
            except Exception:
                continue
            if (snapshot_round != archive_round
                    or not archive_round.startswith(archive_head + "-")
                    or archive.get("repo") != repo
                    or type(archive.get("pr_number")) is not int
                    or archive.get("pr_number") != pr_number):
                continue
            trusted_archives.append(archive)

        for archive in trusted_archives:
            if archive["round_id"] in seen_rounds or archive["round_id"] == current_round:
                continue
            seen_rounds.add(archive["round_id"])
            snapshot = copy.deepcopy(archive["snapshot"])
            if backend_ready and attachment_access_allowed:
                snapshot["log_capability"] = issue_capability(
                    self.config, repo, pr_number, snapshot["head_sha"], archive["round_id"],
                    purpose=DOWNLOAD_PURPOSE, resource="log:" + archive["round_id"],
                )
                snapshot["deployment_logs"] = self.evidence_service._trusted_deployment_logs(
                    snapshot, repo, pr_number, archive["head_sha"], archive["round_id"],
                )
            snapshot["deployments"] = self._enrich_deployments_for_render(
                snapshot.get("deployments", []), repo, historical=True,
                historical_machine_groups=snapshot.get("machine_groups"),
            )
            archive_head = archive["head_sha"]
            archive_round = archive["round_id"]
            archive_attachment_rows = {}
            archive_deleted_rows = {}
            archive_attachment_wrappers = {}
            archive_operation_rows = {}
            archive_operation_wrappers = {}
            for wrapper in archive.get("attachment_records", []):
                if (not isinstance(wrapper, dict)
                        or wrapper.get("kind") not in {"attachment", "operation"}):
                    continue
                data = wrapper.get("data")
                if not isinstance(data, dict):
                    continue
                record_kind = wrapper["kind"]
                attachment_id = data.get("attachment_id")
                if (not isinstance(attachment_id, str)
                        or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", attachment_id) is None
                        or not isinstance(wrapper.get("key"), str)
                        or not isinstance(wrapper.get("sha256"), str)
                        or re.fullmatch(r"[0-9a-f]{64}", wrapper["sha256"]) is None
                        or data.get("repo") != repo
                        or type(data.get("pr_number")) is not int
                        or data.get("pr_number") != pr_number
                        or data.get("head_sha") != archive_head
                        or data.get("round_id") != archive_round):
                    continue
                identity = (repo, pr_number, archive_head, archive_round, attachment_id)
                if record_kind == "attachment":
                    # Archive wrappers were captured in read_evidence_records
                    # order, so overwriting mirrors EvidenceService Latest.
                    archive_attachment_rows[identity] = data
                    archive_attachment_wrappers[identity] = wrapper
                    if attachment_is_deleted(data):
                        archive_deleted_rows[identity] = data
                else:
                    archive_operation_rows[identity] = data
                    archive_operation_wrappers[identity] = wrapper

            def wrapper_matches_trusted_record(wrapper, kind):
                if not isinstance(wrapper, dict):
                    return False
                record = trusted_records_by_key.get((kind, wrapper.get("key")))
                return bool(
                    record is not None
                    and record.get("sha256") == wrapper.get("sha256")
                    and record.get("data") == wrapper.get("data")
                )

            def archived_invite_proof(identity, attachment_row):
                """Require paired, integrity-bound archive records for legacy invite rows."""
                attachment_wrapper = archive_attachment_wrappers.get(identity)
                operation_wrapper = archive_operation_wrappers.get(identity)
                operation = archive_operation_rows.get(identity)
                if (not wrapper_matches_trusted_record(attachment_wrapper, "attachment")
                        or not wrapper_matches_trusted_record(operation_wrapper, "operation")
                        or not isinstance(operation, dict)
                        or operation.get("status") != "ready"
                        or operation.get("upload_method") != "signed_invite"
                        or operation.get("upload_link_authorized") is not True
                        or operation.get("actor_verified") is not False
                        or operation.get("github_user_authenticated") is not False
                        or operation.get("actor") != "shared-link"
                        or operation.get("cos_content_verified") is not True
                        or attachment_row.get("upload_method") != "signed_invite"
                        or attachment_row.get("actor") != "shared-link"):
                    return False
                # Missing legacy fields are supplied only by the paired,
                # trusted operation record. Any present contradiction rejects
                # the compatibility path; absence itself is never a grant.
                for field, expected in (
                    ("upload_link_authorized", True),
                    ("actor_verified", False),
                    ("github_user_authenticated", False),
                    ("cos_content_verified", True),
                ):
                    if field in attachment_row and attachment_row[field] is not expected:
                        return False
                _, filename, _ = attachment_key_inputs(attachment_row)
                return all(
                    operation.get(field) == value
                    for field, value in (
                        ("repo", repo), ("pr_number", pr_number),
                        ("head_sha", identity[2]), ("round_id", identity[3]),
                        ("attachment_id", identity[4]),
                        ("object_key", attachment_row.get("object_key")),
                        ("filename", filename), ("size", attachment_row.get("size")),
                        ("sha256", attachment_row.get("sha256")),
                    )
                )

            snapshot_attachment_map = {}
            legacy_signed_invite_identities = set()
            identities = list(archive_attachment_rows)
            identities.extend(
                identity for identity in latest_by_identity
                if identity[:4] == (repo, pr_number, archive_head, archive_round)
            )
            identities = dict.fromkeys(identities)
            for identity in identities:
                archived_row = archive_attachment_rows.get(identity)
                selected = (
                    deleted_by_identity.get(identity)
                    or archive_deleted_rows.get(identity)
                    or latest_by_identity.get(identity)
                    or archived_row
                )
                if selected is None:
                    continue
                attachment_id = identity[4]
                snapshot_attachment_map[identity] = copy.deepcopy(selected)
                if (archived_row is not None and selected == archived_row
                        and archived_invite_proof(identity, selected)):
                    legacy_signed_invite_identities.add(identity)
            snapshot_attachments = list(snapshot_attachment_map.values())
            snapshot["attachments"] = (await bind_download_capabilities(
                snapshot_attachments, snapshot["head_sha"], archive["round_id"],
                # Prefer the scoped Controller download. Signed COS links are
                # a bounded fallback when no stable HTTPS Controller origin is
                # available for historical attachment downloads.
                include_cos_urls=not bool(public_base_url or upload_public_base_url),
                cos_sign_budget=historical_cos_sign_budget,
                legacy_signed_invite_identities=legacy_signed_invite_identities,
            ) if backend_ready and attachment_access_allowed else snapshot_attachments)
            # The archive's nested wrappers were reconciled with current
            # Latest records into this render-only snapshot. Do not let the
            # renderer append stale immutable revisions a second time.
            bundle = {
                key: value for key, value in archive.items()
                if key != "attachment_records"
            }
            bundle["snapshot"] = snapshot
            if archive.get("round_id") in round_numbers:
                bundle["round_number"] = round_numbers[archive["round_id"]]
            bundles.append(bundle)
        download_url_expiry = getattr(store, "download_url_expiry", None)
        def validate_cos_download_url(url, *, key, filename, attachment_id):
            if not callable(download_url_expiry):
                return None
            return download_url_expiry(
                url, key=key, filename=filename, attachment_id=attachment_id,
            )
        inline_url_expiry = getattr(store, "projection_inline_url_expiry", None)
        def validate_cos_inline_url(url, *, key, filename, attachment_id):
            if not callable(inline_url_expiry):
                return None
            return inline_url_expiry(
                url, key=key, filename=filename, attachment_id=attachment_id,
            )
        section = renderer(repo, pr_number, render_state, current_rows[-20:], bundles,
                           public_base_url=public_base_url,
                           upload_public_base_url=(
                               upload_public_base_url
                               if backend_ready and attachment_access_allowed else ""
                           ),
                           cos_download_url_expiry=validate_cos_download_url,
                           cos_inline_url_expiry=validate_cos_inline_url)
        if not isinstance(section, str):
            raise GitHubStateProxyError("Evidence renderer must return markdown")
        section = remove_attachment_page_download_links(section)
        # Refresh existing sections before removing duplicate top-level
        # presentation blocks. History and the old projection marker provide
        # safe boundaries for older Summaries whose deployment table is gone.
        visible = self._strip_legacy_evidence_blocks(visible)
        visible, history = self._extract_visible_history(visible)
        visible = self._strip_legacy_lifecycle_display_fields(
            visible,
            remove_current_deployment=verified_current_round or bool(trusted_archives),
        )
        start, end = "<!-- evidence-projection:start -->", "<!-- evidence-projection:end -->"
        def projection_body(rendered_section):
            projection = start + "\n" + rendered_section + "\n" + end
            result = visible.rstrip() + "\n\n" + projection
            if history:
                result += "\n\n" + history
            return result

        body = projection_body(section)
        if _count_visible_bytes(body) > _MAX_VISIBLE_LIFECYCLE_BYTES:
            # Compact the visible evidence projection to the current upload
            # entry. Evidence and archive records remain stored for read APIs.
            compact_current_rows = []
            for row in current_rows[-20:]:
                item = copy.deepcopy(row)
                if item.pop("_projection_date_only", False):
                    item.pop("created_at", None)
                    item.pop("uploaded_at", None)
                for field in (
                    "note", "text", "display_note", "display_note_complete",
                    "evidence_kind", "cos_download_url",
                ):
                    item.pop(field, None)
                compact_current_rows.append(item)
            compact_state = copy.deepcopy(render_state)
            compact_state["attachments"] = compact_current_rows
            compact_machines = sorted({
                deployment.get("machine") for deployment in render_state.get("deployments", [])
                if isinstance(deployment, dict)
                and deployment.get("phase") == "deployed"
                and isinstance(deployment.get("machine"), str)
            })
            compact_state["deployments"] = [
                {"machine": machine, "phase": "deployed"}
                for machine in compact_machines
            ]
            source_machine_logs = render_state.get("deployment_logs", {})
            compact_log_machines = {
                machine for machine, record in source_machine_logs.items()
                if isinstance(source_machine_logs, dict)
                and isinstance(machine, str) and isinstance(record, dict)
                and record.get("head_sha") == state["head_sha"]
                and record.get("round_id") == current_round
                and record.get("status") in {"pending", "ready", "unavailable"}
            } if isinstance(source_machine_logs, dict) else set()
            compact_state["deployment_logs"] = {
                machine: {
                    field: source_machine_logs[machine][field]
                    for field in ("head_sha", "round_id", "status", "capability")
                    if field in source_machine_logs[machine]
                }
                for machine in compact_log_machines
            }
            compact_state["_compact_projection"] = True
            compact_state["components"] = []
            compact_state["machine_groups"] = []
            compact_state["case_results"] = {}
            # Keep this render bound to the current HEAD and round without
            # carrying a display-only round number into the upload-only UI.
            compact_state.pop("round_number", None)
            compact_section = renderer(
                repo, pr_number, compact_state, compact_current_rows, bundles,
                public_base_url=public_base_url,
                upload_public_base_url=(
                    upload_public_base_url
                    if backend_ready and attachment_access_allowed else ""
                ),
                cos_download_url_expiry=validate_cos_download_url,
                cos_inline_url_expiry=validate_cos_inline_url,
            )
            if not isinstance(compact_section, str):
                raise GitHubStateProxyError(
                    "Compact Evidence renderer must return markdown",
                )
            compact_section = remove_attachment_page_download_links(compact_section)
            evidence_end = "<!-- deploy-approval-evidence:end -->"
            if compact_section.rfind(evidence_end) < 0:
                raise GitHubStateProxyError(
                    "Compact Evidence renderer omitted its end marker",
                )
            body = projection_body(compact_section)
            if _count_visible_bytes(body) > _MAX_VISIBLE_LIFECYCLE_BYTES:
                # Drop attachment rows if needed, while retaining the current
                # and archived round structure in the compact Summary.
                minimal_state = copy.deepcopy(compact_state)
                minimal_state["attachments"] = []
                minimal_section = renderer(
                    repo, pr_number, minimal_state, [], bundles,
                    public_base_url=public_base_url,
                    upload_public_base_url=(
                        upload_public_base_url
                        if backend_ready and attachment_access_allowed else ""
                    ),
                    cos_download_url_expiry=validate_cos_download_url,
                    cos_inline_url_expiry=validate_cos_inline_url,
                )
                if not isinstance(minimal_section, str):
                    raise GitHubStateProxyError(
                        "Minimal Evidence renderer must return markdown",
                    )
                minimal_section = remove_attachment_page_download_links(minimal_section)
                minimal_end = minimal_section.rfind(evidence_end)
                if minimal_end < 0:
                    raise GitHubStateProxyError(
                        "Minimal Evidence renderer omitted its end marker",
                    )
                body = projection_body(minimal_section)
                if _count_visible_bytes(body) > _MAX_VISIBLE_LIFECYCLE_BYTES:
                    raise GitHubStateProxyError(
                        "Evidence projection cannot fit the 48 KiB visible comment budget",
                    )
        return body

    async def project_evidence(self, repo: str, pr_number: int) -> None:
        """Watcher-only projection. HTTP handlers never call this writer."""
        if self.evidence_service is None:
            return
        pr = await self.proxy.get_pr(repo, pr_number)
        if (not isinstance(pr, dict) or pr.get("state") not in {"open", "closed"}
                or pr.get("draft")
                or pr.get("base", {}).get("repo", {}).get("full_name", "").lower() != repo.lower()):
            return
        comment = await self.proxy.find_trusted_lifecycle_comment(repo, pr_number)
        if comment is None:
            return
        body = comment.get("body", "")
        state = _extract_hidden_state(body)
        if state is None:
            raise GitHubStateProxyError("Evidence projection has no trusted state")
        if pr.get("head", {}).get("sha") != state.get("head_sha"):
            return
        from .github_state_proxy import HIDDEN_STATE_MARKER
        visible = body.split(HIDDEN_STATE_MARKER, 1)[0].rstrip()
        await self._write_lifecycle_with_history(
            repo, pr_number, state, visible, evidence_projection_only=True,
        )

    async def _write_lifecycle_with_history(
        self,
        repo: str,
        pr_number: int,
        state: dict,
        new_visible_markdown: str,
        event: dict | None = None,
        events: list[dict] | None = None,
        expected_record_test_state: dict | None = None,
        expected_terminal_state: dict | None = None,
        expected_record_test_comment: dict | None = None,
        expected_acceptance_state: dict | None = None,
        expected_acceptance_comment: dict | None = None,
        evidence_projection_only: bool = False,
        expected_lifecycle_state: dict | None = None,
        write_guard: Any | None = None,
        archive_reason: str = "Lifecycle snapshot replaced",
        runtime_projection_only: bool = False,
    ) -> bool:
        """Write lifecycle comment with automatic history management.

        If event is provided, it is appended to the visible History section.
        Legacy v1 migration is handled automatically on first meaningful event.
        Preserves existing History events across lifecycle rewrites.

        runtime_projection_only persists refreshed runtime scan results by
        replacing only the existing Next action inside the current Summary.
        It does not rebuild the Summary, recreate the Evidence Projection or
        normalize History, and it never appends a lifecycle event.
        """
        runtime_checks = state.get("runtime_checks", [])
        display_pr = None
        if isinstance(runtime_checks, list) and runtime_checks:
            try:
                display_pr = await self.proxy.get_pr(repo, pr_number)
            except Exception:
                display_pr = None
        if runtime_projection_only:
            from .github_state_proxy import HIDDEN_STATE_MARKER
            source_comment = await self.proxy.find_trusted_lifecycle_comment(
                repo, pr_number,
            )
            if (not isinstance(source_comment, dict)
                    or not isinstance(source_comment.get("id"), int)
                    or not isinstance(source_comment.get("body"), str)):
                return False
            source_body = source_comment["body"]
            hidden_index = source_body.find(HIDDEN_STATE_MARKER)
            if hidden_index < 0:
                return False
            source_visible = source_body[:hidden_index].rstrip("\n")
            # Replacing only the Next action keeps every other byte of the
            # current Summary (Status, Workflow, Evidence, History) intact.
            projected_visible = await self._render_runtime_checks_for_display(
                source_visible,
                runtime_checks if isinstance(runtime_checks, list) else [],
                state.get("components", []), repo, state.get("status", ""), display_pr,
            )
            before_bounds = comments_mod._next_action_body_bounds(source_visible)
            outside_changed = True
            if before_bounds is None:
                # No locatable Next action: the renderer must not have touched
                # anything at all, otherwise the write would rewrite sections
                # this path is not allowed to rebuild.
                outside_changed = projected_visible != source_visible
            else:
                source_prefix = source_visible[:before_bounds[0]]
                next_action_body = source_visible[before_bounds[0]:before_bounds[1]]
                source_suffix = source_visible[before_bounds[1]:]
                trailing = next_action_body[len(next_action_body.rstrip("\n")):]
                if projected_visible.startswith(source_prefix):
                    rest = projected_visible[len(source_prefix):]
                    rendered_body = None
                    if source_suffix and rest.endswith(source_suffix):
                        rendered_body = rest[:-len(source_suffix)]
                    elif source_suffix and rest.endswith(source_suffix.lstrip("\n")):
                        # First runtime insertion into a Summary that had no
                        # runtime marker consumes the blank line that keeps the
                        # next section on its own line. The suffix itself is
                        # otherwise untouched.
                        rendered_body = rest[:-len(source_suffix.lstrip("\n"))]
                    elif not source_suffix:
                        rendered_body = rest
                    if rendered_body is not None:
                        # Rebuild as original prefix + rendered Next action
                        # body + original trailing separator + original
                        # suffix. Every byte outside Next action is reused
                        # from the current Summary, never re-rendered.
                        if trailing and not rendered_body.endswith(trailing):
                            rendered_body = rendered_body.rstrip("\n") + trailing
                        projected_visible = (
                            source_prefix + rendered_body + source_suffix
                        )
                        outside_changed = False
            if outside_changed:
                # The renderer touched bytes outside Next action. Never persist
                # that; the next scan retries against a well-formed Summary.
                logger.warning(
                    "runtime image projection skipped: rendering would change "
                    "content outside Next action repo=%s pr=%s",
                    repo, pr_number,
                )
                return False
            async with self._evidence_lock:
                if expected_lifecycle_state is not None:
                    fresh_state = await self.proxy.read_hidden_state(repo, pr_number)
                    if fresh_state != expected_lifecycle_state:
                        return False
                current_pr = await self.proxy.get_pr(repo, pr_number)
                if (not isinstance(current_pr, dict)
                        or current_pr.get("state") != "open"
                        or current_pr.get("merged") or current_pr.get("draft")
                        or current_pr.get("head", {}).get("sha") != state.get("head_sha")):
                    return False
                written = await self.proxy.write_hidden_state(
                    repo, pr_number, projected_visible, state,
                    expected_comment=(source_comment["id"], source_body),
                )
                if not isinstance(written, dict):
                    raise GitHubStateProxyError(
                        "Lifecycle state write was not confirmed",
                    )
                return True
        new_visible_markdown = await self._render_runtime_checks_for_display(
            new_visible_markdown,
            runtime_checks if isinstance(runtime_checks, list) else [],
            state.get("components", []), repo, state.get("status", ""), display_pr,
        )
        archive_source = None
        projection_state_expected = copy.deepcopy(state) if evidence_projection_only else None
        async def write_if_current(visible: str) -> bool:
            async with self._evidence_lock:
                if expected_lifecycle_state is not None:
                    fresh_state = await self.proxy.read_hidden_state(repo, pr_number)
                    if fresh_state != expected_lifecycle_state:
                        return False
                if archive_source is not None:
                    # Capture the prior round once under the evidence lock,
                    # after the expected lifecycle state has been checked.
                    state["round_archive"] = await self._archive_round_unlocked(
                        repo, pr_number, archive_source, archive_reason,
                    )
                if expected_lifecycle_state is not None:
                    fresh_state = await self.proxy.read_hidden_state(repo, pr_number)
                    if fresh_state != expected_lifecycle_state:
                        return False
                # History/archive discovery also awaits GitHub. Recheck after all
                # of those awaits, immediately before a terminal record_test write.
                if expected_record_test_state is not None:
                    fresh = await self._revalidate_record_test_state(
                        repo, pr_number, expected_record_test_state,
                        "pass" if state.get("status") == "succeeded" else "fail",
                        expected_comment=expected_record_test_comment,
                    )
                    if fresh is None:
                        return False
                if expected_acceptance_state is not None:
                    fresh_pr = await self.proxy.get_pr(repo, pr_number)
                    fresh_state = await self.proxy.read_hidden_state(repo, pr_number)
                    expected_comment_id = expected_acceptance_comment.get("id")
                    fresh_command_comment = await self.proxy.get_comment(
                        repo, expected_comment_id,
                    )
                    expected_user = expected_acceptance_comment.get("user", {})
                    fresh_user = (fresh_command_comment.get("user", {})
                                  if isinstance(fresh_command_comment, dict) else {})
                    fresh_base = (fresh_pr.get("base", {})
                                  if isinstance(fresh_pr, dict) else {})
                    fresh_base_repo = (fresh_base.get("repo", {})
                                       if isinstance(fresh_base, dict) else {})
                    fresh_base_name = (fresh_base_repo.get("full_name", "")
                                       if isinstance(fresh_base_repo, dict) else "")
                    from .commands import parse_command
                    fresh_command = parse_command(
                        fresh_command_comment.get("body", "")
                        if isinstance(fresh_command_comment, dict) else ""
                    )
                    fresh_pr_head = (fresh_pr.get("head", {}).get("sha", "")
                                     if isinstance(fresh_pr, dict) else "")
                    api_base = self.config.github_api_url.rstrip("/")
                    if (not isinstance(fresh_pr, dict)
                            or fresh_pr.get("state") != "open"
                            or fresh_pr.get("merged") or fresh_pr.get("draft")
                            or not isinstance(fresh_base_name, str)
                            or fresh_base_name.casefold() != repo.casefold()
                            or fresh_pr_head != expected_acceptance_state.get("head_sha")
                            or fresh_state != expected_acceptance_state
                            or not isinstance(fresh_command_comment, dict)
                            or not isinstance(fresh_user, dict)
                            or fresh_command_comment.get("id") != expected_comment_id
                            or fresh_command_comment.get("url")
                            != f"{api_base}/repos/{repo}/issues/comments/{expected_comment_id}"
                            or fresh_command_comment.get("issue_url")
                            != f"{api_base}/repos/{repo}/issues/{pr_number}"
                            or fresh_command_comment.get("body") != expected_acceptance_comment.get("body")
                            or fresh_command_comment.get("created_at") != expected_acceptance_comment.get("created_at")
                            or fresh_command_comment.get("updated_at") != expected_acceptance_comment.get("updated_at")
                            or fresh_user.get("id") != expected_user.get("id")
                            or fresh_user.get("login") != expected_user.get("login")
                            or fresh_command.kind != "request_acceptance"
                            or self.proxy.is_bot_comment(fresh_command_comment)):
                        return False
                if expected_terminal_state is not None:
                    pr = await self.proxy.get_pr(repo, pr_number)
                    fresh = await self.proxy.read_hidden_state(repo, pr_number)
                    if (fresh != expected_terminal_state
                            or pr.get("head", {}).get("sha") != state.get("head_sha")
                            or pr.get("state") != "open" or pr.get("merged") or pr.get("draft")):
                        return False
                current_pr = await self.proxy.get_pr(repo, pr_number)
                if evidence_projection_only:
                    current_pr_valid = (
                        isinstance(current_pr, dict)
                        and current_pr.get("state") in {"open", "closed"}
                        and not current_pr.get("draft")
                        and current_pr.get("base", {}).get("repo", {}).get("full_name", "").lower()
                        == repo.lower()
                        and current_pr.get("head", {}).get("sha") == state.get("head_sha")
                    )
                else:
                    current_pr_valid = (
                        current_pr.get("state") == "open" and not current_pr.get("merged")
                        and not current_pr.get("draft")
                        and current_pr.get("head", {}).get("sha") == state.get("head_sha")
                    )
                if not current_pr_valid:
                    raise GitHubStateProxyError("Lifecycle PR context changed before write")
                current_comment = await self.proxy.find_trusted_lifecycle_comment(repo, pr_number)
                if ((comment is None) != (current_comment is None)
                        or (comment is not None and (
                            current_comment.get("id") != comment.get("id")
                            or current_comment.get("body") != comment.get("body")))):
                    raise GitHubStateProxyError("Lifecycle History changed before write")
                if expected_lifecycle_state is not None or write_guard is not None:
                    # Archiving awaited GitHub. Re-read the lifecycle CAS
                    # inputs and PR identity before replacing the comment.
                    if expected_lifecycle_state is not None:
                        fresh_state = await self.proxy.read_hidden_state(repo, pr_number)
                        if fresh_state != expected_lifecycle_state:
                            return False
                    final_pr = await self.proxy.get_pr(repo, pr_number)
                    final_base = final_pr.get("base", {}) if isinstance(final_pr, dict) else {}
                    final_base_repo = final_base.get("repo", {}) if isinstance(final_base, dict) else {}
                    final_pr_valid = (
                        isinstance(final_pr, dict)
                        and type(final_pr.get("number")) is int
                        and final_pr.get("number") == pr_number
                        and final_pr.get("state") == "open"
                        and not final_pr.get("merged")
                        and not final_pr.get("draft")
                        and final_pr.get("head", {}).get("sha") == state.get("head_sha")
                        and isinstance(final_base_repo, dict)
                        and isinstance(final_base_repo.get("full_name"), str)
                        and final_base_repo["full_name"].casefold() == repo.casefold()
                    )
                    if not final_pr_valid:
                        return False
                    final_comment = await self.proxy.find_trusted_lifecycle_comment(
                        repo, pr_number,
                    )
                    if ((comment is None) != (final_comment is None)
                            or (comment is not None and (
                                final_comment.get("id") != comment.get("id")
                                or final_comment.get("body") != comment.get("body")))):
                        return False
                if write_guard is not None:
                    # Archive creation can take several GitHub calls. Recheck
                    # the complete Review provenance after that wait and just
                    # before the lifecycle CAS so a superseded run cannot win.
                    guard_result = write_guard()
                    if inspect.isawaitable(guard_result):
                        guard_result = await guard_result
                    if guard_result is not True:
                        return False
                if evidence_projection_only:
                    current_state = await self.proxy.read_hidden_state(repo, pr_number)
                    if current_state != projection_state_expected:
                        raise GitHubStateProxyError(
                            "Lifecycle state changed before evidence projection write",
                        )
                    final_pr = await self.proxy.get_pr(repo, pr_number)
                    if (not isinstance(final_pr, dict)
                            or final_pr.get("state") not in {"open", "closed"}
                            or final_pr.get("draft")
                            or final_pr.get("base", {}).get("repo", {}).get("full_name", "").lower()
                            != repo.lower()
                            or final_pr.get("head", {}).get("sha") != state.get("head_sha")):
                        raise GitHubStateProxyError(
                            "Lifecycle PR context changed before evidence projection write",
                        )
                written = await self.proxy.write_hidden_state(
                    repo, pr_number, visible, state,
                    expected_comment=((comment.get("id"), comment.get("body"))
                                      if comment is not None else (None, None)),
                )
                if not isinstance(written, dict):
                    raise GitHubStateProxyError("Lifecycle state write was not confirmed")
                return True

        comment = await self.proxy.find_trusted_lifecycle_comment(repo, pr_number)
        if comment is not None:
            old = _extract_hidden_state(comment.get("body", ""))
            if old is None:
                raise GitHubStateProxyError("Cannot replace unreadable prior round")
            old = _validate_hidden_state(old)
            if (expected_lifecycle_state is not None
                    and old != expected_lifecycle_state):
                return False
            if evidence_projection_only:
                if old != state:
                    raise GitHubStateProxyError("Lifecycle state changed before evidence projection")
                projected = await self._render_evidence_projection(
                    repo, pr_number, old, new_visible_markdown,
                )
                if projected == new_visible_markdown:
                    return True
                return await write_if_current(projected)
            old_round = round_id_for_state(old)
            head_changed = old.get("head_sha") != state.get("head_sha")
            if "round_id" not in state and not head_changed:
                state["round_id"] = old_round
            round_changed = state.get("round_id") != old_round
            lost_fields = any(old.get(k) and not state.get(k) for k in
                              ("components", "deployments", "case_results", "review_evidence", "approve_attempts", "test_result"))
            lost_attempt = any(a not in state.get("approve_attempts", []) for a in old.get("approve_attempts", []))
            destructive = (head_changed or round_changed or lost_fields or lost_attempt
                           or (old.get("cos", {}).get("object_key") and any(
                               old["cos"].get(k) != state.get("cos", {}).get(k)
                               for k in ("object_key", "sha256", "size"))))
            if destructive:
                archive_source = copy.deepcopy(old)
                guarded_write = (
                    expected_lifecycle_state is not None or write_guard is not None
                )
                if not guarded_write:
                    # Preserve the original behavior for legacy lifecycle
                    # callers. Only guarded transitions defer archive capture.
                    state["round_archive"] = await self._archive_round(
                        repo, pr_number, old, archive_reason,
                    )
                if head_changed or (lost_fields and not round_changed):
                    state["round_id"] = make_round_id(state["head_sha"], state.get("command", {}).get("comment_id", 0))
                    state["round_started_at"] = utc_now()
                    state.pop("deployment_logs", None)
                    state.pop("acceptance_request", None)
            if "round_started_at" not in state and old.get("round_started_at") and not head_changed and not round_changed:
                state["round_started_at"] = old["round_started_at"]
        if comment is None:
            if evidence_projection_only or expected_lifecycle_state is not None:
                return False
            if events is not None:
                # Multiple events: newest-first; then insert existing fresh markdown
                built = new_visible_markdown
                for evt in reversed(events):
                    built = _insert_history_into_visible(built, evt)
                final_visible = built
            elif event is not None:
                final_visible = _insert_history_into_visible(new_visible_markdown, event)
            else:
                final_visible = new_visible_markdown
            return await write_if_current(final_visible)

        existing_body = comment.get("body", "")
        if not isinstance(existing_body, str):
            if events is not None:
                built = new_visible_markdown
                for evt in reversed(events):
                    built = _insert_history_into_visible(built, evt)
                final_visible = built
            elif event is not None:
                final_visible = _insert_history_into_visible(new_visible_markdown, event)
            else:
                final_visible = new_visible_markdown
            return await write_if_current(final_visible)

        from .github_state_proxy import HIDDEN_STATE_MARKER
        idx = existing_body.find(HIDDEN_STATE_MARKER)
        if idx < 0:
            if events is not None:
                built = new_visible_markdown
                for evt in reversed(events):
                    built = _insert_history_into_visible(built, evt)
                final_visible = built
            elif event is not None:
                final_visible = _insert_history_into_visible(new_visible_markdown, event)
            else:
                final_visible = new_visible_markdown
            return await write_if_current(final_visible)

        existing_visible = existing_body[:idx].rstrip()

        # Check if this is a legacy comment (missing new-format markers)
        # Only migrate a recognizable old Deploy Approval lifecycle. Transient
        # statuses such as "Deploying..." are not lifecycle documents.
        is_legacy = (
            VISIBLE_HISTORY_START_MARKER not in existing_visible
            and "### Workflow" not in existing_visible
            and "<!-- deploy-approval-agent -->" in existing_visible
            and "Deploy Approval" in existing_visible
            and ("**Status:**" in existing_visible or "### Deploy Approval" in existing_visible)
        )

        created_archives = []
        if is_legacy and (event is not None or events is not None):
            # First meaningful event on a legacy comment
            # 1. Preserve legacy visible markdown in an archive
            legacy_snapshot = existing_visible

            existing_comments = await self.proxy.get_issue_comments(repo, pr_number)
            archive = await self._ensure_history_archive(
                repo, pr_number, existing_comments,
                extra_text=(
                    "Legacy lifecycle snapshot preserved before history-enabled renderer migration.\n\n"
                    + legacy_snapshot
                ),
            )
            created_archives.append(archive)

        # Preserve the original event bytes, including fields the legacy parser
        # does not understand. Render only newly appended events.
        h_start = existing_visible.find(VISIBLE_HISTORY_START_MARKER)
        h_end = existing_visible.find(VISIBLE_HISTORY_END_MARKER)
        history_block = ""
        if h_start >= 0 or h_end >= 0:
            if (h_start < 0 or h_end <= h_start
                    or existing_visible.count(VISIBLE_HISTORY_START_MARKER) != 1
                    or existing_visible.count(VISIBLE_HISTORY_END_MARKER) != 1):
                raise GitHubStateProxyError("Cannot safely preserve malformed History markers")
            history_block = existing_visible[h_start:h_end + len(VISIBLE_HISTORY_END_MARKER)]
        elif event is not None or events:
            # Wrap unmarked legacy events when appending new History.
            old_history = re.search(r"(?ms)^### History[ \t]*\n.*?(?=^### |\Z)", existing_visible)
            if old_history:
                history_block = (VISIBLE_HISTORY_START_MARKER
                                 + old_history.group(0).partition("\n")[2]
                                 + VISIBLE_HISTORY_END_MARKER)
        else:
            # Projection-only rewrites also normalize a legacy unmarked History
            # section. Keep its original event text intact inside the wrapper.
            old_history = re.search(r"(?ms)^### History[ \t]*\n.*?(?=^### |\Z)", existing_visible)
            if old_history:
                folded = self._fold_history_content(
                    old_history.group(0).partition("\n")[2],
                )
                if folded:
                    history_block = (
                        VISIBLE_HISTORY_START_MARKER + "\n" + folded + "\n"
                        + VISIBLE_HISTORY_END_MARKER
                    )
        incoming = list(events) if events is not None else ([event] if event is not None else [])
        if incoming:
            new_block = _build_history_block(incoming)
            if history_block:
                def event_content(block):
                    content = block[
                        len(VISIBLE_HISTORY_START_MARKER):
                        -len(VISIBLE_HISTORY_END_MARKER)
                    ].strip("\n")
                    return self._unwrap_history_details(content)

                new_events_body = event_content(new_block).rstrip("\n")
                old_events_body = event_content(history_block).lstrip("\n")
                history_block = (
                    VISIBLE_HISTORY_START_MARKER
                    + "\n<details>\n<summary>History · 历史事件</summary>\n\n"
                    + new_events_body
                    + ("\n\n" + old_events_body if old_events_body else "")
                    + "\n\n</details>\n"
                    + VISIBLE_HISTORY_END_MARKER
                )
            else:
                history_block = new_block
        final_visible = new_visible_markdown.rstrip()
        if history_block:
            final_visible += "\n\n" + history_block + "\n"
        elif not incoming:
            # Retain an unmarked History section only when no marked block was
            # available to relocate above.
            old_history = re.search(r"(?ms)^### History[ \t]*\n.*?(?=^### |\Z)", existing_visible)
            if old_history:
                folded = self._fold_history_content(
                    old_history.group(0).partition("\n")[2],
                )
                if folded:
                    final_visible += (
                        "\n\n" + VISIBLE_HISTORY_START_MARKER + "\n"
                        + folded + "\n" + VISIBLE_HISTORY_END_MARKER
                    )

        if history_block:
            history_start = VISIBLE_HISTORY_START_MARKER
            history_end = VISIBLE_HISTORY_END_MARKER
            if (history_block.count(history_start) != 1
                    or history_block.count(history_end) != 1
                    or history_block.find(history_end) < history_block.find(history_start)):
                raise GitHubStateProxyError("Cannot safely normalize malformed History markers")
            history_body = history_block[
                history_block.find(history_start) + len(history_start):
                history_block.find(history_end)
            ]
            folded_history = self._fold_history_content(history_body)
            history_block = (
                history_start + "\n" + folded_history + "\n" + history_end
            )

        # Keep published archive links even if fresh discovery is unavailable.
        old_archives = re.search(r"(?ms)^### Archived history[ \t]*\n.*?(?=^### |\Z)", existing_visible)
        archives_block = old_archives.group(0).rstrip() if old_archives else ""
        archive_links = list(created_archives)
        try:
            existing_comments = await self.proxy.get_issue_comments(repo, pr_number)
            archive_links += self._discover_trusted_archive_links(
                existing_comments, repo, pr_number,
            )
        except Exception:
            pass
        seen_pages = set(re.findall(r"History Archive Page ([0-9]+)", archives_block))
        for archive in archive_links:
            if str(archive["page"]) in seen_pages:
                continue
            rendered = comments_mod._archives_link_block([archive])
            archives_block += ("\n" + rendered.split("\n", 2)[2]) if archives_block else rendered
            seen_pages.add(str(archive["page"]))
        if archives_block:
            h_start = final_visible.find("### History")
            if h_start >= 0:
                final_visible = final_visible[:h_start] + archives_block.rstrip() + "\n\n" + final_visible[h_start:]
            else:
                final_visible += "\n\n" + archives_block

        # Projection is supplied only from trusted independent records.
        final_visible = await self._render_evidence_projection(repo, pr_number, state, final_visible)
        return await write_if_current(final_visible)

    def _discover_trusted_archive_links(
        self, comments: list[dict], repo: str, pr_number: int,
    ) -> list[dict]:
        """Discover trusted History Archive comments from GitHub.

        Only accepts comments with both BOT_MARKER, the archive marker,
        AND GitHub App provenance via self.proxy.is_bot_comment().
        Never stores archive list in hidden state.
        Returns dicts with page and url for the archive link block.
        """
        from .comments import BOT_MARKER
        links: list[dict] = []
        seen_pages: set[int] = set()
        for c in comments:
            if not isinstance(c, dict):
                continue
            cbody = c.get("body", "")
            if not isinstance(cbody, str):
                continue
            # Must contain bot marker
            if BOT_MARKER not in cbody:
                continue
            # Must be authored by the configured GitHub App
            if not self.proxy.is_bot_comment(c):
                continue
            marker_prefix = f"{HISTORY_ARCHIVE_MARKER_PREFIX}{repo}:{pr_number}:"
            if marker_prefix not in cbody:
                continue
            # Extract page number
            try:
                after_prefix = cbody.split(marker_prefix, 1)[1]
                page_str = after_prefix.split(" -->", 1)[0].strip()
                page_num = int(page_str)
                if page_num <= 0 or page_num in seen_pages:
                    continue
                seen_pages.add(page_num)
            except (ValueError, IndexError):
                continue
            links.append({
                "page": page_num,
                "url": c.get("html_url", ""),
            })
        # Sort by page ascending
        links.sort(key=lambda x: x["page"])
        return links

    async def _supersede_head_drift(
        self, repo: str, pr_number: int, state: dict,
        new_head: str, comment_id: int, command_kind: str = "approve_deploy",
    ) -> None:
        """Handle HEAD drift by superseding the current deployment."""
        pr = await self.proxy.get_pr(repo, pr_number)
        if (pr.get("state") != "open" or pr.get("merged") or pr.get("draft")
                or not re.fullmatch(r"[0-9a-f]{40}", str(new_head))
                or pr.get("head", {}).get("sha") != new_head):
            return
        old_head = state.get("head_sha", "")
        old_status = state.get("status", "review-required")
        archived = await self._archive_round(
            repo, pr_number, copy.deepcopy(state), "HEAD changed",
        )
        pr = await self.proxy.get_pr(repo, pr_number)
        if (pr.get("state") != "open" or pr.get("merged") or pr.get("draft")
                or pr.get("head", {}).get("sha") != new_head):
            return
        state["status"] = "review-required"
        state["head_sha"] = new_head
        state["round_id"] = make_round_id(
            new_head, comment_id,
        )
        state.pop("acceptance_request", None)
        state["round_started_at"] = utc_now()
        state.pop("deployment_logs", None)
        state["review_evidence"] = {}
        state["components"] = []
        state["deployments"] = []
        state.pop("runtime_checks", None)
        state.pop("runtime_redeploy", None)
        state["approve_attempts"] = []
        state["approve_attempts_total"] = 0
        state["approve_attempts_truncated"] = False
        state["case_results"] = {}
        state["test_result"] = ""
        state["cos"] = {"object_key": "", "sha256": "", "size": 0}
        state["round_archive"] = archived
        state["command"] = {
            "comment_id": comment_id,
            "kind": command_kind,
            "phase": "completed",
            "args": {"superseded": True},
        }
        state["last_processed_comment_id"] = comment_id

        markdown = comments_mod.superseded_comment(
            repo, pr_number, old_head, new_head,
        )
        event = {
            "event": "HEAD drift detected",
            "lifecycle": f"`{old_status}` \u2192 `review-required`",
            "timestamp": comments_mod.beijing_now_str(),
        }
        await self._write_lifecycle_with_history(
            repo, pr_number, state, markdown, event=event,
        )
        await self.proxy.project_status_label(repo, pr_number, "review-required")
        await self._post_command_reply(
            repo, pr_number, comment_id,
            "PR 有了新提交，之前的审核和审批已不再对应当前代码，这次命令没有执行。",
            topic="pr-head-updated", error=True,
        )

    async def _invalidate_review_required(
        self,
        repo: str,
        pr_number: int,
        state: dict,
        head_sha: str,
        comment_id: int,
        reason: str,
    ) -> None:
        """Invalidate the current validation snapshot and return to review-required."""
        pr = await self.proxy.get_pr(repo, pr_number)
        if (pr.get("state") != "open" or pr.get("merged") or pr.get("draft")
                or not re.fullmatch(r"[0-9a-f]{40}", str(head_sha))
                or pr.get("head", {}).get("sha") != head_sha):
            return
        head_changed = state.get("head_sha") != head_sha
        archived = None
        if head_changed:
            archived = await self._archive_round(
                repo, pr_number, copy.deepcopy(state), "HEAD changed",
            )
            pr = await self.proxy.get_pr(repo, pr_number)
            if (pr.get("state") != "open" or pr.get("merged") or pr.get("draft")
                    or not re.fullmatch(r"[0-9a-f]{40}", str(head_sha))
                    or pr.get("head", {}).get("sha") != head_sha):
                return
        state["status"] = "review-required"
        if head_changed:
            state["head_sha"] = head_sha
            state["round_id"] = make_round_id(head_sha, comment_id)
            state["round_started_at"] = utc_now()
            state.pop("deployment_logs", None)
            state["round_archive"] = archived
            state.pop("acceptance_request", None)
        state["review_evidence"] = {}
        state["components"] = []
        state["deployments"] = []
        state["approve_attempts"] = []
        state["approve_attempts_total"] = 0
        state["approve_attempts_truncated"] = False
        state["case_results"] = {}
        state["test_result"] = ""
        state["cos"] = {"object_key": "", "sha256": "", "size": 0}
        state["command"] = {
            "comment_id": comment_id,
            "kind": "approve_deploy",
            "phase": "completed",
            "args": {"reason": reason},
        }
        state["last_processed_comment_id"] = comment_id

        markdown = comments_mod.review_required(repo, pr_number, head_sha)
        event = {
            "event": reason,
            "lifecycle": "`deploy-requested` \u2192 `review-required`",
            "timestamp": comments_mod.beijing_now_str(),
        }
        await self._write_lifecycle_with_history(
            repo, pr_number, state, markdown, event=event,
        )
        await self.proxy.project_status_label(repo, pr_number, "review-required")
        await self._post_command_reply(
            repo, pr_number, comment_id,
            "部署前的最终检查发现当前代码或审核结果已经变化，这次没有发出部署请求。",
            topic="predeploy-validation-invalidated", error=True,
        )

    async def _current_testing_upload_url(
        self, repo: str, pr_number: int, *, head_sha: str, round_id: str,
        approval_comment_id: int,
    ) -> str:
        """Return the permanent per-PR upload address while this round tests.

        The address depends only on the configured stable origin, the repository
        and the PR number. It never embeds HEAD, round, expiry or a capability:
        authority is minted by the page from trusted GitHub state. The trusted
        Summary must already advertise that entry; a legacy ``?cap=`` reference
        is still accepted for compatibility but is never returned.
        """
        try:
            pr = await self.proxy.get_pr(repo, pr_number)
            state = await self.proxy.read_hidden_state(repo, pr_number)
            base = pr.get("base", {}) if isinstance(pr, dict) else {}
            base_repo = base.get("repo", {}) if isinstance(base, dict) else {}
            full_name = base_repo.get("full_name") if isinstance(base_repo, dict) else None
            if (not isinstance(pr, dict) or pr.get("state") != "open"
                    or pr.get("merged") or pr.get("draft")
                    or not isinstance(full_name, str)
                    or full_name.casefold() != repo.casefold()
                    or (pr.get("head") or {}).get("sha") != head_sha
                    or not isinstance(state, dict)
                    or state.get("status") != "testing"
                    or state.get("head_sha") != head_sha
                    or round_id_for_state(state) != round_id):
                return ""
            command = state.get("command", {})
            command_is_approval = (
                isinstance(command, dict)
                and command.get("kind") == "approve_deploy"
                and command.get("comment_id") == approval_comment_id
            )
            acceptance = state.get("acceptance_request", {})
            command_is_pending_acceptance = (
                isinstance(command, dict)
                and command.get("kind") == "request_acceptance"
                and command.get("comment_id") == approval_comment_id
                and isinstance(acceptance, dict)
                and acceptance.get("status") == "pending"
                and acceptance.get("head_sha") == head_sha
                and acceptance.get("round_id") == round_id
            )
            if not (command_is_approval or command_is_pending_acceptance):
                return ""

            try:
                from .evidence_auth import UPLOAD_PURPOSE, readiness, verify_capability
            except Exception:
                return ""
            evidence_status = readiness(self.config, self.evidence_service)
            store = getattr(self.evidence_service, "store", None)
            if (not isinstance(evidence_status, dict)
                    or evidence_status.get("EVIDENCE_BACKEND_READY") is not True
                    or evidence_status.get("PUBLIC_HTTPS_INGRESS_READY") is not True
                    or not callable(getattr(store, "dispatch", None))):
                return ""

            configured_origin = str(
                getattr(self.config, "evidence_public_base_url", "") or "",
            ).rstrip("/")
            if not is_evidence_ingress_url(configured_origin):
                return ""
            page_path = comments_mod._evidence_path(repo, pr_number).replace(
                "/api/evidence/", "/evidence/", 1,
            )
            if not page_path.startswith("/evidence/"):
                return ""
            fixed_url = configured_origin + page_path

            comment = await self.proxy.find_trusted_lifecycle_comment(repo, pr_number)
            body = comment.get("body") if isinstance(comment, dict) else None
            if not isinstance(body, str):
                return ""
            from .github_state_proxy import HIDDEN_STATE_MARKER
            visible = body.split(HIDDEN_STATE_MARKER, 1)[0]
            embedded_state = _extract_hidden_state(body)
            if embedded_state != state:
                return ""
            link_match = re.search(
                r"(?m)^\[deploy-approval-upload\]:[ \t]*<(?P<url>https://[^<>\s]+)>[ \t]*$",
                visible,
            )
            if link_match is None:
                return ""
            candidate = comments_mod._trusted_upload_page_url(
                link_match.group("url"), repo, pr_number,
            )
            if not candidate:
                return ""
            parsed = urlsplit(candidate)
            configured_parts = urlsplit(configured_origin)
            if (parsed.scheme != "https"
                    or parsed.netloc.casefold() != configured_parts.netloc.casefold()):
                return ""
            if parsed.query:
                # Legacy Summary reference: verify it was minted for this exact
                # round, then hand out only the parameter-free permanent path.
                query = parse_qs(parsed.query, strict_parsing=True)
                values = query.get("cap")
                if set(query) != {"cap"} or not isinstance(values, list) or len(values) != 1:
                    return ""
                claims = verify_capability(
                    self.config, values[0], repo, pr_number,
                    purpose=UPLOAD_PURPOSE,
                )
                if (claims.get("head") != head_sha
                        or claims.get("round") != round_id
                        or claims.get("status") != "testing"):
                    return ""
            return fixed_url
        except Exception as exc:
            logger.warning("current testing upload link unavailable %s#%s exception=%s",
                           repo, pr_number, type(exc).__name__)
            return ""

    async def _post_bound_notice(
        self, repo: str, pr_number: int, *, head_sha: str, round_id: str,
        comment_id: int, topic: str, message: str,
        result: str | None = None,
        expected_command_kind: str = "",
        allow_bot_origin: bool = False,
        allow_missing_state: bool = False,
        reply_to: int | None = None,
    ) -> bool:
        """Post one command-bound public reply, confirming uncertain POSTs by readback."""
        if result is not None and result not in {"accepted", "rejected", "uncertain"}:
            return False
        if reply_to is not None and (not isinstance(reply_to, int) or reply_to <= 0):
            return False
        if (not isinstance(head_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", head_sha)
                or not isinstance(round_id, str)
                or not re.fullmatch(re.escape(head_sha) + r"-[0-9]+", round_id)
                or type(comment_id) is not int or comment_id <= 0):
            return False
        try:
            pr = await self.proxy.get_pr(repo, pr_number)
            state = await self.proxy.read_hidden_state(repo, pr_number)
            origin = await self.proxy.get_comment(repo, comment_id)
            comments = await self.proxy.get_issue_comments(repo, pr_number)
        except Exception as exc:
            logger.warning("notice preflight %s#%s failed: %s",
                           repo, pr_number, type(exc).__name__)
            return False
        api_base = self.config.github_api_url.rstrip("/")
        expected_issue_url = f"{api_base}/repos/{repo}/issues/{pr_number}"
        expected_comment_url = f"{api_base}/repos/{repo}/issues/comments/{comment_id}"
        if (not isinstance(pr, dict) or pr.get("state") != "open" or pr.get("merged")
                or pr.get("draft") or (pr.get("head") or {}).get("sha") != head_sha
                or not isinstance(origin, dict) or origin.get("id") != comment_id
                or origin.get("url") != expected_comment_url
                or origin.get("issue_url") != expected_issue_url
                or not isinstance(origin.get("created_at"), str)
                or origin.get("updated_at") != origin.get("created_at")
                or (self.proxy.is_bot_comment(origin) and not allow_bot_origin)
                or not isinstance(comments, list)):
            return False
        if isinstance(state, dict) and state.get("head_sha") == head_sha:
            if round_id_for_state(state) != round_id:
                return False
        elif (not allow_missing_state or expected_command_kind
              or round_id != make_round_id(head_sha, comment_id)):
            return False
        if expected_command_kind:
            command = state.get("command", {})
            if (not isinstance(command, dict)
                    or command.get("kind") != expected_command_kind
                    or command.get("comment_id") != comment_id):
                return False
        identity = "\0".join((repo, str(pr_number), head_sha, round_id,
                               str(comment_id), topic))
        marker = "<!-- deploy-approval-notice:v1:" + hashlib.sha256(
            identity.encode("utf-8"),
        ).hexdigest() + " -->"
        reply_marker = "<!-- deploy-approval-reply-to-comment:" + str(comment_id) + " -->"
        reply_marker_re = re.compile(
            r"<!--\s*deploy-approval-reply-to-comment:(\d+)\s*-->"
        )
        result_marker_re = re.compile(
            r"<!--\s*deploy-approval-result:([a-z-]+)\s*-->"
        )

        def found_marker(items):
            return next((item for item in items
                         if isinstance(item, dict)
                         and isinstance(item.get("body"), str)
                         and marker in item["body"]
                         and self.proxy.is_bot_comment(item)), None)

        def existing_final_result(items):
            bound = [
                item for item in items
                if isinstance(item, dict)
                and isinstance(item.get("body"), str)
                and self.proxy.is_bot_comment(item)
                and str(comment_id) in reply_marker_re.findall(item["body"])
            ]
            if not bound:
                return False, ""
            if len(bound) != 1:
                return True, ""
            body_value = bound[0]["body"]
            if (reply_marker_re.findall(body_value) != [str(comment_id)]):
                return True, ""
            results = result_marker_re.findall(body_value)
            if len(results) != 1 or results[0] not in {
                    "accepted", "rejected", "uncertain"}:
                return True, ""
            return True, results[0]

        notice_result = result
        has_final, existing_result = existing_final_result(comments)
        if has_final and result is not None:
            if not existing_result:
                self._record_command_reply_delivery(
                    repo, pr_number, comment_id, False,
                )
                return False
            if existing_result == result or (
                    existing_result == "uncertain" and result == "accepted"):
                # A source command may have only one terminal result marker.
                # Later completion topics remain deliverable, but cannot
                # replace an earlier result or add a second marker.
                notice_result = None
            else:
                self._record_command_reply_delivery(
                    repo, pr_number, comment_id, False,
                )
                return False
        existing_notice = found_marker(comments)
        if existing_notice and notice_result is None:
            self._record_command_reply_delivery(repo, pr_number, comment_id, True)
            return True
        payload = message.strip()
        if payload.startswith(comments_mod.BOT_MARKER):
            payload = payload[len(comments_mod.BOT_MARKER):].lstrip()
        if not payload:
            # Never publish a marker-only comment: a reply without text cannot
            # tell the developer what happened or what to do next.
            logger.warning("notice payload empty %s#%s topic=%s",
                           repo, pr_number, topic)
            return False
        body_parts = [comments_mod.BOT_MARKER]
        if not existing_notice:
            body_parts.append(marker)
        result_marker = (
            f"<!-- deploy-approval-result:{notice_result} -->"
            if notice_result else ""
        )
        if result_marker:
            body_parts.extend(("", reply_marker, result_marker))
        body_parts.extend(("", payload))
        body = "\n".join(body_parts)

        def is_delivered(items):
            if notice_result is None:
                return bool(found_marker(items))
            has_result, observed = existing_final_result(items)
            return has_result and observed == notice_result

        try:
            posted = await self.proxy.post_issue_comment(repo, pr_number, body)
        except Exception as post_error:
            # A lost response may still have created the comment. Read before
            # returning so a retry can never blindly duplicate the notice.
            try:
                latest = await self.proxy.get_issue_comments(repo, pr_number)
            except Exception as read_error:
                logger.warning("notice POST outcome unknown %s#%s topic=%s",
                               repo, pr_number, topic)
                self._record_command_reply_delivery(repo, pr_number, comment_id, False)
                return False
            delivered = bool(isinstance(latest, list) and is_delivered(latest))
            self._record_command_reply_delivery(repo, pr_number, comment_id, delivered)
            return delivered
        if isinstance(posted, dict) and posted.get("id"):
            body_value = posted.get("body", "")
            if not isinstance(body_value, str):
                body_value = ""
            marker_present = (
                notice_result is None and marker in body_value
                or notice_result is not None
                and reply_marker in body_value and result_marker in body_value
            )
            if marker_present and self.proxy.is_bot_comment(posted):
                self._record_command_reply_delivery(repo, pr_number, comment_id, True)
                return True
        try:
            latest = await self.proxy.get_issue_comments(repo, pr_number)
        except Exception:
            self._record_command_reply_delivery(repo, pr_number, comment_id, False)
            return False
        delivered = bool(isinstance(latest, list) and is_delivered(latest))
        self._record_command_reply_delivery(repo, pr_number, comment_id, delivered)
        return delivered

    async def _post_deploy_ready_notice(
        self, repo: str, pr_number: int, *, head_sha: str, round_id: str,
        review_evidence: dict, components: list[dict],
    ) -> bool:
        """Notify once for one freshly verified Review Agent result."""
        build_comment_id = review_evidence.get("build_comment_id")
        if type(build_comment_id) is not int or build_comment_id <= 0:
            return False
        event_fingerprint = hashlib.sha256(
            repr(sorted(self._review_evidence_identity(review_evidence).items())).encode(),
        ).hexdigest()
        notice_identity = "\0".join((
            repo, str(pr_number), head_sha, round_id, "deploy-ready",
            str(build_comment_id), event_fingerprint,
        ))
        marker = "<!-- deploy-approval-notice:v1:" + hashlib.sha256(
            notice_identity.encode("utf-8"),
        ).hexdigest() + " -->"

        async def context_is_current() -> bool:
            try:
                pr = await self.proxy.get_pr(repo, pr_number)
                state = await self.proxy.read_hidden_state(repo, pr_number)
            except Exception:
                return False
            if not isinstance(pr, dict):
                return False
            base = pr.get("base", {}) if isinstance(pr, dict) else {}
            base_repo = base.get("repo", {}) if isinstance(base, dict) else {}
            head = pr.get("head")
            full_name = base_repo.get("full_name") if isinstance(base_repo, dict) else None
            if (pr.get("state") != "open"
                    or pr.get("merged") or pr.get("draft")
                    or pr.get("number") != pr_number
                    or not isinstance(head, dict) or head.get("sha") != head_sha
                    or not isinstance(full_name, str)
                    or full_name.casefold() != repo.casefold()
                    or not isinstance(state, dict)
                    or state.get("status") != "deploy-ready"
                    or state.get("head_sha") != head_sha
                    or round_id_for_state(state) != round_id
                    or not isinstance(state.get("review_evidence"), dict)
                    or self._review_evidence_identity(state.get("review_evidence", {}))
                    != self._review_evidence_identity(review_evidence)
                    or self._canonical_component_snapshot(state.get("components", []))
                    != self._canonical_component_snapshot(components)):
                return False
            return await self._fresh_review_evidence_matches_state(
                repo, pr_number, head_sha, review_evidence,
                expected_components=components,
            )

        def marker_exists(comments) -> bool:
            if not isinstance(comments, list):
                return False
            return any(
                isinstance(comment, dict)
                and isinstance(comment.get("body"), str)
                and marker in comment["body"]
                and self.proxy.is_bot_comment(comment)
                for comment in comments
            )

        if not await context_is_current():
            return False
        try:
            comments = await self.proxy.get_issue_comments(repo, pr_number)
        except Exception:
            return False
        if not isinstance(comments, list):
            return False
        if marker_exists(comments):
            return True
        # The trusted review may have changed while the marker read waited.
        if not await context_is_current():
            return False

        try:
            display_pr = await self.proxy.get_pr(repo, pr_number)
        except Exception:
            display_pr = None
        test_only = self._is_test_only_pr(display_pr)
        all_groups = self._get_machine_groups_for_components(components, repo)
        verified_groups = await self._machine_groups_verify_endpoints(
            all_groups, repo, components,
        )
        command_lines = await self._machine_notice_lines(
            verified_groups, repo, mention_owners=False, test_only=test_only,
            components=components,
        )
        required_ids = {
            component.get("component_id") for component in components
            if isinstance(component, dict) and isinstance(component.get("component_id"), str)
        }
        full_groups = [
            group for group in verified_groups if isinstance(group, dict)
            and group.get("approval_available") is True and required_ids
            and required_ids.issubset(set(group.get("component_ids", [])))
        ]
        message_lines = ["当前提交的构建和审核已经完成，可以开始部署审批。"]
        if command_lines:
            message_lines.extend(["可以按下面的机器命令审批：", *command_lines])
            if len(full_groups) == 1:
                message_lines.append(
                    "只有一台机器完整适配全部组件，也可以直接执行 `/approve_deploy`。",
                )
            elif len(full_groups) > 1:
                message_lines.append("有多台机器完整适配，请用上面的命令明确指定一台。")
            elif required_ids:
                message_lines.append("没有单台机器覆盖全部组件，请按上面的命令分批审批。")
        else:
            message_lines.extend(self._machine_blocking_summary(all_groups))
        message_lines.append("`/request_deploy` 是可选的，不是部署审批的前提。")
        body = "\n".join((comments_mod.BOT_MARKER, marker, "", *message_lines))
        if not await context_is_current():
            return False
        try:
            posted = await self.proxy.post_issue_comment(repo, pr_number, body)
        except Exception:
            try:
                latest = await self.proxy.get_issue_comments(repo, pr_number)
            except Exception:
                return False
            return bool(isinstance(latest, list) and marker_exists(latest))
        if (isinstance(posted, dict) and marker in posted.get("body", "")
                and self.proxy.is_bot_comment(posted)):
            return True
        try:
            latest = await self.proxy.get_issue_comments(repo, pr_number)
        except Exception:
            return False
        return bool(isinstance(latest, list) and marker_exists(latest))

    _PARSE_ERROR_REASONS = {
        "duplicate_argument": "同一个参数填写了不止一次，请只保留一个值。",
        "invalid_ip_format": "机器选择器的 IP 格式不正确。",
        "extra_parameter": "这条命令不接受多余的内容，请只发送命令本身。",
        "missing_machine_value": "机器选择器为空，请选择一个具体机器。",
        "missing_parameter": "命令缺少必填参数。",
        "invalid_parameter": "命令中的参数值不可用。",
        "unknown_argument": "命令包含不支持的参数。",
        "invalid_arguments": "命令参数格式不正确。",
        "parameter_error": "命令参数格式不正确。",
        "command_not_found": "无法识别这条部署审批命令。",
        "machine_not_unique": "这个机器选择器对应多台机器，请明确选择一台。",
        "machine_selector_not_found": "找不到你填写的机器。",
    }

    _TOPIC_REASONS = (
        ("head_changed", "PR 有了新提交，之前的审核和审批已不再对应当前代码。"),
        ("pr_head_updated", "PR 有了新提交，之前的审核和审批已不再对应当前代码。"),
        ("pr_merged", "这个 PR 已经合并，部署命令不再适用。"),
        ("pr_closed", "这个 PR 已经关闭，部署命令不再适用。"),
        ("pr_draft", "这个 PR 还是草稿，部署命令暂时不可用。"),
        ("machine_not_found", "找不到你填写的机器。"),
        ("permission_denied", "当前账号没有执行这项操作的权限。"),
        ("authorization", "当前账号没有执行这项操作的权限。"),
        ("permission", "当前账号没有执行这项操作的权限。"),
        ("machine_incompatible", "这台机器不能部署本次需要的组件。"),
        ("incompatible", "这台机器不能部署本次需要的组件。"),
        ("policy", "目前无法确认仓库的机器配置，因此不能安全执行这条命令。"),
        ("already_processed", "这一轮已经处理过这项操作。"),
        ("already_matches", "机器上已经在运行本轮批准的镜像，不需要重新部署。"),
        ("deployment_failed", "本次部署没有完成。"),
        ("github_timeout", "GitHub 请求暂时超时，当前无法确认命令结果；请先查看 PR Summary。"),
        ("deployment_interrupted", "部署过程已中断，结果仍在确认中；请勿重复审批。"),
        ("runtime_mismatch", "Driver 运行镜像与批准的目标不一致，部署没有开始。"),
        ("uncertain", "部署结果还在确认中，这次没有重复提交部署。"),
        ("already_in_progress", "部署正在进行中，这次没有重复提交部署。"),
        ("in_progress", "部署正在进行中，这次没有重复提交部署。"),
        ("preflight", "机器没有通过部署前的安全检查，部署没有继续。"),
        ("not_ready", "当前阶段还不能执行这项操作。"),
        ("state_unavailable", "目前无法确认机器运行状态。"),
        ("unavailable", "目前无法连接机器确认运行状态。"),
        ("not_running", "目标组件当前没有运行，暂时无法确认运行镜像。"),
        ("identity_changed", "机器身份或运行时的绑定发生了变化，暂时无法确认。"),
        ("review", "当前代码的审核或构建证据还不能确认。"),
        ("evidence", "当前代码的审核或构建证据还不能确认。"),
        ("comment_invalid", "这条命令已经失效，需要重新发送。"),
        ("revoked", "这条审批已经失效，需要重新审批。"),
        ("no_drift", "目前没有确认到需要重新部署的镜像差异。"),
        ("no_confirmed", "目前没有确认到需要重新部署的镜像差异。"),
        ("no_compatible", "目前没有可以部署这些组件的机器。"),
        ("request_deploy", "当前条件不允许创建部署申请。"),
        ("state_not_allowed", "当前阶段还不能执行这项操作。"),
    )

    # The watcher posts some rejections with only the command name in the
    # topic. Explain those in terms of the command the developer actually sent.
    _COMMAND_FALLBACK_REASONS = (
        ("approve_deploy", "这次部署审批没有执行。"),
        ("request_deploy", "这次部署申请没有创建。"),
        ("request_acceptance", "这次验收申请没有提交。"),
        ("record_test", "这次验收结果没有记录。"),
    )

    _GENERIC_ERROR_REASON = "当前条件下无法执行这项操作。"
    _FAILURE_PREFIX = "这条命令没有执行。"

    @classmethod
    def _failure_lead(cls, reason: str) -> str:
        """Give every rejected command the same two-block user-facing shape."""
        text = reason.strip() if isinstance(reason, str) else ""
        if not text:
            text = cls._GENERIC_ERROR_REASON
        if text.startswith(cls._FAILURE_PREFIX):
            return text
        return f"{cls._FAILURE_PREFIX}\n\n原因：{text}"

    def _command_error_reason(
        self, *, command_kind: str = "", parsed_error: str = "",
        topic: str = "", message: str = "", exception: Exception | None = None,
    ) -> str:
        """Return one developer-readable Chinese reason for a failed command.

        This is the single error-to-text entry point. It never echoes internal
        error codes, exception types, stack traces, YAML/DB names, or the
        original command text.
        """
        topic_text = topic.casefold().replace("-", "_") if isinstance(topic, str) else ""
        message_text = message.casefold() if isinstance(message, str) else ""
        code_text = parsed_error if isinstance(parsed_error, str) else ""
        code = code_text.partition(":")[0].strip().casefold().replace("-", "_")
        category_match = re.search(
            r"(?:错误分类|error\s+category)\s*[:：]\s*`?([a-z][a-z0-9_-]*)",
            message if isinstance(message, str) else "", re.IGNORECASE,
        )
        category = (category_match.group(1).casefold().replace("-", "_")
                    if category_match else "")
        classification = code or category or (
            command_kind.casefold().replace("-", "_")
            if isinstance(command_kind, str) else ""
        )

        if classification == "duplicate_argument" and code_text.partition(":")[2].strip() == "machine":
            return "机器参数填写了两次，请保留一个机器 IP。"
        if classification in self._PARSE_ERROR_REASONS:
            return self._PARSE_ERROR_REASONS[classification]
        if exception is not None:
            # Exception type is diagnostic only; never expose its text.
            exception_text = type(exception).__name__.casefold()
            message_text = message_text or exception_text
        if category in self._PARSE_ERROR_REASONS:
            return self._PARSE_ERROR_REASONS[category]

        if _is_machine_not_found_error(message or "") or any(value in message_text for value in (
                "unknown machine alias", "no machine found", "machine not found")):
            return "找不到你填写的机器。"
        if any(value in message_text for value in (
                "permission denied", "not authorized", "not a machine owner",
                "insufficient collaborator", "无权限", "没有权限", "未获授权",
                "没有验收权限", "only the pr author", "only the", "cannot approve")):
            return "当前账号没有执行这项操作的权限。"
        if "test_reviewers" in message_text or "白名单" in message_text:
            if "没有有效的验收人白名单" in message_text:
                return "当前仓库还没有可用的验收账号。"
            return "当前账号没有记录验收结果的权限。"

        # A handler-supplied message that is already user-facing Chinese is
        # the most precise reason. Only its first line is kept so the
        # "correct operation" block always comes from lifecycle guidance.
        raw_message = message.strip() if isinstance(message, str) else ""
        forbidden = (
            "HEAD", "round", "Lifecycle", "lifecycle", "yaml", "YAML",
            "ZERO deploy POST", "MATCH", "MISMATCH", "UNAVAILABLE",
            "Owner：", "Traceback", "Exception", "数据库", "database",
            "/approve_deploy", "/request_deploy", "/request_acceptance",
            "/record_test", "machine=",
        )
        if raw_message and re.search(r"[\u4e00-\u9fff]", raw_message) \
                and not any(token in raw_message for token in forbidden):
            first_line = next(
                (line.strip() for line in raw_message.splitlines() if line.strip()),
                "",
            )
            if first_line:
                return first_line

        for prefix, reason in self._TOPIC_REASONS:
            if prefix in topic_text:
                return reason
        for prefix, reason in self._TOPIC_REASONS:
            if prefix in message_text:
                return reason

        if "incompatible" in message_text or "不兼容" in message_text or "does not match" in message_text:
            return "这台机器不能部署本次需要的组件。"
        if "head changed" in message_text or "head 已变化" in message_text:
            return "PR 有了新提交，之前的审核和审批已不再对应当前代码。"
        if "github" in message_text and any(token in message_text for token in ("timeout", "timed out", "超时")):
            return "GitHub 请求暂时超时，当前无法确认命令结果；请先查看 PR Summary。"
        if "runtime" in message_text and any(token in message_text for token in ("mismatch", "不一致", "duplicate", "unique")):
            return "Driver 运行镜像或 Runtime ID 与批准组件不匹配，部署没有开始。"
        if "interrupted" in message_text or "中断" in message_text:
            return "部署过程已中断，结果仍在确认中；请勿重复审批。"
        if "pr is not open" in message_text or "draft" in message_text:
            return "这个 PR 当前不可部署。"
        if not message_text and not code_text and not category:
            # The watcher identifies some rejections only by the command name;
            # keep the explanation rooted in what the developer actually sent.
            command_hint = topic_text or classification
            for command_name, reason in self._COMMAND_FALLBACK_REASONS:
                if command_name in command_hint:
                    return reason
        if not topic_text and not message_text and not code_text:
            return "这条命令当前不能执行。"
        return self._GENERIC_ERROR_REASON

    @staticmethod
    def _format_user_reply(lead: str, next_step: str = "") -> str:
        """Format every command reply as exactly two user-facing blocks.

        ``lead`` states what happened; ``next_step`` states what to do now.
        No headings, labels, internal values, or trailing explanations.
        """
        lead_text = lead.strip() if isinstance(lead, str) else ""
        next_text = next_step.strip() if isinstance(next_step, str) else ""
        lead_text = re.sub(r"\n{3,}", "\n\n", lead_text)
        next_text = re.sub(r"\n{3,}", "\n\n", next_text)
        if not lead_text:
            lead_text = "这条命令当前不能执行。"
        if not next_text:
            next_text = "请按 PR Summary 中当前显示的机器命令操作。"
        return f"{lead_text}\n\n{next_text}"

    async def _post_command_reply(
        self, repo: str, pr_number: int, comment_id: int, message: str,
        *, topic: str = "command-error", error: bool = False,
        final: bool = True, result: str | None = None,
    ) -> bool:
        """Bind an operation reply to the current PR HEAD, round, and source comment."""
        if not isinstance(comment_id, int) or comment_id <= 0:
            return False
        # Command replies always use the existing comment_id/result contract.
        final = True
        successful_topics = {
            "runtime-redeploy-request-created",
            "runtime-redeploy-already-target",
            "runtime-redeploy-already-matches",
            "deployment-requested-next-approver",
            "partial-deployment-next-approver",
            "deployment-complete-testing-next",
            "acceptance-requested",
            "test-result-recorded",
            "deployment-recovered-complete",
            "deployment-recovered-partial",
            "deploy-status",
            "deploy-help",
        }
        rejected_topic = topic not in successful_topics and (
            topic.startswith((
                "runtime-redeploy-", "request-deploy-", "approve-deploy-",
                "deployment-preflight-", "deployment-pr-", "deployment-head-",
                "machine-offline-", "approval-preflight-", "command-not-ready",
                "command-error-", "command-rejected-", "predeploy-validation-",
                "pr-head-updated", "evidence-link-deprecated",
            )) or topic in {
            "deployment-already-in-progress",
            "approve-deploy-already-processed",
            "record-test-already-processed",
            "deployment-pr-no-longer-open",
            "deployment-pr-check-unavailable",
            "deployment-head-check-unavailable",
            "deployment-failed",
            }
        )
        error = error or rejected_topic
        try:
            pr = await self.proxy.get_pr(repo, pr_number)
            state = await self.proxy.read_hidden_state(repo, pr_number)
        except Exception as exc:
            logger.warning("command reply context %s#%s unavailable: %s",
                           repo, pr_number, type(exc).__name__)
            self._record_command_reply_delivery(
                repo, pr_number, comment_id, False,
            )
            return False
        head = ((pr.get("head") or {}).get("sha")
                if isinstance(pr, dict) else "")
        if not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40}", head):
            self._record_command_reply_delivery(
                repo, pr_number, comment_id, False,
            )
            return False
        has_current_head_state = (
            isinstance(state, dict) and state.get("head_sha") == head
        )
        if has_current_head_state:
            round_id = round_id_for_state(state)
        else:
            # No persisted lifecycle round exists for the current HEAD. Bind
            # this rejected command to a deterministic event-scoped identity.
            round_id = make_round_id(head, comment_id)
        if error:
            if topic == "machine-offline-approval-preflight":
                guidance = await self._lifecycle_next_action_guidance(
                    repo, pr_number, detail=False,
                )
                message = self._format_user_reply(message, guidance)
            else:
                try:
                    origin = await self.proxy.get_comment(repo, comment_id)
                except Exception:
                    origin = None
                source_body = origin.get("body", "") if isinstance(origin, dict) else ""
                from .commands import parse_command
                parsed = parse_command(
                    source_body if isinstance(source_body, str) else "",
                    comment_id=comment_id,
                )
                parse_error = parsed.error or ""
                reason = self._command_error_reason(
                    command_kind=parsed.kind if isinstance(parsed.kind, str) else "",
                    parsed_error=parse_error,
                    topic=topic,
                    message=message,
                )
                guidance = await self._lifecycle_next_action_guidance(
                    repo, pr_number, detail=False,
                )
                message = self._format_user_reply(self._failure_lead(reason), guidance)
        else:
            guidance = await self._lifecycle_next_action_guidance(repo, pr_number)
            message = self._format_user_reply(message, guidance)
        if final:
            final_result = result
            if final_result not in {"accepted", "rejected", "uncertain"}:
                normalized_topic = topic.casefold().replace("_", "-")
                final_result = (
                    "uncertain" if any(value in normalized_topic for value in (
                        "uncertain", "outcome-unknown", "result-unknown",
                        "recovery-waiting", "deployment-interrupted",
                    )) else "rejected" if error else "accepted"
                )
            return await self._post_final_reply(
                repo, pr_number, comment_id, message, final_result,
                topic=topic,
            )
        try:
            delivered = await self._post_bound_notice(
                repo, pr_number, head_sha=head, round_id=round_id,
                comment_id=comment_id, topic=topic, message=message,
                allow_missing_state=not has_current_head_state,
            )
        except Exception as exc:
            logger.warning("command reply post %s#%s unavailable: %s",
                           repo, pr_number, type(exc).__name__)
            delivered = False
        self._record_command_reply_delivery(
            repo, pr_number, comment_id, delivered is True,
        )
        return delivered is True

    async def _post_final_reply(
        self, repo: str, pr_number: int, comment_id: int, message: str,
        result: str, *, qa: dict | None = None, topic: str = "command-error",
    ) -> bool:
        """Post a final command reply bound to the source comment with the Codex C contract markers."""
        if (result not in {"accepted", "rejected", "uncertain"}
                or not isinstance(comment_id, int) or comment_id <= 0):
            return False
        try:
            pr = await self.proxy.get_pr(repo, pr_number)
            origin = await self.proxy.get_comment(repo, comment_id)
            comments = await self.proxy.get_issue_comments(repo, pr_number)
        except Exception as exc:
            logger.warning("final command reply context %s#%s unavailable: %s",
                           repo, pr_number, type(exc).__name__)
            return False
        api_base = self.config.github_api_url.rstrip("/")
        expected_issue_url = f"{api_base}/repos/{repo}/issues/{pr_number}"
        expected_comment_url = f"{api_base}/repos/{repo}/issues/comments/{comment_id}"
        if (not isinstance(pr, dict) or pr.get("number") != pr_number
                or not isinstance(origin, dict) or origin.get("id") != comment_id
                or origin.get("url") != expected_comment_url
                or origin.get("issue_url") != expected_issue_url
                or not isinstance(comments, list)):
            return False
        if result == "rejected":
            try:
                labels = await self.proxy.get_issue_labels(repo, pr_number)
            except Exception as exc:
                labels = None
                logger.info("rejected command labels unavailable %s#%s reason=%s",
                            repo, pr_number, type(exc).__name__)
            from .commands import parse_command
            parsed = parse_command(
                origin.get("body", "") if isinstance(origin.get("body"), str) else "",
                comment_id=comment_id,
            )
            from .commands import detect_deployment_command_intent
            parse_error = parsed.error if isinstance(parsed.error, str) else ""
            if not parse_error and parsed.kind == "unknown":
                source = origin.get("body") or ""
                if detect_deployment_command_intent(source):
                    parse_error = "command_not_found"
            qa = self._final_reply_qa(
                pr, labels, topic, message, parse_error,
            )
        marker = "<!-- deploy-approval-reply-to-comment:" + str(comment_id) + " -->"
        result_marker = f"<!-- deploy-approval-result:{result} -->"

        def delivered(items) -> bool:
            if not isinstance(items, list):
                return False
            return any(
                isinstance(item, dict)
                and isinstance(item.get("body"), str)
                and marker in item["body"]
                and result_marker in item["body"]
                and self.proxy.is_bot_comment(item)
                for item in items
            )

        if delivered(comments):
            self._record_command_reply_delivery(repo, pr_number, comment_id, True)
            return True
        body_parts = [comments_mod.BOT_MARKER, "", marker, result_marker, message]
        if isinstance(qa, dict) and qa:
            body_parts.append("<!-- deploy-approval-qa:" + json.dumps(qa, ensure_ascii=False) + " -->")
        body = "\n".join(body_parts) + "\n"
        try:
            posted = await self.proxy.post_issue_comment(repo, pr_number, body)
        except Exception as exc:
            logger.warning("final command reply %s#%s unavailable: %s", repo, pr_number, type(exc).__name__)
            posted = None
        if (isinstance(posted, dict) and posted.get("id")
                and marker in str(posted.get("body", ""))
                and result_marker in str(posted.get("body", ""))
                and self.proxy.is_bot_comment(posted)):
            self._record_command_reply_delivery(repo, pr_number, comment_id, True)
            return True
        try:
            latest = await self.proxy.get_issue_comments(repo, pr_number)
        except Exception:
            self._record_command_reply_delivery(repo, pr_number, comment_id, False)
            return False
        delivered_reply = delivered(latest)
        self._record_command_reply_delivery(repo, pr_number, comment_id, delivered_reply)
        return delivered_reply

    @staticmethod
    def _visible_command_lines(message: str) -> list[str]:
        """Extract the executable commands actually shown in a reply body."""
        pattern = re.compile(
            r"(?<![A-Za-z0-9_])/(?:approve_deploy|request_deploy|request_bot_review|"
            r"record_test|request_acceptance|deploy_status|deploy_help)(?:[ \t]+[^\s`]+)*",
        )
        lines: list[str] = []
        for line in message.splitlines():
            lines.extend(
                match.group(0).strip().rstrip(".,;:，。；：")
                for match in pattern.finditer(line)
            )
        return lines

    def _final_reply_qa(
        self, pr: dict, labels, topic: str, message: str,
        parse_error: str = "",
    ) -> dict | None:
        """Build the hidden QA block for rejected final replies.

        ``next_commands`` mirrors exactly the commands shown in the visible
        reply; no internal codes leak to the visible text.
        """
        if not isinstance(pr, dict):
            return None
        label_list = [label for label in labels if isinstance(label, str)] \
            if isinstance(labels, list) else None
        status_labels = [label for label in label_list or []
                         if label.startswith("status:")]
        status = status_labels[0].split(":", 1)[1].strip() if len(status_labels) == 1 else "unknown"
        normalized_topic = re.sub(r"[^a-z0-9]+", "_", topic.casefold()).strip("_")
        normalized_parse_error = re.sub(
            r"[^a-z0-9]+", "_", parse_error.casefold(),
        ).strip("_")
        if normalized_parse_error:
            error_category = parse_error
        else:
            category_rules = (
                ("machine_offline", "machine_unavailable"),
                ("permission", "permission_denied"),
                ("head", "pr_head_changed"),
                ("policy", "machine_policy_unavailable"),
                ("incompatible", "machine_incompatible"),
                ("machine_selection", "machine_selection_required"),
                ("preflight", "deployment_preflight_failed"),
                ("runtime_redeploy", "runtime_image_mismatch"),
                ("uncertain", "deployment_outcome_uncertain"),
            )
            error_category = next((category for cue, category in category_rules
                                   if cue in normalized_topic),
                                  normalized_topic or "command_rejected")
        head_obj = pr.get("head", {})
        head_sha = str(head_obj.get("sha", "") or "") if isinstance(head_obj, dict) else ""
        if not re.fullmatch(r"[0-9a-f]{40}", head_sha):
            head_sha = ""
        visible_commands = self._visible_command_lines(message)
        return {
            "status": status or "unknown",
            "error": error_category,
            "head": head_sha,
            "labels": label_list,
            "next_commands": visible_commands,
        }

    @staticmethod
    def _is_test_only_pr(pr: dict | None) -> bool:
        title = pr.get("title", "") if isinstance(pr, dict) else ""
        return isinstance(title, str) and "[TEST ONLY]" in title.upper()

    @staticmethod
    def _acceptance_request_is_pending(state: dict | None) -> bool:
        """Report whether this round is waiting for an independent acceptance.

        ``request_acceptance`` stores the wait in ``acceptance_request`` while
        the Lifecycle status stays ``testing``; every reply must read both so
        the wait step never asks for a second ``/request_acceptance``.
        """
        if not isinstance(state, dict):
            return False
        request = state.get("acceptance_request")
        if (not isinstance(request, dict)
                or request.get("status") != "pending"
                or request.get("head_sha") != state.get("head_sha")):
            return False
        try:
            expected_round = round_id_for_state(state)
        except Exception:
            return False
        return request.get("round_id") == expected_round

    def _eligible_acceptance_reviewers(
        self, repo: str, pr: dict | None,
    ) -> tuple[bool, list[str]]:
        try:
            configured_reviewers = self.policy.reviewers_for_repo(repo)
        except Exception as exc:
            logger.warning("acceptance reviewer policy unavailable %s exception=%s",
                           repo, type(exc).__name__)
            return False, []
        valid_reviewers = []
        seen = set()
        for reviewer in configured_reviewers if isinstance(configured_reviewers, list) else []:
            if (not isinstance(reviewer, str)
                    or not _LOGIN_RE.fullmatch(reviewer.strip())
                    or reviewer.strip().casefold().endswith("[bot]")):
                continue
            key = reviewer.strip().casefold()
            if key in seen:
                continue
            seen.add(key)
            valid_reviewers.append(reviewer.strip())
        reviewers_configured = bool(valid_reviewers)
        if self._is_test_only_pr(pr):
            pr_user = pr.get("user", {}) if isinstance(pr, dict) else {}
            pr_author = (pr_user.get("login") or "").strip() if isinstance(pr_user, dict) else ""
            author_match = next((r for r in valid_reviewers if r.casefold() == pr_author.casefold()), None) if pr_author else None
            if author_match:
                return reviewers_configured, [author_match]
            return reviewers_configured, []
        return reviewers_configured, valid_reviewers

    def _acceptance_reviewer_guidance(
        self, repo: str, pr: dict | None, reviewers_configured: bool,
        eligible_reviewers: list[str],
    ) -> str:
        """Describe repo-scoped acceptance authorization in user-facing terms."""
        if self._is_test_only_pr(pr):
            try:
                configured_reviewers = self.policy.reviewers_for_repo(repo)
            except Exception:
                configured_reviewers = []
            valid_reviewers = []
            seen = set()
            for r in configured_reviewers if isinstance(configured_reviewers, list) else []:
                if isinstance(r, str) and _LOGIN_RE.fullmatch(r.strip()) and not r.strip().casefold().endswith("[bot]"):
                    k = r.strip().casefold()
                    if k not in seen:
                        seen.add(k)
                        valid_reviewers.append(r.strip())
            whitelist_display = " ".join(valid_reviewers) if valid_reviewers else "无"
            pr_user = pr.get("user", {}) if isinstance(pr, dict) else {}
            pr_author = (pr_user.get("login") or "").strip() if isinstance(pr_user, dict) else ""
            author_match = next((r for r in valid_reviewers if r.casefold() == pr_author.casefold()), None) if pr_author else None
            if author_match:
                return f"测试阶段验收由 @{author_match} 执行（当前仓库验收名单：{whitelist_display}）。"
            test_account_display = f"当前测试账号 {pr_author}" if pr_author else "当前 PR 作者"
            if not reviewers_configured:
                return f"当前仓库没有配置验收账号，{test_account_display} 没有验收权限。测试阶段不提醒其他账号。"
            return f"{test_account_display} 未在当前仓库验收名单中（当前验收名单：{whitelist_display}），没有验收权限。测试阶段不提醒其他账号。"
        if eligible_reviewers:
            return "验收由这些 GitHub 账号执行：" + " ".join(
                f"@{reviewer}" for reviewer in eligible_reviewers
            )
        if not reviewers_configured:
            return "目前没有可确认的验收账号，请联系仓库维护者检查验收名单。"
        return "当前验收名单中没有可用的 GitHub 账号，请联系仓库维护者检查验收名单。"

    _MACHINE_BLOCKING_GUIDANCE = (
        ("REPOSITORY_POLICY_MISSING",
         "仓库还没有可用的机器配置，暂时无法生成审批命令；请联系仓库维护者。"),
        ("MACHINE_NOT_AUTHORIZED",
         "机器还没有加入当前仓库的可用机器清单；请联系仓库维护者。"),
        ("MACHINE_IDENTITY_MISMATCH",
         "机器登记信息与机器实际身份不一致；请联系仓库维护者核对。"),
        ("OWNER_NOT_CONFIGURED",
         "机器还没有可用的负责人账号；请联系仓库维护者配置。"),
        ("AGENT_CORE_CREDENTIAL_MISSING",
         "机器还没有配置部署访问凭证；请联系仓库维护者处理。"),
        ("AGENT_CORE_UNAVAILABLE",
         "机器暂时无法连接，请稍后重试。"),
        ("AGENT_CORE_UNKNOWN",
         "机器连接状态还没有确认；审批时会先做一次只读检查。"),
        ("TARGET_UNSUPPORTED",
         "机器不支持本次部署的组件类型。"),
        ("PLATFORM_MISMATCH",
         "本次构建平台与机器不匹配。"),
        ("PLATFORM_UNVERIFIED",
         "构建平台或机器平台还没有确认。"),
        ("VARIANT_MISMATCH",
         "机器不支持本次组件的版本。"),
        ("DRIVER_PATH_MISMATCH",
         "机器不支持本次组件的驱动路径。"),
        ("PRIMARY_IP_AMBIGUOUS",
         "同一个主 IP 对应了多台机器，暂时无法安全选择。"),
    )

    def _machine_blocking_summary(self, groups: list[dict]) -> list[str]:
        """Explain why no approval command exists without dumping every machine."""
        if not groups:
            return ["暂时读取不到机器清单，因此没有生成审批命令。"]
        present: set[str] = set()
        for group in groups:
            if not isinstance(group, dict):
                continue
            for reason in group.get("blocking_reasons", []) or []:
                if isinstance(reason, str):
                    present.add(reason)
        if not present:
            return ["当前没有可以审批的兼容机器；请联系仓库维护者检查机器配置。"]
        lines = ["当前没有可以执行的审批命令："]
        for reason, guidance in self._MACHINE_BLOCKING_GUIDANCE:
            if reason in present:
                lines.append(f"- {guidance}")
        return lines

    @staticmethod
    def _component_summary_labels(
        component_ids: list, components: list[dict] | None,
    ) -> str:
        """Describe compatible components as ``target variant``; never dump ids."""
        by_id = {
            item.get("component_id"): item for item in components or []
            if isinstance(item, dict) and isinstance(item.get("component_id"), str)
        }
        labels: list[str] = []
        for component_id in component_ids if isinstance(component_ids, list) else []:
            component = by_id.get(component_id)
            if isinstance(component, dict):
                target = str(component.get("target", "") or "").strip()
                variant = str(component.get("variant", "") or "").strip()
                driver_path = str(component.get("driver_path", "") or "").strip()
                if target == "driver" and driver_path:
                    label = f"{target} {driver_path}"
                elif target and variant:
                    label = f"{target} {variant}"
                else:
                    label = target or component_id[:8]
            else:
                label = str(component_id)[:8]
            if label and label not in labels:
                labels.append(label)
        return "、".join(labels)

    async def _machine_notice_lines(
        self, groups: list[dict], repo: str, *, mention_owners: bool,
        test_only: bool = False, components: list[dict] | None = None,
        show_components: bool = True, pr: dict | None = None,
    ) -> list[str]:
        lines: list[str] = []
        seen_endpoint_commands: set[tuple[str, str, tuple[str, ...]]] = set()
        verified_groups = await self._machine_groups_verify_endpoints(
            groups if isinstance(groups, list) else [], repo, components,
        )
        for group in verified_groups:
            if (not isinstance(group, dict)
                    or group.get("approval_available") is not True
                    or not group.get("component_ids")):
                continue
            alias = str(group.get("alias", "") or "").strip()
            if not alias:
                continue
            primary_ip = self._canonical_primary_ipv4(group.get("primary_ip", ""))
            try:
                current_machine = self.policy.get_machine(alias, repo=repo)
            except Exception:
                current_machine = None
            if current_machine is None:
                continue
            group_ids = set(group.get("component_ids", []))
            required_ids = set(group.get(
                "required_component_ids", group_ids,
            ))
            group_components = [
                item for item in (components or [])
                if isinstance(item, dict) and item.get("component_id") in required_ids
            ]
            if (not group_components or not required_ids
                    or {item.get("component_id") for item in group_components}
                    != required_ids):
                continue
            verified_endpoints = group.get("verified_endpoints", [])
            verified_endpoints = [
                endpoint for endpoint in verified_endpoints
                if isinstance(endpoint, dict)
                and required_ids.issubset(set(endpoint.get("component_ids", [])))
            ]
            if not verified_endpoints:
                continue
            owners = group.get("owners", [])
            valid_owners = sorted({
                owner.strip() for owner in owners
                if isinstance(owner, str) and _LOGIN_RE.fullmatch(owner.strip())
                and not owner.strip().casefold().endswith("[bot]")
            }, key=str.casefold)
            can_mention_owners = (
                mention_owners
                and group.get("repo_authorized") is True
                and group.get("approval_available") is True
                and bool(group.get("component_ids"))
            )
            # Owner reminders belong only to a fresh /request_deploy notice.
            # deploy-ready keeps the machine commands; deploy-requested adds
            # exact @mentions of the configured machine Owners.
            if test_only:
                if can_mention_owners and valid_owners:
                    requester_note = (
                        "，请机器负责人 " + "、".join(valid_owners) + " 审批"
                    )
                elif valid_owners:
                    requester_note = f"（机器负责人：{' '.join(valid_owners)}）"
                else:
                    requester_note = ""
            else:
                if can_mention_owners and valid_owners:
                    requester_note = "，请 " + " ".join(f"@{owner}" for owner in valid_owners) + " 审批"
                elif valid_owners:
                    requester_note = f"（机器负责人：{' '.join(valid_owners)}）"
                else:
                    requester_note = ""
            for endpoint in verified_endpoints:
                endpoint_ip = self._canonical_primary_ipv4(endpoint.get("ip", ""))
                endpoint_ids = sorted(required_ids.intersection(
                    set(endpoint.get("component_ids", []))
                ))
                if not endpoint_ip or not endpoint_ids:
                    continue
                command_key = (alias, endpoint_ip, tuple(sorted(endpoint_ids)))
                if command_key in seen_endpoint_commands:
                    continue
                seen_endpoint_commands.add(command_key)
                endpoint_components = [
                    item for item in group_components
                    if item.get("component_id") in endpoint_ids
                ]
                component_label = (
                    self._component_summary_labels(endpoint_ids, endpoint_components)
                    if show_components else ""
                )
                component_note = f"，兼容组件：{component_label}" if component_label else ""
                address_label = str(endpoint.get("label", "") or "").strip()
                address_note = f"，地址用途：{address_label}" if address_label else ""
                primary_note = "，主 IP" if endpoint_ip == primary_ip else ""
                lines.append(
                    f"机器 `{alias}`（实际验证 IP：`{endpoint_ip}`{primary_note}）"
                    f"{address_note}{component_note}{requester_note}"
                )
                lines.append(f"`/approve_deploy machine={endpoint_ip}`")
        return lines

    @staticmethod
    def _runtime_transition_owner_labels(
        owners: list[str],
    ) -> list[str]:
        return sorted({
            owner.strip() for owner in owners
            if isinstance(owner, str) and _LOGIN_RE.fullmatch(owner.strip())
            and not owner.strip().casefold().endswith("[bot]")
        }, key=str.casefold)

    async def _approval_command_guidance(self, repo: str, pr_number: int, *, detail: bool = False) -> str:
        """Build executable approval guidance from the current trusted lifecycle."""
        try:
            pr = await self.proxy.get_pr(repo, pr_number)
            if (not isinstance(pr, dict) or pr.get("state") != "open"
                    or pr.get("merged") or pr.get("draft")):
                return "这个 PR 目前不能部署，审批命令暂时不可用。"
            head = pr.get("head", {}).get("sha", "")
            state = await self.proxy.read_hidden_state(repo, pr_number)
            if (not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40}", head)
                    or not isinstance(state, dict) or state.get("head_sha") != head):
                return "PR 的提交或部署进度已经变化，请等 PR Summary 更新后再操作。"
            status = state.get("status", "")
            if status not in {
                    "deploy-ready", "deploy-requested", "testing",
                    "succeeded", "failed"}:
                return "当前阶段还不能部署审批，请等 PR Summary 更新后再操作。"
            review_evidence = state.get("review_evidence")
            components = state.get("components")
            if (not isinstance(review_evidence, dict) or not isinstance(components, list)
                    or not await self._fresh_review_evidence_matches_state(
                        repo, pr_number, head, review_evidence,
                        expected_components=components,
                    )):
                return "当前提交的审核和构建结果还不能确认，请等 PR Summary 更新。"
            if status in {"testing", "succeeded", "failed"}:
                drift_commands = await self._runtime_drift_command_lines(state, repo)
                if drift_commands:
                    return "已确认运行镜像需要重新部署，请使用对应机器的审批命令：\n" + "\n".join(
                        f"`{command}`" for command in drift_commands
                    )
                checks = state.get("runtime_checks", [])
                unreadable = self._runtime_unreadable_lines(checks)
                if unreadable:
                    if not detail:
                        return (
                            "目前无法确认机器上的运行镜像，因此暂时不能判断是否需要重新部署。"
                            "请等待下一次状态检查，或联系机器负责人确认机器可以正常读取。"
                        )
                    return "\n".join([
                        "目前无法确认机器上的运行镜像，暂时不能判断是否需要重新部署。",
                        *unreadable,
                    ])
                return "机器上已经在运行本次批准的镜像，不需要重新部署。"
            if status == "deploy-requested" and state.get("runtime_redeploy"):
                drift_commands = await self._runtime_drift_command_lines(state, repo)
                if not drift_commands:
                    unreadable = self._runtime_unreadable_lines(
                        state.get("runtime_checks", []),
                    )
                    if unreadable:
                        if not detail:
                            return (
                                "目前无法确认机器的运行镜像，因此还不能生成重新审批命令。"
                                "请等待下一次状态检查，或联系机器负责人确认机器可以正常读取。"
                            )
                        return "\n".join([
                            "目前无法确认机器的运行镜像，因此还不能生成重新审批命令。",
                            *unreadable,
                        ])
                    return "目前还没有确认到需要重新部署的镜像差异，请等状态更新。"
                return "这台机器需要重新部署，请使用对应的审批命令：\n" + "\n".join(
                    f"`{command}`" for command in drift_commands
                )
            if status not in {"deploy-ready", "deploy-requested"}:
                return "当前阶段还不能部署审批，请等 PR Summary 更新后再操作。"
            deployed_ids = _component_id_set(state.get("deployments", []))
            remaining = [
                component for component in components
                if isinstance(component, dict)
                and component.get("component_id") not in deployed_ids
            ]
            groups = self._get_machine_groups_for_components(remaining, repo)
            command_lines = await self._machine_notice_lines(
                groups, repo, mention_owners=False,
                test_only=self._is_test_only_pr(pr), components=remaining,
            )
            if not command_lines:
                return "\n".join(self._machine_blocking_summary(groups))
            lines = ["可以执行的机器审批命令：", *command_lines]
            required_ids = {
                component.get("component_id") for component in remaining
                if isinstance(component, dict) and isinstance(component.get("component_id"), str)
            }
            full_groups = [
                group for group in groups
                if required_ids and required_ids.issubset(set(group.get("component_ids", [])))
            ]
            if status == "deploy-ready" and len(full_groups) == 1:
                lines.append("只有一台机器完整适配全部组件，也可以直接执行 `/approve_deploy`。")
            elif len(full_groups) > 1:
                lines.append("多台机器完整适配，请从上方选择对应的审批命令。")
            return "\n".join(lines)
        except Exception as exc:
            logger.warning("approval guidance unavailable %s#%s exception=%s",
                           repo, pr_number, type(exc).__name__)
            return "目前无法确认可用的机器，请先查看 PR Summary 再操作。"

    async def _lifecycle_next_action_guidance(
        self, repo: str, pr_number: int, *, detail: bool = True,
        _retry_count: int = 0,
    ) -> str:
        """Return next-step guidance from the current GitHub status label.

        Hidden lifecycle data supplies evidence and safety checks only. It never
        selects the requested lifecycle action.
        """
        status_unavailable = (
            "暂时无法确认最新流程进度，因此不能安全判断下一步。"
            "请等待 PR Summary 同步；确认前不要重复提交部署。"
        )
        status_sync_conflict = (
            "当前代码进度与可信部署记录暂时不一致，无法安全生成下一步操作。"
            "请等待 PR Summary 同步后再操作。"
        )
        tick = chr(96)

        def parse_status_labels(labels):
            status_labels = [
                label for label in labels
                if isinstance(label, str)
                and label.casefold().startswith(STATUS_PREFIX.casefold())
            ] if isinstance(labels, list) else []
            if (len(status_labels) != 1
                    or status_labels[0] not in _ALLOWED_STATUS_LABELS):
                return None
            label_status = status_labels[0]
            prefix, separator, lifecycle_status = label_status.partition(":")
            lifecycle_status = lifecycle_status.strip()
            if prefix + ":" != STATUS_PREFIX or not separator:
                return None
            return status_labels, label_status, lifecycle_status

        def log_status_conflict(candidate_state, candidate_label_status):
            hidden_status = candidate_state.get("status")
            if hidden_status != lifecycle_status:
                logger.error(
                    "SECURITY lifecycle status label conflicts with hidden state "
                    "%s#%s head=%s label=%r hidden_status=%r",
                    repo, pr_number, head, candidate_label_status,
                    str(hidden_status)[:80],
                )

        def deployment_safety_message(candidate_state):
            command = candidate_state.get("command")
            if not isinstance(command, dict) or command.get("kind") != "approve_deploy":
                return ""
            phase = command.get("phase")
            args = command.get("args")
            args = args if isinstance(args, dict) else {}
            if phase in {"executing", "uncertain"}:
                return (
                    "部署正在进行或结果仍在确认。请等待机器状态更新，"
                    "不要重复提交审批或部署请求。"
                )
            if phase == "completed" and args.get("preflight_pending") is True:
                return (
                    "部署前检查仍在进行，目前尚未发送部署请求。"
                    "请等待 PR Summary 更新，不要重复提交审批。"
                )
            return ""

        async def confirm_machine_guidance():
            final_pr = await self.proxy.get_pr(repo, pr_number)
            if (not isinstance(final_pr, dict) or final_pr.get("state") != "open"
                    or final_pr.get("merged") or final_pr.get("draft")):
                return "这个 PR 目前不能部署。请在 PR 保持开放、未合并且非草稿时再操作。"
            final_head = (final_pr.get("head") or {}).get("sha", "")
            final_labels = await self.proxy.get_issue_labels(repo, pr_number)
            final_snapshot = parse_status_labels(final_labels)
            if final_snapshot is None:
                return status_unavailable
            final_status_labels, final_label_status, final_lifecycle_status = final_snapshot
            if len(final_status_labels) != 1:
                return status_unavailable
            if final_head != head or final_lifecycle_status != lifecycle_status:
                if _retry_count < 1:
                    return await self._lifecycle_next_action_guidance(
                        repo, pr_number, detail=detail,
                        _retry_count=_retry_count + 1,
                    )
                return status_unavailable

            final_state = await self.proxy.read_hidden_state(repo, pr_number)
            if (not isinstance(final_state, dict)
                    or final_state.get("head_sha") != final_head):
                logger.error(
                    "SECURITY machine guidance hidden state changed or mismatched "
                    "%s#%s head=%s",
                    repo, pr_number, final_head,
                )
                return status_sync_conflict
            final_hidden_status = final_state.get("status")
            final_pending_acceptance = self._acceptance_request_is_pending(final_state)
            final_status_mapping_valid = (
                final_hidden_status == final_lifecycle_status
                or final_hidden_status == "testing"
                and final_lifecycle_status == "acceptance-required"
                and final_pending_acceptance
            )
            if not final_status_mapping_valid:
                logger.error(
                    "SECURITY lifecycle status label conflicts with hidden state "
                    "%s#%s head=%s label=%r hidden_status=%r",
                    repo, pr_number, final_head, final_label_status,
                    str(final_hidden_status)[:80],
                )
                return status_sync_conflict
            final_safety_message = deployment_safety_message(final_state)
            if final_safety_message:
                return final_safety_message

            business_keys = (
                "review_evidence", "components", "deployments",
                "runtime_redeploy", "runtime_checks", "command",
            )
            if any(final_state.get(key) != state.get(key) for key in business_keys):
                if _retry_count < 1:
                    return await self._lifecycle_next_action_guidance(
                        repo, pr_number, detail=detail,
                        _retry_count=_retry_count + 1,
                    )
                return status_sync_conflict
            if lifecycle_status in {"deploy-ready", "deploy-requested"}:
                components = final_state.get("components", [])
                if (not isinstance(components, list)
                        or not await self._fresh_review_evidence_matches_state(
                            repo, pr_number, final_head,
                            final_state.get("review_evidence", {}),
                            expected_components=components,
                        )):
                    return status_sync_conflict
                deployed_ids = _component_id_set(final_state.get("deployments", []))
                remaining = [item for item in components
                             if isinstance(item, dict)
                             and item.get("component_id") not in deployed_ids]
                fresh_groups = (
                    self._runtime_redeploy_machine_groups(
                        final_state, remaining, repo,
                    ) if final_state.get("runtime_redeploy") else
                    self._get_machine_groups_for_components(remaining, repo)
                )
                fresh_lines = await self._machine_notice_lines(
                    fresh_groups, repo,
                    mention_owners=lifecycle_status == "deploy-requested",
                    test_only=self._is_test_only_pr(final_pr),
                    components=remaining,
                    show_components=(detail and lifecycle_status == "deploy-ready"),
                    pr=final_pr,
                )
                fresh_commands = {
                    line for line in fresh_lines
                    if line.startswith(f"{tick}/approve_deploy")
                }
                old_commands = {
                    line for line in command_lines
                    if line.startswith(f"{tick}/approve_deploy")
                }
                if not fresh_commands:
                    return (
                        "当前没有通过最新 Policy 和设备身份确认的可执行机器命令。"
                        "请检查机器配置与 Feishu 设备快照后再操作。"
                    )
                if fresh_commands != old_commands or fresh_lines != command_lines:
                    if _retry_count < 1:
                        return await self._lifecycle_next_action_guidance(
                            repo, pr_number, detail=detail,
                            _retry_count=_retry_count + 1,
                        )
                    return status_sync_conflict
            if (lifecycle_status == "failed"
                    and not await self._runtime_drift_command_lines(final_state, repo)):
                return status_sync_conflict
            return ""

        try:
            pr = await self.proxy.get_pr(repo, pr_number)
            if (not isinstance(pr, dict) or pr.get("state") != "open"
                    or pr.get("merged") or pr.get("draft")):
                return "这个 PR 目前不能部署。请在 PR 保持开放、未合并且非草稿时再操作。"
            head = (pr.get("head") or {}).get("sha", "")
            if not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40}", head):
                return status_unavailable

            labels = await self.proxy.get_issue_labels(repo, pr_number)
            status_snapshot = parse_status_labels(labels)
            if status_snapshot is None:
                logger.warning(
                    "SECURITY lifecycle status labels are missing, ambiguous, or unknown "
                    "%s#%s count=%s",
                    repo, pr_number,
                    sum(1 for label in labels
                        if isinstance(label, str) and label.startswith("status:"))
                    if isinstance(labels, list) else "unavailable",
                )
                return status_unavailable
            status_labels, label_status, lifecycle_status = status_snapshot
            if len(status_labels) != 1:
                return status_unavailable

            state = await self.proxy.read_hidden_state(repo, pr_number)
            if not isinstance(state, dict):
                logger.error(
                    "SECURITY lifecycle status label has no usable hidden data "
                    "%s#%s head=%s label=%r",
                    repo, pr_number, head, label_status,
                )
                return status_sync_conflict

            # Re-read both GitHub sources after reading hidden data so that the
            # selected label and PR HEAD are current before building guidance.
            latest_pr = await self.proxy.get_pr(repo, pr_number)
            if (not isinstance(latest_pr, dict) or latest_pr.get("state") != "open"
                    or latest_pr.get("merged") or latest_pr.get("draft")):
                return "这个 PR 目前不能部署。请在 PR 保持开放、未合并且非草稿时再操作。"
            latest_head = (latest_pr.get("head") or {}).get("sha", "")
            if latest_head != head:
                logger.error(
                    "SECURITY lifecycle hidden data HEAD is stale %s#%s old_head=%s current_head=%s",
                    repo, pr_number, head, str(latest_head)[:40],
                )
                return status_sync_conflict
            latest_labels = await self.proxy.get_issue_labels(repo, pr_number)
            latest_snapshot = parse_status_labels(latest_labels)
            if latest_snapshot is None:
                logger.warning(
                    "SECURITY lifecycle status labels became unavailable "
                    "%s#%s",
                    repo, pr_number,
                )
                return status_unavailable
            status_labels, label_status, lifecycle_status = latest_snapshot
            if len(status_labels) != 1:
                return status_unavailable

            hidden_status = state.get("status")
            status_conflict = hidden_status != lifecycle_status
            status_mapping_valid = (
                not status_conflict
                or hidden_status == "testing"
                and lifecycle_status == "acceptance-required"
                and self._acceptance_request_is_pending(state)
            )
            if status_conflict:
                log_status_conflict(state, label_status)
            if not status_mapping_valid:
                return status_sync_conflict

            if state.get("head_sha") != head:
                logger.error(
                    "SECURITY lifecycle hidden state does not match current PR HEAD "
                    "%s#%s pr_head=%s state_head=%s",
                    repo, pr_number, head,
                    str(state.get("head_sha", ""))[:40],
                )
                return status_sync_conflict

            safety_message = deployment_safety_message(state)
            if safety_message:
                return safety_message

            if lifecycle_status == "review-required":
                guidance = (
                    "请由 PR 作者执行 "
                    f"{tick}/request_bot_review{tick}，然后等待审核和构建结果。"
                )
                confirmation = await confirm_machine_guidance()
                return confirmation or guidance

            if lifecycle_status == "reviewing":
                return (
                    "审核和镜像构建正在进行，请等待完成；暂时不要部署。"
                )

            if lifecycle_status in {"deploy-ready", "deploy-requested"}:
                review_evidence = state.get("review_evidence")
                components = state.get("components")
                if (not isinstance(review_evidence, dict)
                        or not isinstance(components, list) or not components):
                    return status_sync_conflict if status_conflict else (
                        "当前提交的审核和镜像构建证据暂时无法确认。"
                        "请等待 PR Summary 更新后再使用部署审批命令。"
                    )
                if not await self._fresh_review_evidence_matches_state(
                    repo, pr_number, head, review_evidence,
                    expected_components=components,
                ):
                    return status_sync_conflict if status_conflict else (
                        "当前提交的审核或镜像构建证据还在确认。"
                        "请等待 PR Summary 更新后再使用部署审批命令。"
                    )

                deployed_ids = _component_id_set(state.get("deployments", []))
                remaining = [
                    component for component in components
                    if isinstance(component, dict)
                    and component.get("component_id") not in deployed_ids
                ]
                if not remaining:
                    return (
                        "GitHub 状态标签要求机器审批，但部署记录显示没有待审批组件；"
                        "状态同步冲突，请等待 PR Summary 更新。"
                    )

                groups = (
                    self._runtime_redeploy_machine_groups(state, remaining, repo)
                    if state.get("runtime_redeploy") else
                    self._get_machine_groups_for_components(remaining, repo)
                )
                mention_owners = lifecycle_status == "deploy-requested"
                command_lines = await self._machine_notice_lines(
                    groups, repo, mention_owners=mention_owners,
                    test_only=self._is_test_only_pr(latest_pr),
                    components=remaining,
                    show_components=detail and lifecycle_status == "deploy-ready",
                    pr=latest_pr,
                )
                if not command_lines:
                    if status_conflict:
                        return status_sync_conflict
                    if not detail:
                        return (
                            "当前没有可确认兼容且有权限审批的机器命令。"
                            "请检查 PR Summary 和机器配置后再操作。"
                        )
                    return "\n".join(self._machine_blocking_summary(groups))

                commands_only = [
                    line for line in command_lines
                    if line.startswith(f"{tick}/approve_deploy")
                ]
                if not commands_only:
                    return status_sync_conflict

                if lifecycle_status == "deploy-ready":
                    remaining_ids = {
                        component.get("component_id") for component in remaining
                        if isinstance(component.get("component_id"), str)
                    }
                    full_groups = [
                        group for group in groups
                        if group.get("approval_available") is True
                        and remaining_ids
                        and remaining_ids.issubset(set(group.get("component_ids", [])))
                    ]
                    lines = ["请按目标机器执行对应审批命令：", *command_lines]
                    if len(full_groups) == 1:
                        lines.append(
                            f"只有一台机器完整适配所有组件，也可以直接执行 {tick}/approve_deploy{tick}。"
                        )
                    elif len(full_groups) > 1:
                        lines.append("有多台机器完整适配，请明确选择机器。")
                    elif remaining_ids:
                        lines.append("没有单台机器覆盖全部组件，请分批审批。")
                    lines.append(
                        f"{tick}/request_deploy{tick} 仍然可选，不是部署审批的前提。"
                    )
                    machine_guidance = "\n".join(lines)
                else:
                    machine_guidance = (
                        "以下机器尚未完成审批，请对应负责人执行：\n"
                        + "\n".join(command_lines)
                    )

                confirmation = await confirm_machine_guidance()
                return confirmation or machine_guidance

            if lifecycle_status == "deploying":
                return (
                    "部署正在进行，请等待结果，不要重复提交审批或部署。"
                )

            if lifecycle_status == "testing":
                components = state.get("components")
                required_ids = {
                    component.get("component_id") for component in components
                    if isinstance(component, dict)
                    and isinstance(component.get("component_id"), str)
                    and component.get("component_id")
                } if isinstance(components, list) else set()
                deployed_ids = _component_id_set(state.get("deployments", []))
                if (not required_ids or not required_ids.issubset(deployed_ids)
                        or state.get("runtime_redeploy")
                        or state.get("test_result") in {"pass", "fail"}):
                    logger.error(
                        "SECURITY testing status label is unsupported by deployment data "
                        "%s#%s head=%s label=%r",
                        repo, pr_number, head, label_status,
                    )
                    return status_sync_conflict
                upload_url = ""
                command = state.get("command", {})
                approval_comment_id = (
                    int(command.get("comment_id", 0) or 0)
                    if isinstance(command, dict) else 0
                )
                if approval_comment_id > 0:
                    upload_url = await self._current_testing_upload_url(
                        repo, pr_number, head_sha=head,
                        round_id=round_id_for_state(state),
                        approval_comment_id=approval_comment_id,
                    )
                upload_text = (
                    f"本轮稳定上传入口：{upload_url}。测试附件上传完全可选，不影响验收。"
                    if upload_url else
                    "测试附件上传完全可选，不影响验收；请使用本轮 PR Summary 显示的固定上传入口。"
                )
                if self._acceptance_request_is_pending(state):
                    guidance = (
                        f"{upload_text}验收申请已经提交，请等待验收结果。"
                    )
                    confirmation = await confirm_machine_guidance()
                    return confirmation or guidance
                guidance = (
                    f"可以开始测试。{upload_text}测试完成后执行 "
                    f"{tick}/request_acceptance{tick} 申请验收。"
                )
                confirmation = await confirm_machine_guidance()
                return confirmation or guidance

            if lifecycle_status == "acceptance-required":
                acceptance_pending = self._acceptance_request_is_pending(state)
                if (state.get("test_result") in {"pass", "fail"}
                        or status_conflict and not acceptance_pending):
                    logger.error(
                        "SECURITY acceptance-required status label is unsupported by acceptance data "
                        "%s#%s head=%s label=%r",
                        repo, pr_number, head, label_status,
                    )
                    return status_sync_conflict
                try:
                    _configured, reviewers = self._eligible_acceptance_reviewers(
                        repo, latest_pr,
                    )
                except Exception:
                    reviewers = []
                reviewer_text = (
                    "有权限验收的 GitHub 账号："
                    + "、".join(f"@{reviewer}" for reviewer in reviewers) + "。"
                    if reviewers else
                    "当前仓库还没有可用的验收账号，请联系仓库维护者配置。"
                )
                guidance = (
                    f"{reviewer_text}验收人检查本轮测试结果后执行 "
                    f"{tick}/record_test result=pass{tick} 或 "
                    f"{tick}/record_test result=fail{tick}。"
                )
                confirmation = await confirm_machine_guidance()
                if confirmation:
                    return confirmation
                try:
                    _, final_reviewers = self._eligible_acceptance_reviewers(
                        repo, latest_pr,
                    )
                except Exception:
                    final_reviewers = []
                if final_reviewers != reviewers:
                    return status_sync_conflict
                return guidance

            if lifecycle_status == "succeeded":
                if state.get("test_result") != "pass":
                    logger.error(
                        "SECURITY succeeded status label is unsupported by test data "
                        "%s#%s head=%s label=%r",
                        repo, pr_number, head, label_status,
                    )
                    return status_sync_conflict
                return "验收已经通过，可以按照仓库流程合并 PR。"

            if lifecycle_status == "failed":
                failure_detail = ""
                try:
                    lifecycle_comment = await self.proxy.find_trusted_lifecycle_comment(
                        repo, pr_number,
                    )
                    body = (
                        lifecycle_comment.get("body", "")
                        if isinstance(lifecycle_comment, dict) else ""
                    )
                    if isinstance(body, str):
                        match = re.search(r"(?m)^\*\*Error:\*\*\s*(.+)$", body)
                        if match:
                            candidate_detail = match.group(1).strip()
                            candidate_detail = next(
                                (line.strip() for line in candidate_detail.splitlines()
                                 if line.strip()),
                                "",
                            )
                            forbidden_detail = re.search(
                                r"(?i)(?:\b(?:exception|traceback|lifecycle|"
                                r"duplicate_argument|unknown_argument|error\s*code|"
                                r"status\s*code|[A-Z][A-Za-z0-9_]*(?:Error|Exception))\b|"
                                r"\b\d{3,}\b|/(?:approve_deploy|request_deploy|"
                                r"request_acceptance|record_test)\b|\bmachine\s*=)",
                                candidate_detail,
                            )
                            if (candidate_detail
                                    and re.search(r"[\u4e00-\u9fff]", candidate_detail)
                                    and forbidden_detail is None):
                                failure_detail = candidate_detail[:240]
                except Exception as exc:
                    logger.warning(
                        "failed lifecycle detail unavailable %s#%s: %s",
                        repo, pr_number, type(exc).__name__,
                    )

                if state.get("test_result") == "pass":
                    logger.error(
                        "SECURITY failed status label conflicts with passing test data "
                        "%s#%s head=%s label=%r",
                        repo, pr_number, head, label_status,
                    )
                    return status_sync_conflict

                if state.get("test_result") == "fail":
                    reason_text = (
                        f"本轮验收未通过：{failure_detail}。" if failure_detail
                        else "本轮验收未通过。"
                    )
                    return (
                        f"{reason_text}请按失败信息修复问题并更新 PR；"
                        "新提交需要重新审核和构建，之后按新的 PR Summary 重新部署和测试。"
                    )

                try:
                    commands = list(dict.fromkeys(
                        await self._runtime_drift_command_lines(state, repo),
                    ))
                except Exception:
                    commands = []
                reason_text = (
                    f"本轮部署失败：{failure_detail}。" if failure_detail
                    else "本轮部署失败。"
                )
                if commands:
                    if status_conflict and not failure_detail:
                        return status_sync_conflict
                    machine_guidance = (
                        f"{reason_text}请先按失败信息修复并确认机器可以正常读取，"
                        "然后由对应机器负责人执行以下重新部署审批命令：\n"
                        + "\n".join(f"- {tick}{command}{tick}" for command in commands)
                        + f"\n{tick}/request_deploy{tick} 是可选步骤。"
                    )
                    confirmation = await confirm_machine_guidance()
                    return confirmation or machine_guidance
                if status_conflict and not failure_detail:
                    return status_sync_conflict
                guidance = (
                    f"{reason_text}请先按失败信息修复并确认机器可以正常读取，"
                    "然后按 PR Summary 中当前可用的机器命令重新审批；"
                    f"{tick}/request_deploy{tick} 是可选步骤。"
                )
                confirmation = await confirm_machine_guidance()
                return confirmation or guidance

            return status_unavailable

        except Exception as exc:
            logger.warning(
                "lifecycle next-action guidance unavailable %s#%s: %s",
                repo, pr_number, type(exc).__name__,
            )
            return status_unavailable

    async def _project_status_best_effort(
        self, repo: str, pr_number: int, status: str,
    ) -> None:
        try:
            await self.proxy.project_status_label(repo, pr_number, status)
        except Exception as exc:
            logger.warning("status label projection %s#%s status=%s exception=%s",
                           repo, pr_number, status, type(exc).__name__)

    async def _block_machine_policy_change(
        self, repo: str, pr_number: int, state: dict, expected_state: dict,
        comment_id: int, machine_alias: str, actor: str, reason: str,
    ) -> bool:
        """Persist a no-POST result when machine policy changes mid-approval."""
        try:
            pr = await self.proxy.get_pr(repo, pr_number)
        except Exception:
            return False
        if (not isinstance(pr, dict) or pr.get("state") != "open"
                or pr.get("merged") or pr.get("draft")
                or (pr.get("head") or {}).get("sha") != state.get("head_sha")):
            return False

        blocked_state = copy.deepcopy(state)
        blocked_state["status"] = self._approval_retry_status(blocked_state)
        blocked_state["command"] = {
            "comment_id": comment_id,
            "kind": "approve_deploy",
            "phase": "completed",
            "args": {
                "machine": machine_alias, "actor": actor,
                "deployment_request_submitted": self._deployment_request_was_submitted(state),
            },
        }
        blocked_state["last_processed_comment_id"] = max(
            int(blocked_state.get("last_processed_comment_id", 0) or 0),
            comment_id,
        )
        deployed_ids = _component_id_set(blocked_state.get("deployments", []))
        remaining = [
            component for component in blocked_state.get("components", [])
            if isinstance(component, dict)
            and component.get("component_id") not in deployed_ids
        ]
        try:
            machine_groups = (
                self._runtime_redeploy_machine_groups(
                    blocked_state, remaining, repo,
                )
                if blocked_state.get("runtime_redeploy") else
                self._get_machine_groups_for_components(remaining, repo)
            )
        except Exception as exc:
            logger.warning("machine policy changed during approval %s#%s exception=%s",
                           repo, pr_number, type(exc).__name__)
            machine_groups = []
        markdown = await self._approval_retry_markdown(
            repo, pr_number, blocked_state, machine_groups,
            test_only=self._is_test_only_pr(pr),
            gate_note=["部署前检查发现机器配置已经变化，这次没有发送部署请求。",
                       "请按 PR Summary 中当前的完整机器命令重新审批。"],
            deployments=self._enrich_deployments_for_render(
                blocked_state.get("deployments", []), repo,
            ),
        )
        written = await self._write_lifecycle_with_history(
            repo, pr_number, blocked_state, markdown,
            event={"event": "Machine policy changed before deployment",
                   "machine": machine_alias,
                   "timestamp": comments_mod.beijing_now_str()},
            expected_lifecycle_state=expected_state,
        )
        if not written:
            return False
        await self._project_status_best_effort(repo, pr_number, blocked_state["status"])
        await self._post_command_reply(
            repo, pr_number, comment_id,
            "部署前检查发现机器策略已经变化，这次没有发送部署请求。",
            topic="machine-policy-changed-before-deploy", error=True,
        )
        return True

    async def _post_command_not_ready(
        self, repo: str, pr_number: int, current_status: str, next_action_text: str,
        *, comment_id: int = 0,
    ) -> None:
        """Post a unified "not ready" reply for a command that cannot run yet."""
        reason = self._command_error_reason(
            topic="command-not-ready", message=next_action_text,
        )
        if comment_id:
            await self._post_command_reply(
                repo, pr_number, comment_id, reason, topic="command-not-ready",
                error=True,
            )
            return
        guidance = await self._lifecycle_next_action_guidance(
            repo, pr_number, detail=False,
        )
        try:
            await self._post_bound_plain_notice(
                repo, pr_number,
                self._format_user_reply(self._failure_lead(reason), guidance),
            )
        except GitHubError as e:
            logger.warning("post command not ready comment %s#%s: %s", repo, pr_number, e)

    async def _post_bound_plain_notice(
        self, repo: str, pr_number: int, message: str,
    ) -> bool:
        """Post a formatted reply that has no source command comment to bind to."""
        payload = message.strip()
        if not payload:
            return False
        body = "\n".join((comments_mod.BOT_MARKER, "", payload))
        posted = await self.proxy.post_issue_comment(repo, pr_number, body)
        return bool(isinstance(posted, dict) and posted.get("id"))

    async def _post_error(
        self, repo: str, pr_number: int, message: str, *, comment_id: int = 0,
    ) -> None:
        """Post a unified failure reply for a command that did not execute."""
        reason = self._command_error_reason(message=message)
        guidance = await self._lifecycle_next_action_guidance(
            repo, pr_number, detail=False,
        )
        body_text = self._format_user_reply(self._failure_lead(reason), guidance)
        if comment_id:
            topic = "command-error-" + hashlib.sha256(
                body_text.encode("utf-8"),
            ).hexdigest()[:12]
            await self._post_command_reply(
                repo, pr_number, comment_id, message, topic=topic, error=True,
            )
        else:
            try:
                await self._post_bound_plain_notice(repo, pr_number, body_text)
            except GitHubError as e:
                logger.warning("post error comment %s#%s: %s", repo, pr_number, e)

    @staticmethod
    def _runtime_check_key(check: dict) -> tuple[str, str, str]:
        return (
            str(check.get("machine", "")), str(check.get("ip", "")),
            str(check.get("component_id", "")),
        )

    @staticmethod
    def _runtime_unreadable_lines(checks: list[dict]) -> list[str]:
        """Name exactly which machine/components could not be read."""
        lines: list[str] = []
        seen: set[tuple[str, str, str, str]] = set()
        for check in checks if isinstance(checks, list) else []:
            if (not isinstance(check, dict)
                    or check.get("status") not in {"unavailable", "identity_changed", "not_running"}):
                continue
            alias = str(check.get("machine", "") or "")
            component_id = str(check.get("component_id", "") or "")
            status = str(check.get("status", ""))
            key = (alias, str(check.get("ip", "")), component_id, status)
            if not alias or key in seen:
                continue
            seen.add(key)
            ip_text = str(check.get("ip", "") or "主 IP 未记录")
            component_text = f"`{component_id}`" if component_id else "未知组件"
            reason = {
                "identity_changed": "机器身份或运行时绑定暂时无法确认",
                "not_running": "组件当前没有运行，运行镜像不可读",
                "unavailable": "暂时无法连接机器读取运行状态",
            }[status]
            lines.append(
                f"- 机器 `{alias}`（{ip_text}），组件 {component_text}：{reason}；"
                "暂时不能生成审批命令。"
            )
        return lines

    @staticmethod
    def _runtime_check_is_due(check: dict | None, now: datetime) -> bool:
        if not isinstance(check, dict):
            return True
        try:
            checked_at = datetime.fromisoformat(
                str(check.get("checked_at", "")).replace("Z", "+00:00"),
            )
            if checked_at.utcoffset() is None:
                return True
        except (TypeError, ValueError):
            return True
        return (now - checked_at.astimezone(timezone.utc)).total_seconds() \
            >= RUNTIME_IMAGE_CHECK_INTERVAL_SECONDS

    @staticmethod
    def _runtime_check_record(
        machine: str, ip_value: str, component: dict, runtime_id: str,
        observed_image: str, status: str, checked_at: str,
    ) -> dict:
        return {
            "machine": machine,
            "ip": ip_value,
            "component_id": component.get("component_id", ""),
            "runtime_id": runtime_id,
            "target_image": component.get("image_ref", ""),
            "observed_image": observed_image,
            "status": status,
            "checked_at": checked_at,
        }

    @staticmethod
    def _runtime_observed_image_for_display(
        check: dict, component: dict | None,
    ) -> str:
        """Expand a legacy Core MATCH tag after the full-ref check succeeded.

        Hidden-state v1 stores Core MATCH observations as their tag. Runtime
        status is assigned only after exact full-reference comparison, so the
        approved target is also the verified running image for display. Keep
        the persisted record unchanged for hidden-state compatibility.
        """
        observed = check.get("observed_image", "")
        if (not isinstance(observed, str)
                or not isinstance(component, dict)
                or component.get("target") != "core"
                or check.get("status") != "match"):
            return observed if isinstance(observed, str) else ""
        target = check.get("target_image")
        if (not isinstance(target, str) or not target
                or target != component.get("image_ref")):
            return observed
        try:
            target = validate_image_ref(target)
        except ValueError:
            return observed
        if observed == _target_tag_from_image_ref(target):
            return target
        return observed

    def _confirmed_runtime_drift(self, state: dict) -> list[dict]:
        checks = state.get("runtime_checks", []) if isinstance(state, dict) else []
        return [check for check in checks if isinstance(check, dict)
                and check.get("status") == "mismatch"]

    def _new_runtime_redeploy_round(
        self, state: dict, *, comment_id: int, command_kind: str,
        actor: str = "", machine: str = "",
    ) -> dict:
        """Start a fresh round without dropping unresolved machine/component bindings."""
        drift_checks = self._confirmed_runtime_drift(state)
        if not drift_checks:
            raise DeployControllerError("no confirmed runtime image drift is available")

        # Keep unresolved bindings from the prior round. A new mismatch on B
        # must not erase A's work just because A's latest probe is unavailable.
        pending_bindings: set[tuple[str, str, str]] = set()
        old_pending = state.get("runtime_redeploy", [])
        if not isinstance(old_pending, list):
            raise DeployControllerError("runtime redeploy bindings are invalid")
        for item in old_pending:
            if not isinstance(item, dict):
                raise DeployControllerError("runtime redeploy binding is invalid")
            alias, ip_value = item.get("machine"), item.get("ip")
            component_ids = item.get("component_ids")
            if (not isinstance(alias, str) or not alias
                    or not isinstance(ip_value, str)
                    or self._canonical_primary_ipv4(ip_value) != ip_value
                    or not isinstance(component_ids, list)):
                raise DeployControllerError("runtime redeploy binding is invalid")
            for component_id in component_ids:
                if not isinstance(component_id, str) or not component_id:
                    raise DeployControllerError("runtime redeploy component binding is invalid")
                pending_bindings.add((alias, ip_value, component_id))

        mismatch_bindings: set[tuple[str, str, str]] = set()
        for check in drift_checks:
            alias = check.get("machine", "")
            ip_value = check.get("ip", "")
            component_id = check.get("component_id", "")
            if (not all(isinstance(value, str) and value
                        for value in (alias, ip_value, component_id))
                    or self._canonical_primary_ipv4(ip_value) != ip_value):
                continue
            mismatch_bindings.add((alias, ip_value, component_id))
        if not mismatch_bindings:
            raise DeployControllerError("confirmed runtime drift has no trusted machine binding")

        all_pending_bindings = pending_bindings | mismatch_bindings
        grouped: dict[tuple[str, str], list[str]] = {}
        seen_bindings: set[tuple[str, str, str]] = set()
        for alias, ip_value, component_id in sorted(all_pending_bindings):
            binding = (alias, ip_value, component_id)
            if binding in seen_bindings:
                continue
            seen_bindings.add(binding)
            grouped.setdefault((alias, ip_value), []).append(component_id)

        preserved_deployments = []
        for deployment in state.get("deployments", []):
            if not isinstance(deployment, dict):
                continue
            deployment_machine = deployment.get("machine", "")
            deployment_ip = self._canonical_primary_ipv4(
                deployment.get("ip", ""),
            )
            kept_ids = [
                component_id for component_id in deployment.get("component_ids", [])
                if (deployment_machine, deployment_ip, component_id)
                not in mismatch_bindings
            ]
            if kept_ids:
                preserved = dict(deployment)
                preserved["component_ids"] = kept_ids
                preserved_deployments.append(preserved)

        deployment_request_submitted = (
            command_kind == "request_deploy"
            or state.get("status") == "deploy-requested"
        )
        new_state = self._init_hidden_state(
            head_sha=state["head_sha"],
            status=("deploy-requested" if deployment_request_submitted else "deploy-ready"),
            review_evidence=state.get("review_evidence", {}),
            components=state.get("components", []),
            deployments=preserved_deployments,
        )
        new_state["round_id"] = make_round_id(state["head_sha"], comment_id)
        new_state["round_started_at"] = utc_now()
        new_state["round_archive"] = state.get("round_archive")
        new_state["runtime_checks"] = copy.deepcopy(state.get("runtime_checks", []))
        new_state["runtime_redeploy"] = [
            {"machine": alias, "ip": ip_value, "component_ids": component_ids}
            for (alias, ip_value), component_ids in grouped.items()
        ]
        args = {}
        if actor:
            args["actor"] = actor
        if machine:
            args["machine"] = machine
        args["deployment_request_submitted"] = deployment_request_submitted
        new_state["command"] = {
            "comment_id": comment_id, "kind": command_kind,
            "phase": "completed", "args": args,
        }
        new_state["last_processed_comment_id"] = comment_id
        self._validate_hidden_state(new_state)
        return new_state

    @staticmethod
    def _runtime_redeploy_ids_for_machine(
        state: dict, machine_alias: str, machine_ip: str,
    ) -> set[str]:
        result = set()
        for item in state.get("runtime_redeploy", []) if isinstance(state, dict) else []:
            if (isinstance(item, dict) and item.get("machine") == machine_alias
                    and item.get("ip") == machine_ip):
                result.update(component_id for component_id in item.get("component_ids", [])
                              if isinstance(component_id, str))
        return result

    @staticmethod
    def _runtime_redeploy_pending_ids(state: dict) -> set[str]:
        return {
            component_id
            for item in state.get("runtime_redeploy", []) if isinstance(item, dict)
            for component_id in item.get("component_ids", [])
            if isinstance(component_id, str)
        }

    def _record_redeployed_runtime_matches(
        self, state: dict, machine, deployed_rows: list[dict], health: list[dict],
    ) -> None:
        """Bind verified/adopted components to a fresh matching runtime observation."""
        component_map = {
            component.get("component_id"): component
            for component in state.get("components", []) if isinstance(component, dict)
        }
        health_map = {
            item.get("component_id"): item for item in health
            if isinstance(item, dict) and isinstance(item.get("component_id"), str)
        }
        checks = [item for item in state.get("runtime_checks", [])
                  if isinstance(item, dict)]
        check_map = {self._runtime_check_key(item): item for item in checks}
        deployed_ids = _component_id_set(deployed_rows)
        deployed_ips_by_component: dict[str, set[str]] = {}
        for row in deployed_rows:
            if not isinstance(row, dict):
                continue
            row_ip = self._canonical_primary_ipv4(row.get("ip", ""))
            if row.get("machine") != machine.alias or not row_ip:
                continue
            for component_id in row.get("component_ids", []):
                if isinstance(component_id, str):
                    deployed_ips_by_component.setdefault(component_id, set()).add(row_ip)
        checked_at = utc_now()
        for component_id in deployed_ids:
            component = component_map.get(component_id)
            health_item = health_map.get(component_id)
            if not isinstance(component, dict) or not isinstance(health_item, dict):
                continue
            if component.get("target") == "core":
                full_target = str(component.get("image_ref", "") or "")
                full_running = str(health_item.get("current_tag", "") or "")
                if not full_target or full_running != full_target:
                    continue
                # The exact full-image check is performed before writing this
                # record. Hidden-state v1 represents Core MATCH observations
                # as the target tag for backward-compatible validation.
                observed = _target_tag_from_image_ref(full_target)
                runtime_id = "core"
            else:
                observed = str(health_item.get("running_image", "") or "")
                runtime_id = str(health_item.get("runtime_id", "") or
                                 component.get("runtime_id", ""))
            if not runtime_id:
                continue
            for deployed_ip in deployed_ips_by_component.get(component_id, set()):
                check = self._runtime_check_record(
                    machine.alias, deployed_ip, component, runtime_id,
                    observed, "match", checked_at,
                )
                check_map[self._runtime_check_key(check)] = check
        state["runtime_checks"] = list(check_map.values())[-32:]
        remaining = []
        for item in state.get("runtime_redeploy", []):
            if not isinstance(item, dict):
                continue
            item_ip = self._canonical_primary_ipv4(item.get("ip", ""))
            if item.get("machine") != machine.alias:
                remaining.append(item)
                continue
            remaining_ids = [component_id for component_id in item.get("component_ids", [])
                             if not (component_id in deployed_ids
                                     and item_ip in deployed_ips_by_component.get(
                                         component_id, set(),
                                     ))]
            if remaining_ids:
                remaining.append({
                    "machine": item["machine"], "ip": item["ip"],
                    "component_ids": remaining_ids,
                })
        if state.get("runtime_redeploy") is not None:
            state["runtime_redeploy"] = remaining

    def _mark_runtime_checks_unavailable(
        self, state: dict, machine, components: list[dict], *,
        status: str = "unavailable", endpoint_ip: str | None = None,
    ) -> None:
        if status not in {"unavailable", "identity_changed", "not_running"}:
            status = "unavailable"
        checks = [item for item in state.get("runtime_checks", [])
                  if isinstance(item, dict)]
        check_map = {self._runtime_check_key(item): item for item in checks}
        checked_at = utc_now()
        machine_ip = self._canonical_primary_ipv4(
            endpoint_ip or getattr(machine, "node_host", ""),
        )
        if not machine_ip:
            return
        for component in components:
            if not isinstance(component, dict):
                continue
            runtime_id = str(component.get("runtime_id", "") or
                             ("core" if component.get("target") == "core" else "unresolved"))
            record = self._runtime_check_record(
                machine.alias, machine_ip, component, runtime_id, "",
                status, checked_at,
            )
            check_map[self._runtime_check_key(record)] = record
        state["runtime_checks"] = list(check_map.values())[-32:]

    async def _post_already_target_redeploy_reply(
        self, repo: str, pr_number: int, comment_id: int,
        machine, health: list[dict],
    ) -> None:
        already_target = [item for item in health
                          if isinstance(item, dict)
                          and item.get("already_target") is True]
        if not already_target:
            return
        primary_ip, _, _ = self._runtime_display_identity(machine.alias, repo)
        display_ip = primary_ip or "主 IP 未记录"
        if len(already_target) == len(health):
            message = (
                f"重新检查确认机器 `{machine.alias}`（主 IP：`{display_ip}`）上已经在运行本次批准的镜像，"
                "不需要重新部署。"
            )
        else:
            message = (
                f"重新检查确认机器 `{machine.alias}`（主 IP：`{display_ip}`）上这部分组件已经在运行本次批准的镜像，"
                "不需要重新部署。"
            )
        await self._post_command_reply(
            repo, pr_number, comment_id, message,
            topic="runtime-redeploy-already-target",
        )

    async def _runtime_drift_command_lines(
        self, state: dict, repo: str | None = None,
    ) -> list[str]:
        if not isinstance(repo, str) or not repo:
            return []
        lines = []
        seen = set()
        drift_checks = self._confirmed_runtime_drift(state)
        component_map = {
            item.get("component_id"): item for item in state.get("components", [])
            if isinstance(item, dict) and isinstance(item.get("component_id"), str)
        }
        ids_by_machine: dict[tuple[str, str], set[str]] = {}
        for check in drift_checks:
            alias = check.get("machine", "")
            node_host = self._canonical_primary_ipv4(check.get("ip", ""))
            component_id = check.get("component_id", "")
            if (isinstance(alias, str) and alias and node_host
                    and isinstance(component_id, str) and component_id):
                ids_by_machine.setdefault((alias, node_host), set()).add(component_id)
        for (alias, ip_value), component_ids in ids_by_machine.items():
            components = [component_map[item] for item in component_ids
                          if item in component_map]
            if len(components) != len(component_ids):
                continue
            candidates = self._get_machine_groups_for_components(components, repo)
            group = next((item for item in candidates
                          if item.get("alias") == alias
                          and item.get("approval_available") is True
                          and component_ids.issubset(set(item.get("component_ids", [])))), None)
            if group is None:
                continue
            try:
                machine = self.policy.get_machine(alias, repo=repo)
            except Exception:
                machine = None
            if (machine is None
                    or ip_value not in {
                        item["ip"] for item in self._policy_machine_endpoints(machine, repo)
                    }
                    or not self._endpoint_allowed_for_repository(
                        repo, machine, ip_value, components=components,
                    )):
                continue
            verified = await self._agent_core_verified_endpoints(
                repo, machine, components, endpoints=[ip_value],
            )
            if not any(component_ids.issubset(set(item.get("component_ids", [])))
                       for item in verified):
                continue
            command = f"/approve_deploy machine={ip_value}"
            if command not in seen:
                seen.add(command)
                lines.append(command)
        return lines

    @staticmethod
    def _runtime_drift_checks_for_machine(
        state: dict, machine_alias: str, machine_ip: str,
    ) -> list[dict]:
        return [check for check in state.get("runtime_checks", [])
                if isinstance(check, dict)
                and check.get("machine") == machine_alias
                and check.get("ip") == machine_ip
                and check.get("status") == "mismatch"]

    async def _reconcile_runtime_image_checks(
        self, repo: str, pr_number: int, state: dict, pr_data: dict,
        *, force: bool = False, machine_filter: tuple[str, str] | None = None,
    ) -> dict:
        """Refresh every due deployed runtime binding using read-only Agent Core calls."""
        if (not isinstance(state, dict)
                or state.get("status") not in {
                    "deploy-ready", "deploy-requested", "testing", "succeeded", "failed",
                }
                or state.get("command", {}).get("phase") in {"executing", "uncertain"}):
            return state
        try:
            current_pr = await self.proxy.get_pr(repo, pr_number)
        except Exception as exc:
            logger.info("runtime image check skipped: PR state unavailable repo=%s pr=%s reason=%s",
                        repo, pr_number, type(exc).__name__)
            return state
        if (not isinstance(current_pr, dict)
                or current_pr.get("state") != "open"
                or current_pr.get("merged")
                or current_pr.get("draft")
                or state.get("head_sha") != (current_pr.get("head") or {}).get("sha")):
            return state
        pr_data = current_pr

        component_map = {
            component.get("component_id"): component
            for component in state.get("components", [])
            if isinstance(component, dict)
        }
        try:
            policy_status = self.policy.repo_policy_status(repo)
            policy_configured = (
                isinstance(policy_status, dict)
                and policy_status.get("authorized") is True
                and policy_status.get("machines_configured") is True
            )
            trusted_machines = (
                self.policy.get_machines(repo=repo) if policy_configured else []
            )
            if not isinstance(trusted_machines, list) or not trusted_machines:
                policy_configured = False
                trusted_machines = []
        except Exception as exc:
            logger.warning("runtime image check policy unavailable repo=%s reason=%s",
                           repo, type(exc).__name__)
            policy_configured = False
            trusted_machines = []

        trusted_alias_counts: dict[str, int] = {}
        trusted_machines_by_alias: dict[str, list] = {}
        for trusted_machine in trusted_machines:
            trusted_alias = str(getattr(trusted_machine, "alias", "") or "")
            if trusted_alias:
                trusted_alias_counts[trusted_alias] = (
                    trusted_alias_counts.get(trusted_alias, 0) + 1
                )
                trusted_machines_by_alias.setdefault(trusted_alias, []).append(
                    trusted_machine,
                )

        def policy_snapshot(machine) -> tuple:
            def values(name: str, *, fold: bool = True):
                raw = getattr(machine, name, None)
                if raw is None:
                    return None
                if not isinstance(raw, (list, tuple, set)):
                    return ("<invalid>",)
                normalized = [
                    item.strip().casefold() if fold and isinstance(item, str)
                    else item.strip() if isinstance(item, str) else "<invalid>"
                    for item in raw
                ]
                return tuple(sorted(normalized))

            return (
                str(getattr(machine, "alias", "") or ""),
                str(getattr(machine, "node_id", "") or "").strip(),
                self._canonical_primary_ipv4(getattr(machine, "node_host", "")),
                values("owners"), values("targets"), values("platforms"),
                values("variants"), values("driver_paths"),
            )

        initial_policy_snapshot = {
            alias: policy_snapshot(machines[0])
            for alias, machines in trusted_machines_by_alias.items()
            if len(machines) == 1
        }

        specs = []
        for deployment in state.get("deployments", []):
            if not isinstance(deployment, dict) or deployment.get("phase") != "deployed":
                continue
            alias = deployment.get("machine")
            stored_ip = deployment.get("ip", "")
            if not isinstance(alias, str) or not alias:
                continue
            current_machine = None
            ip_missing = not stored_ip
            if ip_missing and policy_configured:
                machine_matches = trusted_machines_by_alias.get(alias, [])
                current_machine = machine_matches[0] if len(machine_matches) == 1 else None
                candidate_ip = getattr(current_machine, "node_host", "")
                try:
                    parsed_ip = ipaddress.ip_address(candidate_ip)
                    stored_ip = str(parsed_ip) if parsed_ip.version == 4 else ""
                except (TypeError, ValueError):
                    stored_ip = ""
            try:
                parsed_ip = ipaddress.ip_address(stored_ip)
            except (TypeError, ValueError):
                continue
            if parsed_ip.version != 4:
                continue
            ip_value = str(parsed_ip)
            for component_id in deployment.get("component_ids", []):
                component = component_map.get(component_id)
                if not isinstance(component, dict):
                    continue
                specs.append((alias, ip_value, component, ip_missing))
        for binding in state.get("runtime_redeploy", []):
            if not isinstance(binding, dict):
                continue
            alias, ip_value = binding.get("machine"), binding.get("ip")
            for component_id in binding.get("component_ids", []):
                component = component_map.get(component_id)
                if (isinstance(alias, str) and isinstance(ip_value, str)
                        and isinstance(component, dict)):
                    specs.append((alias, ip_value, component, False))
        specs_by_key = {}
        for spec in specs:
            alias, ip_value, component, ip_missing = spec
            specs_by_key[(alias, ip_value, component.get("component_id", ""))] = spec
        specs = list(specs_by_key.values())
        if not specs:
            return state

        old_checks = state.get("runtime_checks", [])
        if not isinstance(old_checks, list):
            old_checks = []
        old_by_key = {
            self._runtime_check_key(check): check for check in old_checks
            if isinstance(check, dict)
        }
        now = datetime.now(timezone.utc)
        # A check cycle is one snapshot of this round, not an independent
        # machine poll. Once any stored observation is due (or an immediate
        # post-deploy check is requested), probe every deployed component so a
        # single visible result never mixes fresh and stale machines.
        check_cycle_due = force or any(
            ip_missing or self._runtime_check_is_due(
                old_by_key.get((alias, ip_value, component.get("component_id", ""))),
                now,
            )
            for alias, ip_value, component, ip_missing in specs
        )
        selected = list(specs) if check_cycle_due else []
        if not selected:
            # Retire only checks whose component is no longer deployed in the current round.
            current_keys = {
                (alias, ip_value, component.get("component_id", ""))
                for alias, ip_value, component, _ in specs
            }
            retained = [check for check in old_checks
                        if isinstance(check, dict)
                        and self._runtime_check_key(check) in current_keys]
            if retained == old_checks:
                return state
            selected_results = {}
        else:
            selected_results = {}
        if not await self._fresh_review_evidence_matches_state(
                repo, pr_number, state.get("head_sha", ""),
                state.get("review_evidence", {}),
                expected_components=state.get("components", [])):
            logger.info("runtime image check skipped: Review Agent evidence is no longer current repo=%s pr=%s",
                        repo, pr_number)
            return state

        checked_at = utc_now()
        # Policy remains repository-scoped; no machine is queried unless its current
        # alias and literal IP match the deployment record for this component.
        groups: dict[tuple[str, str], list[tuple[dict, bool]]] = {}
        for alias, ip_value, component, ip_missing in selected:
            groups.setdefault((alias, ip_value), []).append((component, ip_missing))

        for (alias, ip_value), group in groups.items():
            pair_results = []
            try:
                if not policy_configured:
                    for component, _ in group:
                        runtime_id = str(component.get("runtime_id", "") or
                                         ("core" if component.get("target") == "core" else "unresolved"))
                        pair_results.append(self._runtime_check_record(
                            alias, ip_value, component, runtime_id, "", "unavailable", checked_at,
                        ))
                    selected_results.update({self._runtime_check_key(item): item for item in pair_results})
                    continue
                machine_matches = trusted_machines_by_alias.get(alias, [])
                machine = machine_matches[0] if len(machine_matches) == 1 else None
                if machine is None:
                    status_value = "identity_changed"
                    machine_binding = None
                else:
                    _, identity_matches = self._machine_identity_matches(
                        alias, machine, None, trusted_machines, repo=repo,
                    )
                    machine_binding = (
                        getattr(machine, "alias", ""), getattr(machine, "node_id", ""),
                        getattr(machine, "node_host", ""),
                    )
                    deployed_components = [component for component, _ in group]
                    if (trusted_alias_counts.get(alias) != 1
                            or not identity_matches
                            or machine_binding[0] != alias
                            or ip_value not in {
                                item["ip"] for item in self._policy_machine_endpoints(
                                    machine, repo,
                                )
                            }
                            or not self._endpoint_allowed_for_repository(
                                repo, machine, ip_value,
                                components=deployed_components,
                                policy_machines=trusted_machines,
                            )
                            or not machine_binding[1]
                            or any(ip_missing for _, ip_missing in group)):
                        status_value = "identity_changed"
                    else:
                        status_value = ""
                if status_value:
                    for component, _ in group:
                        runtime_id = str(component.get("runtime_id", "") or
                                         ("core" if component.get("target") == "core" else "unresolved"))
                        pair_results.append(self._runtime_check_record(
                            alias, ip_value, component, runtime_id, "", status_value,
                            checked_at,
                        ))
                    selected_results.update({self._runtime_check_key(item): item for item in pair_results})
                    continue

                try:
                    endpoint_errors = []
                    core = None
                    try:
                        core = await self._core_for_machine_endpoint(
                            machine, ip_value, repo,
                            timeout=AGENT_CORE_STATUS_PROBE_TIMEOUT_SECONDS,
                        )
                    except Exception as endpoint_error:
                        endpoint_errors.append(endpoint_error)
                    if core is None:
                        raise DeployControllerError(
                            self._preflight_failure_reason(endpoint_errors)
                        )
                except Exception as exc:
                    logger.info("runtime image Agent Core unavailable repo=%s machine=%s reason=%s",
                                repo, alias, type(exc).__name__)
                    for component, _ in group:
                        runtime_id = str(component.get("runtime_id", "") or
                                         ("core" if component.get("target") == "core" else "unresolved"))
                        pair_results.append(self._runtime_check_record(
                            alias, ip_value, component, runtime_id, "", "unavailable",
                            checked_at,
                        ))
                    selected_results.update({self._runtime_check_key(item): item for item in pair_results})
                    continue

                drivers = None
                agent_core_unavailable = False
                if any(component.get("target") != "core" for component, _ in group):
                    try:
                        drivers = await asyncio.wait_for(
                            core.list_drivers(), timeout=AGENT_CORE_STATUS_PROBE_TIMEOUT_SECONDS,
                        )
                        if not isinstance(drivers, list):
                            raise DeployControllerError("invalid Agent Core driver catalog")
                    except Exception as exc:
                        logger.info("runtime image driver catalog unavailable repo=%s machine=%s reason=%s",
                                    repo, alias, type(exc).__name__)
                        drivers = None
                        agent_core_unavailable = True
                update_info = None
                for component, _ in group:
                    target_image = str(component.get("image_ref", "") or "")
                    runtime_id = str(component.get("runtime_id", "") or "")
                    observed = ""
                    status_value = "unavailable"
                    try:
                        if component.get("target") == "core":
                            runtime_id = "core"
                            if not target_image:
                                status_value = "unavailable"
                            else:
                                if update_info is None:
                                    update_info = await asyncio.wait_for(
                                        core.core_update_check(),
                                        timeout=AGENT_CORE_STATUS_PROBE_TIMEOUT_SECONDS,
                                    )
                                if not isinstance(update_info, dict):
                                    status_value = "unavailable"
                                else:
                                    current_image = self._current_core_image(update_info)
                                    if not current_image:
                                        status_value = "unavailable"
                                    else:
                                        observed = current_image
                                        status_value = (
                                            "match" if current_image == target_image else "mismatch"
                                        )
                                        if status_value == "match":
                                            # The hidden-state v1 schema stores
                                            # Core MATCH observations as a tag.
                                            # Exact full-reference equality has
                                            # already been checked above.
                                            observed = _target_tag_from_image_ref(target_image)
                        elif drivers is None or not runtime_id:
                            status_value = "identity_changed" if not runtime_id else "unavailable"
                        else:
                            resolved = self._resolve_component_runtime(drivers, component)
                            if (resolved is None
                                    or resolved.get("runtime_id") != runtime_id):
                                status_value = "identity_changed"
                            else:
                                status_data = await asyncio.wait_for(
                                    core.driver_status(runtime_id),
                                    timeout=AGENT_CORE_STATUS_PROBE_TIMEOUT_SECONDS,
                                )
                                if not isinstance(status_data, dict):
                                    status_value = "unavailable"
                                else:
                                    actual_status = status_data.get("status")
                                    actual_image = status_data.get("running_image", "")
                                    if (not isinstance(actual_status, str)
                                            or not isinstance(actual_image, str)
                                            or len(actual_image) > 1024
                                            or any(ord(char) < 32 or ord(char) == 127
                                                   for char in actual_image)):
                                        status_value = "unavailable"
                                    elif actual_status.casefold() == "running":
                                        if not actual_image:
                                            status_value = "unavailable"
                                        else:
                                            try:
                                                validate_image_ref(actual_image)
                                            except ValueError:
                                                status_value = "unavailable"
                                            else:
                                                observed = actual_image
                                                status_value = (
                                                    "match" if actual_image == target_image else "mismatch"
                                                )
                                    elif actual_status.casefold() in {
                                            "deploying", "updating", "starting", "restarting",
                                            "stopping"}:
                                        observed = actual_image
                                        status_value = "unavailable"
                                    elif actual_status.casefold() in {
                                            "stopped", "exited", "not_running", "failed"}:
                                        observed = actual_image
                                        status_value = "not_running"
                                    else:
                                        observed = actual_image
                                        status_value = "unavailable"
                    except Exception as exc:
                        logger.info("runtime image observation unavailable repo=%s machine=%s component=%s reason=%s",
                                    repo, alias, component.get("component_id", ""), type(exc).__name__)
                        status_value = "unavailable"
                        observed = ""
                        agent_core_unavailable = True
                    pair_results.append(self._runtime_check_record(
                        alias, ip_value, component, runtime_id, observed,
                        status_value, checked_at,
                    ))

                if agent_core_unavailable:
                    self._record_agent_core_health(repo, machine, "unavailable")
                elif any(item.get("status") in {"match", "mismatch", "not_running"}
                         for item in pair_results):
                    self._record_agent_core_health(repo, machine, "available")

                selected_results.update({self._runtime_check_key(item): item for item in pair_results})
            except Exception as exc:
                logger.warning(
                    "runtime image machine check failed repo=%s machine=%s reason=%s",
                    repo, alias, type(exc).__name__,
                )
                unavailable_results = []
                for component, _ in group:
                    runtime_id = str(component.get("runtime_id", "") or
                                     ("core" if component.get("target") == "core" else "unresolved"))
                    unavailable_results.append(self._runtime_check_record(
                        alias, ip_value, component, runtime_id, "", "unavailable", checked_at,
                    ))
                selected_results.update({
                    self._runtime_check_key(item): item for item in unavailable_results
                })

        # Re-read policy once after probing every deployed machine. A policy
        # refresh during the scan invalidates the whole affected machine result
        # set, so one cycle never publishes observations from mixed identities.
        policy_snapshot_readable = False
        policy_snapshot_changed = False
        latest_machines_by_alias: dict[str, list] = {}
        try:
            latest_policy_status = self.policy.repo_policy_status(repo)
            latest_machines = self.policy.get_machines(repo=repo)
            if isinstance(latest_machines, list):
                policy_snapshot_readable = True
                for latest_machine in latest_machines:
                    latest_alias = str(getattr(latest_machine, "alias", "") or "")
                    if latest_alias:
                        latest_machines_by_alias.setdefault(latest_alias, []).append(
                            latest_machine,
                        )
                if (not isinstance(latest_policy_status, dict)
                        or latest_policy_status.get("authorized") is not True
                        or latest_policy_status.get("machines_configured") is not True):
                    policy_snapshot_changed = True
        except Exception as exc:
            logger.info("runtime image policy snapshot recheck unavailable repo=%s reason=%s",
                        repo, type(exc).__name__)

        for (alias, ip_value), group in groups.items():
            latest_matches = latest_machines_by_alias.get(alias, [])
            current_fingerprint = (
                policy_snapshot(latest_matches[0]) if len(latest_matches) == 1 else None
            )
            initial_fingerprint = initial_policy_snapshot.get(alias)
            identity_changed = (
                policy_snapshot_changed
                or policy_snapshot_readable and (
                    len(latest_matches) != 1
                    or initial_fingerprint is None
                    or current_fingerprint != initial_fingerprint
                )
            )
            if identity_changed or not policy_snapshot_readable:
                invalid_status = (
                    "identity_changed" if identity_changed else "unavailable"
                )
                for component, _ in group:
                    record = self._runtime_check_record(
                        alias, ip_value, component,
                        str(component.get("runtime_id", "") or
                            ("core" if component.get("target") == "core" else "unresolved")),
                        "", invalid_status, checked_at,
                    )
                    selected_results[self._runtime_check_key(record)] = record

        current_keys = {
            (alias, ip_value, component.get("component_id", ""))
            for alias, ip_value, component, _ in specs
        }
        new_checks = []
        for alias, ip_value, component, _ in specs:
            key = (alias, ip_value, component.get("component_id", ""))
            check = selected_results.get(key) or old_by_key.get(key)
            if isinstance(check, dict):
                new_checks.append(check)
        new_state = copy.deepcopy(state)
        new_state["runtime_checks"] = new_checks
        old_runtime_redeploy = state.get("runtime_redeploy", [])
        pending_redeploy = copy.deepcopy(old_runtime_redeploy) \
            if isinstance(old_runtime_redeploy, list) else []
        pending_bindings = {
            (item.get("machine"), item.get("ip"), component_id)
            for item in pending_redeploy if isinstance(item, dict)
            for component_id in item.get("component_ids", [])
        }
        adopted_bindings = {
            key for key, check in selected_results.items()
            if check.get("status") == "match" and key in pending_bindings
        }
        if adopted_bindings:
            deployments = list(new_state.get("deployments", []))
            for machine_alias, ip_value, component_id in adopted_bindings:
                existing = next((item for item in deployments
                                 if isinstance(item, dict)
                                 and item.get("machine") == machine_alias
                                 and item.get("ip") == ip_value
                                 and item.get("phase") == "deployed"), None)
                if existing is None:
                    deployments.append({
                        "machine": machine_alias, "ip": ip_value,
                        "component_ids": [component_id], "phase": "deployed",
                    })
                elif component_id not in existing.get("component_ids", []):
                    existing["component_ids"].append(component_id)
            new_state["deployments"] = deployments
            remaining_bindings = []
            for item in pending_redeploy:
                kept_ids = [component_id for component_id in item.get("component_ids", [])
                            if (item.get("machine"), item.get("ip"), component_id)
                            not in adopted_bindings]
                if kept_ids:
                    remaining_bindings.append({
                        "machine": item["machine"], "ip": item["ip"],
                        "component_ids": kept_ids,
                    })
            new_state["runtime_redeploy"] = remaining_bindings
            all_ids = {
                component.get("component_id") for component in new_state.get("components", [])
                if isinstance(component, dict)
            }
            deployed_ids = _component_id_set(new_state.get("deployments", []))
            if (new_state.get("status") == "deploy-requested"
                    and not remaining_bindings and all_ids and all_ids.issubset(deployed_ids)):
                new_state["status"] = "testing"
                new_state.pop("acceptance_request", None)
        check_candidates = list(selected_results.values()) + [
            item for item in new_checks
            if self._runtime_check_key(item) not in selected_results
        ]
        status_priority = {
            "mismatch": 0, "not_running": 1, "unavailable": 2,
            "identity_changed": 3, "match": 4,
        }
        check_candidates.sort(key=lambda item: (
            status_priority.get(item.get("status"), 5),
            item.get("machine", ""), item.get("ip", ""),
            item.get("component_id", ""),
        ))
        unique_candidates = []
        candidate_keys = set()
        for item in check_candidates:
            key = self._runtime_check_key(item)
            if key not in candidate_keys:
                candidate_keys.add(key)
                unique_candidates.append(item)
        mandatory_keys = {
            (binding.get("machine"), binding.get("ip"), component_id)
            for binding in new_state.get("runtime_redeploy", [])
            if isinstance(binding, dict)
            for component_id in binding.get("component_ids", [])
        }
        mandatory_keys.update(adopted_bindings)
        mandatory_checks = [item for item in unique_candidates
                            if self._runtime_check_key(item) in mandatory_keys]
        if {self._runtime_check_key(item) for item in mandatory_checks} != mandatory_keys:
            logger.warning("runtime image state omitted a required redeploy binding repo=%s pr=%s",
                           repo, pr_number)
            return state
        new_state["runtime_checks"] = list(mandatory_checks)
        try:
            _validate_hidden_state(new_state)
            _build_hidden_state_body("", new_state)
        except GitHubStateProxyError:
            logger.warning("runtime image base state exceeds safe hidden-state capacity repo=%s pr=%s",
                           repo, pr_number)
            return state
        for item in unique_candidates:
            key = self._runtime_check_key(item)
            if key in mandatory_keys or key in {
                    self._runtime_check_key(existing)
                    for existing in new_state["runtime_checks"]}:
                continue
            candidate_state = copy.deepcopy(new_state)
            candidate_state["runtime_checks"] = [*new_state["runtime_checks"], item]
            try:
                _validate_hidden_state(candidate_state)
                _build_hidden_state_body("", candidate_state)
            except GitHubStateProxyError:
                continue
            new_state["runtime_checks"].append(item)
        persisted_check_keys = {
            self._runtime_check_key(item)
            for item in new_state.get("runtime_checks", [])
        }
        selected_results = {
            key: check for key, check in selected_results.items()
            if key in persisted_check_keys
        }
        if new_state == state:
            return state
        test_only = pr_data is None or self._is_test_only_pr(pr_data)

        try:
            lifecycle = await self.proxy.find_trusted_lifecycle_comment(repo, pr_number)
            if not isinstance(lifecycle, dict) or not isinstance(lifecycle.get("body"), str):
                return state
            from .github_state_proxy import HIDDEN_STATE_MARKER
            visible = lifecycle["body"].split(HIDDEN_STATE_MARKER, 1)[0].rstrip()
            lifecycle_transition = state.get("status") != new_state.get("status")
            if lifecycle_transition and new_state.get("status") == "testing":
                updated_visible = comments_mod.testing(
                    repo, pr_number, new_state["head_sha"],
                    deployments=self._enrich_deployments_for_render(
                        new_state.get("deployments", []), repo,
                    ),
                    components=new_state.get("components", []),
                    deployments_complete=True,
                )
            else:
                updated_visible = visible
            transitions: dict[tuple[str, str, str, str], list[tuple[dict, str]]] = {}
            for key, check in selected_results.items():
                old = old_by_key.get(key)
                old_status = old.get("status") if isinstance(old, dict) else None
                status_value = check.get("status")
                if (status_value in {"mismatch", "not_running"}
                        and old_status != status_value
                        or status_value == "match"
                        and old_status in {"mismatch", "not_running"}):
                    previous_status = (
                        old_status if isinstance(old_status, str) and old_status
                        else "unobserved"
                    )
                    previous_checked_at = (
                        old.get("checked_at", "") if isinstance(old, dict) else ""
                    )
                    transitions.setdefault(
                        (check["machine"], check["ip"], previous_status, status_value), [],
                    ).append((check, previous_checked_at))
            written = await self._write_lifecycle_with_history(
                repo, pr_number, new_state, updated_visible,
                expected_lifecycle_state=state,
                runtime_projection_only=not lifecycle_transition,
            )
            if not written:
                return state
            round_id = round_id_for_state(new_state)
            anchor_comment_id = int(round_id.rsplit("-", 1)[1])
            for (machine_alias, ip_value, previous_status, status_value), items in transitions.items():
                checks = [check for check, _ in items]
                primary_ip, command_selector, owners = self._runtime_display_identity(
                    machine_alias, repo,
                )
                owner_labels = self._runtime_transition_owner_labels(owners)
                owner_text = " ".join(owner_labels) if owner_labels else "负责人待配置"
                detail_lines = []
                for check in checks:
                    component = component_map.get(check.get("component_id"))
                    target_name = (
                        str(component.get("target", "") or "")
                        if isinstance(component, dict) else ""
                    )
                    detail_lines.append(
                        f"- {target_name or '组件'}"
                    )
                details = "\n".join(detail_lines)
                if status_value == "match":
                    message = (
                        f"机器 `{machine_alias}`（主 IP：`{primary_ip or '未记录'}`）"
                        f"{' 的 ' + details.lstrip('- ') if details else ''}已经在运行本轮批准的镜像，不需要重新部署。"
                    )
                elif status_value == "mismatch":
                    mismatch_ids = {
                        check.get("component_id") for check in checks
                        if isinstance(check.get("component_id"), str)
                    }
                    component_by_id = {
                        item.get("component_id"): item
                        for item in new_state.get("components", [])
                        if isinstance(item, dict)
                        and isinstance(item.get("component_id"), str)
                    }
                    mismatch_components = [component_by_id[item] for item in mismatch_ids
                                           if item in component_by_id]
                    image_lines = []
                    for check in checks:
                        if check.get("status") != "mismatch":
                            continue
                        component = component_by_id.get(check.get("component_id"))
                        approved_image = str(
                            check.get("target_image", "") or
                            (component.get("image_ref", "")
                             if isinstance(component, dict) else "") or ""
                        )
                        observed_image = self._runtime_observed_image_for_display(
                            check, component,
                        )
                        image_lines.append(
                            "批准镜像 "
                            f"`{approved_image or '未读取'}`，实际运行镜像 "
                            f"`{observed_image or '未读取'}`。"
                        )
                    image_detail = "\n\n" + "\n".join(image_lines) if image_lines else ""
                    eligible_group = next((group for group in
                        self._get_machine_groups_for_components(mismatch_components, repo)
                        if group.get("alias") == machine_alias
                        and group.get("approval_available") is True
                        and mismatch_ids.issubset(set(group.get("component_ids", [])))),
                        None) if (mismatch_ids and len(mismatch_components) == len(mismatch_ids)) else None
                    try:
                        current_machine = self.policy.get_machine(machine_alias, repo=repo)
                    except Exception:
                        current_machine = None
                    verified_endpoint = []
                    if (eligible_group is not None and current_machine is not None
                            and ip_value in {
                                item["ip"] for item in self._policy_machine_endpoints(
                                    current_machine, repo,
                                )
                            }
                            and self._endpoint_allowed_for_repository(
                                repo, current_machine, ip_value,
                                components=mismatch_components,
                            )):
                        verified_endpoint = await self._agent_core_verified_endpoints(
                            repo, current_machine, mismatch_components,
                            endpoints=[ip_value],
                        )
                    command_selector = (
                        ip_value if any(mismatch_ids.issubset(set(item.get(
                            "component_ids", [],
                        ))) for item in verified_endpoint) else ""
                    )
                    if command_selector and eligible_group is not None:
                        owners = list(eligible_group.get("owners", []) or owners)
                        owner_labels = self._runtime_transition_owner_labels(owners)
                        owner_text = " ".join(owner_labels) if owner_labels else ""
                    if command_selector:
                        message = (
                            f"机器 `{machine_alias}`（实际检查 IP：`{ip_value}`；主 IP：`{primary_ip or '未记录'}`）上运行的镜像与本次批准的版本不一致，需要重新部署。"
                            f"{image_detail}"
                            + (f"\n\n请执行 `/approve_deploy machine={command_selector}`。" if not owner_text
                               else f"\n\n请 {owner_text} 执行 `/approve_deploy machine={command_selector}`。")
                        )
                    else:
                        message = (
                            f"机器 `{machine_alias}`（实际检查 IP：`{ip_value}`；主 IP：`{primary_ip or '未记录'}`）上运行的镜像与本次批准的版本不一致，需要重新部署。"
                            f"{image_detail}"
                            "\n\n目前还没有可确认的审批命令，请联系仓库维护者核对机器配置。"
                        )
                elif status_value == "not_running":
                    message = (
                        f"机器 `{machine_alias}`（主 IP：`{primary_ip or '未记录'}`）上的组件当前没有运行，"
                        "暂时无法确认运行镜像。请等待组件恢复运行后重新检查。"
                    )
                elif status_value == "identity_changed":
                    message = (
                        f"机器 `{machine_alias}`（主 IP：`{primary_ip or '未记录'}`）的登记信息发生了变化，"
                        "暂时无法确认运行镜像。请联系仓库维护者核对机器配置。"
                    )
                else:
                    message = (
                        f"目前无法连接机器 `{machine_alias}`（主 IP：`{primary_ip or '未记录'}`）确认运行镜像，"
                        "请等待机器恢复可访问后重新检查。"
                    )
                transition_identity = repr(sorted(
                    (check.get("component_id", ""), previous_checked_at,
                     check.get("checked_at", ""))
                    for check, previous_checked_at in items
                ))
                transition_fingerprint = hashlib.sha256(
                    transition_identity.encode("utf-8"),
                ).hexdigest()[:20]
                topic = (
                    f"runtime-image:{machine_alias}:{ip_value}:"
                    f"{previous_status}-to-{status_value}:{transition_fingerprint}"
                )
                try:
                    await self._post_bound_notice(
                        repo, pr_number, head_sha=new_state["head_sha"],
                        round_id=round_id, comment_id=anchor_comment_id,
                        topic=topic, message=message,
                    )
                except Exception as exc:
                    logger.warning("runtime image notice failed repo=%s pr=%s reason=%s",
                                   repo, pr_number, type(exc).__name__)
            return new_state
        except Exception as exc:
            logger.warning("runtime image state refresh failed repo=%s pr=%s reason=%s",
                           repo, pr_number, type(exc).__name__)
            return state

    # ── Reconcile ──

    async def reconcile_pr(self, repo: str, pr_number: int) -> None:
        """Reconcile lifecycle state for a PR.

        Called by the watcher before processing commands each cycle.
        Handles uncertain command state and status label projection.
        """
        state = await self.proxy.read_hidden_state(repo, pr_number)
        pr_data = await self.proxy.get_pr(repo, pr_number)
        if inspect.isawaitable(pr_data):
            pr_data = await pr_data
        if not isinstance(pr_data, dict):
            return
        pr_state = pr_data.get("state", "")
        pr_merged = pr_data.get("merged", False)
        current_head = str(pr_data.get("head", {}).get("sha", "") or "")

        if pr_state == "open" and pr_data.get("draft") is True:
            # Draft PRs need an explicit status label, but they are not
            # lifecycle evidence. Never initialize or advance review status
            # from comments until GitHub marks the PR ready for review.
            label_status = "review-required"
            if (isinstance(state, dict)
                    and re.fullmatch(r"[0-9a-f]{40}", current_head)
                    and state.get("head_sha") == current_head):
                label_status = state.get("status", "review-required")
                acceptance = state.get("acceptance_request")
                if (label_status == "testing"
                        and isinstance(acceptance, dict)
                        and acceptance.get("status") == "pending"
                        and acceptance.get("head_sha") == current_head
                        and acceptance.get("round_id") == round_id_for_state(state)):
                    label_status = "acceptance-required"
            if label_status in {
                "review-required", "reviewing", "deploy-ready",
                "deploy-requested", "deploying", "testing", "acceptance-required",
                "succeeded", "failed",
            }:
                try:
                    await self.proxy.project_status_label(
                        repo, pr_number, label_status,
                    )
                except Exception as exc:
                    logger.warning(
                        "reconcile draft PR label projection %s#%s exception=%s",
                        repo, pr_number, type(exc).__name__,
                    )
            return

        if pr_state != "open" or pr_merged or pr_data.get("draft"):
            # Closed PRs do not participate in lifecycle recovery or label projection.
            return
        if not re.fullmatch(r"[0-9a-f]{40}", current_head):
            return

        if state is not None:
            pending_logs = state.get("deployment_logs", {})
            if isinstance(pending_logs, dict):
                for machine_alias, log_task in list(pending_logs.items()):
                    if (isinstance(log_task, dict) and log_task.get("status") == "pending"
                            and log_task.get("head_sha") == state.get("head_sha")
                            and log_task.get("round_id") == state.get("round_id")):
                        await self._save_deployed_machine_log(repo, pr_number, state, machine_alias)
                        refreshed = await self.proxy.read_hidden_state(repo, pr_number)
                        if not isinstance(refreshed, dict) or refreshed.get("head_sha") != current_head:
                            return
                        state = refreshed
            cmd = state.get("command", {})
            cmd_phase = cmd.get("phase", "") if isinstance(cmd, dict) else ""
            same_head = current_head == state.get("head_sha", "")
            command_args = cmd.get("args", {}) if isinstance(cmd, dict) else {}
            if (same_head
                    and isinstance(cmd, dict)
                    and cmd.get("kind") == "approve_deploy"
                    and cmd_phase == "completed"
                    and isinstance(command_args, dict)
                    and command_args.get("preflight_pending") is True):
                try:
                    restored = await self._restore_interrupted_approval_preflight(
                        repo, pr_number,
                        reason="上一次审批在部署前检查阶段中断，当时没有发送部署请求，这次也没有重复发送。",
                        topic="approval-preflight-retry-required",
                        require_stale=True,
                    )
                except Exception as exc:
                    logger.warning(
                        "approval preflight recovery %s#%s failed: %s",
                        repo, pr_number, type(exc).__name__,
                    )
                    restored = False
                if restored:
                    return
                try:
                    latest_state = await self.proxy.read_hidden_state(repo, pr_number)
                except Exception as exc:
                    logger.warning(
                        "approval preflight recovery readback %s#%s failed: %s",
                        repo, pr_number, type(exc).__name__,
                    )
                    return
                latest_command = (
                    latest_state.get("command")
                    if isinstance(latest_state, dict) else None
                )
                latest_args = (
                    latest_command.get("args", {})
                    if isinstance(latest_command, dict) else {}
                )
                if (not isinstance(latest_state, dict)
                        or latest_state.get("head_sha") != current_head
                        or not isinstance(latest_command, dict)
                        or latest_command.get("kind") != "approve_deploy"
                        or latest_command.get("phase") != "completed"
                        or latest_command.get("comment_id") != cmd.get("comment_id")
                        or not isinstance(latest_args, dict)
                        or latest_args.get("preflight_pending") is not True):
                    return
                await self._project_status_best_effort(
                    repo, pr_number, "deploying",
                )
                return
            if (cmd_phase == "executing" and same_head
                    and state.get("status") in {"deploying", "deploy-requested", "deploy-ready"}):
                await self._handle_uncertain_if_needed(repo, pr_number, state)
                return
            if (cmd_phase == "uncertain" and same_head
                    and state.get("status") in {"deploying", "deploy-requested", "deploy-ready"}):
                await self._recover_uncertain_deployment_tick(
                    repo, pr_number, state, pr_data,
                )
                return

            if current_head and current_head != state.get("head_sha", ""):
                old_status = state.get("status", "review-required")
                archived = await self._archive_round(
                    repo, pr_number, copy.deepcopy(state), "HEAD changed",
                )
                self._reset_review_lifecycle_state(
                    state,
                    head_sha=current_head,
                    status="review-required",
                    review_evidence={},
                )
                state["round_archive"] = archived
                state["command"] = {
                    "comment_id": int(state.get("last_processed_comment_id", 0) or 0),
                    "kind": "",
                    "phase": "completed",
                    "args": {},
                }
                try:
                    markdown = comments_mod.review_required(repo, pr_number, current_head)
                    event = {
                        "event": "HEAD drift detected",
                        "lifecycle": f"`{old_status}` \u2192 `review-required`",
                        "timestamp": comments_mod.beijing_now_str(),
                    }
                    await self._write_lifecycle_with_history(
                        repo, pr_number, state, markdown, event=event,
                    )
                    await self.proxy.project_status_label(repo, pr_number, "review-required")
                except Exception as e:
                    logger.warning(
                        "reconcile head drift %s#%s: %s", repo, pr_number, e,
                    )
                return

            if (state.get("status") in {
                    "deploy-requested", "testing", "succeeded", "failed",
                }
                    and isinstance(state.get("deployments"), list)
                    and any(isinstance(deployment, dict)
                            and deployment.get("phase") == "deployed"
                            and deployment.get("component_ids")
                            for deployment in state["deployments"])):
                state = await self._reconcile_runtime_image_checks(
                    repo, pr_number, state, pr_data,
                )

            if state.get("status") in ("succeeded", "failed"):
                try:
                    await self.proxy.project_status_label(repo, pr_number, state["status"])
                except Exception as exc:
                    logger.warning("reconcile label projection %s#%s exception=%s",
                                   repo, pr_number, type(exc).__name__)
                await self._retry_terminal_cos(repo, pr_number, state)
                return

            if state.get("status") == "deploy-requested":
                try:
                    state = await self._recover_deploy_requested_review(
                        repo, pr_number, state, current_head,
                    )
                except Exception as e:
                    # A read or identity failure leaves the frozen request
                    # untouched. The approval path independently keeps its
                    # fresh-evidence gate closed.
                    logger.warning(
                        "reconcile review recovery %s#%s: %s",
                        repo, pr_number, type(e).__name__,
                    )
                try:
                    await self.proxy.project_status_label(
                        repo, pr_number, state.get("status", "review-required"),
                    )
                except Exception as e:
                    logger.warning(
                        "reconcile label projection %s#%s: %s", repo, pr_number, e,
                    )
                return

            # Deployment and manual testing are decoupled. Preserve any legacy
            # case_results as history, but never launch automated Cases here.
            if state.get("status") == "testing":
                try:
                    acceptance = state.get("acceptance_request")
                    pending_acceptance = (
                        isinstance(acceptance, dict)
                        and acceptance.get("status") == "pending"
                        and acceptance.get("head_sha") == state.get("head_sha")
                        and acceptance.get("round_id") == round_id_for_state(state)
                    )
                    await self.proxy.project_status_label(
                        repo, pr_number,
                        "acceptance-required" if pending_acceptance else "testing",
                    )
                except Exception as e:
                    logger.warning(
                        "reconcile label projection %s#%s: %s", repo, pr_number, e,
                    )
                return

            if state.get("status") == "deploying":
                try:
                    await self.proxy.project_status_label(repo, pr_number, "deploying")
                except Exception as exc:
                    logger.warning("reconcile deploying label %s#%s exception=%s",
                                   repo, pr_number, type(exc).__name__)
                return

        if pr_state != "open" or pr_merged:
            if state is not None:
                try:
                    await self.proxy.project_status_label(
                        repo, pr_number, state.get("status", "review-required"),
                    )
                except Exception as e:
                    logger.warning(
                        "reconcile label projection %s#%s: %s", repo, pr_number, e,
                    )
            return

        if not current_head:
            return

        # Fetch PR comments and extract review evidence from GitHub comments
        components: list[dict] = []
        try:
            comments = await self.github.get_issue_comments(repo, pr_number)
            if not isinstance(comments, list):
                raise GitHubStateProxyError(
                    "GitHub PR comments response was not a list",
                )

            from .review_comment_parser import extract_latest_review_job_anchor

            # Step 1: Get canonical latest anchor FIRST
            latest_anchor = extract_latest_review_job_anchor(
                comments,
                self.config.review_comment_author_id,
                self.config.review_comment_author_login,
            )

            if latest_anchor is None:
                desired_status = "review-required"
                review_evidence_data: dict = {}
                build_infos: list[BuildInfo] = []
            else:
                resolved_head = await self._resolve_commit_prefix_for_head(
                    repo, current_head, latest_anchor.commit_prefix,
                )
                if resolved_head is None:
                    # Cannot resolve anchor commit prefix to fresh HEAD
                    desired_status = "review-required"
                    review_evidence_data = {}
                    build_infos = []
                elif latest_anchor.state == "terminal":
                    # Build failed / malformed — must NOT fall back
                    desired_status = "review-required"
                    review_evidence_data = {}
                    build_infos = []
                elif latest_anchor.state == "reviewing":
                    # Queued / Building / incomplete — project reviewing, NEVER fall back
                    desired_status = "reviewing"
                    review_evidence_data = {}
                    build_infos = []
                elif latest_anchor.state == "build-succeeded":
                    # Build completed successfully — get full evidence for deploy-ready check
                    evidence = await self._review_evidence_from_comments(repo, pr_number, current_head, comments)
                    if evidence is None:
                        # Build succeeded but Test/Code Review not yet complete
                        desired_status = "reviewing"
                        review_evidence_data = {}
                        build_infos = []
                    else:
                        resolved_head_ev = await self._resolve_review_evidence_for_head(
                            repo, current_head, evidence, pr_number=pr_number,
                        )
                        build_infos = self._review_build_infos(repo, evidence)
                        components = await self._build_component_snapshot(
                            repo, pr_number, current_head, build_infos,
                        ) if resolved_head_ev == current_head else None
                        if resolved_head_ev != current_head or not components:
                            desired_status = "review-required"
                            review_evidence_data = {}
                            build_infos = []
                        else:
                            desired_status = "deploy-ready"
                            review_evidence_data = self._review_evidence_snapshot(evidence, resolved_head_ev)
                else:
                    desired_status = "review-required"
                    review_evidence_data = {}
                    build_infos = []
        except Exception as e:
            logger.warning(
                "reconcile comment evidence %s#%s head=%s: %s",
                repo, pr_number, current_head, e,
            )
            # An incomplete/transient comment read is not evidence that prior
            # review approval disappeared. Never initialize from an unknown
            # response, nor clear a trusted current-HEAD deployment or result.
            # A label repair may still reflect the verified hidden-state value.
            if (isinstance(state, dict)
                    and state.get("head_sha") == current_head):
                try:
                    label_status = state.get("status", "")
                    acceptance = state.get("acceptance_request")
                    if (label_status == "testing"
                            and isinstance(acceptance, dict)
                            and acceptance.get("status") == "pending"
                            and acceptance.get("head_sha") == current_head
                            and acceptance.get("round_id") == round_id_for_state(state)):
                        label_status = "acceptance-required"
                    if label_status in {
                        "review-required", "reviewing", "deploy-ready",
                        "deploy-requested", "deploying", "testing", "acceptance-required",
                        "succeeded", "failed",
                    }:
                        await self.proxy.project_status_label(
                            repo, pr_number, label_status,
                        )
                except Exception as label_exc:
                    logger.warning(
                        "reconcile fallback label projection %s#%s exception=%s",
                        repo, pr_number, type(label_exc).__name__,
                    )
            return

        lifecycle_before_update = copy.deepcopy(state) if isinstance(state, dict) else None
        state_was_none = state is None
        if state is None:
            state = self._init_hidden_state(
                head_sha=current_head,
                status=desired_status,
                review_evidence=review_evidence_data,
                components=components if desired_status == "deploy-ready" else [],
                deployments=[],
            )
            state["command"] = {
                "comment_id": 0,
                "kind": "",
                "phase": "completed",
                "args": {},
            }
            state["last_processed_comment_id"] = 0
        else:
            prev_status = state.get("status", "review-required")
            prev_head = state.get("head_sha", "")
            prev_evidence = state.get("review_evidence", {})
            state["head_sha"] = current_head
            state["status"] = desired_status
            state["review_evidence"] = review_evidence_data
            state["components"] = components if desired_status == "deploy-ready" else []
            state["deployments"] = []
            state["approve_attempts"] = []
            state["approve_attempts_total"] = 0
            state["approve_attempts_truncated"] = False
            state["case_results"] = {}
            state["test_result"] = ""
            state["cos"] = {"object_key": "", "sha256": "", "size": 0}
            state["command"] = {
                "comment_id": int(state.get("last_processed_comment_id", 0) or 0),
                "kind": "",
                "phase": "completed",
                "args": {},
            }

        if desired_status == "deploy-ready":
            build_comment_id = review_evidence_data.get("build_comment_id")
            if type(build_comment_id) is int and build_comment_id > 0:
                state["round_id"] = make_round_id(current_head, build_comment_id)
                state["round_started_at"] = state.get("round_started_at") or utc_now()

        # No-churn: only write lifecycle/history if there is a real change
        # (prev_status/prev_head/prev_evidence captured BEFORE state mutation above)
        if state_was_none:
            meaningful_change = True
        else:
            meaningful_change = (
                prev_status != desired_status
                or prev_head != current_head
                or prev_evidence != review_evidence_data
            )

        if not meaningful_change:
            # Same state, no meaningful change — only project status label
            try:
                await self.proxy.project_status_label(repo, pr_number, desired_status)
            except Exception as e:
                logger.warning(
                    "reconcile label projection %s#%s: %s", repo, pr_number, e,
                )
            if desired_status == "deploy-ready":
                await self._post_deploy_ready_notice(
                    repo, pr_number, head_sha=current_head,
                    round_id=round_id_for_state(state),
                    review_evidence=state.get("review_evidence", {}),
                    components=state.get("components", []),
                )
        else:
            try:
                if desired_status == "reviewing":
                    markdown = comments_mod.reviewing(repo, pr_number, current_head)
                elif desired_status == "review-required":
                    markdown = comments_mod.review_required(repo, pr_number, current_head)
                else:
                    all_machine_groups = self._get_machine_groups_for_components(
                        components, repo,
                    )
                    verified_groups = await self._machine_groups_verify_endpoints(
                        all_machine_groups, repo, components,
                    )
                    markdown = comments_mod.deploy_ready(
                        repo, pr_number, current_head, build_infos,
                        review_evidence=review_evidence_data,
                        machine_groups=verified_groups,
                        components=components,
                    )
                if state_was_none:
                    event = {
                        "event": "Lifecycle initialized",
                        "lifecycle": f"`none` \u2192 `{desired_status}`",
                        "timestamp": comments_mod.beijing_now_str(),
                    }
                else:
                    event = {
                        "event": "Review lifecycle transitioned",
                        "lifecycle": f"`{prev_status}` \u2192 `{desired_status}`",
                        "timestamp": comments_mod.beijing_now_str(),
                    }
                async def guard_deploy_ready_review() -> bool:
                    return await self._fresh_review_evidence_matches_state(
                        repo, pr_number, current_head, review_evidence_data,
                        expected_components=components,
                    )

                written = await self._write_lifecycle_with_history(
                    repo, pr_number, state, markdown, event=event,
                    expected_lifecycle_state=lifecycle_before_update,
                    write_guard=(guard_deploy_ready_review
                                 if desired_status == "deploy-ready" else None),
                )
                if not written:
                    return
                await self._project_status_best_effort(
                    repo, pr_number, desired_status,
                )
                if desired_status == "deploy-ready":
                    await self._post_deploy_ready_notice(
                        repo, pr_number, head_sha=current_head,
                        round_id=round_id_for_state(state),
                        review_evidence=review_evidence_data,
                        components=components,
                    )
            except Exception as e:
                logger.warning(
                    "reconcile lifecycle %s#%s: %s", repo, pr_number, e,
                )

    @staticmethod
    def _ensure_uncertain_since(command: dict) -> tuple[float | None, bool]:
        """Persist one stable epoch timestamp in command args for recovery timing."""
        args = command.get("args") if isinstance(command, dict) else None
        if not isinstance(args, dict):
            return None, False
        for key in ("uncertain_since", "execution_started_at"):
            value = args.get(key)
            if type(value) not in {int, float}:
                continue
            try:
                timestamp = float(value)
            except (OverflowError, ValueError):
                continue
            if math.isfinite(timestamp) and timestamp > 0:
                if key == "uncertain_since":
                    return timestamp, False
                args["uncertain_since"] = timestamp
                return timestamp, True
        value = time.time()
        args["uncertain_since"] = value
        return value, True

    async def _handle_uncertain_if_needed(
        self, repo: str, pr_number: int, state: dict,
    ) -> None:
        """On startup, if hidden command.phase is executing, mark as uncertain."""
        original_state = copy.deepcopy(state)
        cmd = state.get("command", {})
        if cmd.get("phase") != "executing":
            return
        args = cmd.get("args", {})
        if isinstance(args, dict) and "execution_started_at" in args:
            try:
                execution_started_at = float(args.get("execution_started_at"))
                stale_after = max(900.0, float(self.config.total_timeout) * 3.0)
            except (TypeError, ValueError, OverflowError):
                execution_started_at = 0.0
                stale_after = 0.0
            execution_age = time.time() - execution_started_at
            if (math.isfinite(execution_started_at) and execution_started_at > 0
                    and 0 <= execution_age < stale_after):
                # A duplicate command or periodic reconciliation may observe a
                # live POST. Preserve its CAS token until the bounded operation
                # window has elapsed; never turn an active attempt uncertain.
                return

        logger.warning(
            "startup: found executing command %s (comment %s) in %s#%s "
            "- marking as uncertain",
            cmd.get("kind", "?"), cmd.get("comment_id", "?"),
            repo, pr_number,
        )

        cmd["phase"] = "uncertain"
        self._ensure_uncertain_since(cmd)
        state["status"] = "deploying"
        state["command"] = cmd
        comment_id = int(cmd.get("comment_id") or 0)
        old_cursor = int(state.get("last_processed_comment_id", 0) or 0)
        if comment_id > old_cursor:
            state["last_processed_comment_id"] = comment_id
        # Extract canonical machine alias from command args (safe read)
        cmd_args = cmd.get("args", {})
        machine_alias = ""
        if isinstance(cmd_args, dict):
            raw_machine = cmd_args.get("machine", "")
            if isinstance(raw_machine, str):
                machine_alias = raw_machine


        markdown = self._set_lifecycle_summary_status(
            comments_mod.uncertain_comment(repo, pr_number, state.get("head_sha", "")),
            "deploying",
        )
        if not self._deployment_request_was_submitted(state):
            markdown = self._mark_request_step_not_submitted(markdown)
        markdown += (
            "\n\n部署结果还在确认中，确认之前不会重复提交部署。"
        )
        event = {
            "event": "Deploy outcome uncertain",
            "result": "uncertain",
            "timestamp": comments_mod.beijing_now_str(),
        }
        if machine_alias:
            event["machine"] = machine_alias
        written = await self._write_lifecycle_with_history(
            repo, pr_number, state, markdown, event=event,
            expected_lifecycle_state=original_state,
        )
        if not written:
            return
        await self.proxy.project_status_label(
            repo, pr_number, "deploying",
        )
        if comment_id:
            try:
                await self._post_bound_notice(
                    repo, pr_number, head_sha=state.get("head_sha", ""),
                    round_id=round_id_for_state(state), comment_id=comment_id,
                    topic="deployment-recovery-waiting",
                    expected_command_kind="approve_deploy",
                    message="部署结果还在确认中，确认之前不会重复提交部署。",
                )
            except Exception as exc:
                logger.warning("uncertain notice %s#%s exception=%s",
                               repo, pr_number, type(exc).__name__)

    async def _recover_uncertain_deployments(
        self, repo: str, old_state: dict, refreshed_state: dict,
    ) -> bool:
        """Observe attempted components within one short budget; never repost."""
        old_command = old_state.get("command", {})
        args = old_command.get("args", {}) if isinstance(old_command, dict) else {}
        if not isinstance(args, dict):
            return False
        machine_alias = args.get("machine", "")
        if not isinstance(machine_alias, str) or not machine_alias:
            return False
        machine = self.policy.get_machine(machine_alias, repo=repo)
        if machine is None:
            return False
        expected_node_id = args.get("node_id")
        expected_node_host = args.get("node_host")
        if (not isinstance(expected_node_id, str) or not expected_node_id
                or not isinstance(expected_node_host, str) or not expected_node_host
                or machine.node_id != expected_node_id
                or not self._machine_endpoint_has_unambiguous_identity(
                    machine, expected_node_host, repo,
                    self._policy_machine_identity(machine, repo),
                )):
            logger.warning(
                "uncertain deployment machine binding changed; refusing to infer completion %s machine=%s",
                repo, machine_alias,
            )
            return False
        old_components = old_state.get("components", [])
        if not isinstance(old_components, list):
            return False
        fresh_components = refreshed_state.get("components", [])
        if not isinstance(fresh_components, list):
            return False
        fresh_command = refreshed_state.get("command", {})
        old_args = args
        fresh_args = fresh_command.get("args", {}) if isinstance(fresh_command, dict) else {}
        if (
            old_state.get("status") not in {
                "deploying", "deploy-requested", "deploy-ready",
            }
            or refreshed_state.get("status") not in {
                "deploying", "deploy-requested", "deploy-ready",
            }
            or old_state.get("head_sha") != refreshed_state.get("head_sha")
            or round_id_for_state(old_state) != round_id_for_state(refreshed_state)
            or old_state.get("round_archive") != refreshed_state.get("round_archive")
            or old_state.get("deployments") != refreshed_state.get("deployments")
            or not isinstance(old_command, dict)
            or not isinstance(fresh_command, dict)
            or old_command.get("kind") != "approve_deploy"
            or fresh_command.get("kind") != "approve_deploy"
            or old_command.get("phase") != "uncertain"
            or fresh_command.get("phase") not in {"uncertain", "completed"}
            or old_command.get("comment_id") != fresh_command.get("comment_id")
            or type(old_command.get("comment_id")) is not int
            or old_command.get("comment_id", 0) <= 0
            or type(old_state.get("last_processed_comment_id")) is not int
            or old_state.get("last_processed_comment_id", 0) < old_command.get("comment_id", 0)
            or type(refreshed_state.get("last_processed_comment_id")) is not int
            or refreshed_state.get("last_processed_comment_id", 0) < old_command.get("comment_id", 0)
            or not isinstance(old_args, dict)
            or not isinstance(fresh_args, dict)
            or not isinstance(old_args.get("machine"), str)
            or not old_args.get("machine")
            or not isinstance(old_args.get("actor"), str)
            or not old_args.get("actor")
            or old_args.get("machine") != fresh_args.get("machine")
            or old_args.get("actor") != fresh_args.get("actor")
            or old_args.get("node_id") != fresh_args.get("node_id")
            or old_args.get("node_host") != fresh_args.get("node_host")
            or old_args.get("pending_component_ids") != fresh_args.get("pending_component_ids")
            or old_args.get("deployment_request_submitted")
            != fresh_args.get("deployment_request_submitted")
            or self._review_evidence_identity(old_state.get("review_evidence", {}))
            != self._review_evidence_identity(refreshed_state.get("review_evidence", {}))
        ):
            return False
        deployed = _component_id_set(old_state.get("deployments", []))
        pending = args.get("pending_component_ids")
        old_by_id: dict[str, dict] = {}
        fresh_by_id: dict[str, dict] = {}
        for components, index in ((old_components, old_by_id), (fresh_components, fresh_by_id)):
            for component in components:
                if not isinstance(component, dict):
                    return False
                component_id = component.get("component_id")
                if not isinstance(component_id, str) or not component_id or component_id in index:
                    return False
                index[component_id] = component
        if (not isinstance(pending, list) or not pending
                or any(not isinstance(cid, str) or not cid for cid in pending)
                or len(set(pending)) != len(pending)
                or not set(pending).issubset(old_by_id)
                or not set(pending).issubset(fresh_by_id)
                or set(pending).intersection(deployed)):
            return False
        recovered = []
        unresolved = []
        deadline = time.monotonic() + AGENT_CORE_STATUS_PROBE_TIMEOUT_SECONDS
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            core = await self._core_for_machine_endpoint(
                machine, expected_node_host, repo, timeout=remaining,
            )
            for component_id in dict.fromkeys(pending):
                if component_id in deployed:
                    continue
                old = old_by_id.get(component_id)
                component = fresh_by_id.get(component_id)
                if not isinstance(old, dict) or not isinstance(component, dict):
                    unresolved.append(component_id)
                    continue
                identity_fields = (
                    "component_id", "target", "driver_path", "variant",
                    "review_image_tag", "image_ref",
                )
                if any(
                    not isinstance(old.get(field), str)
                    or old.get(field) != component.get(field)
                    for field in identity_fields
                ):
                    unresolved.append(component_id)
                    continue
                if (not old.get("target") or not old.get("review_image_tag")
                        or not old.get("image_ref")
                        or component_id not in self._get_component_ids_for_machine(
                            machine_alias, [component], repo,
                        )):
                    unresolved.append(component_id)
                    continue
                old_runtime_id = old.get("runtime_id")
                fresh_runtime_id = component.get("runtime_id")
                if old.get("target") == "core":
                    if old_runtime_id != "core" or fresh_runtime_id != "core":
                        unresolved.append(component_id)
                        continue
                    runtime_id = "core"
                else:
                    if not isinstance(old_runtime_id, str) or not old_runtime_id:
                        unresolved.append(component_id)
                        continue
                    if ("runtime_id" in component
                            and fresh_runtime_id != old_runtime_id):
                        unresolved.append(component_id)
                        continue
                    runtime_id = old_runtime_id
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    unresolved.append(component_id)
                    continue
                image_ref = old.get("image_ref")
                try:
                    observed_image = ""
                    if component.get("target") == "core":
                        update_info = await asyncio.wait_for(
                            core.core_update_check(), timeout=remaining,
                        )
                        running_image = self._current_core_image(update_info)
                        verified = bool(
                            running_image and running_image == image_ref
                        )
                        if verified:
                            observed_image = running_image
                        runtime_id = "core"
                    else:
                        status = await asyncio.wait_for(
                            core.driver_status(runtime_id), timeout=remaining,
                        )
                        verified = bool(
                            isinstance(status, dict) and status.get("status") == "running"
                            and status.get("running_image") == image_ref
                        )
                        if verified:
                            observed_image = str(status.get("running_image", "") or "")
                except (AgentCoreError, asyncio.TimeoutError):
                    verified = False
                if verified:
                    recovered.append((component, image_ref, runtime_id, observed_image))
                else:
                    unresolved.append(component_id)
        except Exception as exc:
            logger.warning("uncertain deployment observation unavailable: %s", type(exc).__name__)
            recovered_component_ids = {
                component["component_id"] for component, _, _, _ in recovered
            }
            unresolved = [
                cid for cid in pending
                if cid not in deployed and cid not in recovered_component_ids
            ]
        # A stale or empty pending list is not proof that any deployment
        # completed. Preserve the uncertain command until an exact target
        # status supplies new deployment evidence.
        if not recovered:
            return False
        already_deployed = _component_id_set(refreshed_state.get("deployments", []))
        refreshed_state["deployments"] = list(refreshed_state.get("deployments", []))
        recovered_rows = []
        recovered_health = []
        for component, image_ref, runtime_id, observed_image in recovered:
            if component["component_id"] in already_deployed:
                continue
            component["runtime_id"] = runtime_id
            component["image_ref"] = image_ref
            row = {
                "machine": machine_alias,
                "ip": expected_node_host,
                "component_ids": [component["component_id"]],
                "phase": "deployed",
            }
            refreshed_state["deployments"].append(row)
            recovered_rows.append(row)
            if component.get("target") == "core":
                recovered_health.append({
                    "component_id": component["component_id"],
                    "runtime_id": "core", "current_tag": observed_image,
                    "target_tag": image_ref,
                    "verified": True,
                })
            else:
                recovered_health.append({
                    "component_id": component["component_id"],
                    "runtime_id": runtime_id, "running_image": observed_image,
                    "status": "running", "verified": True,
                })
        if recovered_rows:
            self._record_redeployed_runtime_matches(
                refreshed_state, machine, recovered_rows, recovered_health,
            )
        updated_command = copy.deepcopy(refreshed_state.get("command", old_command))
        if not isinstance(updated_command, dict):
            return False
        updated_args = updated_command.get("args", {})
        if not isinstance(updated_args, dict):
            updated_args = {}
        updated_args = dict(updated_args)
        updated_args["pending_component_ids"] = unresolved
        updated_command["args"] = updated_args
        updated_command["phase"] = "uncertain" if unresolved else "completed"
        refreshed_state["command"] = updated_command
        all_ids = {c["component_id"] for c in refreshed_state.get("components", [])}
        if all_ids and all_ids == _component_id_set(refreshed_state.get("deployments", [])):
            refreshed_state["status"] = "testing"
            refreshed_state.pop("acceptance_request", None)
        elif not unresolved:
            refreshed_state["status"] = self._approval_retry_status(refreshed_state)
        else:
            refreshed_state["status"] = "deploying"
        return not unresolved

    async def _post_deployment_recovery_escalation(
        self, repo: str, pr_number: int, state: dict,
    ) -> bool:
        """Post one idempotent operator notice for a long-running uncertain deployment."""
        command = state.get("command", {})
        args = command.get("args", {}) if isinstance(command, dict) else {}
        if not isinstance(args, dict):
            return False
        machine_alias = args.get("machine")
        endpoint = self._canonical_primary_ipv4(args.get("node_host"))
        comment_id = command.get("comment_id") if isinstance(command, dict) else None
        head_sha = state.get("head_sha", "")
        if (not isinstance(machine_alias, str) or not machine_alias
                or not endpoint or type(comment_id) is not int or comment_id <= 0
                or not isinstance(head_sha, str)):
            return False
        pending = args.get("pending_component_ids")
        if not isinstance(pending, list):
            return False
        pending_ids = list(dict.fromkeys(
            item for item in pending if isinstance(item, str) and item
        ))
        if not pending_ids:
            return False
        components = state.get("components", [])
        by_id = {
            item.get("component_id"): item
            for item in components if isinstance(item, dict)
            and isinstance(item.get("component_id"), str)
        } if isinstance(components, list) else {}
        lines = []
        for component_id in pending_ids:
            component = by_id.get(component_id, {})
            target = str(component.get("target") or component_id)
            image_ref = component.get("image_ref") or component.get("review_image_tag")
            image_text = f"`{image_ref}`" if isinstance(image_ref, str) and image_ref else "无法从当前状态读取"
            lines.append(
                f"- {target}（`{component_id}`）：目标镜像 {image_text}"
            )
        message = "\n".join([
            "部署结果已超过 15 分钟仍无法确认。",
            f"机器：`{machine_alias}`",
            f"本次审批时已验证并绑定的 IP：`{endpoint}`",
            "未确认的组件及目标镜像：",
            *lines,
            "请检查 Agent Core 和机器运行状态。",
            "不要重复执行 `/approve_deploy`。",
            "控制器会继续只读核对，确认后自动更新状态。",
        ])
        return await self._post_bound_notice(
            repo, pr_number,
            head_sha=head_sha,
            round_id=round_id_for_state(state),
            comment_id=comment_id,
            topic="deployment-recovery-escalation",
            result=None,
            expected_command_kind="approve_deploy",
            message=message,
        )

    async def _recover_uncertain_deployment_tick(
        self, repo: str, pr_number: int, state: dict, pr_data: dict,
    ) -> None:
        """Run one short restart-safe observation tick and persist only changes."""
        command = state.get("command", {})
        if (not isinstance(command, dict) or command.get("kind") != "approve_deploy"
                or command.get("phase") != "uncertain"
                or state.get("status") not in {
                    "deploying", "deploy-requested", "deploy-ready",
                }
                or pr_data.get("head", {}).get("sha") != state.get("head_sha")):
            return
        refreshed = copy.deepcopy(state)
        if refreshed.get("status") in {"deploy-ready", "deploy-requested"}:
            refreshed["status"] = "deploying"
        try:
            await self._recover_uncertain_deployments(repo, state, refreshed)
        except Exception as exc:
            logger.warning("uncertain deployment recovery tick %s#%s failed: %s",
                           repo, pr_number, type(exc).__name__)
        refreshed_command = refreshed.get("command", {})
        uncertain_since = None
        if (isinstance(refreshed_command, dict)
                and refreshed_command.get("phase") == "uncertain"):
            uncertain_since, _ = self._ensure_uncertain_since(refreshed_command)
            refreshed["command"] = refreshed_command
        pending_ids = (
            refreshed_command.get("args", {}).get("pending_component_ids", [])
            if isinstance(refreshed_command, dict)
            and isinstance(refreshed_command.get("args"), dict) else []
        )
        escalation_due = (
            state.get("status") in {
                "deploying", "deploy-requested", "deploy-ready",
            }
            and refreshed.get("status") == "deploying"
            and isinstance(refreshed_command, dict)
            and refreshed_command.get("phase") == "uncertain"
            and isinstance(uncertain_since, (int, float))
            and time.time() - uncertain_since >= DEPLOYMENT_UNCERTAIN_ESCALATION_SECONDS
            and isinstance(pending_ids, list)
            and any(isinstance(item, str) and item for item in pending_ids)
        )
        if refreshed == state:
            if escalation_due:
                try:
                    await self._post_deployment_recovery_escalation(
                        repo, pr_number, refreshed,
                    )
                except Exception as exc:
                    logger.warning(
                        "deployment recovery escalation %s#%s failed: %s",
                        repo, pr_number, type(exc).__name__,
                    )
            await self._project_status_best_effort(
                repo, pr_number, state.get("status", "deploying"),
            )
            return
        refreshed["last_processed_comment_id"] = max(
            int(state.get("last_processed_comment_id", 0) or 0),
            int(command.get("comment_id", 0) or 0),
        )
        args = command.get("args", {}) if isinstance(command.get("args"), dict) else {}
        machine_alias = str(args.get("machine", "") or "")
        recovered_ids = _component_id_set(refreshed.get("deployments", [])) - _component_id_set(
            state.get("deployments", []),
        )
        required_ids = {
            item.get("component_id") for item in refreshed.get("components", [])
            if isinstance(item, dict) and isinstance(item.get("component_id"), str)
        }
        deployments_complete = bool(required_ids) and required_ids.issubset(
            _component_id_set(refreshed.get("deployments", [])),
        )
        if refreshed.get("status") == "testing":
            markdown = comments_mod.testing(
                repo, pr_number, refreshed.get("head_sha", ""), case_result="",
                deployments=self._enrich_deployments_for_render(refreshed.get("deployments", []), repo),
                components=refreshed.get("components", []),
                deployments_complete=deployments_complete,
            )
        else:
            unresolved = refreshed.get("command", {}).get("args", {}).get(
                "pending_component_ids", [],
            )
            remaining_components = [
                item for item in refreshed.get("components", [])
                if item.get("component_id") not in _component_id_set(
                    refreshed.get("deployments", []),
                )
            ]
            remaining_groups = (
                self._runtime_redeploy_machine_groups(
                    refreshed, remaining_components, repo,
                ) if refreshed.get("runtime_redeploy") else
                self._get_machine_groups_for_components(remaining_components, repo)
            )
            gate_note = ([
                "上一次部署还在确认中，确认之前不会重复提交部署。",
            ] if unresolved else [
                "上一次部署已经确认完成，剩余组件需要重新审批。",
            ])
            markdown = await self._approval_retry_markdown(
                repo, pr_number, refreshed, remaining_groups,
                test_only=self._is_test_only_pr(pr_data),
                gate_note=gate_note,
                deployments=self._enrich_deployments_for_render(refreshed.get("deployments", []), repo),
                display_status=refreshed.get("status", "deploy-requested"),
            )
        event = None
        if recovered_ids:
            event = {
                "event": "Deployment status recovered",
                "result": "verified",
                "machine": machine_alias,
                "timestamp": comments_mod.beijing_now_str(),
            }
        written = await self._write_lifecycle_with_history(
            repo, pr_number, refreshed, markdown, event=event,
            expected_terminal_state=state,
        )
        if written:
            if recovered_ids and machine_alias:
                try:
                    await self._save_deployed_machine_log(repo, pr_number, refreshed, machine_alias)
                except Exception:
                    logger.warning("recovered machine log save failed %s#%s", repo, pr_number)
            try:
                await self.proxy.project_status_label(repo, pr_number, refreshed["status"])
            except Exception as exc:
                logger.warning("uncertain recovery label %s#%s exception=%s",
                               repo, pr_number, type(exc).__name__)
            if escalation_due:
                try:
                    await self._post_deployment_recovery_escalation(
                        repo, pr_number, refreshed,
                    )
                except Exception as exc:
                    logger.warning(
                        "deployment recovery escalation %s#%s failed: %s",
                        repo, pr_number, type(exc).__name__,
                    )
            if (refreshed.get("status") == "testing"
                    and state.get("status") != "testing"):
                approval_comment_id = int(command.get("comment_id", 0) or 0)
                upload_url = await self._current_testing_upload_url(
                    repo, pr_number, head_sha=refreshed["head_sha"],
                    round_id=round_id_for_state(refreshed),
                    approval_comment_id=approval_comment_id,
                )
                upload_message = (
                    f"可选上传测试视频或图片，方便验收人了解实际效果：[打开固定上传页面](<{upload_url}>)。"
                    if upload_url else
                    "测试视频或图片上传完全可选；公共上传入口暂时不可用时不影响测试和验收，"
                    "恢复后 PR Summary 会出现同一个固定链接。"
                )
                await self._post_bound_notice(
                    repo, pr_number, head_sha=refreshed["head_sha"],
                    round_id=round_id_for_state(refreshed),
                    comment_id=approval_comment_id,
                    topic="deployment-recovered-complete",
                    expected_command_kind="approve_deploy",
                    result="accepted",
                    message=(
                        "上一次部署已经确认完成，现在可以开始测试。\n\n"
                        f"{upload_message}\n\n"
                        "测试完成后，请发送 `/request_acceptance` 提交验收。"
                    ),
                )
            elif recovered_ids and refreshed.get("status") in {"deploy-requested", "deploy-ready"}:
                remaining = [
                    item for item in refreshed.get("components", [])
                    if item.get("component_id") not in _component_id_set(refreshed.get("deployments", []))
                ]
                remaining_groups = (
                    self._runtime_redeploy_machine_groups(refreshed, remaining, repo)
                    if refreshed.get("runtime_redeploy") else
                    self._get_machine_groups_for_components(remaining, repo)
                )
                lines = await self._machine_notice_lines(
                    remaining_groups, repo,
                    mention_owners=False, test_only=self._is_test_only_pr(pr_data),
                    components=remaining,
                )
                await self._post_bound_notice(
                    repo, pr_number, head_sha=refreshed["head_sha"],
                    round_id=round_id_for_state(refreshed),
                    comment_id=int(command.get("comment_id", 0) or 0),
                    topic="deployment-recovered-partial",
                    expected_command_kind="approve_deploy",
                    result="accepted",
                    message="\n".join([
                        "部署已经部分完成，剩余组件需要其他机器审批。",
                        *(
                            lines if lines else
                            self._machine_blocking_summary(remaining_groups)
                        ),
                    ]),
                )

    async def _refresh_uncertain_state(
        self, repo: str, pr_number: int, state: dict,
    ) -> str:
        """Refresh an uncertain command without replaying the old comment.

        Returns:
        - "deploy-requested" when a fresh validation snapshot was rebuilt.
        - "testing" when every deployment was observed successful without POST.
        - "review-required" when the head drifted.
        - "uncertain" when the rebuild could not complete but must stay pending.
        - "noop" when the PR is no longer open/active.
        """
        original_state = copy.deepcopy(state)
        cmd = state.get("command", {})
        machine_alias = str(cmd.get("args", {}).get("machine", "") or "")
        comment_id = int(cmd.get("comment_id", 0) or 0)
        old_cursor = int(state.get("last_processed_comment_id", 0) or 0)

        pr_data = await self.proxy.get_pr(repo, pr_number)
        pr_state = pr_data.get("state", "")
        pr_merged = pr_data.get("merged", False)
        current_head = pr_data.get("head", {}).get("sha", "")

        if pr_state != "open" or pr_merged or pr_data.get("draft"):
            return "noop"

        if not current_head:
            return "uncertain"
        if not re.fullmatch(r"[0-9a-f]{40}", str(current_head)):
            return "uncertain"
        if current_head != state.get("head_sha", ""):
            archived = await self._archive_round(
                repo, pr_number, copy.deepcopy(state), "HEAD changed",
            )
            old_status = state.get("status", "review-required")
            state["status"] = "review-required"
            state["round_id"] = make_round_id(current_head, comment_id)
            state["round_started_at"] = utc_now()
            state.pop("deployment_logs", None)
            state.pop("acceptance_request", None)
            state["review_evidence"] = {}
            state["components"] = []
            state["deployments"] = []
            state.pop("runtime_checks", None)
            state.pop("runtime_redeploy", None)
            state["approve_attempts"] = []
            state["approve_attempts_total"] = 0
            state["approve_attempts_truncated"] = False
            state["case_results"] = {}
            state["test_result"] = ""
            state["cos"] = {"object_key": "", "sha256": "", "size": 0}
            state["round_archive"] = archived
            state["command"] = {
                "comment_id": comment_id,
                "kind": "approve_deploy",
                "phase": "completed",
                "args": dict(cmd.get("args", {}) or {}),
            }
            state["last_processed_comment_id"] = max(old_cursor, comment_id)
            markdown = comments_mod.review_required(
                repo, pr_number, current_head or state.get("head_sha", ""),
            )
            event = {
                "event": "HEAD drift detected",
                "lifecycle": f"`{old_status}` \u2192 `review-required`",
                "timestamp": comments_mod.beijing_now_str(),
            }
            written = await self._write_lifecycle_with_history(
                repo, pr_number, state, markdown, event=event,
                expected_lifecycle_state=original_state,
            )
            if not written:
                return "uncertain"
            await self.proxy.project_status_label(repo, pr_number, "review-required")
            return "review-required"

        # Get build evidence from PR comments
        try:
            comments = await self.github.get_issue_comments(repo, pr_number)
            if not isinstance(comments, list):
                comments = []
            evidence = await self._review_evidence_from_comments(repo, pr_number, current_head, comments)
        except Exception as e:
            logger.warning(
                "refresh_uncertain comment evidence %s#%s: %s",
                repo, pr_number, e,
            )
            evidence = None

        if evidence is None:
            # Missing evidence cannot erase the fact that a POST may have run.
            return "uncertain"

        # Convert evidence builds to BuildInfo
        resolved_head = await self._resolve_review_evidence_for_head(
            repo, current_head, evidence, pr_number=pr_number,
        )
        if resolved_head is None:
            return "uncertain"
        builds = self._review_build_infos(repo, evidence)

        review_evidence_data = self._review_evidence_snapshot(evidence, resolved_head)
        fresh_components = await self._build_component_snapshot(
            repo, pr_number, current_head, builds,
        )
        if fresh_components is None:
            logger.warning(
                "uncertain recovery snapshot rebuild unavailable %s#%s head=%s",
                repo, pr_number, current_head,
            )
            state["status"] = "deploying"
            uncertain_args = dict(cmd.get("args", {}) or {})
            self._ensure_uncertain_since({"args": uncertain_args})
            state["command"] = {
                "comment_id": comment_id,
                "kind": "approve_deploy",
                "phase": "uncertain",
                "args": uncertain_args,
            }
            state["last_processed_comment_id"] = max(old_cursor, comment_id)
            markdown = self._set_lifecycle_summary_status(
                comments_mod.uncertain_comment(repo, pr_number, current_head),
                "deploying",
            )
            if not self._deployment_request_was_submitted(state):
                markdown = self._mark_request_step_not_submitted(markdown)
            if machine_alias:
                markdown += "\n\n" + "\n".join([
                    "目前无法确认机器上的运行状态。",
                    "等待状态可读后按最新 PR Summary 操作，不要重复审批。",
                ])
            event = {
                "event": "Restart recovery snapshot unavailable",
                "result": "uncertain",
                "machine": machine_alias,
                "timestamp": comments_mod.beijing_now_str(),
            }
            await self._write_lifecycle_with_history(
                repo, pr_number, state, markdown, event=event,
                expected_lifecycle_state=original_state,
            )
            return "uncertain"

        old_review_evidence = state.get("review_evidence", {})
        old_components = state.get("components", [])

        # Build semantic-key maps for migration compatibility.
        # A semantic key change (target/driver_path/variant/image_tag) means
        # a genuinely different build — reset everything.
        old_semantic_key_list = [
            self._component_semantic_key(oc)
            for oc in old_components
            if isinstance(oc, dict)
        ]
        old_semantic_duplicate = (
            len(old_semantic_key_list) != len(set(old_semantic_key_list))
        )
        old_semantic_keys = set(old_semantic_key_list)
        fresh_semantic_keys = {
            self._component_semantic_key(fc)
            for fc in fresh_components
            if isinstance(fc, dict)
        }

        # A true evidence/tag change resets everything.
        evidence_changed = (
            self._review_evidence_identity(old_review_evidence)
            != self._review_evidence_identity(review_evidence_data)
        )
        # Symmetric set comparison: detects added, removed, and changed components.
        semantic_changed = old_semantic_duplicate or old_semantic_keys != fresh_semantic_keys

        snapshot_reset = evidence_changed or semantic_changed
        if snapshot_reset:
            # A command may have sent a POST whose result is still unknown.
            # New evidence cannot release that machine/component binding or
            # make the old POST safe to repeat.
            return "uncertain"
        # Same evidence AND same semantic keys — apply migration rules.
        deployed_component_ids: set[str] = set()
        for dep in state.get("deployments", []):
            if isinstance(dep, dict) and dep.get("phase") == "deployed":
                for cid in dep.get("component_ids", []):
                    if isinstance(cid, str) and cid:
                        deployed_component_ids.add(cid)

        # Fail-closed: deployed components must have non-empty runtime_id.
        # If not, keep the outcome uncertain instead of releasing its binding.
        _migration_ok = True
        for old_comp in old_components:
            if not isinstance(old_comp, dict):
                continue
            old_cid = old_comp.get("component_id", "")
            if (old_cid in deployed_component_ids and old_comp.get("target") != "core"):
                runtime_id = old_comp.get("runtime_id", "")
                if not isinstance(runtime_id, str) or not runtime_id:
                    _migration_ok = False
                    break

        if not _migration_ok:
            return "uncertain"
        semantic_map: dict[tuple, dict] = {}
        for fc in fresh_components:
            if isinstance(fc, dict):
                semantic_map[self._component_semantic_key(fc)] = fc

        migrated: list[dict] = []
        for old_comp in old_components:
            if not isinstance(old_comp, dict):
                continue
            skey = self._component_semantic_key(old_comp)
            fresh = semantic_map.get(skey)
            if not fresh:
                continue
            old_cid = old_comp.get("component_id", "")
            is_deployed = old_cid in deployed_component_ids
            if is_deployed:
                migrated_component = {
                    "component_id": old_cid,
                    "target": fresh["target"],
                    "driver_path": fresh["driver_path"],
                    "variant": fresh["variant"],
                    "review_image_tag": fresh["review_image_tag"],
                    "image_ref": old_comp.get("image_ref", ""),
                    "resolved_platform": fresh["resolved_platform"],
                }
                migrated_component = self._fresh_component_runtime_binding(
                    migrated_component
                )
                if fresh["target"] != "core":
                    migrated_component["runtime_id"] = old_comp.get("runtime_id", "")
                migrated.append(migrated_component)
            else:
                migrated.append(self._fresh_component_runtime_binding({
                    "component_id": old_cid,
                    "target": fresh["target"],
                    "driver_path": fresh["driver_path"],
                    "variant": fresh["variant"],
                    "review_image_tag": fresh["review_image_tag"],
                    "image_ref": fresh["image_ref"],
                    "resolved_platform": fresh["resolved_platform"],
                }))

        updated_state = dict(state)
        updated_state["review_evidence"] = review_evidence_data
        updated_state["status"] = "deploying"
        updated_state["command"] = {
            "comment_id": comment_id,
            "kind": "approve_deploy",
            "phase": "completed",
            "args": dict(cmd.get("args", {}) or {}),
        }
        updated_state["last_processed_comment_id"] = max(old_cursor, comment_id)
        updated_state["components"] = migrated

        if snapshot_reset:
            # A fresh build must never adopt old runtime/image provenance as
            # this round's deployment. Only a new approval may deploy it.
            build_id = review_evidence_data.get("build_comment_id") or comment_id
            updated_state["round_id"] = make_round_id(current_head, build_id)
            updated_state["round_started_at"] = utc_now()
            updated_state.pop("deployment_logs", None)
            updated_state.pop("acceptance_request", None)
        old_deployment_facts = copy.deepcopy(state.get("deployments", []))
        if not snapshot_reset and not await self._recover_uncertain_deployments(
            repo, state, updated_state,
        ):
            logger.warning("uncertain deployment remains pending; refusing repeated POST %s#%s", repo, pr_number)
            return "uncertain"
        recovered_machines = set()
        if not snapshot_reset:
            old_facts = {
                (dep.get("machine"), tuple(dep.get("component_ids", ())))
                for dep in old_deployment_facts
                if isinstance(dep, dict) and dep.get("phase") == "deployed"
            }
            recovered_machines = {
                dep.get("machine")
                for dep in updated_state.get("deployments", [])
                if isinstance(dep, dict) and dep.get("phase") == "deployed"
                and isinstance(dep.get("machine"), str) and dep.get("machine")
                and (dep.get("machine"), tuple(dep.get("component_ids", ()))) not in old_facts
            }
        if not await self._fresh_review_evidence_matches_state(
            repo, pr_number, current_head, review_evidence_data,
            expected_components=updated_state.get("components", []),
        ):
            return "uncertain"

        state.clear()
        state.update(updated_state)

        gate_note = [
            "当前提交的部署校验信息已经重新确认。",
        ]
        if machine_alias:
            gate_note.append(
                "之前选择的机器不会自动沿用，请按 PR Summary 中的命令重新审批。"
            )
        remaining_components = [
            c for c in state.get("components", [])
            if c.get("component_id", "") not in _component_id_set(state.get("deployments", []))
        ]
        machine_groups = (
            self._runtime_redeploy_machine_groups(state, remaining_components, repo)
            if state.get("runtime_redeploy") else
            self._get_machine_groups_for_components(remaining_components, repo)
        )
        markdown = await self._approval_retry_markdown(
            repo, pr_number, state, machine_groups,
            display_status=state.get("status", "deploy-requested"),
            test_only=self._is_test_only_pr(pr_data),
            gate_note=gate_note,
            deployments=self._enrich_deployments_for_render(state.get("deployments", []), repo),
        )
        if state["status"] == "testing":
            required_component_ids = {
                c.get("component_id") for c in state.get("components", [])
                if isinstance(c, dict) and c.get("component_id")
            }
            markdown = comments_mod.testing(
                repo, pr_number, current_head, case_result="",
                deployments=self._enrich_deployments_for_render(state.get("deployments", []), repo),
                components=state.get("components", []),
                deployments_complete=(bool(required_component_ids)
                                      and required_component_ids.issubset(
                                          _component_id_set(state.get("deployments", [])))),
            )
        event = {
            "event": "Restart recovery: evidence refreshed",
            "timestamp": comments_mod.beijing_now_str(),
        }
        lifecycle_written = await self._write_lifecycle_with_history(
            repo, pr_number, state, markdown, event=event,
            expected_lifecycle_state=original_state,
        )
        if not lifecycle_written:
            return "uncertain"
        if lifecycle_written:
            for recovered_machine in sorted(recovered_machines):
                try:
                    await self._save_deployed_machine_log(
                        repo, pr_number, state, recovered_machine,
                    )
                except Exception:
                    logger.warning("refreshed machine log save failed %s#%s", repo, pr_number)
            await self.proxy.project_status_label(repo, pr_number, state["status"])
        return state["status"]

    async def _resolve_review_evidence_for_head(
        self, repo: str, fresh_head: str, evidence: "ReviewCommentEvidence",
        *, pr_number: int | None = None,
    ) -> str | None:
        """Resolve evidence.commit_prefix to full SHA and verify == fresh_head.

        Returns resolved 40-hex SHA on success, or None on any failure.
        """
        from .review_comment_parser import ReviewCommentEvidence
        if not isinstance(evidence, ReviewCommentEvidence):
            return None
        if evidence.head_sha and evidence.head_sha != fresh_head:
            return None
        builds = self._review_build_infos(repo, evidence)
        if not builds or any(not build.success or not build.deployable for build in builds):
            return None
        commit_prefix = evidence.commit_prefix
        if not isinstance(commit_prefix, str) or not re.fullmatch(r"[0-9a-f]{7,40}", commit_prefix):
            logger.warning(
                "resolve evidence commit_prefix invalid: %r", commit_prefix
            )
            return None
        try:
            resolved = await self.github.resolve_commit_sha(repo, commit_prefix)
        except Exception as e:
            logger.warning(
                "resolve_commit_sha %s %s: %s", repo, commit_prefix, e
            )
            return None
        if not isinstance(resolved, str) or not re.fullmatch(r"[0-9a-f]{40}", resolved):
            logger.warning(
                "resolve_commit_sha returned malformed sha: %r", resolved
            )
            return None
        if resolved != fresh_head:
            logger.warning(
                "resolved sha %s != fresh_head %s", resolved, fresh_head
            )
            return None
        if pr_number is not None:
            # Commit resolution awaits GitHub after the run-binding HEAD check.
            try:
                final_pr = await self.proxy.get_pr(repo, pr_number)
            except Exception:
                return None
            if (not isinstance(final_pr, dict)
                    or final_pr.get("head", {}).get("sha") != fresh_head
                    or final_pr.get("state") != "open" or final_pr.get("merged")
                    or final_pr.get("draft") is True):
                return None
        return resolved

        # ── Hidden state validation ──


    async def _revalidate_approve_comment(self, repo: str, comment_id: int, expected_actor_id: str, expected_machine_alias: str):
        """Re-read the exact approval comment from GitHub and validate it.

        Returns the comment dict on success, None on any failure.
        """
        try:
            comment = await self.proxy.get_comment(repo, comment_id)
        except Exception:
            return None
        if not isinstance(comment, dict):
            return None
        cid = comment.get("id")
        if not isinstance(cid, int) or cid <= 0 or isinstance(cid, bool):
            return None
        if cid != comment_id:
            return None
        user = comment.get("user")
        if not isinstance(user, dict):
            return None
        uid = user.get("id")
        if not isinstance(uid, int) or uid <= 0 or isinstance(uid, bool):
            return None
        if str(uid) != expected_actor_id:
            return None
        body = comment.get("body")
        if not isinstance(body, str):
            return None
        from .commands import parse_command
        parsed = parse_command(body)
        if not parsed or parsed.kind != "approve_deploy":
            return None
        if parsed.machine_alias != expected_machine_alias:
            return None
        return comment

    async def _revalidate_request_deploy_comment(
        self, repo: str, pr_number: int, comment_id: int,
        expected_author_id: str,
    ) -> dict | None:
        """Re-read the exact PR-author request before creating a drift round."""
        try:
            comment = await self.proxy.get_comment(repo, comment_id)
        except Exception:
            return None
        if (not isinstance(comment, dict) or type(comment_id) is not int
                or comment_id <= 0 or type(comment.get("id")) is not int
                or comment.get("id") != comment_id):
            return None
        user = comment.get("user")
        if (not isinstance(user, dict)
                or str(user.get("id") or "") != expected_author_id
                or self.proxy.is_bot_comment(comment)):
            return None
        created_at = comment.get("created_at")
        if (not isinstance(created_at, str)
                or comment.get("updated_at") != created_at
                or comment.get("url") != (
                    f"{self.config.github_api_url.rstrip('/')}/repos/{repo}/issues/comments/{comment_id}"
                )
                or comment.get("issue_url") != (
                    f"{self.config.github_api_url.rstrip('/')}/repos/{repo}/issues/{pr_number}"
                )):
            return None
        body = comment.get("body")
        if not isinstance(body, str):
            return None
        from .commands import parse_command
        parsed = parse_command(body)
        return comment if parsed and parsed.kind == "request_deploy" else None

    async def _revalidate_hidden_state(
        self,
        repo: str,
        pr_number: int,
        expected_head: str,
        expected_review_evidence: dict,
        expected_status: str = "deploy-requested",
        expected_component_snapshot: list | None = None,
        expected_deployments: list | None = None,
    ):
        """Re-read hidden state before unsafe POST.

        Requires the supplied lifecycle status and command.phase == "completed".
        Returns the state dict on match, None on any mismatch.
        """
        state = await self.proxy.read_hidden_state(repo, pr_number)
        if state is None:
            return None
        if state.get("status") != expected_status:
            return None
        if state.get("head_sha") != expected_head:
            return None
        if state.get("review_evidence") != expected_review_evidence:
            return None
        if state.get("command", {}).get("phase") != "completed":
            return None
        if expected_component_snapshot is not None:
            if self._canonical_component_snapshot(
                state.get("components", []),
            ) != expected_component_snapshot:
                return None
        if expected_deployments is not None:
            if state.get("deployments", []) != expected_deployments:
                return None
        return state


    async def _fresh_review_evidence_matches_state(
        self, repo: str, pr_number: int, fresh_head: str,
        persisted_review_evidence: dict,
        *, expected_components: list[dict] | None = None,
    ):
        """Fresh-read PR Conversation and validate evidence matches persisted snapshot."""
        try:
            comments = await self.proxy.get_issue_comments(repo, pr_number)
        except Exception:
            return False
        if not isinstance(comments, list):
            return False
        persisted_build_id = persisted_review_evidence.get("build_comment_id")
        if (type(persisted_build_id) is int
                and self._has_untrusted_newer_review_comment(
                    comments, persisted_build_id,
                )):
            return False
        evidence = await self._review_evidence_from_comments(repo, pr_number, fresh_head, comments)
        if evidence is None:
            return False
        resolved_head = await self._resolve_review_evidence_for_head(
            repo, fresh_head, evidence, pr_number=pr_number,
        )
        if resolved_head != fresh_head:
            return False
        fresh_components = await self._build_component_snapshot(
            repo, pr_number, fresh_head, self._review_build_infos(repo, evidence),
        )
        if not fresh_components:
            return False
        if expected_components is not None:
            # Compare semantic identities so historical digest/runtime bindings
            # survive, while a truncated or duplicated matrix cannot reach POST.
            if sorted(self._component_semantic_key(c) for c in fresh_components) != sorted(
                self._component_semantic_key(c) for c in expected_components
            ):
                return False
            if any(c.get("resolved_platform") != get_deploy_platform() for c in expected_components):
                return False
        fresh_snapshot = self._review_evidence_snapshot(evidence, resolved_head)
        return (
            self._review_evidence_identity(fresh_snapshot)
            == self._review_evidence_identity(persisted_review_evidence)
        )


    def _validate_hidden_state(self, state: dict) -> None:
        """Validate hidden state before persisting."""
        try:
            _validate_hidden_state(state)
        except Exception as e:
            raise DeployControllerError(str(e)) from e

    # ── Command dispatcher ──

    async def on_command(
        self, cmd, repo: str, pr_number: int, comment_id: int,
    ) -> bool:
        """Dispatch a parsed command to the appropriate handler.

        Returns True if the command was handled (cursor advances).
        """
        # Re-read the comment to verify author identity
        author_id, author_login = await self.proxy.comment_identity(
            repo, comment_id
        )
        if not author_id and not author_login:
            logger.warning(
                "on_command: cannot verify author for %s#%s cid=%s",
                repo, pr_number, comment_id,
            )
            await self._post_error(
                repo, pr_number,
                "无法确认这条命令的发送者，因此没有执行。",
                comment_id=comment_id,
            )
            return True

        intent = getattr(cmd, "intent", "") or cmd.kind
        if getattr(cmd, "error", "") or getattr(cmd, "intent", ""):
            await self._post_error(
                repo, pr_number,
                self._command_error_reason(
                    command_kind=str(intent or ""),
                    parsed_error=str(getattr(cmd, "error", "") or ""),
                ),
                comment_id=comment_id,
            )
            return True

        if cmd.kind == "request_deploy":
            return await self.handle_request_deploy(
                repo, pr_number, comment_id,
            )

        if cmd.kind == "approve_deploy":
            machine_alias = cmd.machine_alias
            return await self.handle_approve_deploy(
                repo, pr_number, comment_id,
                machine_alias, author_login, author_id,
            )

        if cmd.kind == "record_test":
            result = cmd.result
            summary = cmd.summary
            if result not in ("pass", "fail"):
                await self._post_error(
                    repo, pr_number,
                    "验收结果只能填写通过或未通过。",
                    comment_id=comment_id,
                )
                return True
            return await self.handle_record_test(
                repo, pr_number, comment_id,
                result, summary, author_login, author_id,
            )

        if cmd.kind == "request_acceptance":
            return await self.handle_request_acceptance(
                repo, pr_number, comment_id, author_login, author_id,
            )

        if cmd.kind == "deploy_status":
            return await self.handle_deploy_status(
                repo, pr_number, comment_id,
            )

        if cmd.kind == "deploy_help":
            return await self.handle_deploy_help(
                repo, pr_number, comment_id,
                topic=cmd.help_topic,
            )

        if cmd.kind == "evidence_link":
            return await self.handle_evidence_link(
                repo, pr_number, comment_id, author_login, author_id,
            )

        if cmd.kind in {"submit_evidence", "remove_evidence"}:
            evidence = self.evidence_service
            if evidence is None:
                await self._post_error(
                    repo, pr_number,
                    "目前无法保存测试证据，这条内容没有被处理。",
                    comment_id=comment_id,
                )
                return True
            try:
                await evidence.handle_native_comment(
                    repo=repo, pr_number=pr_number, comment_id=comment_id,
                    actor_id=int(author_id), actor_login=author_login,
                    action=cmd.kind, arguments=cmd.evidence_args or {},
                )
            except Exception as exc:
                # Business rejections are terminal comments; network/API/COS
                # exceptions escape so the watcher retries this exact comment.
                if getattr(exc, "status_code", None) in {400, 403, 404, 409, 410, 413}:
                    await self._post_error(
                        repo, pr_number,
                        "测试证据没有被接受，请检查上传内容后重新提交。",
                        comment_id=comment_id,
                    )
                    return True
                raise
            return True

        logger.warning("on_command: unknown kind %s", cmd.kind)
        await self._post_error(
            repo, pr_number,
            self._PARSE_ERROR_REASONS["command_not_found"],
            comment_id=comment_id,
        )
        return True


# Backward-compatible aliases
DeployServiceError = DeployControllerError
DeploymentService = DeployController
