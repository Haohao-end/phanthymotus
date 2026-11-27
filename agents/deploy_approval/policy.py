"""Authority, machine owners, and image policy checks (pre-merge validation).

Pre-merge validation: one approver suffices (collaborator OR machine owner).
Self-approval is allowed when the actor satisfies machine-owner or collaborator authorization.
Every decision is fail-closed: an unknown target, user, machine or image is a
hard error, never a pass.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import ipaddress
import re
import weakref
from collections.abc import Mapping
from typing import Any

import yaml

from .config import (
    Config,
    MAX_REPO_POLICY_FILE_BYTES,
    parse_test_reviewers_yaml,
)
from .models import MachineInfo
from .repo_policy import RepositoryPolicyStore
from .feishu_machine_source import FeishuMachineSource

logger = logging.getLogger(__name__)


class PolicyError(Exception):
    pass


class MachineLoadError(Exception):
    pass


_CANONICAL_VARIANTS = {"5.11", "6.1"}
_LEGACY_VARIANTS = {
    "jetson-jp5.11": "5.11",
    "jetson-jp6.1": "6.1",
}

def _normalize_variant(value: str) -> str:
    raw = value.strip()
    if not raw:
        raise MachineLoadError("variant must be a non-empty string")
    if raw in _CANONICAL_VARIANTS:
        return raw
    if raw in _LEGACY_VARIANTS:
        return _LEGACY_VARIANTS[raw]
    raise MachineLoadError(f"unsupported variant: {raw!r}")


def _validate_literal_ip(host: str, alias: str) -> str:
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError as e:
        raise MachineLoadError(
            f"machine {alias!r}: node_host must be a literal IP address"
        ) from e
    if parsed.version != 4:
        raise MachineLoadError(
            f"machine {alias!r}: node_host must be an IPv4 address"
        )
    return str(parsed)





def _validate_driver_paths(raw: Any, alias: str, *, required: bool) -> list[str] | None:
    if raw is None:
        if required:
            raise MachineLoadError(
                f"machine {alias!r}: driver_paths is required for driver machines"
            )
        return None
    if not isinstance(raw, list):
        raise MachineLoadError(
            f"machine {alias!r}: driver_paths must be a non-empty list"
        )
    if not raw:
        raise MachineLoadError(
            f"machine {alias!r}: driver_paths must be a non-empty list"
        )
    deduped: list[str] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, str):
            raise MachineLoadError(
                f"machine {alias!r}: driver_paths must contain non-empty strings"
            )
        path = item.strip()
        if not path:
            raise MachineLoadError(
                f"machine {alias!r}: driver_paths must contain non-empty strings"
            )
        if path.startswith("/") or path.endswith("/"):
            raise MachineLoadError(
                f"machine {alias!r}: driver_paths must be repo-relative POSIX paths"
            )
        if "\\" in path or "//" in path:
            raise MachineLoadError(
                f"machine {alias!r}: driver_paths must be repo-relative POSIX paths"
            )
        segments = path.split("/")
        if len(segments) < 2 or any(seg in {"", ".", ".."} for seg in segments):
            raise MachineLoadError(
                f"machine {alias!r}: driver_paths must contain at least two safe path segments"
            )
        if path not in seen:
            seen.add(path)
            deduped.append(path)
    return deduped


def load_machines(path: str) -> dict[str, MachineInfo]:
    """Load machines.yaml and return {alias: MachineInfo}.

    Final schema:
      version: 1
      machines:
        <alias>:
          node_id: <unique-node-id>
          owners:
            - <github-login>

    Startup fail-closed: missing, invalid, or malformed YAML raises.
    """
    if not path or not os.path.exists(path):
        raise MachineLoadError(f"machine owners file not found: {path}")
    with open(path, "r") as f:
        raw = yaml.safe_load(f)
    return _load_machines_data(raw)


def parse_machines_yaml(content: bytes | str) -> dict[str, MachineInfo]:
    """Parse repository-provided machines.yaml with the standard schema checks."""
    if isinstance(content, bytes):
        if len(content) > MAX_REPO_POLICY_FILE_BYTES:
            raise MachineLoadError("machines YAML exceeds the policy file size limit")
        try:
            content = content.decode("utf-8")
        except UnicodeDecodeError:
            raise MachineLoadError("machines YAML must be UTF-8") from None
    if not isinstance(content, str):
        raise MachineLoadError("machines YAML must be UTF-8 text")
    try:
        content_size = len(content.encode("utf-8"))
    except UnicodeEncodeError:
        raise MachineLoadError("machines YAML must be UTF-8") from None
    if content_size > MAX_REPO_POLICY_FILE_BYTES:
        raise MachineLoadError("machines YAML exceeds the policy file size limit")
    try:
        raw = yaml.safe_load(content)
    except yaml.YAMLError:
        # Parser errors may quote YAML lines; keep untrusted source out of logs.
        raise MachineLoadError("machines YAML is malformed") from None
    return _load_machines_data(raw)


def _load_machines_data(raw: Any) -> dict[str, MachineInfo]:
    if not isinstance(raw, dict):
        raise MachineLoadError("machines YAML must be a dict at top level")
    version = raw.get("version")
    if type(version) is not int or version != 1:
        raise MachineLoadError(
            f"machines YAML version must be 1, got {version!r}"
        )
    machines_raw = raw.get("machines")
    if not isinstance(machines_raw, dict):
        raise MachineLoadError("machines YAML must contain a 'machines' mapping")
    if not machines_raw:
        raise MachineLoadError("machines mapping must not be empty")
    machines: dict[str, MachineInfo] = {}
    node_ids_seen: set[str] = set()
    feishu_numbers_seen: set[str] = set()
    aliases_seen: set[str] = set()
    for alias, entry in machines_raw.items():
        if not isinstance(alias, str) or not alias.strip():
            raise MachineLoadError("machine alias must be a non-empty string")
        alias = alias.strip()
        if alias in aliases_seen:
            raise MachineLoadError(f"duplicate machine alias: {alias!r}")
        aliases_seen.add(alias)
        if not isinstance(entry, dict):
            raise MachineLoadError(
                f"machine {alias!r} must be a mapping, got {type(entry).__name__}"
            )
        node_id = str(entry.get("node_id", "")).strip()
        if not node_id:
            raise MachineLoadError(f"machine {alias!r}: node_id is required and must be non-empty")
        if node_id in node_ids_seen:
            raise MachineLoadError(f"duplicate node_id: {node_id!r}")
        node_ids_seen.add(node_id)
        owners_raw = entry.get("owners", [])
        if not isinstance(owners_raw, list):
            raise MachineLoadError(
                f"machine {alias!r}: owners must be a list, got {type(owners_raw).__name__}"
            )
        if not owners_raw:
            raise MachineLoadError(f"machine {alias!r}: owners list is empty")
        if not all(isinstance(o, str) and o.strip() for o in owners_raw):
            raise MachineLoadError(f"machine {alias!r}: each owner must be a non-empty string")
        owners = list(dict.fromkeys(o.strip().lower() for o in owners_raw if o.strip()))
        if not owners:
            raise MachineLoadError(f"machine {alias!r}: no valid owners after dedup")
        # node_host/node_hosts are legacy runtime fields. Read neither value:
        # an old address must not select a physical device or block a new IP.
        feishu_number_raw = entry.get("feishu_number")
        feishu_number = None
        if feishu_number_raw is not None and not (
            isinstance(feishu_number_raw, str) and not feishu_number_raw.strip()
        ):
            if isinstance(feishu_number_raw, bool) or not isinstance(
                    feishu_number_raw, (str, int)):
                raise MachineLoadError(
                    f"machine {alias!r}: feishu_number must be a numeric string"
                )
            feishu_number_text = str(feishu_number_raw).strip()
            if not re.fullmatch(r"[0-9]+", feishu_number_text):
                raise MachineLoadError(
                    f"machine {alias!r}: feishu_number must be a numeric string"
                )
            feishu_number = feishu_number_text.zfill(3)
            if feishu_number in feishu_numbers_seen:
                raise MachineLoadError(
                    f"duplicate feishu_number: {feishu_number!r}"
                )
            feishu_numbers_seen.add(feishu_number)
        targets_raw = entry.get("targets")
        if not isinstance(targets_raw, list) or not targets_raw:
            raise MachineLoadError(
                f"machine {alias!r}: targets must be a non-empty list"
            )
        if not all(isinstance(t, str) and t.strip() for t in targets_raw):
            raise MachineLoadError(
                f"machine {alias!r}: targets must contain non-empty strings"
            )
        platforms_raw = entry.get("platforms")
        if not isinstance(platforms_raw, list) or not platforms_raw:
            raise MachineLoadError(
                f"machine {alias!r}: platforms must be a non-empty list"
            )
        if not all(isinstance(p, str) and p.strip() for p in platforms_raw):
            raise MachineLoadError(
                f"machine {alias!r}: platforms must contain non-empty strings"
            )
        targets = list(dict.fromkeys(t.strip() for t in targets_raw))
        platforms = list(dict.fromkeys(p.strip() for p in platforms_raw))
        driver_paths = _validate_driver_paths(
            entry.get("driver_paths"),
            alias,
            required="driver" in targets,
        )
        variants_raw = entry.get("variants")
        variants = None
        if variants_raw is not None:
            if not isinstance(variants_raw, list):
                raise MachineLoadError(
                    f"machine {alias!r}: variants must be a list"
                )
            if not variants_raw:
                raise MachineLoadError(
                    f"machine {alias!r}: variants must not be empty when set"
                )
            normalized: list[str] = []
            for variant in variants_raw:
                if not isinstance(variant, str) or not variant.strip():
                    raise MachineLoadError(
                        f"machine {alias!r}: variants must contain non-empty strings"
                    )
                normalized.append(_normalize_variant(variant))
            variants = list(dict.fromkeys(normalized))
            if not variants:
                raise MachineLoadError(
                    f"machine {alias!r}: variants must contain at least one supported variant"
                )
        machines[alias] = MachineInfo(
            alias=alias, node_id=node_id, owners=owners,
            feishu_number=feishu_number,
            feishu_identity_confirmed=False,
            feishu_identity_reason=(
                "Feishu number is not configured; pending binding"
                if feishu_number is None else "Feishu identity has not been refreshed"
            ),
            feishu_stale=True,
            targets=targets,
            platforms=platforms,
            variants=variants,
            driver_paths=driver_paths,
        )
    return machines


class Policy:
    _instances = weakref.WeakSet()
    def __init__(self, config: Config):
        self.config = config
        self.machines: dict[str, MachineInfo] = {}
        self._repository_policies = RepositoryPolicyStore(
            config,
            machine_parser=parse_machines_yaml,
            reviewer_parser=parse_test_reviewers_yaml,
        )
        self._feishu_machine_source: FeishuMachineSource | None = None
        self._reported_feishu_conflicts: set[tuple] = set()
        Policy._instances.add(self)

    def set_feishu_machine_source(self, source: FeishuMachineSource) -> None:
        self._feishu_machine_source = source

    def load_machines(self) -> None:
        raw_machines = load_machines(self.config.machine_owners_file)
        source = self._feishu_machine_source
        view = source.state if source is not None else None
        self.machines = {
            alias: self._with_feishu_identity(
                machine, None, view=view,
            )
            for alias, machine in raw_machines.items()
        }

    def get_machine_by_node_id(
        self, node_id: str, repo: str | None = None,
    ) -> MachineInfo | None:
        machines = self.machines if repo is None else self._repository_policies.machines_for(repo)
        source = self._feishu_machine_source
        view = source.state if source is not None else None
        for m in machines.values():
            if m.node_id == node_id:
                return self._with_feishu_identity(copy.deepcopy(m), repo, view=view)
        return None

    def get_machine(self, alias: str, repo: str | None = None) -> MachineInfo | None:
        source = self._feishu_machine_source
        view = source.state if source is not None else None
        if repo is None:
            machine = self.machines.get(alias)
            return self._with_feishu_identity(copy.deepcopy(machine), repo, view=view) if machine else None
        machine = self._repository_policies.machine_for(alias, repo)
        return self._with_feishu_identity(machine, repo, view=view) if machine else None

    # GitHub collaborator permissions that may approve.
    COLLABORATOR_WRITE = frozenset({"write", "maintain", "admin"})

    @staticmethod
    def collaborator_can_approve(permission: str) -> bool:
        return isinstance(permission, str) and permission in Policy.COLLABORATOR_WRITE

    def get_machines(self, repo: str | None = None) -> list[MachineInfo]:
        """Return machines, optionally from one isolated repository policy."""
        machines = self.machines if repo is None else self._repository_policies.machines_for(repo)
        source = self._feishu_machine_source
        view = source.state if source is not None else None
        return [self._with_feishu_identity(copy.deepcopy(machine), repo, view=view)
                for machine in machines.values()]

    def reviewers_for_repo(self, repo: str) -> list[str]:
        """Return only the verified acceptance allowlist for ``repo``."""
        return self._repository_policies.reviewers_for_repo(repo)

    def repo_policy_status(self, repo: str) -> dict:
        """Report whether this repository has independently verified policy."""
        return self._repository_policies.status(repo)

    async def refresh_if_due(self, repo: str, github_client) -> dict:
        """Refresh one authorized repository's main-branch policy files."""
        result = await self._repository_policies.refresh_if_due(repo, github_client)
        if result.get("status") != "not_due":
            self.get_machines(repo=repo)
        return result

    def resolve_machine_selector(
        self, selector: str | Mapping[str, "MachineInfo"], repo: str | None = None,
    ) -> "MachineInfo":
        """Resolve an exact alias or IPv4 to one repository machine.

        The instance form is ``policy.resolve_machine_selector(selector, repo)``.
        The class-style mapping form remains for service.py compatibility.
        """
        if isinstance(self, Policy):
            actual_selector = selector
            if isinstance(repo, str):
                machines = {machine.alias: machine for machine in self.get_machines(repo)}
            elif isinstance(repo, Mapping):
                machines = dict(repo)
            else:
                raise PolicyError("repository is required to resolve a machine selector")
        else:
            # Existing service.py calls Policy.resolve_machine_selector(value, machine_map).
            # The requested class-style (selector, repo) form is also supported when
            # exactly one Policy instance owns that repository in this process.
            actual_selector = self
            if isinstance(selector, Mapping):
                machines = dict(selector)
            elif isinstance(selector, str):
                candidates = [instance for instance in Policy._instances
                              if instance._repository_policies._canonical_repo(selector) is not None]
                if len(candidates) != 1:
                    raise PolicyError("use a Policy instance to resolve this repository")
                machines = {
                    machine.alias: machine
                    for machine in candidates[0].get_machines(selector)
                }
            else:
                machines = {}
        if not isinstance(actual_selector, str) or not actual_selector:
            raise PolicyError("machine selector must be a non-empty string")
        machine = machines.get(actual_selector)
        selected_by_alias = machine is not None
        if machine is None:
            try:
                parsed = ipaddress.ip_address(actual_selector)
            except ValueError:
                raise PolicyError(
                    f"invalid machine selector {actual_selector!r}: "
                    "not a known alias or valid IPv4 address"
                ) from None
            if parsed.version != 4:
                raise PolicyError(
                    f"invalid machine selector {actual_selector!r}: only IPv4 addresses are supported"
                )
            canonical_ipv4 = str(parsed)
            ambiguous_entries = [
                address
                for candidate in machines.values()
                for address in (getattr(candidate, "node_addresses", []) or [])
                if (isinstance(address, Mapping)
                    and address.get("ip") == canonical_ipv4
                    and address.get("ambiguous") == "true")
            ]
            ambiguous_owners = sorted({
                owner
                for address in ambiguous_entries
                for owner in str(address.get("ambiguous_owners", "")).split(",")
                if owner
            })
            if ambiguous_entries:
                owner_text = f"; Feishu devices {', '.join(ambiguous_owners)}" if ambiguous_owners else ""
                raise PolicyError(
                    f"ambiguous Feishu IP {canonical_ipv4!r}{owner_text}"
                )
            matches = [
                candidate for candidate in machines.values()
                if getattr(candidate, "feishu_identity_confirmed", None) is True
                and not getattr(candidate, "feishu_stale", False)
                and canonical_ipv4 in (getattr(candidate, "node_hosts", []) or [])
            ]
            if len(matches) == 0:
                raise PolicyError(f"no machine found with IP {canonical_ipv4!r}")
            if len(matches) > 1:
                aliases = sorted(candidate.alias for candidate in matches)
                raise PolicyError(
                    f"ambiguous IP {canonical_ipv4!r}: matches machines "
                    f"{', '.join(f'`{alias}`' for alias in aliases)}"
                )
            machine = matches[0]
        # Legacy policies without an explicit number remain resolvable by
        # alias so they can be reported as pending binding. Their old IPs are
        # never selectors and they cannot produce a deployment endpoint.
        if selected_by_alias and not getattr(machine, "feishu_number", None):
            return machine
        if getattr(machine, "feishu_stale", False):
            reason = getattr(machine, "feishu_identity_reason", "")
            raise PolicyError(reason or "Feishu machine identity snapshot is stale")
        if getattr(machine, "feishu_identity_confirmed", None) is not True:
            reason = getattr(machine, "feishu_identity_reason", "")
            raise PolicyError(reason or "Feishu machine identity is not confirmed")
        return machine

    def _log_feishu_conflict(
        self, number: str, alias: str, ip: str, reason: str, *,
        generation: int | None = None, repo: str | None = None,
    ) -> None:
        source = self._feishu_machine_source
        if generation is None:
            generation = getattr(source, "generation", 0)
        item = (generation, repo, number, alias, ip, reason)
        if item in self._reported_feishu_conflicts:
            return
        self._reported_feishu_conflicts.add(item)
        logger.error(
            "FEISHU_IDENTITY_CONFLICT generation=%d repo=%s number=%s "
            "alias=%s ip=%s reason=%s",
            generation, repo or "unknown", number, alias, ip, reason,
        )

    def _with_feishu_identity(
        self, machine: MachineInfo, repo: str | None, *, view=None,
        log_conflicts: bool = True,
    ) -> MachineInfo:
        """Project one authorized alias onto its exact current Feishu device.

        machines.yaml grants repository permissions only. In particular, its
        legacy endpoint fields and alias text are never used to infer a device
        or to keep an old IP alive when the snapshot changes.
        """
        source = self._feishu_machine_source
        machine.node_host = ""
        machine.node_hosts = []
        machine.node_addresses = []
        machine.feishu_brand = None
        machine.feishu_model = None
        machine.feishu_identity_confirmed = False

        if source is None:
            machine.feishu_stale = True
            machine.feishu_identity_reason = (
                "Feishu number is not configured; pending binding"
                if not machine.feishu_number else
                "Feishu machine source is unavailable"
            )
            return machine
        view = view if view is not None else source.state
        machine.feishu_snapshot_generation = view.generation
        machine.feishu_stale = bool(view.stale)

        if not machine.feishu_number:
            machine.feishu_identity_reason = (
                "Feishu number is not configured; pending binding"
            )
            return machine

        raw_number = str(machine.feishu_number).strip()
        if not re.fullmatch(r"[0-9]+", raw_number):
            machine.feishu_identity_reason = "configured Feishu number is invalid"
            return machine
        policy_number = raw_number.zfill(3)
        machine.feishu_number = policy_number

        is_stale = view.stale
        if is_stale:
            machine.feishu_identity_reason = "Feishu snapshot is stale"
            return machine

        snapshot = view.devices
        if not snapshot:
            machine.feishu_identity_reason = "Feishu snapshot has no successful sync"
            return machine

        devices_by_ip: dict[str, set[str]] = {}
        for device_number, observed_device in snapshot.items():
            for address in observed_device.addresses:
                devices_by_ip.setdefault(address.ip, set()).add(device_number)
        for address, numbers in view.ip_conflicts.items():
            devices_by_ip.setdefault(address, set()).update(numbers)

        device = snapshot.get(policy_number)
        if device is None or device.number != policy_number:
            machine.feishu_identity_reason = (
                f"configured Feishu number {policy_number} is absent from the current snapshot"
            )
            return machine

        machine.feishu_number = device.number
        machine.feishu_brand = device.brand
        machine.feishu_model = device.model
        usable_hosts: list[str] = []
        observed_ips: set[str] = set()
        machine.node_addresses = []
        for address in device.addresses:
            if address.ip in observed_ips:
                continue
            observed_ips.add(address.ip)
            owners = devices_by_ip.get(address.ip, set())
            ambiguous = len(owners) > 1
            if ambiguous:
                if log_conflicts:
                    for owner_number in sorted(owners):
                        self._log_feishu_conflict(
                            owner_number, machine.alias, address.ip,
                            "Feishu assigns this IP to multiple device numbers",
                            generation=view.generation, repo=repo,
                        )
            machine.node_addresses.append({
                "ip": address.ip,
                "label": address.label,
                "ambiguous": "true" if ambiguous else "false",
                "ambiguous_owners": ",".join(sorted(owners)) if ambiguous else "",
            })
            if not ambiguous:
                usable_hosts.append(address.ip)

        machine.node_hosts = usable_hosts
        machine.node_host = usable_hosts[0] if usable_hosts else ""
        machine.feishu_identity_confirmed = True
        machine.feishu_identity_reason = (
            "all current Feishu IP addresses are conflicted"
            if not usable_hosts else
            "some Feishu IP addresses were excluded due to conflicts"
            if len(usable_hosts) != len(machine.node_addresses) else ""
        )
        return machine

    @staticmethod
    def _identity_addresses(machine: MachineInfo) -> list[dict[str, str]]:
        if (machine.feishu_stale or not machine.feishu_brand or not machine.feishu_model):
            return []
        return [dict(address) for address in machine.node_addresses]

    @staticmethod
    def _confirmed_endpoints(machine: MachineInfo) -> list[dict[str, str]]:
        if (machine.feishu_stale or machine.feishu_identity_confirmed is not True):
            return []
        return [
            {"ip": address["ip"], "label": address.get("label", "")}
            for address in Policy._identity_addresses(machine)
            if address.get("ambiguous") != "true"
        ]

    def get_machine_endpoints(
        self, machine: MachineInfo | str, repo: str,
    ) -> list[dict[str, str]]:
        """Return ordered, identity-confirmed IPs with Feishu address labels."""
        resolved = self.get_machine(machine, repo=repo) if isinstance(machine, str) else (
            self.get_machine(machine.alias, repo=repo) if machine is not None else None
        )
        return self._confirmed_endpoints(resolved) if resolved is not None else []

    def machine_identity(self, machine: MachineInfo | str, repo: str) -> dict:
        """Return the Feishu identity result without granting repository access."""
        alias = machine if isinstance(machine, str) else getattr(machine, "alias", "")
        resolved = self.get_machine(alias, repo=repo) if isinstance(alias, str) else None
        if resolved is None:
            source = self._feishu_machine_source
            view = source.state if source is not None else None
            return {
                "alias": str(alias or ""), "number": None,
                "brand": None, "model": None, "confirmed": False,
                "stale": bool(view.stale) if view is not None else True,
                "status": "not_authorized",
                "reason": "machine is not authorized by this repository", "addresses": [],
            }
        confirmed = (
            resolved.feishu_identity_confirmed is True
            and not resolved.feishu_stale
        )
        if not resolved.feishu_number:
            identity_status = "pending_binding"
        elif resolved.feishu_stale:
            identity_status = "stale"
        elif resolved.feishu_identity_confirmed is not True:
            identity_status = "unconfirmed"
        elif not resolved.node_hosts:
            identity_status = "no_unconflicted_ip"
        else:
            identity_status = "confirmed"
        return {
            "alias": resolved.alias,
            "number": resolved.feishu_number,
            "brand": resolved.feishu_brand,
            "model": resolved.feishu_model,
            "confirmed": confirmed,
            "stale": resolved.feishu_stale,
            "status": identity_status,
            "reason": resolved.feishu_identity_reason,
            "addresses": self._identity_addresses(resolved),
        }

    def machine_projection_version(self, repo: str) -> str:
        """Return a stable digest of repository authorization and Feishu view.

        The projection is built only from the current in-memory repository
        policy and Feishu snapshot. It does not fetch either source, and omits
        snapshot generation and timestamps so a duplicate sync is stable.
        """
        policy_status = self._repository_policies.status(repo)
        raw_machines = self._repository_policies.machines_for(repo)
        source = self._feishu_machine_source
        view = source.state if source is not None else None
        machines = [
            self._with_feishu_identity(
                copy.deepcopy(machine), repo, view=view, log_conflicts=False,
            )
            for machine in raw_machines.values()
        ]

        def optional_list(value):
            return list(value) if value is not None else None

        machine_rows = []
        for machine in sorted(machines, key=lambda item: item.alias):
            machine_rows.append({
                "authorization": {
                    "alias": machine.alias,
                    "node_id": machine.node_id,
                    "feishu_number": machine.feishu_number,
                    "owners": list(machine.owners or []),
                    "targets": optional_list(machine.targets),
                    "platforms": optional_list(machine.platforms),
                    "variants": optional_list(machine.variants),
                    "driver_paths": optional_list(machine.driver_paths),
                },
                "identity": {
                    "number": machine.feishu_number,
                    "brand": machine.feishu_brand,
                    "model": machine.feishu_model,
                    "addresses": [
                        {
                            "ip": address.get("ip", ""),
                            "label": address.get("label", ""),
                            "ambiguous": address.get("ambiguous", "false"),
                            "ambiguous_owners": address.get("ambiguous_owners", ""),
                        }
                        for address in machine.node_addresses
                    ],
                    "node_host": machine.node_host,
                    "node_hosts": list(machine.node_hosts or []),
                    "confirmed": machine.feishu_identity_confirmed is True,
                    "stale": machine.feishu_stale,
                    "reason": machine.feishu_identity_reason,
                },
            })

        snapshot_status = (
            "unavailable" if view is None else
            "stale" if view.stale else
            "empty" if not view.devices else "fresh"
        )
        projection = {
            "repository": repo.casefold() if isinstance(repo, str) else "",
            "repository_policy": {
                "authorized": policy_status.get("authorized") is True,
                "machines_configured": policy_status.get("machines_configured") is True,
                "machines_yaml_status": policy_status.get("machines_yaml_status", ""),
            },
            "feishu_snapshot_status": snapshot_status,
            "machines": machine_rows,
        }
        serialized = json.dumps(
            projection, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def machine_supports_target(
        self, alias: str, target: str, repo: str | None = None,
    ) -> bool:
        """Check if a machine supports a given target based on static config.

        Fail closed: targets must be explicit.
        """
        machine = self.get_machine(alias, repo=repo)
        if machine is None:
            return False
        if not machine.targets:
            return False
        return target in machine.targets
