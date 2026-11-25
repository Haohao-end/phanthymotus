"""Authority, machine owners, and image policy checks (pre-merge validation).

Pre-merge validation: one approver suffices (collaborator OR machine owner).
Self-approval is allowed when the actor satisfies machine-owner or collaborator authorization.
Every decision is fail-closed: an unknown target, user, machine or image is a
hard error, never a pass.
"""

from __future__ import annotations

import copy
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
    node_hosts_seen: dict[str, str] = {}
    for alias, entry in machines_raw.items():
        if not isinstance(alias, str) or not alias.strip():
            raise MachineLoadError("machine alias must be a non-empty string")
        alias = alias.strip()
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
        node_host = str(entry.get("node_host", "") or "").strip()
        if not node_host:
            raise MachineLoadError(
                f"machine {alias!r}: node_host is required and must be non-empty"
            )
        node_host = _validate_literal_ip(node_host, alias)
        configured_hosts_raw = entry.get("node_hosts", [])
        if not isinstance(configured_hosts_raw, list):
            raise MachineLoadError(f"machine {alias!r}: node_hosts must be a list")
        node_hosts = [node_host]
        for raw_host in configured_hosts_raw:
            if not isinstance(raw_host, str) or not raw_host.strip():
                raise MachineLoadError(
                    f"machine {alias!r}: node_hosts must contain non-empty IPv4 strings"
                )
            canonical_host = _validate_literal_ip(raw_host.strip(), alias)
            if canonical_host not in node_hosts:
                node_hosts.append(canonical_host)
        for configured_host in node_hosts:
            previous_alias = node_hosts_seen.get(configured_host)
            if previous_alias is not None and previous_alias != alias:
                raise MachineLoadError(
                    f"duplicate node host {configured_host!r}: machines "
                    f"{previous_alias!r} and {alias!r} cannot share one physical IP address"
                )
            node_hosts_seen[configured_host] = alias
        feishu_number_raw = entry.get("feishu_number")
        feishu_number = None
        if feishu_number_raw is not None:
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
            alias=alias, node_id=node_id, owners=owners, node_host=node_host,
            node_hosts=node_hosts,
            node_addresses=[{"ip": host, "label": ""} for host in node_hosts],
            feishu_number=feishu_number,
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
        self.machines = load_machines(self.config.machine_owners_file)

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
            matches = [candidate for candidate in machines.values()
                       if canonical_ipv4 in (getattr(candidate, "node_hosts", []) or [])
                       or getattr(candidate, "node_host", "") == canonical_ipv4]
            if len(matches) == 0:
                raise PolicyError(f"no machine found with IP {canonical_ipv4!r}")
            if len(matches) > 1:
                aliases = sorted(candidate.alias for candidate in matches)
                raise PolicyError(
                    f"ambiguous IP {canonical_ipv4!r}: matches machines "
                    f"{', '.join(f'`{alias}`' for alias in aliases)}"
                )
            machine = matches[0]
        if getattr(machine, "feishu_stale", False):
            reason = getattr(machine, "feishu_identity_reason", "")
            raise PolicyError(reason or "Feishu machine identity snapshot is stale")
        if getattr(machine, "feishu_identity_confirmed", None) is False:
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
    ) -> MachineInfo:
        source = self._feishu_machine_source
        if source is None:
            machine.feishu_stale = True
            machine.feishu_identity_confirmed = False
            machine.feishu_identity_reason = "Feishu machine source is unavailable"
            return machine
        view = view if view is not None else source.state
        snapshot = view.devices
        is_stale = view.stale
        machine.feishu_snapshot_generation = view.generation
        machine.feishu_stale = is_stale
        machine.feishu_identity_confirmed = False
        machine.feishu_identity_reason = "Feishu snapshot is stale" if is_stale else ""
        configured_hosts = list(dict.fromkeys(
            [host for host in [machine.node_host, *(machine.node_hosts or [])] if host]
        ))
        machine.node_hosts = list(configured_hosts)
        machine.node_addresses = [{"ip": host, "label": ""} for host in configured_hosts]
        if is_stale:
            machine.feishu_identity_reason = "Feishu snapshot is stale"
            return machine
        if not snapshot:
            machine.feishu_identity_reason = "Feishu snapshot has no successful sync"
            return machine

        devices_by_ip: dict[str, set[str]] = {}
        for device_number, observed_device in snapshot.items():
            for address in observed_device.addresses:
                devices_by_ip.setdefault(address.ip, set()).add(device_number)
        for address, numbers in view.ip_conflicts.items():
            devices_by_ip.setdefault(address, set()).update(numbers)
        machine.node_addresses = [
            {
                "ip": host,
                "label": "",
                "ambiguous": "true" if len(devices_by_ip.get(host, set())) > 1 else "false",
                "ambiguous_owners": ",".join(sorted(devices_by_ip.get(host, set())))
                if len(devices_by_ip.get(host, set())) > 1 else "",
            }
            for host in configured_hosts
        ]
        machine.node_hosts = [
            host for host in configured_hosts
            if len(devices_by_ip.get(host, set())) <= 1
        ]

        policy_number = machine.feishu_number
        device = snapshot.get(policy_number) if policy_number else None

        def log_ip_owners(host: str, owner_numbers: set[str], reason: str) -> None:
            for owner_number in sorted(owner_numbers):
                self._log_feishu_conflict(
                    owner_number, machine.alias, host, reason,
                    generation=view.generation, repo=repo,
                )

        configured_conflicts: dict[str, set[str]] = {}
        for host in configured_hosts:
            owner_numbers = devices_by_ip.get(host, set())
            if len(owner_numbers) > 1:
                configured_conflicts[host] = owner_numbers
                log_ip_owners(
                    host, owner_numbers,
                    "Feishu assigns this IP to multiple device numbers",
                )

        if policy_number and device is None:
            observed: set[str] = set()
            for host in configured_hosts:
                owner_numbers = devices_by_ip.get(host, set())
                if owner_numbers:
                    observed.update(owner_numbers)
                    log_ip_owners(
                        host, owner_numbers,
                        "configured number has no matching Feishu device",
                    )
            if observed:
                machine.feishu_identity_reason = (
                    f"configured Feishu number {policy_number} is absent; "
                    f"configured IP belongs to Feishu device(s) {', '.join(sorted(observed))}"
                )
            else:
                machine.feishu_identity_reason = (
                    f"configured Feishu number {policy_number} is absent from the current snapshot"
                )
            return machine

        if device is None:
            observed_numbers = {
                next(iter(devices_by_ip[host]))
                for host in configured_hosts if len(devices_by_ip.get(host, set())) == 1
            }
            if len(observed_numbers) != 1:
                if len(observed_numbers) > 1:
                    for host in configured_hosts:
                        owner_numbers = devices_by_ip.get(host, set())
                        if owner_numbers:
                            log_ip_owners(
                                host, owner_numbers,
                                "configured IPs map to different Feishu devices",
                            )
                    machine.feishu_identity_reason = (
                        "configured IPs map to multiple Feishu devices: "
                        + ", ".join(sorted(observed_numbers))
                    )
                elif configured_conflicts:
                    details = [
                        f"{host} is shared by {', '.join(sorted(numbers))}"
                        for host, numbers in sorted(configured_conflicts.items())
                    ]
                    machine.feishu_identity_reason = (
                        "configured IP identity is ambiguous: " + "; ".join(details)
                    )
                else:
                    unmatched_hosts = [
                        host for host in configured_hosts if host not in devices_by_ip
                    ]
                    machine.feishu_identity_reason = (
                        "no Feishu number is configured and "
                        + ("configured IPs are absent from the snapshot: "
                           + ", ".join(unmatched_hosts) if unmatched_hosts else
                           "no configured IP maps to a unique device")
                    )
                return machine
            device = snapshot[next(iter(observed_numbers))]

        conflict_reasons = [
            f"configured IP {host} is shared by Feishu devices "
            f"{', '.join(sorted(numbers))}"
            for host, numbers in sorted(configured_conflicts.items())
        ]
        for host in configured_hosts:
            owner_numbers = devices_by_ip.get(host, set())
            if owner_numbers != {device.number}:
                if owner_numbers:
                    reason = (
                        f"configured IP {host} belongs to Feishu device(s) "
                        f"{', '.join(sorted(owner_numbers))}, not {device.number}"
                    )
                else:
                    reason = (
                        f"configured IP {host} is absent from Feishu device {device.number}"
                    )
                if reason not in conflict_reasons:
                    conflict_reasons.append(reason)
                log_ip_owners(host, owner_numbers, reason)
                if not owner_numbers:
                    self._log_feishu_conflict(
                        device.number, machine.alias, host, reason,
                        generation=view.generation, repo=repo,
                    )
        ambiguous_device_ips = [
            address.ip for address in device.addresses
            if len(devices_by_ip.get(address.ip, set())) > 1
        ]
        if ambiguous_device_ips:
            for address in ambiguous_device_ips:
                log_ip_owners(
                    address, devices_by_ip[address],
                    "Feishu assigns this device IP to multiple device numbers",
                )
        if policy_number and policy_number != device.number:
            conflict_reasons.append(
                f"configured Feishu number {policy_number} does not match {device.number}"
            )
            self._log_feishu_conflict(
                device.number, machine.alias, machine.node_host,
                "configured Feishu number does not match the numbered device",
                generation=view.generation, repo=repo,
            )
        machine.feishu_number = device.number
        machine.feishu_brand = device.brand
        machine.feishu_model = device.model
        ambiguous_ip_set = set(ambiguous_device_ips)
        machine.node_addresses = [
            {
                "ip": address.ip,
                "label": address.label,
                "ambiguous": "true" if address.ip in ambiguous_ip_set else "false",
                "ambiguous_owners": ",".join(
                    sorted(devices_by_ip.get(address.ip, set()))
                ) if address.ip in ambiguous_ip_set else "",
            }
            for address in device.addresses
        ]
        if machine.node_host in {address["ip"] for address in machine.node_addresses}:
            machine.node_addresses.sort(key=lambda address: address["ip"] != machine.node_host)
        machine.node_hosts = [
            address["ip"] for address in machine.node_addresses
            if address["ambiguous"] != "true"
        ]
        machine.feishu_identity_confirmed = not conflict_reasons and not is_stale
        machine.feishu_identity_reason = "; ".join(conflict_reasons)
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
                "reason": "machine is not authorized by this repository", "addresses": [],
            }
        confirmed = (
            resolved.feishu_identity_confirmed is True
            and not resolved.feishu_stale
        )
        return {
            "alias": resolved.alias,
            "number": resolved.feishu_number,
            "brand": resolved.feishu_brand,
            "model": resolved.feishu_model,
            "confirmed": confirmed,
            "stale": resolved.feishu_stale,
            "reason": resolved.feishu_identity_reason,
            "addresses": self._identity_addresses(resolved),
        }

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
