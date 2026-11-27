"""Data models for the Deploy Approval Agent (stateless GitHub persistence).

The ONLY persistence is the GitHub lifecycle comment hidden state.
No SQLite, no DeploymentStore, no deployment DB rows.

The hidden-state schema and its status transitions are owned exclusively by
github_state_proxy._validate_hidden_state (the production validator).
"""

from __future__ import annotations

from dataclasses import dataclass, field


# Machine owners configuration
@dataclass
class MachineInfo:
    alias: str
    node_id: str
    owners: list[str]  # GitHub logins (case-insensitive)
    # Runtime-only projection from the latest Feishu identity snapshot.
    # machines.yaml legacy endpoint fields are ignored by policy parsing.
    node_host: str = ""
    # All current, non-conflicting Feishu endpoints in snapshot order.
    node_hosts: list[str] = field(default_factory=list)
    node_addresses: list[dict[str, str]] = field(default_factory=list, repr=False)
    feishu_number: str | None = None
    feishu_identity_confirmed: bool | None = field(default=None, repr=False)
    feishu_identity_reason: str = field(default="", repr=False)
    feishu_stale: bool = field(default=False, repr=False)
    feishu_brand: str | None = field(default=None, repr=False)
    feishu_model: str | None = field(default=None, repr=False)
    feishu_snapshot_generation: int = field(default=0, repr=False)
    targets: list[str] | None = None  # allowed targets (None = all)
    platforms: list[str] | None = None  # allowed platforms (None = all)
    variants: list[str] | None = None  # allowed variants (None = all)
    driver_paths: list[str] | None = None  # allowed driver paths (None = all)


@dataclass
class BuildInfo:
    """One build result from the Review Agent, as used in the lifecycle comment."""
    target: str
    driver_path: str
    variant: str
    success: bool
    image_tag: str
    deployable: bool  # computed by Controller: target=core|perception|actucore|driver
    component_id: str = ""


__all__ = [
    "MachineInfo",
    "BuildInfo",
]
