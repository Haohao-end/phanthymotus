"""Configuration for the Deploy Approval Agent (pre-merge validation only).

Stateless GitHub persistence: no INVALID_REMOVED required at runtime.
"""

from __future__ import annotations

import logging
import os
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


DEFAULT_GITHUB_REPOS = (
    "4paradigm/phanthymotus",
    "4paradigm/phanthymotus-driver",
)

SUPPORTED_GITHUB_REPOS = frozenset(DEFAULT_GITHUB_REPOS)


@dataclass
class Config:
    host: str = "0.0.0.0"
    port: int = 25001
    api_token: str = ""

    github_token: str = ""
    github_api_url: str = "https://api.github.com"
    github_webhook_secret: str = ""
    webhook_enabled: bool = False
    poll_enabled: bool = True
    github_command_poll_interval_seconds: int = 60
    github_repos: list[str] = field(
        default_factory=lambda: list(DEFAULT_GITHUB_REPOS)
    )
    poll_initial_lookback_hours: int = 24 * 7
    github_comment_max_pages: int = 20
    github_comment_max_comments: int = 500
    github_comment_max_bytes: int = 4 * 1024 * 1024

    review_agent_base_url: str = "http://host.docker.internal:25000"
    review_agent_api_token: str = ""
    agent_core_token: str = ""

    # Machine owners configuration
    machine_owners_file: str = "/run/deploy-approval/machines.yaml"

    # Security
    allow_private_http: bool = False
    http_allowed_cidrs: list[str] = field(default_factory=list)
    max_response_bytes: int = 8 * 1024 * 1024
    connect_timeout: float = 10.0
    read_timeout: float = 30.0
    total_timeout: float = 60.0
    health_poll_interval_seconds: float = 5.0
    health_timeout_seconds: float = 300.0

    # COS evidence storage
    cos_region: str = ""
    cos_bucket: str = ""
    cos_secret_id: str = ""
    cos_secret_key: str = ""
    cos_session_token: str = ""
    cos_prefix: str = "deploy-approval"
    cos_signed_url_ttl_seconds: int = 604800

    # Registry
    registry_user_env: str = "REGISTRY_USER"
    registry_password_env: str = "REGISTRY_PASSWORD"
    registry_auth_host_allowlist: list[str] = field(default_factory=list)


def _env_int(name: str, default: int, *, min_val: int = 1, max_val: int | None = None) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    if isinstance(raw, bool):
        raise ValueError(f"{name} must be a positive int, got bool")
    try:
        val = int(raw)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a positive int, got {raw!r}")
    if isinstance(val, bool):
        raise ValueError(f"{name} must be a positive int, got bool")
    if val <= 0:
        raise ValueError(f"{name} must be a positive int, got {val!r}")
    if max_val is not None and val > max_val:
        raise ValueError(f"{name} must be <= {max_val}, got {val!r}")
    if min_val is not None and val < min_val:
        raise ValueError(f"{name} must be >= {min_val}, got {val!r}")
    return val


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        f = float(raw)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a real number, got {raw!r}")
    if f <= 0 or f != f or f in (float("inf"), float("-inf")):
        raise ValueError(f"{name} must be a positive finite number, got {raw!r}")
    return f


_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off", ""}


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    val = raw.strip().lower()
    if val == "":
        return default
    if val in _TRUE_VALUES:
        return True
    if val in _FALSE_VALUES:
        return False
    raise ValueError(
        f"invalid boolean value for {name}={raw!r} \u2014 expected one of "
        f"{sorted(_TRUE_VALUES | _FALSE_VALUES)}"
    )


def _env_str_list(name: str, default: list[str] | None = None) -> list[str]:
    raw = os.getenv(name)
    if raw is None:
        return default or []
    if not raw.strip():
        return []
    result = [x.strip() for x in raw.split(",") if x.strip()]
    for item in result:
        if not isinstance(item, str):
            raise ValueError(f"{name} must be a comma-separated list of strings, got non-string element")
    return result


def load_config() -> Config:
    cfg = Config(
        host=os.getenv("APP_HOST", "0.0.0.0"),
        port=_env_int("APP_PORT", 25001, max_val=65535),
        api_token=os.getenv("API_TOKEN", ""),
        github_token=os.getenv("GITHUB_TOKEN", ""),
        github_api_url=os.getenv("GITHUB_API_URL", "https://api.github.com"),
        github_webhook_secret=os.getenv("GITHUB_WEBHOOK_SECRET", ""),
        webhook_enabled=_env_bool("WEBHOOK_ENABLED", False),
        poll_enabled=_env_bool("POLL_ENABLED", True),
        github_command_poll_interval_seconds=_env_int(
            "GITHUB_COMMAND_POLL_INTERVAL_SECONDS", 60
        ),
        github_repos=list(
            DEFAULT_GITHUB_REPOS if os.getenv("GITHUB_REPOS") is None
            else _env_str_list("GITHUB_REPOS")
        ),
        review_agent_base_url=os.getenv(
            "REVIEW_AGENT_BASE_URL", "http://host.docker.internal:25000"
        ),
        review_agent_api_token=os.getenv("REVIEW_AGENT_API_TOKEN", ""),
        agent_core_token=os.getenv("AGENT_CORE_TOKEN", ""),
        machine_owners_file=os.getenv(
            "MACHINE_OWNERS_FILE", "/run/deploy-approval/machines.yaml"
        ),
        allow_private_http=_env_bool("ALLOW_PRIVATE_HTTP", False),
        http_allowed_cidrs=_env_str_list("HTTP_ALLOWED_CIDRS"),
        connect_timeout=_env_float("HTTP_CONNECT_TIMEOUT", 10.0),
        read_timeout=_env_float("HTTP_READ_TIMEOUT", 30.0),
        total_timeout=_env_float("HTTP_TOTAL_TIMEOUT", 60.0),
        health_poll_interval_seconds=_env_float(
            "HEALTH_POLL_INTERVAL_SECONDS", 5.0
        ),
        health_timeout_seconds=_env_float("HEALTH_TIMEOUT_SECONDS", 300.0),
        cos_region=os.getenv("COS_REGION", ""),
        cos_bucket=os.getenv("COS_BUCKET", ""),
        cos_secret_id=os.getenv("COS_SECRET_ID", ""),
        cos_secret_key=os.getenv("COS_SECRET_KEY", ""),
        cos_session_token=os.getenv("COS_SESSION_TOKEN", ""),
        cos_prefix=os.getenv("COS_PREFIX", "deploy-approval"),
        cos_signed_url_ttl_seconds=_env_int(
            "COS_SIGNED_URL_TTL_SECONDS", 604800
        ),
        registry_user_env=os.getenv(
            "REGISTRY_USER_ENV", "REGISTRY_USER"
        ),
        registry_password_env=os.getenv(
            "REGISTRY_PASSWORD_ENV", "REGISTRY_PASSWORD"
        ),
        registry_auth_host_allowlist=_env_str_list(
            "REGISTRY_AUTH_HOST_ALLOWLIST"
        ),
    )
    validate_config(cfg)
    return cfg


def validate_config(cfg: Config) -> None:
    if not cfg.github_token:
        raise ValueError("GITHUB_TOKEN is required")
    if not cfg.github_repos:
        raise ValueError("GITHUB_REPOS is required")
    unknown_repos = [repo for repo in cfg.github_repos if repo not in SUPPORTED_GITHUB_REPOS]
    if unknown_repos:
        raise ValueError(
            "unsupported repository in GITHUB_REPOS: "
            + ", ".join(sorted(unknown_repos))
        )
    if not cfg.poll_enabled and not cfg.webhook_enabled:
        raise ValueError(
            "neither POLL_ENABLED nor WEBHOOK_ENABLED is true"
        )
    if cfg.webhook_enabled and not cfg.github_webhook_secret:
        raise ValueError(
            "WEBHOOK_ENABLED is true but GITHUB_WEBHOOK_SECRET is empty"
        )
    if not cfg.agent_core_token:
        raise ValueError("AGENT_CORE_TOKEN is required")
    if not isinstance(cfg.port, int) or isinstance(cfg.port, bool):
        raise ValueError(f"APP_PORT must be an int, got {cfg.port!r}")
    if cfg.port < 1 or cfg.port > 65535:
        raise ValueError(f"APP_PORT must be 1..65535, got {cfg.port}")
    if not isinstance(cfg.host, str):
        raise ValueError("APP_HOST must be a string")
    if not isinstance(cfg.github_repos, list):
        raise ValueError("GITHUB_REPOS must be a list")
    if not isinstance(cfg.http_allowed_cidrs, list):
        raise ValueError("HTTP_ALLOWED_CIDRS must be a list")
    if not isinstance(cfg.registry_auth_host_allowlist, list):
        raise ValueError("REGISTRY_AUTH_HOST_ALLOWLIST must be a list")
    _int_fields = {
        "GITHUB_COMMAND_POLL_INTERVAL_SECONDS": cfg.github_command_poll_interval_seconds,
        "MAX_RESPONSE_BYTES": cfg.max_response_bytes,
    }
    for name, v in _int_fields.items():
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError(f"{name} must be an int, got {v!r}")
        if v <= 0:
            raise ValueError(f"{name} must be positive, got {v!r}")
    for r in cfg.github_repos:
        if not isinstance(r, str):
            raise ValueError(f"GITHUB_REPOS member must be a string, got {r!r}")
    try:
        ipaddress.ip_address(cfg.host)
    except ValueError:
        pass
    for r in cfg.http_allowed_cidrs:
        if not isinstance(r, str):
            raise ValueError(f"HTTP_ALLOWED_CIDRS member must be a string, got {r!r}")
    if cfg.cos_signed_url_ttl_seconds <= 0 or cfg.cos_signed_url_ttl_seconds > 604800:
        raise ValueError(
            f"COS_SIGNED_URL_TTL_SECONDS must be 1..604800, got {cfg.cos_signed_url_ttl_seconds}"
        )
