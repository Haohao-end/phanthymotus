"""Config tests (final alignment)."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from ..config import (
    Config,
    load_config,
    validate_config,
    _env_bool,
    _env_float,
    _env_int,
)


def test_config_defaults():
    c = Config(github_token="tok", github_repos=["org/repo"])
    assert c.host == "0.0.0.0"
    assert c.port == 25001
    assert c.poll_enabled is True
    assert c.machine_owners_file == "/run/deploy-approval/machines.yaml"


def test_validate_config_requires_token():
    with pytest.raises(ValueError, match="GITHUB_TOKEN is required"):
        validate_config(
            Config(
                github_repos=[
                    "4paradigm/phanthymotus",
                    "4paradigm/phanthymotus-driver",
                ]
            )
        )


def test_validate_config_default_repos():
    """Default github_repos includes the two official repos."""
    c = Config(github_token="tok")
    assert "4paradigm/phanthymotus" in c.github_repos
    assert "4paradigm/phanthymotus-driver" in c.github_repos
    # Explicit empty overrides defaults — must fail closed
    with pytest.raises(ValueError, match="GITHUB_REPOS is required"):
        validate_config(Config(github_token="tok", github_repos=[]))


def test_validate_config_requires_webhook_secret():
    with pytest.raises(ValueError, match="GITHUB_WEBHOOK_SECRET is empty"):
        validate_config(
            Config(
                github_token="tok",
                github_repos=[
                    "4paradigm/phanthymotus",
                    "4paradigm/phanthymotus-driver",
                ],
                webhook_enabled=True,
            )
        )


def test_validate_config_requires_polling():
    with pytest.raises(ValueError, match="requires polling"):
        validate_config(
            Config(
                github_token="tok",
                github_repos=[
                    "4paradigm/phanthymotus",
                    "4paradigm/phanthymotus-driver",
                ],
                poll_enabled=False,
                webhook_enabled=True,
                github_webhook_secret="secret",
            )
        )


def test_env_int():
    os.environ["TEST_INT"] = "42"
    assert _env_int("TEST_INT", 1) == 42
    os.environ["TEST_INT"] = "0"
    with pytest.raises(ValueError):
        _env_int("TEST_INT", 1)
    del os.environ["TEST_INT"]


def test_env_bool():
    os.environ["TEST_BOOL"] = "true"
    assert _env_bool("TEST_BOOL") is True
    os.environ["TEST_BOOL"] = "false"
    assert _env_bool("TEST_BOOL") is False
    os.environ["TEST_BOOL"] = "invalid"
    with pytest.raises(ValueError):
        _env_bool("TEST_BOOL")
    del os.environ["TEST_BOOL"]


def test_env_float():
    os.environ["TEST_FLOAT"] = "3.5"
    assert _env_float("TEST_FLOAT", 1.0) == 3.5
    os.environ["TEST_FLOAT"] = "0"
    with pytest.raises(ValueError):
        _env_float("TEST_FLOAT", 1.0)
    del os.environ["TEST_FLOAT"]


def test_config_env_override(monkeypatch):
    """Explicit GITHUB_REPOS overrides the default."""
    monkeypatch.setenv("GITHUB_REPOS", "4paradigm/phanthymotus,4paradigm/phanthymotus-driver")
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setenv("POLL_INTERVAL_SECONDS", "30")
    cfg = load_config()
    assert cfg.github_repos == ["4paradigm/phanthymotus", "4paradigm/phanthymotus-driver"]


def test_config_env_empty_fails_closed(monkeypatch):
    """Explicit empty GITHUB_REPOS must fail closed."""
    monkeypatch.setenv("GITHUB_REPOS", "")
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setenv("POLL_INTERVAL_SECONDS", "30")
    with pytest.raises(ValueError, match="GITHUB_REPOS is required"):
        load_config()


def test_config_env_unset_uses_default(monkeypatch):
    """GITHUB_REPOS unset uses DEFAULT_GITHUB_REPOS."""
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setenv("POLL_INTERVAL_SECONDS", "30")
    monkeypatch.delenv("GITHUB_REPOS", raising=False)
    cfg = load_config()
    assert "4paradigm/phanthymotus" in cfg.github_repos
    assert "4paradigm/phanthymotus-driver" in cfg.github_repos
