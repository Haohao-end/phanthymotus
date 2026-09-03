"""Shared fixtures (final alignment). All external systems are mocked."""
from __future__ import annotations

import pytest

from ..config import Config
from ..policy import Policy


def make_config(**overrides):
    defaults = dict(
        allow_private_http=False,
        http_allowed_cidrs=[],
        review_agent_base_url="http://host.docker.internal:25000",
        github_api_url="https://api.github.com",
        webhook_enabled=True,
        github_webhook_secret="test-secret",
        machine_owners_file="/dev/null",
        github_repos=["4paradigm/phanthymotus"],
        poll_enabled=True,
        poll_interval_seconds=30,
        health_timeout_seconds=0.05,
        health_poll_interval_seconds=0.0,
    )
    defaults.update(overrides)
    return Config(**defaults)


@pytest.fixture
def config():
    return make_config()


@pytest.fixture
def policy(config):
    return Policy(config)
