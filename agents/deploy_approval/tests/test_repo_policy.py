"""Mocked behavior tests for official repository policy authorization."""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import time
from types import SimpleNamespace

import pytest

from ..comments import _repo_policy_display_status
from ..config import Config, parse_test_reviewers_yaml
from ..github_client import GitHubPermissionError, GitHubTransientError
from ..policy import parse_machines_yaml
from ..repo_policy import POLICY_REFRESH_SECONDS, RepositoryPolicyStore


CORE = "4paradigm/phanthymotus"
DRIVER = "4paradigm/phanthymotus-driver"
CORE_REPO = CORE
DRIVER_REPO = DRIVER


def _machine_yaml(alias: str, node_id: str, host: str) -> bytes:
    return (
        "version: 1\n"
        "machines:\n"
        f"  {alias}:\n"
        f"    node_id: {node_id}\n"
        f"    node_host: {host}\n"
        "    owners: [test-owner]\n"
        "    targets: [perception]\n"
        "    platforms: [linux/arm64]\n"
    ).encode()


def _reviewers_yaml(login: str) -> bytes:
    return f"version: 1\nreviewers: [{login}]\n".encode()


def _github_file(path: str, content: bytes, etag: str = '"policy-v1"') -> dict:
    blob_sha = hashlib.sha1(
        b"blob " + str(len(content)).encode("ascii") + b"\0" + content,
    ).hexdigest()
    return {
        "not_modified": False,
        "path": path,
        "sha": blob_sha,
        "content": content,
        "etag": etag,
    }


def _config(**overrides) -> Config:
    values = {
        "github_repos": [CORE_REPO, DRIVER_REPO],
        "active_repos": [CORE_REPO, DRIVER_REPO],
        "policy_active_repos": [CORE, DRIVER],
        "auth_valid": True,
    }
    values.update(overrides)
    return Config(**values)


def _store(config: Config | None = None) -> RepositoryPolicyStore:
    return RepositoryPolicyStore(
        config or _config(),
        machine_parser=parse_machines_yaml,
        reviewer_parser=parse_test_reviewers_yaml,
    )


class _Reader:
    def __init__(self):
        self.responses: dict[tuple[str, str], object] = {}
        self.calls: list[tuple[str, str, str | None]] = []

    async def get_repository_file_at_ref(self, repo, path, *, ref="main", etag=None):
        assert ref == "main"
        self.calls.append((repo, path, etag))
        response = self.responses.get((repo, path))
        if isinstance(response, Exception):
            raise response
        if callable(response):
            response = response(etag)
        return response


def _set_main_files(reader: _Reader, repo: str, alias: str, reviewer: str):
    reader.responses[(repo, "machines.yaml")] = _github_file(
        "machines.yaml", _machine_yaml(alias, f"{alias}-node", "192.0.2.10"),
        f'"{alias}-machines"',
    )
    reader.responses[(repo, "test_reviewers.yaml")] = _github_file(
        "test_reviewers.yaml", _reviewers_yaml(reviewer), f'"{alias}-reviewers"',
    )


def _mark_due(store: RepositoryPolicyStore, repo: str):
    store._state(repo).last_checked = time.monotonic() - POLICY_REFRESH_SECONDS - 1


@pytest.mark.asyncio
async def test_official_policy_read_uses_its_own_repository():
    store = _store()
    reader = _Reader()
    _set_main_files(reader, CORE, "core-machine", "corereviewer")

    await store.refresh_if_due(CORE_REPO, reader)

    assert {repo for repo, _path, _etag in reader.calls} == {CORE}
    assert list(store.machines_for(CORE_REPO)) == ["core-machine"]


@pytest.mark.asyncio
async def test_core_and_driver_keep_four_yaml_files_independent():
    store = _store()
    reader = _Reader()
    _set_main_files(reader, CORE, "core-machine", "corereviewer")
    _set_main_files(reader, DRIVER, "driver-machine", "driverreviewer")

    await store.refresh_if_due(CORE_REPO, reader)
    await store.refresh_if_due(DRIVER_REPO, reader)

    assert set(store.machines_for(CORE_REPO)) == {"core-machine"}
    assert set(store.machines_for(DRIVER_REPO)) == {"driver-machine"}
    assert store.reviewers_for_repo(CORE_REPO) == ["corereviewer"]
    assert store.reviewers_for_repo(DRIVER_REPO) == ["driverreviewer"]
    assert {(repo, path) for repo, path, _ in reader.calls} == {
        (CORE, "machines.yaml"),
        (CORE, "test_reviewers.yaml"),
        (DRIVER, "machines.yaml"),
        (DRIVER, "test_reviewers.yaml"),
    }


@pytest.mark.asyncio
async def test_untrusted_repository_does_not_read_or_fallback(monkeypatch):
    config = _config(policy_active_repos=[])
    store = _store(config)
    reader = _Reader()
    fallback_calls = []

    def local_fallback(repo, filename):
        fallback_calls.append((repo, filename))
        return _machine_yaml("unexpected", "unexpected-node", "192.0.2.20")

    monkeypatch.setattr(
        RepositoryPolicyStore, "_local_candidate_bytes", staticmethod(local_fallback),
    )
    result = await store.refresh_if_due(CORE_REPO, reader)

    assert result["status"] == "unauthorized"
    assert reader.calls == []
    assert fallback_calls == []
    assert store.machines_for(CORE_REPO) == {}


@pytest.mark.asyncio
async def test_invalid_app_auth_blocks_policy_even_when_repo_is_in_snapshot():
    store = _store(_config(auth_valid=False))
    reader = _Reader()

    result = await store.refresh_if_due(CORE_REPO, reader)

    assert result["status"] == "unauthorized"
    assert reader.calls == []
    assert store.machines_for(CORE_REPO) == {}


@pytest.mark.asyncio
async def test_core_policy_authorization_does_not_authorize_driver():
    config = _config(policy_active_repos=[CORE])
    store = _store(config)
    reader = _Reader()

    result = await store.refresh_if_due(DRIVER_REPO, reader)

    assert result["status"] == "unauthorized"
    assert reader.calls == []
    assert store.machines_for(DRIVER_REPO) == {}


@pytest.mark.asyncio
async def test_configured_fork_maps_to_matching_official_policy_only():
    fork_core = "test-owner/phanthymotus"
    fork_driver = "test-owner/phanthymotus-driver"
    config = _config(github_repos=[fork_core, fork_driver], active_repos=[fork_core, fork_driver])
    store, reader = _store(config), _Reader()
    _set_main_files(reader, CORE, "core-machine", "core-reviewer")
    _set_main_files(reader, DRIVER, "driver-machine", "driver-reviewer")
    await store.refresh_if_due(fork_core, reader)
    await store.refresh_if_due(fork_driver, reader)
    assert set(store.machines_for(fork_core)) == {"core-machine"}
    assert set(store.machines_for(fork_driver)) == {"driver-machine"}
    assert {(repo, filename) for repo, filename, _ in reader.calls} == {
        (CORE, "machines.yaml"), (CORE, "test_reviewers.yaml"),
        (DRIVER, "machines.yaml"), (DRIVER, "test_reviewers.yaml"),
    }


@pytest.mark.asyncio
async def test_unconfigured_same_name_fork_is_unsupported():
    fork = "stranger/phanthymotus"
    store = _store(_config(github_repos=[CORE], active_repos=[CORE]))
    reader = _Reader()
    result = await store.refresh_if_due(fork, reader)
    assert result["status"] == "unsupported_repository"
    assert reader.calls == []


@pytest.mark.asyncio
async def test_contents_403_never_uses_local_fallback(monkeypatch):
    store = _store()
    reader = _Reader()
    reader.responses[(CORE, "machines.yaml")] = GitHubPermissionError(
        "installation access denied", status_code=403,
    )
    fallback_calls = []
    monkeypatch.setattr(
        RepositoryPolicyStore,
        "_local_candidate_bytes",
        staticmethod(
            lambda repo, path: fallback_calls.append((repo, path))
        ),
    )
    result = await store.refresh_if_due(CORE_REPO, reader)

    assert result["status"] == "unauthorized"
    assert fallback_calls == []
    assert all(repo == CORE for repo, _path, _etag in reader.calls)


@pytest.mark.asyncio
async def test_authorized_official_404_uses_only_same_repository_local_candidate(monkeypatch):
    store = _store()
    reader = _Reader()
    reader.responses[(CORE, "machines.yaml")] = None
    reader.responses[(CORE, "test_reviewers.yaml")] = None
    candidates = {
        (CORE, "machines.yaml"): _machine_yaml("local-core", "local-core-node", "192.0.2.11"),
        (CORE, "test_reviewers.yaml"): _reviewers_yaml("localreviewer"),
    }
    local_reads = []

    def read_candidate(repo, filename):
        local_reads.append((repo, filename))
        return candidates.get((repo, filename))

    monkeypatch.setattr(
        RepositoryPolicyStore, "_local_candidate_bytes", staticmethod(read_candidate),
    )
    result = await store.refresh_if_due(CORE_REPO, reader)

    assert result["status"] == "updated"
    assert store.status(CORE_REPO)["machines_source"] == "local_fallback"
    assert store.status(CORE_REPO)["test_reviewers_source"] == "local_fallback"
    assert set(local_reads) == {(CORE, "machines.yaml"), (CORE, "test_reviewers.yaml")}
    assert store.machines_for(CORE_REPO)["local-core"].node_host == "192.0.2.11"
    assert store.reviewers_for_repo(CORE_REPO) == ["localreviewer"]


@pytest.mark.asyncio
async def test_network_error_retains_last_trusted_main_snapshot():
    store = _store()
    reader = _Reader()
    _set_main_files(reader, CORE, "core-machine", "corereviewer")
    await store.refresh_if_due(CORE_REPO, reader)
    original_sha = store.status(CORE_REPO)["source_sha"]["machines.yaml"]

    _mark_due(store, CORE)
    reader.responses[(CORE, "machines.yaml")] = GitHubTransientError(
        status_code=503, retry_after_seconds=1,
    )
    reader.responses[(CORE, "test_reviewers.yaml")] = GitHubTransientError(
        status_code=503, retry_after_seconds=1,
    )
    result = await store.refresh_if_due(CORE_REPO, reader)

    assert result["status"] == "partial_error"
    assert store.machines_for(CORE_REPO)["core-machine"].node_id == "core-machine-node"
    status = store.status(CORE_REPO)
    assert status["source_sha"]["machines.yaml"] == original_sha
    assert status["machines_yaml_status"] == "valid"
    assert status["last_attempt_status"]["machines.yaml"] == "network_error"


@pytest.mark.asyncio
async def test_invalid_official_schema_retains_last_trusted_main_snapshot():
    store = _store()
    reader = _Reader()
    _set_main_files(reader, CORE, "core-machine", "corereviewer")
    await store.refresh_if_due(CORE_REPO, reader)
    original_sha = store.status(CORE_REPO)["source_sha"]["machines.yaml"]

    _mark_due(store, CORE)
    reader.responses[(CORE, "machines.yaml")] = _github_file(
        "machines.yaml", b"version: 99\nmachines: {}\n", '"invalid-v2"',
    )
    reader.responses[(CORE, "test_reviewers.yaml")] = {
        "not_modified": True,
        "etag": '"core-reviewers"',
    }
    await store.refresh_if_due(CORE_REPO, reader)

    status = store.status(CORE_REPO)
    assert store.machines_for(CORE_REPO)["core-machine"].node_id == "core-machine-node"
    assert status["source_sha"]["machines.yaml"] == original_sha
    assert status["rejected_sha"]["machines.yaml"] != original_sha
    assert status["machines_yaml_status"] == "valid"
    assert status["last_attempt_status"]["machines.yaml"] == "invalid_schema"


@pytest.mark.asyncio
async def test_invalid_local_schema_keeps_previous_trusted_local_snapshot(monkeypatch):
    store = _store()
    reader = _Reader()
    reader.responses[(CORE, "machines.yaml")] = None
    reader.responses[(CORE, "test_reviewers.yaml")] = None
    candidates = {
        (CORE, "machines.yaml"): _machine_yaml("local-core", "local-core-node", "192.0.2.12"),
        (CORE, "test_reviewers.yaml"): _reviewers_yaml("localreviewer"),
    }
    monkeypatch.setattr(
        RepositoryPolicyStore,
        "_local_candidate_bytes",
        staticmethod(lambda repo, path: candidates.get((repo, path))),
    )
    await store.refresh_if_due(CORE_REPO, reader)
    original_sha = store.status(CORE_REPO)["source_sha"]["machines.yaml"]

    _mark_due(store, CORE)
    candidates[(CORE, "machines.yaml")] = b"version: 9\nmachines: {}\n"
    await store.refresh_if_due(CORE_REPO, reader)

    status = store.status(CORE_REPO)
    assert store.machines_for(CORE_REPO)["local-core"].node_id == "local-core-node"
    assert status["source_sha"]["machines.yaml"] == original_sha
    assert status["machines_source"] == "local_fallback"
    assert status["machines_yaml_status"] == "valid"
    assert status["last_attempt_status"]["machines.yaml"] == "invalid_schema"


@pytest.mark.asyncio
async def test_invalid_first_local_candidate_fails_closed(monkeypatch):
    store = _store()
    reader = _Reader()
    reader.responses[(CORE, "machines.yaml")] = None
    reader.responses[(CORE, "test_reviewers.yaml")] = None
    candidates = {
        (CORE, "machines.yaml"): b"version: 9\nmachines: {}\n",
        (CORE, "test_reviewers.yaml"): _reviewers_yaml("localreviewer"),
    }
    monkeypatch.setattr(
        RepositoryPolicyStore,
        "_local_candidate_bytes",
        staticmethod(lambda repo, path: candidates.get((repo, path))),
    )

    await store.refresh_if_due(CORE_REPO, reader)

    status = store.status(CORE_REPO)
    assert store.machines_for(CORE_REPO) == {}
    assert "machines.yaml" not in status["source_sha"]
    assert status["machines_yaml_status"] == "invalid_schema"


@pytest.mark.asyncio
async def test_deleted_local_candidate_fails_closed_without_replacing_trusted_sha(monkeypatch):
    store = _store()
    reader = _Reader()
    reader.responses[(CORE, "machines.yaml")] = None
    reader.responses[(CORE, "test_reviewers.yaml")] = None
    candidates = {
        (CORE, "machines.yaml"): _machine_yaml("local-core", "local-core-node", "192.0.2.13"),
        (CORE, "test_reviewers.yaml"): _reviewers_yaml("localreviewer"),
    }
    monkeypatch.setattr(
        RepositoryPolicyStore,
        "_local_candidate_bytes",
        staticmethod(lambda repo, path: candidates.get((repo, path))),
    )
    await store.refresh_if_due(CORE_REPO, reader)
    original_sha = store.status(CORE_REPO)["source_sha"]["machines.yaml"]

    _mark_due(store, CORE)
    candidates[(CORE, "machines.yaml")] = None
    await store.refresh_if_due(CORE_REPO, reader)

    assert store.machines_for(CORE_REPO) == {}
    status = store.status(CORE_REPO)
    assert status["source_sha"]["machines.yaml"] == original_sha
    assert status["machines_yaml_status"] == "missing"


@pytest.fixture
def local_policy_directory(tmp_path, monkeypatch):
    tmp_root = tmp_path.resolve()
    policy_root = tmp_root / "policy-candidates"
    core_dir = policy_root / "core"
    core_dir.mkdir(parents=True)
    root_parts = tuple(tmp_root.parts[1:]) + ("policy-candidates",)
    monkeypatch.setattr("agents.deploy_approval.repo_policy._LOCAL_POLICY_ROOT_PARTS", root_parts)

    # Linux test runners often put pytest's temporary directory below the
    # shared, sticky /tmp directory. Production policy roots remain checked;
    # mask only that test fixture ancestor so the candidate checks are reached.
    real_fstat = os.fstat
    calls = {"count": 0}

    def fixture_fstat(fd):
        result = real_fstat(fd)
        calls["count"] += 1
        if tmp_root.parts[1:2] == ("tmp",) and calls["count"] == 1:
            return SimpleNamespace(st_mode=result.st_mode & ~(stat.S_IWGRP | stat.S_IWOTH))
        return result

    monkeypatch.setattr("agents.deploy_approval.repo_policy.os.fstat", fixture_fstat)
    return core_dir


def test_local_candidate_symlink_is_rejected(local_policy_directory, tmp_path):
    target = tmp_path / "trusted.yaml"
    target.write_bytes(_machine_yaml("machine", "node", "192.0.2.14"))
    (local_policy_directory / "machines.yaml").symlink_to(target)

    with pytest.raises(OSError) as error:
        RepositoryPolicyStore._local_candidate_bytes(CORE, "machines.yaml")

    assert error.value.errno in {errno.ELOOP, errno.EMLINK}


@pytest.mark.parametrize("unsafe_location", ["file", "directory"])
def test_local_candidate_group_or_world_writable_is_rejected(
    local_policy_directory, unsafe_location,
):
    candidate = local_policy_directory / "machines.yaml"
    candidate.write_bytes(_machine_yaml("machine", "node", "192.0.2.15"))
    if unsafe_location == "file":
        candidate.chmod(0o666)
    else:
        local_policy_directory.chmod(0o777)

    with pytest.raises(ValueError, match="permissions are unsafe"):
        RepositoryPolicyStore._local_candidate_bytes(CORE, "machines.yaml")


@pytest.mark.asyncio
async def test_unchanged_etag_restores_main_file_valid_status():
    store = _store()
    reader = _Reader()
    _set_main_files(reader, CORE, "core-machine", "corereviewer")
    await store.refresh_if_due(CORE_REPO, reader)
    _mark_due(store, CORE)
    for filename in ("machines.yaml", "test_reviewers.yaml"):
        store._state(CORE).file_checked_at[filename] = (
            time.monotonic() - POLICY_REFRESH_SECONDS - 1
        )
    assert store.status(CORE_REPO)["machines_yaml_status"] == "stale"
    reader.responses[(CORE, "machines.yaml")] = lambda etag: (
        {"not_modified": True, "etag": etag} if etag else None
    )
    reader.responses[(CORE, "test_reviewers.yaml")] = lambda etag: (
        {"not_modified": True, "etag": etag} if etag else None
    )

    await store.refresh_if_due(CORE_REPO, reader)

    assert store.status(CORE_REPO)["machines_yaml_status"] == "valid"
    assert store.status(CORE_REPO)["test_reviewers_yaml_status"] == "valid"
    assert reader.calls[-2][2] == '"core-machine-machines"'
    assert reader.calls[-1][2] == '"core-machine-reviewers"'
    assert store.machines_for(CORE_REPO)["core-machine"].node_id == "core-machine-node"


def test_summary_hides_internal_local_source_name():
    summary = _repo_policy_display_status(
        CORE_REPO,
        {
            "github_app_authorized": True,
            "machines_configured": True,
            "machines_yaml_status": "valid",
            "machines_source": "local_fallback",
            "source_sha": {"machines.yaml": "a" * 64},
            "authorized_machines": {"core-machine": True},
            "test_reviewers_yaml_status": "missing",
            "test_reviewers_source": "",
        },
        {},
    )

    assert summary["machines_status"] == (
        "服务器本地临时配置：正式 main 尚未提供该文件，当前使用服务器已验证的配置。"
    )
    assert "local_fallback" not in summary["machines_status"]
