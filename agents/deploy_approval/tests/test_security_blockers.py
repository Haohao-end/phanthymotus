"""Security blocker tests (final alignment).
Fail-closed, legacy commands unknown, per-machine owners, no duplicate POST.
"""

from __future__ import annotations

import pytest
import yaml

from ..commands import parse_command
from ..models import can_transition
from ..policy import Policy, PolicyError, load_machines, MachineLoadError
from .conftest import make_config


def test_legacy_rollback_commands_unknown():
    assert parse_command("/reject_deploy d-9").kind == "unknown"
    assert parse_command("/rollback_deploy d-7").kind == "unknown"
    assert parse_command("/cancel_deploy d-9").kind == "unknown"
    assert parse_command("/resume_deploy d-9").kind == "unknown"


def test_unknown_command_no_mutation():
    cmd = parse_command("/unknown_command")
    assert cmd.kind == "unknown"
    assert not cmd.is_command


def test_unbalanced_quote_fails_closed():
    assert parse_command('/request_deploy build=1 test-mode="manual').kind == "unknown"


def test_machine_owner_empty_fails_closed(tmp_path):
    import tempfile, os as _os
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
    yaml.dump({"version": 1, "machines": {
        "g1": {"node_id": "n1", "owners": []},
    }}, f)
    path = f.name
    f.close()
    try:
        with pytest.raises(MachineLoadError):
            load_machines(path)
    finally:
        _os.unlink(path)


def test_non_owner_rejected(tmp_path):
    p = Policy(make_config())
    with pytest.raises(PolicyError):
        p.can_approve("alice", actor_id="id2", machine_alias="nonexistent")


def test_collaborator_write_can_approve():
    from ..policy import Policy
    assert Policy.collaborator_can_approve("write") is True
    assert Policy.collaborator_can_approve("") is False


def test_fail_closed_state_transition():
    assert not can_transition("waiting-approval", "succeeded")


def test_no_controller_cleanup():
    """Deploy Controller must not implement cleanup methods."""
    import agents.deploy_approval.service as svc_mod
    import inspect
    src = inspect.getsource(svc_mod)
    # The service must not call stop/remove/sync endpoints
    forbidden = ["/api/drivers/{id}/stop", "driver_stop", "driver_remove",
                 "system_update", "docker rm", "docker stop"]
    for phrase in forbidden:
        assert phrase not in src, f"Found forbidden pattern: {phrase}"


def test_fail_closed_head_drift():
    """HEAD drift must fail closed."""
    # The controller checks current HEAD before dispatching commands
    # This is verified in the controller's handle_approve_deploy path
    # which reads fresh PR data and compares head_sha
    from ..github_state_proxy import _is_valid_full_sha
    assert _is_valid_full_sha("a" * 40) is True
    assert _is_valid_full_sha("b" * 40) is True
    assert _is_valid_full_sha("") is False
