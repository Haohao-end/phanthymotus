"""Tests for Deploy Approval command parsing."""
from __future__ import annotations

import pytest
from ..commands import parse_command, command_starts_line_any


class TestRequestDeploy:
    def test_parameterless(self):
        cmd = parse_command("/request_deploy")
        assert cmd.kind == "request_deploy"
        assert cmd.is_command

    def test_rejects_build_parameter(self):
        cmd = parse_command("/request_deploy build=0")
        assert cmd.kind == "unknown"
        assert not cmd.is_command

    def test_rejects_machine_parameter(self):
        cmd = parse_command("/request_deploy machine=x")
        assert cmd.kind == "unknown"

    def test_rejects_test_mode_parameter(self):
        cmd = parse_command("/request_deploy test-mode=plan")
        assert cmd.kind == "unknown"

    def test_rejects_test_plan_parameter(self):
        cmd = parse_command("/request_deploy test-plan=...")
        assert cmd.kind == "unknown"

    def test_rejects_test_case_parameter(self):
        cmd = parse_command("/request_deploy test-case=...")
        assert cmd.kind == "unknown"

    def test_rejects_positional(self):
        cmd = parse_command("/request_deploy 1")
        assert cmd.kind == "unknown"


class TestApproveDeploy:
    def test_requires_machine(self):
        cmd = parse_command("/approve_deploy machine=g1-bj-wifi")
        assert cmd.kind == "approve_deploy"
        assert cmd.is_command
        assert cmd.machine_alias == "g1-bj-wifi"

    def test_rejects_without_machine(self):
        cmd = parse_command("/approve_deploy")
        assert cmd.kind == "unknown"

    def test_rejects_positional(self):
        cmd = parse_command("/approve_deploy dpl_x machine=x")
        assert cmd.kind == "unknown"


class TestRecordTest:
    def test_result_pass(self):
        cmd = parse_command("/record_test result=pass")
        assert cmd.kind == "record_test"
        assert cmd.is_command
        assert cmd.result == "pass"

    def test_result_fail(self):
        cmd = parse_command("/record_test result=fail")
        assert cmd.kind == "record_test"
        assert cmd.result == "fail"

    def test_result_fail_with_summary(self):
        cmd = parse_command('/record_test result=fail summary="test failed"')
        assert cmd.kind == "record_test"
        assert cmd.result == "fail"
        assert cmd.summary == "test failed"

    def test_rejects_machine_parameter(self):
        cmd = parse_command("/record_test machine=x result=pass")
        assert cmd.kind == "unknown"

    def test_rejects_positional(self):
        cmd = parse_command("/record_test dpl_x result=pass")
        assert cmd.kind == "unknown"

    def test_rejects_evidence_parameter(self):
        cmd = parse_command("/record_test result=pass evidence=...")
        assert cmd.kind == "unknown"

    def test_invalid_result(self):
        cmd = parse_command("/record_test result=maybe")
        assert cmd.kind == "unknown"


class TestDeployStatus:
    def test_parameterless(self):
        cmd = parse_command("/deploy_status")
        assert cmd.kind == "deploy_status"
        assert cmd.is_command

    def test_rejects_positional(self):
        cmd = parse_command("/deploy_status dpl_01abc")
        assert cmd.kind == "unknown"


class TestDeployHelp:
    def test_parameterless(self):
        cmd = parse_command("/deploy_help")
        assert cmd.kind == "deploy_help"
        assert cmd.is_command

    def test_with_topic(self):
        cmd = parse_command("/deploy_help request_deploy")
        assert cmd.kind == "deploy_help"
        assert cmd.help_topic == "request_deploy"


class TestUnknownCommands:
    def test_legacy_reject(self):
        assert parse_command("/reject_deploy").kind == "unknown"

    def test_legacy_rollback(self):
        assert parse_command("/rollback_deploy").kind == "unknown"

    def test_legacy_cancel(self):
        assert parse_command("/cancel_deploy").kind == "unknown"

    def test_legacy_resume(self):
        assert parse_command("/resume_deploy").kind == "unknown"

    def test_empty(self):
        cmd = parse_command("")
        assert cmd.kind == "unknown"
        assert not cmd.is_command

    def test_not_a_command(self):
        assert not command_starts_line_any("not a command")

    def test_unbalanced_quote(self):
        cmd = parse_command('/approve_deploy machine="unclosed')
        assert cmd.kind == "unknown"


class TestCommandStartsLine:
    def test_command_starts_line(self):
        assert command_starts_line_any("/request_deploy")
        assert command_starts_line_any("/approve_deploy machine=g1")
        assert command_starts_line_any("/record_test result=pass")
        assert command_starts_line_any("/deploy_status")
        assert command_starts_line_any("/deploy_help")
        assert not command_starts_line_any("")
        assert not command_starts_line_any("not a command")
