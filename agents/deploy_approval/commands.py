"""Parsing and validation for PR-conversation deploy commands (pre-merge validation).

Commands must start a line. Only the PR's main-conversation comments are read.
Parsing is strict: unknown flags, a duplicated required arg or a stray argument
are rejected as ``unknown``.

Five commands are public:
  - ``/request_deploy`` — PR Author requests a deployment (ZERO parameters)
  - ``/approve_deploy`` — Machine Owner approves a deployment
  - ``/record_test`` — Machine Owner records test result (no machine=)
  - ``/deploy_status`` — Read-only status query
  - ``/deploy_help`` — Help for commands
"""

from __future__ import annotations

from dataclasses import dataclass
import shlex
from typing import Literal


CommandKind = Literal[
    "request_deploy",
    "approve_deploy",
    "record_test",
    "deploy_status",
    "deploy_help",
    "unknown",
]


@dataclass
class ParsedCommand:
    kind: CommandKind
    machine_alias: str = ""
    result: str = ""
    summary: str = ""
    help_topic: str = ""
    raw: str = ""
    comment_id: int = 0

    @property
    def is_command(self) -> bool:
        return self.kind != "unknown"


_KNOWN = {
    "request_deploy",
    "approve_deploy",
    "record_test",
    "deploy_status",
    "deploy_help",
}


def _split_token(t: str):
    if "=" in t:
        k, _, v = t.partition("=")
        return k.strip().lower(), v.strip().strip('"').strip("'")
    return None, t


def _parse_args(tokens: list[str]) -> tuple[list[str], dict[str, str]]:
    positional: list[str] = []
    kv: dict[str, str] = {}
    for t in tokens:
        k, v = _split_token(t)
        if k is None:
            positional.append(str(v))
        else:
            if k in kv:
                raise ValueError(f"duplicate argument {k}")
            kv[k] = v
    return positional, kv


# Allowed key=value arguments for each command.
_ALLOWED_KV = {
    "request_deploy": frozenset(),        # ZERO parameters
    "approve_deploy": frozenset({"machine"}),
    "record_test": frozenset({"result", "summary"}),
    "deploy_status": frozenset(),
    "deploy_help": frozenset(),
}


def parse_command(comment_text: str) -> ParsedCommand:
    """Parse the first line-starting command in ``comment_text``."""
    if not comment_text:
        return ParsedCommand(kind="unknown", raw="")
    for raw_line in comment_text.splitlines():
        line = raw_line.strip()
        if not line.startswith("/"):
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            return ParsedCommand(kind="unknown", raw="")
        if not tokens:
            continue
        name = tokens[0][1:].strip().lower()
        if name not in _KNOWN:
            continue
        try:
            positional, kv = _parse_args(tokens[1:])
        except ValueError:
            return ParsedCommand(kind="unknown", raw="")
        allowed = _ALLOWED_KV[name]
        if any(k not in allowed for k in kv):
            return ParsedCommand(kind="unknown", raw="")
        # request_deploy: reject any positional args or key=value args
        if name == "request_deploy":
            if positional:
                return ParsedCommand(kind="unknown", raw="")
            # Also reject any key=value args (allowed set is empty)
            return ParsedCommand(kind="request_deploy", raw=raw_line.strip())
        return _build_command(name, positional, kv, tokens[1:])
    return ParsedCommand(kind="unknown", raw="")


def _build_command(name: str, positional: list[str], kv: dict[str, str],
                   raw_tokens: list[str]) -> ParsedCommand:
    raw = name + " " + " ".join(raw_tokens)
    if name == "request_deploy":
        # Already handled above
        return ParsedCommand(kind="request_deploy", raw=raw)
    if name == "approve_deploy":
        if positional:
            return ParsedCommand(kind="unknown", raw="")
        machine_alias = kv.get("machine", "")
        if not machine_alias:
            return ParsedCommand(kind="unknown", raw="")
        return ParsedCommand(
            kind="approve_deploy", machine_alias=machine_alias, raw=raw
        )
    if name == "record_test":
        if positional:
            return ParsedCommand(kind="unknown", raw="")
        result = kv.get("result", "")
        if result not in ("pass", "fail"):
            return ParsedCommand(kind="unknown", raw="")
        # Reject machine= parameter
        if "machine" in kv:
            return ParsedCommand(kind="unknown", raw="")
        summary = kv.get("summary", "")
        return ParsedCommand(
            kind="record_test", result=result, summary=summary, raw=raw
        )
    if name == "deploy_status":
        if positional:
            return ParsedCommand(kind="unknown", raw="")
        return ParsedCommand(kind="deploy_status", raw=raw)
    if name == "deploy_help":
        topic = " ".join(positional) if positional else ""
        return ParsedCommand(
            kind="deploy_help", help_topic=topic, raw=raw
        )
    return ParsedCommand(kind="unknown", raw="")


def command_starts_line(text: str, kind: str) -> bool:
    prefix = "/" + kind
    for line in text.splitlines():
        if line.strip().startswith(prefix):
            return True
    return False


def command_starts_line_any(text: str) -> bool:
    for line in text.splitlines():
        if line.strip().startswith("/"):
            name = line.strip().split()[0][1:].lower()
            if name in _KNOWN:
                return True
    return False
