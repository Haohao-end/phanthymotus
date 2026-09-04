"""Minimal COS evidence bundle builder for Deploy Approval."""

from __future__ import annotations

import hashlib
import io
import json
import re
import tarfile
from datetime import datetime, timezone
from typing import Any

from .config import Config

_SECRET_PATTERNS = [
    "authorization",
    "token",
    "secret",
    "password",
    "private_key",
    "cookie",
    "credential",
    "session",
    "registry_auth",
    "cos_secret",
    "cos_key",
    "github_token",
]


def _redact_value(key: str, value: Any) -> Any:
    if isinstance(value, str):
        key_lower = key.lower() if isinstance(key, str) else ""
        for pattern in _SECRET_PATTERNS:
            if pattern in key_lower:
                return "***REDACTED***"
        if len(value) > 256 and not key_lower.endswith("log"):
            return value[:64] + "...[truncated]"
        return value
    if isinstance(value, dict):
        return {k: _redact_value(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(key, v) for v in value]
    return value


def _redact_dict(data: dict) -> dict:
    return _redact_value("", data)


def _sanitize_text(value: str) -> str:
    text = str(value or "")
    for key in ("signed_url", "token", "authorization", "cookie"):
        text = re.sub(rf"{re.escape(key)}=[^\s]+", f"{key}=[REDACTED]", text, flags=re.IGNORECASE)
    text = re.sub(
        r"https?://[^\s?]+[^\s]*[?][^\s]*(?:X-Amz-Signature|X-Amz-Credential|X-Amz-Algorithm|X-Goog-Signature|Signature|sig=)[^\s]*",
        "[REDACTED_PRESIGNED_URL]",
        text,
        flags=re.IGNORECASE,
    )
    return text


def _case_id_for_target(target: str) -> str:
    if target == "perception":
        return "perception-health-check"
    if target == "actucore":
        return "actucore-health-check"
    if target == "driver":
        return "driver-health-check"
    return ""


def _short_digest(ref: str) -> str:
    value = str(ref or "").strip()
    if "@sha256:" not in value:
        return ""
    digest = value.rsplit("@sha256:", 1)[-1]
    if len(digest) < 12:
        return ""
    return digest[:12]


def _compact_running_image(ref: str) -> str:
    digest = _short_digest(ref)
    return f"@sha256:{digest}" if digest else "occupied"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _bound_text(text: str, limit: int) -> str:
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    lines = text.splitlines()
    out: list[str] = []
    total = 0
    marker = "[truncated]"
    marker_bytes = len(marker.encode("utf-8"))
    for line in lines:
        line_bytes = len((line + "\n").encode("utf-8"))
        if total + line_bytes + marker_bytes > limit:
            break
        out.append(line)
        total += line_bytes
    out.append(marker)
    return "\n".join(out)


class EvidenceBuilder:
    def __init__(self, config: Config):
        self.config = config

    async def build_evidence(
        self,
        *,
        repo: str,
        pr_number: int,
        head_sha: str,
        state: dict,
        result: str,
        summary: str = "",
        context: dict | None = None,
    ) -> tuple[bytes, str, int]:
        if context is None:
            context = {}
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            manifest = _redact_dict(
                self._build_manifest(repo, pr_number, head_sha, state, result, summary, context)
            )
            self._add_fileobj(
                tar,
                "manifest.json",
                json.dumps(manifest, ensure_ascii=False, separators=(",", ":"), default=str),
            )
            self._add_fileobj(
                tar,
                "evidence.log",
                self._build_evidence_log(repo, pr_number, head_sha, state, result, summary),
            )

        archive_bytes = buf.getvalue()
        sha256_hex = hashlib.sha256(archive_bytes).hexdigest()
        return archive_bytes, sha256_hex, len(archive_bytes)

    def _build_manifest(
        self,
        repo: str,
        pr_number: int,
        head_sha: str,
        state: dict,
        result: str,
        summary: str,
        context: dict,
    ) -> dict:
        components: list[dict[str, Any]] = []
        for comp in state.get("components", []):
            if not isinstance(comp, dict):
                continue
            component_id = str(comp.get("component_id", "") or "")
            if not component_id:
                continue
            components.append({
                "component_id": component_id,
                "target": str(comp.get("target", "") or ""),
                "driver_path": str(comp.get("driver_path", "") or ""),
                "variant": str(comp.get("variant", "") or ""),
                "review_image_tag": str(comp.get("review_image_tag", "") or ""),
                "platform": str(comp.get("resolved_platform", "") or ""),
                "image_ref": str(comp.get("image_ref", "") or ""),
                "runtime_id": str(comp.get("runtime_id", "") or ""),
            })

        approve_attempts_source = context.get("approve_attempts", state.get("approve_attempts", []))
        approve_attempts_total = context.get(
            "approve_attempts_total",
            state.get("approve_attempts_total", len(approve_attempts_source or [])),
        )
        if isinstance(approve_attempts_total, bool) or not isinstance(approve_attempts_total, int) or approve_attempts_total < 0:
            approve_attempts_total = len(approve_attempts_source or [])
        approve_attempts_truncated = context.get(
            "approve_attempts_truncated",
            state.get("approve_attempts_truncated", approve_attempts_total > len(approve_attempts_source or [])),
        )
        if not isinstance(approve_attempts_truncated, bool):
            approve_attempts_truncated = bool(approve_attempts_total > len(approve_attempts_source or []))
        approve_attempts: list[dict[str, Any]] = []
        for attempt in approve_attempts_source or []:
            if not isinstance(attempt, dict):
                continue
            approve_attempts.append({
                "comment_id": int(attempt.get("comment_id") or 0),
                "actor": str(attempt.get("actor", "") or ""),
                "machine": str(attempt.get("machine", "") or ""),
                "preflight": [
                    {
                        "component_id": str(item.get("component_id", "") or ""),
                        "runtime_id": str(item.get("runtime_id", "") or ""),
                        "running_image": _short_digest(str(item.get("running_image", "") or "")),
                    }
                    for item in (attempt.get("preflight", []) or [])
                    if isinstance(item, dict)
                ],
                "outcome": str(attempt.get("outcome", "") or ""),
                "health": [
                    {
                        "component_id": str(item.get("component_id", "") or ""),
                        "runtime_id": str(item.get("runtime_id", "") or ""),
                        "running_image": _short_digest(str(item.get("running_image", "") or "")),
                        "passed": bool(item.get("passed", False)),
                    }
                    for item in (attempt.get("health", []) or [])
                    if isinstance(item, dict)
                ],
            })

        case_source = context.get("case", None)
        case_results = state.get("case_results", {})
        if not isinstance(case_results, dict):
            case_results = {}
        cases: list[dict[str, Any]] = []
        if isinstance(case_source, list) and case_source:
            for item in case_source:
                if not isinstance(item, dict):
                    continue
                cases.append({
                    "component_id": str(item.get("component_id", "") or ""),
                    "case_id": str(item.get("case_id", "") or ""),
                    "result": str(item.get("result", "") or ""),
                    "advisory": bool(item.get("advisory", True)),
                })
        else:
            for comp in components:
                cid = comp["component_id"]
                cases.append({
                    "component_id": cid,
                    "case_id": _case_id_for_target(comp.get("target", "")),
                    "result": case_results.get(cid, "n/a"),
                    "advisory": True,
                })

        return {
            "schema_version": 1,
            "source": {
                "repo": repo,
                "pr_number": pr_number,
                "head_sha": head_sha,
                "review_job_id": state.get("review_job_id", ""),
            },
            "components": components,
            "approve_attempts": approve_attempts,
            "approve_attempts_total": approve_attempts_total,
            "approve_attempts_truncated": approve_attempts_truncated,
            "case": cases,
            "final": {
                "status": state.get("status", ""),
                "result": result or state.get("test_result", ""),
                "summary": _sanitize_text(summary),
                "actor": str(state.get("command", {}).get("args", {}).get("actor", "") or ""),
                "comment_id": int(state.get("command", {}).get("comment_id", 0) or 0),
                "recorded_at": _utc_now_iso(),
            },
        }

    def _build_evidence_log(
        self,
        repo: str,
        pr_number: int,
        head_sha: str,
        state: dict,
        result: str,
        summary: str,
    ) -> str:
        lines: list[str] = [
            f"[source] {repo}#{pr_number} head={head_sha[:7]} review_job={state.get('review_job_id', '')}",
        ]
        components = state.get("components", [])
        if isinstance(components, list) and components:
            comp_text = ", ".join(
                f"{str(c.get('component_id', ''))}:{str(c.get('target', ''))}"
                for c in components
                if isinstance(c, dict) and c.get("component_id")
            )
            if comp_text:
                lines.append(f"[request_deploy] components={comp_text}")
        approve_attempts = state.get("approve_attempts", [])
        if isinstance(approve_attempts, list):
            for attempt in approve_attempts:
                if not isinstance(attempt, dict):
                    continue
                lines.append(
                    f"[approve] comment={attempt.get('comment_id', 0)} actor={attempt.get('actor', '')} machine={attempt.get('machine', '')} outcome={attempt.get('outcome', '')}"
                )
                for item in attempt.get("preflight", []) or []:
                    if not isinstance(item, dict):
                        continue
                    lines.append(
                        f"[preflight] runtime={item.get('runtime_id', '')} running_image={_compact_running_image(item.get('running_image', ''))} component={item.get('component_id', '')}"
                    )
                for item in attempt.get("health", []) or []:
                    if not isinstance(item, dict):
                        continue
                    lines.append(
                        f"[health] runtime={item.get('runtime_id', '')} running_image={_compact_running_image(item.get('running_image', ''))} passed={bool(item.get('passed', False))}"
                    )
        case_results = state.get("case_results", {})
        if isinstance(case_results, dict):
            for cid, case_result in case_results.items():
                lines.append(f"[case] component={cid} result={case_result} advisory=true")
        lines.append(f"[record_test] result={result or state.get('test_result', '')} summary={_sanitize_text(summary)}")
        return _bound_text("\n".join(lines), 256 * 1024)

    def _add_fileobj(self, tar: tarfile.TarFile, arcname: str, data: str) -> None:
        encoded = data.encode("utf-8")
        info = tarfile.TarInfo(name=arcname)
        info.size = len(encoded)
        info.mtime = 0
        info.uid = 0
        info.gid = 0
        info.uname = ""
        info.gname = ""
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(encoded))
