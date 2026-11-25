
"""Read the approved Feishu Wiki device table as a complete identity snapshot.

This reader uses a persisted user OAuth grant, accepts only Docx Wiki nodes,
and parses the documented block/table response schema. It never reads
raw_content and never logs credentials or source document content.
"""

from __future__ import annotations

import asyncio
import fcntl
import ipaddress
import json
import logging
import os
import re
import stat
import tempfile
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping
from urllib.parse import quote, urlencode

import httpx

from .clients_common import require_2xx, stream_request
from .config import Config

logger = logging.getLogger(__name__)

FEISHU_API_ROOT = "https://open.feishu.cn/open-apis"
FEISHU_OAUTH_TOKEN_URL = "https://accounts.feishu.cn/oauth/v3/token"
FEISHU_WIKI_NODE_TOKEN = "I09iwCY3jiJAnjkGP0vc5WCGnfS"
FEISHU_SYNC_INTERVAL_SECONDS = 3600
FEISHU_ACCESS_TOKEN_EARLY_REFRESH_SECONDS = 120
FEISHU_TOKEN_MAINTENANCE_INTERVAL_SECONDS = 30
DOCX_BLOCK_PAGE_SIZE = 500
_IPV4_RE = re.compile(r"(?<![0-9A-Fa-f:.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9A-Fa-f:.])")
_LABELS = ("上位机", "下位机", "底盘", "有线", "北京", "深圳")
_HEADER_ALIASES = {
    "number": {"编号", "设备编号", "机器编号", "number", "machinenumber", "no", "machineno"},
    "brand": {"品牌", "brand"},
    "model": {"型号", "设备型号", "model"},
    "ip": {"ip", "ip地址", "设备ip", "设备ip地址", "机器ip", "机器ip地址", "ipv4"},
    "ip_labels": {
        "用途", "地址用途", "ip用途", "ip地址用途", "备注", "地址备注",
        "ip备注", "ip地址备注", "说明",
    },
}
_SENSITIVE_LABEL_RE = re.compile(
    r"\b(?:password|passwd|passphrase|passcode|pwd|secret|token|ssh|"
    r"private[ _-]?key|access[ _-]?key|api[ _-]?key|client[ _-]?id|"
    r"app[ _-]?id|authorization|root|admin|administrator|login|credential)\b|"
    r"账号|账户|用户名|登录|认证|"
    r"密码|口令|密钥|凭证|私钥",
    re.IGNORECASE,
)
_LONG_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_+/=-]{20,}(?![A-Za-z0-9])")
_LONG_NUMERIC_RE = re.compile(r"(?<!\d)\d{6,}(?!\d)")
_TEXT_BLOCK_FIELDS = {
    1: "page", 2: "text", 3: "heading1", 4: "heading2", 5: "heading3",
    6: "heading4", 7: "heading5", 8: "heading6", 9: "heading7",
    10: "heading8", 11: "heading9", 12: "bullet", 13: "ordered",
    14: "code", 15: "quote", 17: "todo",
}


class FeishuSyncError(Exception):
    """A safe, non-sensitive failure while reading or validating the snapshot."""


class FeishuReauthorizationRequired(FeishuSyncError):
    """The saved user grant cannot safely be used or refreshed."""


class FeishuOAuthOutcomeUnknown(FeishuSyncError):
    """A one-time refresh may have succeeded, so its old token cannot be replayed."""


class FeishuTemporaryOAuthError(FeishuSyncError):
    """The OAuth service explicitly refused a refresh temporarily."""


@dataclass(frozen=True)
class FeishuAddress:
    ip: str
    label: str


@dataclass(frozen=True)
class FeishuMachine:
    number: str
    brand: str
    model: str
    addresses: tuple[FeishuAddress, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "number": self.number,
            "brand": self.brand,
            "model": self.model,
            "addresses": [
                {"ip": address.ip, "label": address.label}
                for address in self.addresses
            ],
        }


@dataclass(frozen=True)
class FeishuSnapshotState:
    devices: Mapping[str, FeishuMachine]
    stale: bool
    last_success: str | None
    generation: int
    ip_conflicts: Mapping[str, tuple[str, ...]]


class FeishuMachineSource:
    """Fetch and atomically replace an immutable Feishu device snapshot."""

    def __init__(self, config: Config, *, http: httpx.AsyncClient | None = None):
        self._config = config
        self._owns_http = http is None
        self._http = http or httpx.AsyncClient(
            timeout=httpx.Timeout(
                config.read_timeout,
                connect=config.connect_timeout,
            ),
            follow_redirects=False,
        )
        self._oauth_lock = asyncio.Lock()
        self._state = FeishuSnapshotState(
            MappingProxyType({}), True, None, 0, MappingProxyType({}),
        )
        self._last_error = "never synced"
        self._schema_status = "BLOCKED_SCHEMA_UNVERIFIED"

    @property
    def snapshot(self):
        return self._state.devices

    @property
    def state(self) -> FeishuSnapshotState:
        """Return one immutable view of data and its freshness metadata."""
        return self._state

    @property
    def stale(self) -> bool:
        return self._state.stale

    @property
    def last_success(self) -> str | None:
        return self._state.last_success

    @property
    def last_error(self) -> str:
        return self._last_error

    @property
    def schema_status(self) -> str:
        return self._schema_status

    @property
    def generation(self) -> int:
        return self._state.generation

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def sync(self) -> bool:
        """Fetch a complete replacement; failures preserve the prior snapshot."""
        try:
            devices, ip_conflicts = await self._read_all_devices()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            previous = self._state
            self._state = FeishuSnapshotState(
                previous.devices, True, previous.last_success,
                previous.generation, previous.ip_conflicts,
            )
            self._last_error = (
                str(exc) if isinstance(exc, FeishuSyncError)
                else type(exc).__name__
            )
            logger.warning(
                "FEISHU_SYNC_FAILED FEISHU_DEVICE_COUNT=%d "
                "FEISHU_LAST_SUCCESS=%s FEISHU_STALE=true FEISHU_REASON=%s "
                "FEISHU_SCHEMA_STATUS=%s",
                len(previous.devices), previous.last_success or "never",
                self._last_error, self._schema_status,
            )
            return False

        # MappingProxyType and frozen records make the single assignment atomic
        # and prevent readers from observing a partially parsed document.
        replacement = MappingProxyType(dict(devices))
        conflicts = MappingProxyType({
            ip: tuple(numbers) for ip, numbers in ip_conflicts.items()
        })
        last_success = datetime.now(timezone.utc).isoformat(timespec="seconds")
        generation = self._state.generation + 1
        self._state = FeishuSnapshotState(
            replacement, False, last_success, generation, conflicts,
        )
        self._last_error = ""
        self._schema_status = "VERIFIED"
        logger.info(
            "FEISHU_SYNC_OK FEISHU_DEVICE_COUNT=%d FEISHU_IP_CONFLICT_COUNT=%d "
            "FEISHU_LAST_SUCCESS=%s FEISHU_STALE=false",
            len(replacement), len(conflicts), last_success,
        )
        return True

    async def _request_json(
        self, method: str, url: str, *, token: str = "",
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        response = await stream_request(
            self._http,
            method,
            url,
            self._config.max_response_bytes,
            headers=headers,
            params=params,
            json=body,
            timeout=self._config.total_timeout,
        )
        try:
            require_2xx(response.status_code, "Feishu API")
        except Exception:
            api_code = None
            try:
                error_payload = response.json()
                candidate = error_payload.get("code") if isinstance(error_payload, dict) else None
                if type(candidate) is int:
                    api_code = candidate
            except (ValueError, UnicodeDecodeError):
                pass
            if api_code in {99991677, 99991679} or response.status_code == 401:
                raise FeishuReauthorizationRequired(
                    "Feishu user access token expired or revoked; reauthorization is required"
                ) from None
            if api_code == 99991672:
                reason = "Feishu user OAuth grant lacks the required API scope (API code 99991672)"
            elif api_code == 131006:
                reason = (
                    "Feishu user-authorized account cannot access the Wiki document "
                    "(API code 131006); grant document access or reauthorize"
                )
            elif response.status_code == 403:
                reason = (
                    "Feishu user-authorized account cannot access this resource "
                    "(HTTP 403); confirm document access or reauthorize"
                )
            else:
                reason = f"Feishu API HTTP status {response.status_code}"
            if (api_code is not None
                    and f"code {api_code}" not in reason):
                reason += f" code {api_code}"
            raise FeishuSyncError(reason) from None
        try:
            payload = response.json()
        except (ValueError, UnicodeDecodeError):
            raise FeishuSyncError("Feishu API response is not JSON") from None
        if (not isinstance(payload, dict) or type(payload.get("code")) is not int
                or payload.get("code") != 0):
            code = payload.get("code") if isinstance(payload, dict) else None
            if type(code) is int:
                if code in {99991677, 99991679}:
                    raise FeishuReauthorizationRequired(
                        "Feishu user access token expired or revoked; reauthorization is required"
                    )
                if code == 99991672:
                    raise FeishuSyncError(
                        "Feishu user OAuth grant lacks the required API scope (API code 99991672)"
                    )
                if code == 131006:
                    raise FeishuSyncError(
                        "Feishu user-authorized account cannot access the Wiki document "
                        "(API code 131006); grant document access or reauthorize"
                    )
                raise FeishuSyncError(f"Feishu API returned code {code}")
            raise FeishuSyncError("Feishu API returned an invalid response")
        return payload

    def _oauth_file_path(self) -> Path:
        path = Path(self._config.feishu_oauth_file)
        if path.name != "feishu-oauth.json":
            raise FeishuReauthorizationRequired(
                "Feishu OAuth initialization file must be named feishu-oauth.json"
            )
        return path

    @staticmethod
    def _check_private_directory(path: Path) -> None:
        try:
            info = path.lstat()
        except OSError:
            raise FeishuReauthorizationRequired(
                "Protected Feishu OAuth persistence directory is unavailable"
            ) from None
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077
                or stat.S_IMODE(info.st_mode) & 0o700 != 0o700):
            raise FeishuReauthorizationRequired(
                "Feishu OAuth persistence directory must be service-account-owned mode 0700"
            )

    @staticmethod
    def _check_private_file(info: os.stat_result, label: str) -> None:
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077
                or stat.S_IMODE(info.st_mode) & 0o400 != 0o400):
            raise FeishuReauthorizationRequired(
                f"{label} must be a service-account-owned private regular file"
            )

    def _read_oauth_state(self) -> dict[str, Any]:
        path = self._oauth_file_path()
        self._check_private_directory(path.parent)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
        except FileNotFoundError:
            raise FeishuReauthorizationRequired(
                "feishu-oauth.json is missing; initialize or reauthorize the Feishu user grant"
            ) from None
        except OSError:
            raise FeishuReauthorizationRequired(
                "feishu-oauth.json cannot be safely opened"
            ) from None
        try:
            self._check_private_file(os.fstat(fd), "feishu-oauth.json")
            with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as handle:
                value = json.load(handle)
        except FeishuSyncError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            raise FeishuReauthorizationRequired(
                "feishu-oauth.json is invalid; initialize or reauthorize the Feishu user grant"
            ) from None
        finally:
            os.close(fd)
        if not isinstance(value, dict):
            raise FeishuReauthorizationRequired(
                "feishu-oauth.json must contain a JSON object"
            )
        required_strings = (
            "client_id", "client_secret", "access_token", "refresh_token", "scope",
        )
        if any(not isinstance(value.get(key), str) or not value[key].strip()
               for key in required_strings):
            raise FeishuReauthorizationRequired(
                "feishu-oauth.json is missing required user OAuth fields"
            )
        if "offline_access" not in value["scope"].split():
            raise FeishuReauthorizationRequired(
                "Feishu user OAuth scope lacks offline_access; reauthorization is required"
            )
        for key in ("access_expires_at", "refresh_expires_at", "authorized_at"):
            if key not in value:
                raise FeishuReauthorizationRequired(
                    "feishu-oauth.json is missing required OAuth expiry metadata"
                )
            try:
                self._timestamp(value[key])
            except (TypeError, ValueError, OverflowError):
                raise FeishuReauthorizationRequired(
                    "feishu-oauth.json contains an invalid OAuth timestamp"
                ) from None
        return value

    def _write_oauth_state(self, value: dict[str, Any]) -> None:
        path = self._oauth_file_path()
        self._check_private_directory(path.parent)
        if path.exists() or path.is_symlink():
            try:
                info = path.lstat()
            except OSError:
                raise FeishuReauthorizationRequired(
                    "feishu-oauth.json cannot be safely replaced"
                ) from None
            if stat.S_ISLNK(info.st_mode):
                raise FeishuReauthorizationRequired(
                    "feishu-oauth.json must not be a symlink"
                )
            self._check_private_file(info, "feishu-oauth.json")

        fd = -1
        temporary_path = None
        try:
            fd, temporary_name = tempfile.mkstemp(
                prefix=".feishu-oauth-", suffix=".tmp", dir=path.parent,
            )
            temporary_path = Path(temporary_name)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8", closefd=True) as handle:
                fd = -1
                json.dump(value, handle, ensure_ascii=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, path)
            dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except (OSError, TypeError, ValueError):
            raise FeishuReauthorizationRequired(
                "Feishu OAuth token rotation could not be durably saved; reauthorization is required"
            ) from None
        finally:
            if fd >= 0:
                os.close(fd)
            if temporary_path is not None:
                try:
                    temporary_path.unlink()
                except FileNotFoundError:
                    pass
                except OSError:
                    pass

    async def _acquire_oauth_file_lock(self) -> int:
        path = self._oauth_file_path()
        self._check_private_directory(path.parent)
        lock_path = path.with_name(f".{path.name}.lock")
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(lock_path, flags, 0o600)
            self._check_private_file(os.fstat(fd), "Feishu OAuth lock file")
        except (OSError, FeishuSyncError):
            try:
                os.close(fd)
            except (UnboundLocalError, OSError):
                pass
            raise FeishuReauthorizationRequired(
                "Feishu OAuth refresh lock is unavailable"
            ) from None
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return fd
                except BlockingIOError:
                    await asyncio.sleep(0.1)
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def _timestamp(value: Any) -> datetime:
        if isinstance(value, bool):
            raise ValueError("boolean is not a timestamp")
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc)
        if not isinstance(value, str):
            raise TypeError("timestamp must be ISO 8601 or Unix seconds")
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("timestamp must include a timezone")
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _iso_timestamp(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

    async def _request_user_oauth_refresh(
        self, state: dict[str, Any], *, now: datetime,
    ) -> str:
        attempted = dict(state)
        attempted["refresh_state"] = "in_flight"
        attempted["refresh_attempted_at"] = self._iso_timestamp(now)
        attempted.pop("refresh_retry_after", None)
        self._write_oauth_state(attempted)

        form = urlencode({
            "grant_type": "refresh_token",
            "client_id": state["client_id"],
            "client_secret": state["client_secret"],
            "refresh_token": state["refresh_token"],
        })
        try:
            response = await stream_request(
                self._http,
                "POST",
                FEISHU_OAUTH_TOKEN_URL,
                self._config.max_response_bytes,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                content=form,
                timeout=self._config.total_timeout,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            # Once the one-time refresh request may have left this process, the
            # old refresh token is never replayed without an explicit refusal.
            raise FeishuOAuthOutcomeUnknown(
                "Feishu OAuth refresh outcome is unknown"
            ) from None

        retry_after = 60
        if response.status_code == 429:
            try:
                candidate = int(response.headers.get("Retry-After", "60"))
                if 1 <= candidate <= 3600:
                    retry_after = candidate
            except (TypeError, ValueError):
                pass
            failed = dict(attempted)
            failed["refresh_state"] = "temporary_failure"
            failed["refresh_retry_after"] = self._iso_timestamp(
                datetime.now(timezone.utc) + timedelta(seconds=retry_after)
            )
            self._write_oauth_state(failed)
            raise FeishuTemporaryOAuthError(
                f"Feishu OAuth refresh temporarily rate-limited; retry after {retry_after} seconds"
            )

        try:
            payload = response.json()
        except (ValueError, UnicodeDecodeError):
            raise FeishuOAuthOutcomeUnknown(
                "Feishu OAuth refresh outcome is unknown because its response was invalid"
            ) from None
        if not isinstance(payload, dict):
            raise FeishuOAuthOutcomeUnknown(
                "Feishu OAuth refresh outcome is unknown because its response was invalid"
            )
        api_code = payload.get("code")
        if type(api_code) is int and api_code != 0:
            if response.status_code < 500:
                rejected = dict(attempted)
                rejected["refresh_state"] = "reauthorization_required"
                rejected["refresh_error_code"] = api_code
                self._write_oauth_state(rejected)
                raise FeishuReauthorizationRequired(
                    f"Feishu user OAuth refresh was rejected (API code {api_code}); reauthorization is required"
                )
            raise FeishuOAuthOutcomeUnknown(
                f"Feishu OAuth refresh outcome is unknown (HTTP {response.status_code})"
            )
        if response.status_code >= 500:
            raise FeishuOAuthOutcomeUnknown(
                f"Feishu OAuth refresh outcome is unknown (HTTP {response.status_code})"
            )
        if response.status_code < 200 or response.status_code >= 300:
            rejected = dict(attempted)
            rejected["refresh_state"] = "reauthorization_required"
            rejected["refresh_http_status"] = response.status_code
            self._write_oauth_state(rejected)
            raise FeishuReauthorizationRequired(
                f"Feishu user OAuth refresh was rejected (HTTP {response.status_code}); reauthorization is required"
            )

        access_token = payload.get("access_token")
        refresh_token = payload.get("refresh_token")
        expires_in = payload.get("expires_in")
        refresh_expires_in = payload.get("refresh_token_expires_in")
        scope = payload.get("scope", state.get("scope", ""))
        if (not isinstance(access_token, str) or not access_token
                or not isinstance(refresh_token, str) or not refresh_token
                or type(expires_in) is not int or expires_in <= 0
                or type(refresh_expires_in) is not int or refresh_expires_in <= 0
                or not isinstance(scope, str)
                or "offline_access" not in scope.split()):
            raise FeishuOAuthOutcomeUnknown(
                "Feishu OAuth refresh response is incomplete; its result will not be retried"
            )
        renewed = dict(attempted)
        renewed.update({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "access_expires_at": self._iso_timestamp(
                datetime.now(timezone.utc) + timedelta(seconds=expires_in)
            ),
            "refresh_expires_at": self._iso_timestamp(
                datetime.now(timezone.utc) + timedelta(seconds=refresh_expires_in)
            ),
            "scope": scope,
            "refresh_state": "ready",
        })
        renewed.pop("refresh_attempted_at", None)
        renewed.pop("refresh_retry_after", None)
        renewed.pop("refresh_error_code", None)
        renewed.pop("refresh_http_status", None)
        self._write_oauth_state(renewed)
        return access_token

    async def _get_user_access_token(self) -> str:
        async with self._oauth_lock:
            lock_fd = await self._acquire_oauth_file_lock()
            try:
                state = self._read_oauth_state()
                now = datetime.now(timezone.utc)
                access_expires_at = self._timestamp(state["access_expires_at"])
                refresh_expires_at = self._timestamp(state["refresh_expires_at"])
                refresh_state = state.get("refresh_state", "ready")
                if refresh_state not in {
                    "ready", "temporary_failure", "in_flight",
                    "reauthorization_required",
                }:
                    raise FeishuReauthorizationRequired(
                        "Feishu OAuth refresh state is invalid; reauthorization is required"
                    )

                if refresh_state == "reauthorization_required":
                    raise FeishuReauthorizationRequired(
                        "Feishu user authorization is invalid or revoked; reauthorization is required"
                    )
                if access_expires_at > now + timedelta(
                    seconds=FEISHU_ACCESS_TOKEN_EARLY_REFRESH_SECONDS
                ):
                    return state["access_token"]
                if refresh_state == "in_flight":
                    if access_expires_at > now:
                        return state["access_token"]
                    raise FeishuReauthorizationRequired(
                        "Feishu OAuth refresh outcome is unknown and the access token expired; reauthorization is required"
                    )
                if refresh_state == "temporary_failure":
                    retry_after = state.get("refresh_retry_after")
                    if isinstance(retry_after, str) and self._timestamp(retry_after) > now:
                        if access_expires_at > now:
                            return state["access_token"]
                        raise FeishuTemporaryOAuthError(
                            "Feishu OAuth refresh is temporarily unavailable"
                        )
                if refresh_expires_at <= now:
                    expired = dict(state)
                    expired["refresh_state"] = "reauthorization_required"
                    self._write_oauth_state(expired)
                    raise FeishuReauthorizationRequired(
                        "Feishu refresh token expired; reauthorization is required"
                    )
                try:
                    return await self._request_user_oauth_refresh(state, now=now)
                except FeishuTemporaryOAuthError:
                    if access_expires_at > now:
                        return state["access_token"]
                    raise
                except FeishuOAuthOutcomeUnknown:
                    if access_expires_at > now:
                        return state["access_token"]
                    raise FeishuReauthorizationRequired(
                        "Feishu OAuth refresh outcome is unknown and no valid access token remains; reauthorization is required"
                    ) from None
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)

    async def ensure_access_token(self) -> None:
        """Refresh the user token independently of the hourly document sync."""
        await self._get_user_access_token()

    async def _read_all_devices(
        self,
    ) -> tuple[dict[str, FeishuMachine], dict[str, tuple[str, ...]]]:
        token = await self._get_user_access_token()
        node_payload = await self._request_json(
            "GET",
            f"{FEISHU_API_ROOT}/wiki/v2/spaces/get_node",
            token=token,
            params={"token": FEISHU_WIKI_NODE_TOKEN},
        )
        data = node_payload.get("data")
        node = data.get("node") if isinstance(data, dict) else None
        if not isinstance(node, dict):
            raise FeishuSyncError("Feishu Wiki node response is invalid")
        if node.get("obj_type") != "docx":
            raise FeishuSyncError("Feishu Wiki node is not a Docx document")
        document_id = node.get("obj_token")
        if not isinstance(document_id, str) or not document_id:
            raise FeishuSyncError("Feishu Wiki node has no Docx object token")

        raw_blocks = await self._list_document_blocks(document_id, token)
        blocks = self._index_document_blocks(document_id, raw_blocks)
        tables = [block for block in blocks.values() if block.get("block_type") == 31]
        devices: dict[str, FeishuMachine] = {}
        ip_owners: dict[str, set[str]] = {}
        recognized_tables = 0
        for table in tables:
            rows = self._table_rows(table)
            header_index, columns = self._find_device_header(rows)
            if header_index is None:
                continue
            recognized_tables += 1
            device_count_before = len(devices)
            for row in rows[header_index + 1:]:
                values = {
                    role: row[column].strip()
                    for role, column in columns.items()
                    if role in {"number", "brand", "model"}
                }
                ip_columns = columns["ip"]
                ip_values = [row[index].strip() for index in ip_columns]
                if not any(values.values()) and not any(ip_values):
                    continue
                if not all(values.values()) or not any(ip_values):
                    raise FeishuSyncError("Feishu device table contains an incomplete row")
                number = self._normalize_number(values["number"])
                brand = self._safe_device_metadata(values["brand"])
                model = self._safe_device_metadata(values["model"])
                row_labels = [row[index].strip() for index in columns.get("ip_labels", [])]
                row_labels_present = any(row_labels)
                addresses: list[FeishuAddress] = []
                for ip_index, ip_value in enumerate(ip_values):
                    if not ip_value:
                        continue
                    header_label = columns.get("ip_header_labels", {}).get(
                        ip_columns[ip_index],
                    )
                    if len(ip_columns) == 1 or len(row_labels) == 1:
                        supplemental_labels = [header_label] if header_label else []
                        supplemental_labels.extend(row_labels)
                    elif len(row_labels) == len(ip_columns):
                        supplemental_labels = [header_label] if header_label else []
                        supplemental_labels.append(row_labels[ip_index])
                    elif row_labels_present:
                        raise FeishuSyncError(
                            "Feishu device table IP labels do not map to IP columns"
                        )
                    else:
                        supplemental_labels = [header_label] if header_label else []
                    addresses = self._merge_addresses(
                        tuple(addresses),
                        self._parse_addresses(ip_value, supplemental_labels),
                    )
                if not addresses:
                    raise FeishuSyncError("Feishu device has no IPv4 address")
                for address in addresses:
                    ip_owners.setdefault(address.ip, set()).add(number)
                previous = devices.get(number)
                if previous is not None:
                    if previous.brand != brand or previous.model != model:
                        raise FeishuSyncError(
                            "Feishu device number has conflicting brand or model values"
                        )
                    addresses = self._merge_addresses(previous.addresses, addresses)
                devices[number] = FeishuMachine(
                    number=number,
                    brand=brand,
                    model=model,
                    addresses=tuple(addresses),
                )
            if len(devices) == device_count_before:
                raise FeishuSyncError("Feishu device table has no complete device rows")
        if recognized_tables == 0 or not devices:
            raise FeishuSyncError("Feishu document has no complete device table")
        conflicts = {
            ip: tuple(sorted(numbers))
            for ip, numbers in ip_owners.items() if len(numbers) > 1
        }
        return devices, conflicts

    async def _list_document_blocks(
        self, document_id: str, token: str,
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        seen_page_tokens: set[str] = set()
        page_token: str | None = None
        while True:
            params: dict[str, Any] = {"page_size": DOCX_BLOCK_PAGE_SIZE}
            if page_token is not None:
                params["page_token"] = page_token
            payload = await self._request_json(
                "GET",
                f"{FEISHU_API_ROOT}/docx/v1/documents/"
                f"{quote(document_id, safe='')}/blocks",
                token=token,
                params=params,
            )
            data = payload.get("data")
            if not isinstance(data, dict) or not isinstance(data.get("items"), list):
                raise FeishuSyncError("Docx blocks response has no items list")
            has_more = data.get("has_more")
            if type(has_more) is not bool:
                raise FeishuSyncError("Docx blocks response has no pagination status")
            page_items = data["items"]
            if not all(isinstance(item, dict) for item in page_items):
                raise FeishuSyncError("Docx blocks response contains an invalid block")
            items.extend(page_items)
            if not has_more:
                return items
            next_page_token = data.get("page_token")
            if (not isinstance(next_page_token, str) or not next_page_token
                    or next_page_token in seen_page_tokens):
                raise FeishuSyncError("Docx blocks pagination is incomplete")
            seen_page_tokens.add(next_page_token)
            page_token = next_page_token

    @classmethod
    def _index_document_blocks(
        cls, document_id: str, raw_blocks: list[dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        blocks: dict[str, dict[str, Any]] = {}
        for raw_block in raw_blocks:
            block = dict(raw_block)
            block_id = block.get("block_id")
            block_type = block.get("block_type")
            if (not isinstance(block_id, str) or not block_id
                    or type(block_type) is not int):
                raise FeishuSyncError("Docx blocks response contains an invalid block")
            if block_id in blocks:
                raise FeishuSyncError("Docx blocks response contains a duplicate block ID")
            block.pop("_children", None)
            blocks[block_id] = block

        children_by_parent: dict[str, list[str]] = {}
        for block_id, block in blocks.items():
            child_ids = block.get("children", [])
            if child_ids is None:
                child_ids = []
            if (not isinstance(child_ids, list)
                    or not all(isinstance(child_id, str) and child_id for child_id in child_ids)
                    or len(child_ids) != len(set(child_ids))):
                raise FeishuSyncError("Docx block child IDs are invalid")
            if block.get("block_type") == 31:
                table = block.get("table")
                props = table.get("property") if isinstance(table, dict) else None
                if not isinstance(table, dict) or not isinstance(props, dict):
                    raise FeishuSyncError("Docx table block structure is invalid")
                rows = props.get("row_size")
                columns = props.get("column_size")
                cell_ids = table.get("cells")
                if (type(rows) is not int or rows <= 0
                        or type(columns) is not int or columns <= 0
                        or not isinstance(cell_ids, list)
                        or not all(isinstance(cell_id, str) and cell_id for cell_id in cell_ids)
                        or len(cell_ids) != rows * columns
                        or len(set(cell_ids)) != len(cell_ids)):
                    raise FeishuSyncError("Docx table dimensions or cells are invalid")
                if child_ids and child_ids != cell_ids:
                    raise FeishuSyncError("Docx table cell order disagrees with the table block")
                child_ids = cell_ids
            children_by_parent[block_id] = child_ids

        for block_id, block in blocks.items():
            child_ids = children_by_parent[block_id]
            for child_id in child_ids:
                child = blocks.get(child_id)
                if child is None:
                    raise FeishuSyncError("Docx parent-child block relation is incomplete")
                child_parent = child.get("parent_id")
                if child_parent not in (None, "") and child_parent != block_id:
                    raise FeishuSyncError("Docx parent-child block relation is inconsistent")
            parent_id = block.get("parent_id")
            if parent_id not in (None, "") and parent_id != document_id:
                if parent_id not in blocks:
                    raise FeishuSyncError("Docx block parent is missing from the response")
                if block_id not in children_by_parent[parent_id]:
                    raise FeishuSyncError("Docx block parent does not list its child")
            block["_child_ids"] = child_ids

        if document_id in blocks:
            roots = [document_id]
        else:
            referenced_children = {
                child_id for child_ids in children_by_parent.values()
                for child_id in child_ids
            }
            roots = [block_id for block_id in blocks if block_id not in referenced_children]
        visited: set[str] = set()

        def visit(block_id: str, depth: int = 0) -> None:
            if depth > 128:
                raise FeishuSyncError("Docx block nesting exceeds the safe traversal depth")
            if block_id in visited:
                raise FeishuSyncError("Docx block graph contains a cycle or duplicate parent")
            visited.add(block_id)
            block = blocks[block_id]
            child_ids = children_by_parent[block_id]
            block["_children"] = [blocks[child_id] for child_id in child_ids]
            for child_id in child_ids:
                visit(child_id, depth + 1)

        for root_id in roots:
            visit(root_id)
        if len(visited) != len(blocks):
            raise FeishuSyncError("Docx blocks response contains unreachable blocks")
        return blocks

    @staticmethod
    def _walk_blocks(blocks: list[dict[str, Any]]):
        for block in blocks:
            yield block
            yield from FeishuMachineSource._walk_blocks(block.get("_children", []))

    @classmethod
    def _block_text(cls, block: dict[str, Any]) -> str:
        field_name = _TEXT_BLOCK_FIELDS.get(block.get("block_type"))
        if field_name is None:
            return ""
        content = block.get(field_name)
        if content is None:
            return ""
        if not isinstance(content, dict):
            raise FeishuSyncError("Docx text block structure is invalid")
        elements = content.get("elements", [])
        if not isinstance(elements, list):
            raise FeishuSyncError("Docx text elements are invalid")
        pieces: list[str] = []
        for element in elements:
            if not isinstance(element, dict):
                raise FeishuSyncError("Docx text element is invalid")
            text_run = element.get("text_run")
            if text_run is None:
                continue
            if not isinstance(text_run, dict):
                raise FeishuSyncError("Docx text run is invalid")
            value = text_run.get("content", "")
            if not isinstance(value, str):
                raise FeishuSyncError("Docx text run content is invalid")
            pieces.append(value)
        return "".join(pieces)

    @classmethod
    def _cell_text(cls, cell: dict[str, Any]) -> str:
        pieces: list[str] = []

        def visit(block: dict[str, Any]) -> None:
            if block.get("block_type") == 31:
                raise FeishuSyncError("Nested tables are not valid device cell content")
            pieces.append(cls._block_text(block))
            for child in block.get("_children", []):
                visit(child)

        for child in cell.get("_children", []):
            visit(child)
        # Text runs inside one block stay contiguous, but different blocks are
        # separated. Feishu can split adjacent IP addresses into separate
        # blocks; concatenating those runs creates an invalid synthetic value.
        return "\n".join(pieces).strip()

    @classmethod
    def _table_rows(cls, table_block: dict[str, Any]) -> list[list[str]]:
        table = table_block.get("table")
        props = table.get("property") if isinstance(table, dict) else None
        children = table_block.get("_children")
        if not isinstance(table, dict) or not isinstance(props, dict) or not isinstance(children, list):
            raise FeishuSyncError("Docx table structure is incomplete")
        rows = props.get("row_size")
        columns = props.get("column_size")
        cell_ids = table.get("cells")
        if (type(rows) is not int or type(columns) is not int
                or not isinstance(cell_ids, list) or len(cell_ids) != rows * columns
                or len(children) != len(cell_ids)):
            raise FeishuSyncError("Docx table rows and columns are incomplete")
        if any(cell.get("block_type") != 32 for cell in children):
            raise FeishuSyncError("Docx table child is not a TableCell block")
        values = [cls._cell_text(cell) for cell in children]
        merge_info = props.get("merge_info")
        if merge_info is not None:
            if not isinstance(merge_info, list):
                raise FeishuSyncError("Docx table merge relations are invalid")
            if merge_info and len(merge_info) != len(cell_ids):
                raise FeishuSyncError("Docx table merge relations are incomplete")
        if merge_info:
            cell_count = rows * columns
            anchor_for = list(range(cell_count))
            for index, merge in enumerate(merge_info):
                if not isinstance(merge, dict):
                    raise FeishuSyncError("Docx table merge relation is invalid")
                row_span = merge.get("row_span", 1)
                column_span = merge.get("col_span", 1)
                if (type(row_span) is not int or row_span < 1
                        or type(column_span) is not int or column_span < 1):
                    raise FeishuSyncError("Docx table merge span is invalid")
                row_index, column_index = divmod(index, columns)
                if row_index + row_span > rows or column_index + column_span > columns:
                    raise FeishuSyncError("Docx table merge span exceeds its grid")
                if (anchor_for[index] != index
                        and (row_span > 1 or column_span > 1)):
                    raise FeishuSyncError("Docx table merge relations overlap")
                for merged_row in range(row_index, row_index + row_span):
                    for merged_column in range(column_index, column_index + column_span):
                        merged_index = merged_row * columns + merged_column
                        if merged_index != index:
                            if anchor_for[merged_index] != merged_index:
                                raise FeishuSyncError("Docx table merge relations overlap")
                            anchor_for[merged_index] = index
            values = [values[anchor] for anchor in anchor_for]
        return [values[offset:offset + columns]
                for offset in range(0, rows * columns, columns)]

    @staticmethod
    def _header_role(value: str) -> str | None:
        value = unicodedata.normalize("NFKC", value).casefold()
        value = re.sub(r"[（(].*?[）)]", "", value)
        compact = re.sub(r"[\s:：()（）\[\]【】/_-]+", "", value)
        for role, aliases in _HEADER_ALIASES.items():
            if compact in aliases:
                return role
        return None

    @classmethod
    def _ip_header_label(cls, value: str) -> str:
        labels = [
            cls._safe_address_label(annotation.strip())
            for annotation in re.findall(r"[（(]([^（）()]{1,24})[）)]", value)
        ]
        return "、".join(label for label in labels if label)

    @classmethod
    def _find_device_header(
        cls, rows: list[list[str]],
    ) -> tuple[int | None, dict[str, Any]]:
        complete: list[tuple[int, dict[str, Any]]] = []
        partial_rows: list[set[str]] = []
        for row_index, row in enumerate(rows):
            positions: dict[str, list[int]] = {}
            ip_header_labels: dict[int, str] = {}
            for column_index, value in enumerate(row):
                role = cls._header_role(value)
                if role is not None:
                    positions.setdefault(role, []).append(column_index)
                    if role == "ip":
                        label = cls._ip_header_label(value)
                        if label:
                            ip_header_labels[column_index] = label
            if not positions:
                continue
            core_positions = {role: columns for role, columns in positions.items()
                              if role != "ip_labels"}
            if any(len(columns) != 1 for role, columns in core_positions.items()
                   if role not in {"ip"}):
                raise FeishuSyncError("Feishu device table has duplicate header columns")
            required = {"number", "brand", "model", "ip"}
            if set(core_positions) == required:
                column_map: dict[str, Any] = {
                    role: columns[0] if role != "ip" else list(columns)
                    for role, columns in core_positions.items()
                }
                column_map["ip_labels"] = positions.get("ip_labels", [])
                column_map["ip_header_labels"] = ip_header_labels
                complete.append((row_index, column_map))
            elif core_positions:
                partial_rows.append(set(core_positions))
        if len(complete) > 1:
            raise FeishuSyncError("Feishu device table has multiple header rows")
        if not complete:
            if partial_rows:
                raise FeishuSyncError("Feishu device table header is incomplete")
            return None, {}
        return complete[0]

    @staticmethod
    def _normalize_number(value: str) -> str:
        normalized = FeishuMachineSource._safe_device_metadata(value)
        if re.fullmatch(r"[0-9]+", normalized):
            normalized = normalized.zfill(3)
        return normalized

    @staticmethod
    def _safe_device_metadata(value: str) -> str:
        normalized = " ".join(value.split())
        if (not normalized or len(normalized) > 128
                or any(ord(char) < 32 or ord(char) == 127 for char in normalized)
                or _SENSITIVE_LABEL_RE.search(normalized)
                or _LONG_TOKEN_RE.search(normalized)
                or "://" in normalized or "@" in normalized):
            raise FeishuSyncError("Feishu device metadata is invalid")
        return normalized

    @classmethod
    def _parse_addresses(
        cls, value: str, supplemental_labels: list[str] | None = None,
    ) -> list[FeishuAddress]:
        matches = list(_IPV4_RE.finditer(value))
        if not matches:
            raise FeishuSyncError("Feishu IP cell contains no IPv4 address")
        normalized_matches: list[tuple[str, re.Match[str]]] = []
        for match in matches:
            try:
                address = ipaddress.ip_address(match.group(0))
            except ValueError:
                raise FeishuSyncError("Feishu IP cell contains an invalid IPv4 address") from None
            if address.version != 4:
                raise FeishuSyncError("Feishu IP cell contains a non-IPv4 address")
            normalized_matches.append((str(address), match))

        labels_by_index: dict[int, list[tuple[int, str]]] = {
            index: [] for index in range(len(normalized_matches))
        }

        def nearest_ip_on_text_line(position: int) -> int | None:
            line_start = value.rfind("\n", 0, position) + 1
            line_end = value.find("\n", position)
            if line_end < 0:
                line_end = len(value)
            candidates = [
                index for index, (_, match) in enumerate(normalized_matches)
                if match.start() >= line_start and match.end() <= line_end
            ]
            if not candidates:
                return None
            return min(
                candidates,
                key=lambda index: min(
                    abs(position - normalized_matches[index][1].start()),
                    abs(position - normalized_matches[index][1].end()),
                ),
            )

        for supplemental_label in supplemental_labels or []:
            label = cls._safe_address_label(supplemental_label)
            if label:
                for index in labels_by_index:
                    labels_by_index[index].append((-1, label))
        for label in _LABELS:
            start = 0
            while True:
                position = value.find(label, start)
                if position < 0:
                    break
                nearest = nearest_ip_on_text_line(position)
                if nearest is not None:
                    labels_by_index[nearest].append((position, label))
                start = position + len(label)

        for annotation in re.finditer(r"[（(]([^（）()]{1,24})[）)]", value):
            label = cls._safe_address_label(annotation.group(1))
            if not label or _IPV4_RE.search(label):
                continue
            nearest = nearest_ip_on_text_line(annotation.start())
            if nearest is not None:
                match = normalized_matches[nearest][1]
                distance = min(
                    abs(annotation.start() - match.start()),
                    abs(annotation.end() - match.end()),
                )
            else:
                distance = 25
            if nearest is not None and distance <= 24:
                labels_by_index[nearest].append((annotation.start(), label))

        addresses: list[FeishuAddress] = []
        position_by_ip: dict[str, int] = {}
        for index, (ip, _) in enumerate(normalized_matches):
            labels = [label for _, label in sorted(set(labels_by_index[index]))]
            label = "、".join(dict.fromkeys(labels))
            existing_index = position_by_ip.get(ip)
            if existing_index is None:
                position_by_ip[ip] = len(addresses)
                addresses.append(FeishuAddress(ip=ip, label=label))
            elif label:
                previous = addresses[existing_index]
                combined = list(dict.fromkeys(
                    [part for part in (previous.label + "、" + label).split("、") if part]
                ))
                addresses[existing_index] = FeishuAddress(
                    ip=ip, label="、".join(combined),
                )
        return addresses

    @staticmethod
    def _safe_address_label(value: str) -> str:
        label = " ".join(value.split())
        if (not label or len(label) > 64
                or any(ord(char) < 32 or ord(char) == 127 for char in label)
                or _SENSITIVE_LABEL_RE.search(label)
                or _LONG_TOKEN_RE.search(label) or _LONG_NUMERIC_RE.search(label)
                or "://" in label or "@" in label):
            return ""
        return label

    @classmethod
    def _merge_addresses(
        cls, existing: tuple[FeishuAddress, ...], new: list[FeishuAddress],
    ) -> list[FeishuAddress]:
        merged = list(existing)
        position_by_ip = {address.ip: index for index, address in enumerate(merged)}
        for address in new:
            position = position_by_ip.get(address.ip)
            if position is None:
                position_by_ip[address.ip] = len(merged)
                merged.append(address)
                continue
            previous = merged[position]
            labels = list(dict.fromkeys(
                part for part in (previous.label + "、" + address.label).split("、")
                if part
            ))
            merged[position] = FeishuAddress(ip=address.ip, label="、".join(labels))
        return merged
