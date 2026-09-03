"""Client for Agent Core's ``{code, data, message}`` HTTP API.

Covers driver/perception/actucore deploy+status, the MCP ping health check and
the core ``POST /api/system/update`` adapter. No sockets, no SSH, no shell.
Tokens are read from the machine's ``token_env`` env var at call time and never
persisted.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from .clients_common import (
    SecurityError,
    enforce_body_size,
    require_2xx,
    require_http_policy,
    stream_request,
)
from .config import Config

logger = logging.getLogger(__name__)


class AgentCoreError(Exception):
    pass


class AgentCoreClient:
    def __init__(
        self,
        config: Config,
        base_url: str = "",
        token_env: str = "",
        ca_file: str = "",
        http: httpx.AsyncClient | None = None,
        node_host: str = "",
    ):
        self.config = config
        if not base_url:
            raise AgentCoreError(
                "no Agent Core endpoint: the selected machine node_host endpoint is required"
            )
        if not isinstance(base_url, str) or not base_url.strip():
            raise AgentCoreError(
                "invalid Agent Core endpoint: must be a non-empty http(s) URL"
            )
        import ipaddress
        # Defense-in-depth: when node_host is provided, validate it as a
        # literal IP address and confirm the URL scheme/host/port are exact.
        if node_host:
            # node_host must be a literal IP address
            try:
                parsed_ip = ipaddress.ip_address(node_host)
            except ValueError as e:
                raise AgentCoreError(
                    f"node_host must be a literal IP address, got {node_host!r}"
                ) from e
            if parsed_ip.version != 4:
                raise AgentCoreError(
                    f"node_host must be an IPv4 address, got {node_host!r}"
                )
            # scheme must be http
            from urllib.parse import urlparse
            parsed = urlparse(base_url)
            if parsed.scheme != "http":
                raise AgentCoreError(
                    f"Agent Core endpoint scheme must be http, got {parsed.scheme!r}"
                )
            # hostname must be canonical node_host
            if parsed.hostname != node_host:
                raise AgentCoreError(
                    f"Agent Core endpoint hostname must match node_host ({node_host}), "
                    f"got {parsed.hostname!r}"
                )
            # port must be exactly 15678
            if parsed.port != 15678:
                raise AgentCoreError(
                    f"Agent Core endpoint port must be 15678, got {parsed.port}"
                )
            # No username/password, no path, no query, no fragment
            if parsed.username or parsed.password:
                raise AgentCoreError("Agent Core endpoint must not contain userinfo")
            if parsed.path not in ("", "/"):
                raise AgentCoreError("Agent Core endpoint must not contain a path")
            if parsed.query:
                raise AgentCoreError("Agent Core endpoint must not contain query")
            if parsed.fragment:
                raise AgentCoreError("Agent Core endpoint must not contain fragment")
            expected_base = f"http://{node_host}:15678"
            if base_url.rstrip("/") != expected_base:
                raise AgentCoreError(
                    "Agent Core endpoint must match the selected machine node_host exactly"
                )
        self.base_url = base_url.rstrip("/")
        self.node_host = node_host
        self.token_env = token_env
        self.ca_file = ca_file
        self.http = http or httpx.AsyncClient(
            timeout=httpx.Timeout(
                config.total_timeout,
                connect=config.connect_timeout,
                read=config.read_timeout,
                write=config.connect_timeout,
                pool=config.connect_timeout,
            ),
            follow_redirects=False,
            # Never disable TLS verification; use the machine's CA file when
            # provided, otherwise the system trust store.
            verify=ca_file if ca_file else True,
        )

    def _headers(self) -> dict:
        h = {}
        token = ""
        if self.token_env:
            token = os.getenv(self.token_env, "")
        if not token:
            token = os.getenv("AGENT_CORE_TOKEN", "")
        if token:
            h["Authorization"] = "Bearer " + token
        return h

    def _check_code(self, data: dict, method: str, path: str) -> None:
        """Fail-closed envelope check: ``code`` must be a *non-boolean* integer
        and only one of 0/200. A boolean is not an int here
        (``isinstance(True, int)`` is True in Python) so a true ``code`` is
        refused. The ``data`` payload type is NOT checked here — each endpoint
        adapter owns its exact shape (list for /api/drivers and /api/mcp,
        object for driver_status/mcp_ping)."""
        code = data.get("code")
        if isinstance(code, bool) or not isinstance(code, int):
            raise AgentCoreError(
                f"agent-core unexpected code {code!r} for {method} {path}"
            )
        if code not in (0, 200):
            raise AgentCoreError(
                f"agent-core unexpected code {code!r} for {method} {path}"
            )
        # The `data` payload shape belongs to each endpoint adapter. Endpoints
        # like GET /api/drivers and GET /api/mcp return `data` as an ARRAY,
        # while /api/drivers/<id>/status and /api/mcp ping return an OBJECT.
        # Requiring an object here would break the real Agent Core contract.

    async def request(self, method: str, path: str, json: dict | None = None):
        url = self.base_url + path
        require_http_policy(
            url, self.config, allow_private=self.config.allow_private_http,
            agent_core_node=self.node_host,
        )
        resp, data = await self._request_impl(method, path, json, url)
        self._check_code(data, method, path)
        return data

    async def _request_impl(self, method, path, json, url):
        try:
            resp = await stream_request(
                self.http, method, url, self.config.max_response_bytes,
                headers=self._headers(), json=json, timeout=self.config.total_timeout)
        except httpx.HTTPError as e:
            raise AgentCoreError(f"agent-core request failed: {e}")
        except SecurityError as e:
            raise AgentCoreError(str(e)) from e
        try:
            require_2xx(resp.status_code, f"agent-core {method} {path}")
        except SecurityError as e:
            raise AgentCoreError(str(e)) from e
        resp = await enforce_body_size(resp, self.config.max_response_bytes)
        try:
            data = resp.json()
        except ValueError:
            raise AgentCoreError("agent-core returned non-JSON")
        if not isinstance(data, dict):
            raise AgentCoreError("agent-core returned unexpected payload")
        return resp, data

    async def verify(self) -> dict:
        """Hit the auth-verify endpoint and return its raw `data`.

        Agent Core's `/api/auth/verify` is the one endpoint that is *not*
        wrapped in the `{code, data}` envelope — it returns the verdict directly
        (`{valid, auth_required}`), and returns HTTP 401 when the token is bad.
        Accept both shapes defensively but never treat a non-2xx as success.
        `valid` / `auth_required` must be real booleans (JSON true/false).
        """
        url = self.base_url + "/api/auth/verify"
        require_http_policy(
            url, self.config, allow_private=self.config.allow_private_http,
            agent_core_node=self.node_host,
        )
        try:
            resp = await stream_request(
                self.http, "GET", url, self.config.max_response_bytes,
                headers=self._headers(), timeout=self.config.total_timeout)
        except httpx.HTTPError as e:
            raise AgentCoreError(f"agent-core auth verify request failed: {e}")
        except SecurityError as e:
            raise AgentCoreError(str(e)) from e
        try:
            require_2xx(resp.status_code, "agent-core auth verify")
        except SecurityError as e:
            raise AgentCoreError(str(e)) from e
        resp = await enforce_body_size(resp, self.config.max_response_bytes)
        try:
            data = resp.json()
        except ValueError:
            raise AgentCoreError("agent-core auth verify returned non-JSON")
        if not isinstance(data, dict):
            raise AgentCoreError("agent-core auth verify unexpected payload")
        # The verify endpoint may be reached two ways: the documented raw
        # `{valid, auth_required}` body (preferred) or a generic `{code,data}`
        # wrapper. In the wrapped form, code must be 0/200 and data must be an
        # object whose `valid` is honoured fail-closed.
        if "code" in data:
            code = data.get("code")
            if isinstance(code, bool) or not isinstance(code, int) or code not in (200, 0):
                raise AgentCoreError(
                    f"agent-core auth verify unexpected code {code!r}"
                )
            inner = data.get("data")
            if not isinstance(inner, dict):
                raise AgentCoreError(
                    "agent-core auth verify envelope data is not an object"
                )
            data = inner
        # Strict booleans: JSON false/true only; a string "false" is refused.
        for key in ("valid", "auth_required"):
            v = data.get(key)
            if not isinstance(v, bool):
                raise AgentCoreError(
                    f"agent-core auth verify {key} must be a boolean"
                )
        # Fail-closed: authentication must be required AND the token valid. A
        # disabled or invalid auth (auth_required=false, or valid=false) is
        # never acceptable for a deployment request.
        if not (data.get("valid") is True and data.get("auth_required") is True):
            raise AgentCoreError(
                "agent-core auth verify did not return "
                "valid=true and auth_required=true"
            )
        return data
    async def list_drivers(self) -> list:
        data = await self.request("GET", "/api/drivers")
        drivers = data.get("data")
        if not isinstance(drivers, list):
            raise AgentCoreError("agent-core list_drivers data must be a list")
        return drivers

    async def registry_catalog(self) -> dict:
        """Return the selected Agent Core's host-arch registry catalog facets.

        Calls the read-only ``GET /api/registry/catalog`` and returns a dict
        containing at least ``data``, ``facets`` and ``filter``:

        {
          "data": <dict>,
          "facets": {"cpu_arch": "arm64", "acc_arch": "jetson-jp5"},
          "filter": <dict-or-empty>,
        }

        ``facets.cpu_arch`` and ``facets.acc_arch`` are the Agent Core's own
        host-architecture detection (never PR text). Malformed envelopes fail
        closed with ``AgentCoreError`` so a node whose host platform cannot be
        proven is never approved.
        """
        response = await self.request("GET", "/api/registry/catalog")
        catalog_data = response.get("data")
        if not isinstance(catalog_data, dict):
            raise AgentCoreError(
                "agent-core registry_catalog data must be an object"
            )
        facets = response.get("facets")
        if not isinstance(facets, dict):
            raise AgentCoreError(
                "agent-core registry_catalog facets must be an object"
            )
        cpu = facets.get("cpu_arch")
        acc = facets.get("acc_arch")
        if not isinstance(cpu, str) or not cpu.strip():
            raise AgentCoreError(
                "agent-core registry_catalog facets.cpu_arch must be a "
                "non-empty string"
            )
        if not isinstance(acc, str) or not acc.strip():
            raise AgentCoreError(
                "agent-core registry_catalog facets.acc_arch must be a "
                "non-empty string"
            )
        filt = response.get("filter")
        if not isinstance(filt, dict):
            raise AgentCoreError(
                "agent-core registry_catalog filter must be an object"
            )
        return {
            "data": catalog_data,
            "facets": {
                "cpu_arch": cpu.strip(),
                "acc_arch": acc.strip(),
            },
            "filter": filt,
        }

    async def list_mcp(self) -> list:
        data = await self.request("GET", "/api/mcp")
        mcps = data.get("data")
        if not isinstance(mcps, list):
            raise AgentCoreError("agent-core list_mcp data must be a list")
        return mcps

    async def deploy_driver(self, driver_id: str, image: str) -> dict:
        """POST the immutable target image to the selected Agent Core driver.

        ``image`` must already be in the exact immutable form
        ``<repo>@sha256:<64hex>``; a mutable tag or any other shape is a hard
        client error so a deploy POST can never carry a user-supplied tag."""
        if not isinstance(driver_id, str) or not driver_id:
            raise AgentCoreError("deploy_driver requires a non-empty driver id")
        if "@" not in image:
            raise AgentCoreError(
                "deploy image must be the immutable repo@sha256:<digest> form"
            )
        _family, _, _digest = image.rpartition("@")
        if not (_digest.startswith("sha256:") and len(_digest) == 71):
            raise AgentCoreError(
                "deploy image must be the immutable repo@sha256:<64hex> form"
            )
        if not all(c in "0123456789abcdefABCDEF" for c in _digest[7:]):
            raise AgentCoreError(
                "deploy image must be the immutable repo@sha256:<64hex> form"
            )
        return await self.request(
            "POST", f"/api/drivers/{driver_id}/deploy", {"image": image}
        )

    async def driver_status(self, driver_id: str) -> dict:
        data = await self.request("GET", f"/api/drivers/{driver_id}/status")
        inner = data.get("data")
        if not isinstance(inner, dict):
            raise AgentCoreError(
                "agent-core driver_status data must be an object"
            )
        status = inner.get("status")
        if status is not None and not isinstance(status, str):
            raise AgentCoreError("agent-core driver_status status must be a string")
        running = inner.get("running_image")
        if running is not None and not isinstance(running, str):
            raise AgentCoreError(
                "agent-core driver_status running_image must be a string"
            )
        return inner

    async def system_update(self, image: str) -> dict:
        return await self.request("POST", "/api/system/update", {"image": image})

    async def system_update_status(self) -> dict:
        data = await self.request("GET", "/api/system/update-status")
        return data.get("data", {})

    async def mcp_ping(self, mcp_id: str) -> dict:
        data = await self.request("POST", f"/api/mcp/{mcp_id}/ping")
        inner = data.get("data")
        if not isinstance(inner, dict):
            raise AgentCoreError("agent-core mcp_ping data must be an object")
        online = inner.get("online")
        if not isinstance(online, bool):
            raise AgentCoreError("agent-core mcp_ping online must be a boolean")
        tools = inner.get("tools")
        if tools is None:
            inner["tools"] = []
        elif isinstance(tools, list):
            # Strict schema, never coerced: a non-dict tool (number/string/null
            # /... ) is a protocol violation, not a tool with a stringified
            # name. The service defense-in-depth validates names separately.
            normalized = []
            for item in tools:
                if not isinstance(item, dict):
                    raise AgentCoreError(
                        "agent-core mcp_ping tools must be a list of objects"
                    )
                normalized.append(dict(item))
            inner["tools"] = normalized
        else:
            raise AgentCoreError(
                "agent-core mcp_ping tools must be a list or null"
            )
        return inner
