"""Client tests: agent-core envelope checks, review client, common transport."""

from __future__ import annotations

import asyncio

import pytest

import httpx

from ..agent_core_client import AgentCoreClient, AgentCoreError
from ..config import Config
from .conftest import make_config


class _Transport(httpx.AsyncBaseTransport):
    """In-memory httpx async transport returning a canned response."""

    def __init__(self, payload, status=200):
        self.payload = payload
        self.status = status

    async def handle_async_request(self, request):
        return httpx.Response(
            self.status,
            json=self.payload,
            request=request,
        )


class _TransportFromScenarios(httpx.AsyncBaseTransport):
    """Routes each request path to a canned transport so one client can serve
    multiple Agent Core endpoints."""

    def __init__(self, transports):
        self.transports = transports

    async def handle_async_request(self, request):
        tr = self.transports.get(request.url.path, self.transports.get(""))
        if tr is None:
            raise AssertionError(f"no transport for {request.url.path}")
        return await tr.handle_async_request(request)


def _client():
    cfg = make_config(allow_private_http=False)
    cfg.ca_file = ""
    return cfg


def test_agent_core_accepts_code_200():
    cfg = _client()
    tr = _Transport({"code": 200, "data": {"running_image": "registry/repo@sha256:" + "a" * 64}})
    c = AgentCoreClient(
        cfg, base_url="https://example.invalid:15678",
        ca_file="", http=httpx.AsyncClient(transport=tr),
    )
    out = asyncio.run(c.driver_status("driver"))
    assert out == {"running_image": "registry/repo@sha256:" + "a" * 64}


def test_agent_core_rejects_missing_running_image():
    cfg = _client()
    tr = _Transport({"code": 200, "data": {"status": "running"}})
    c = AgentCoreClient(
        cfg, base_url="https://example.invalid:15678",
        ca_file="", http=httpx.AsyncClient(transport=tr),
    )
    with pytest.raises(AgentCoreError):
        asyncio.run(c.driver_status("driver"))


def test_agent_core_rejects_missing_data_envelope():
    cfg = _client()
    tr = _Transport({"message": "boom", "data": None})
    c = AgentCoreClient(
        cfg, base_url="https://example.invalid:15678",
        ca_file="", http=httpx.AsyncClient(transport=tr),
    )
    with pytest.raises(AgentCoreError):
        asyncio.run(c.driver_status("driver"))


def test_agent_core_rejects_non_200_code():
    cfg = _client()
    tr = _Transport({"code": 500, "message": "boom", "data": None})
    c = AgentCoreClient(
        cfg, base_url="https://example.invalid:15678",
        ca_file="", http=httpx.AsyncClient(transport=tr),
    )
    with pytest.raises(AgentCoreError):
        asyncio.run(c.driver_status("driver"))


def test_agent_core_auth_verify_accepts_raw_shape():
    # /api/auth/verify returns raw {valid, auth_required}, not a {code,data}
    # wrapper — the client must accept both.
    cfg = _client()
    tr = _Transport({"valid": True, "auth_required": True})
    c = AgentCoreClient(
        cfg, base_url="https://example.invalid:15678",
        ca_file="", http=httpx.AsyncClient(transport=tr),
    )
    out = asyncio.run(c.verify())
    assert out.get("valid") is True
    assert out.get("auth_required") is True


def test_agent_core_auth_disabled_fails_closed():
    # Authentication must be required AND valid: an auth-disabled Agent Core
    # (auth_required=false or valid=false) is never acceptable for a deploy.
    import pytest
    for payload in (
        {"valid": True, "auth_required": False},
        {"valid": False, "auth_required": True},
        {"valid": False, "auth_required": False},
        {"valid": "true", "auth_required": True},
    ):
        cfg = _client()
        tr = _Transport(payload)
        c = AgentCoreClient(
            cfg, base_url="https://example.invalid:15678",
            ca_file="", http=httpx.AsyncClient(transport=tr),
        )
        with pytest.raises(AgentCoreError):
            asyncio.run(c.verify())


def test_agent_core_rejects_http_401():
    cfg = _client()
    tr = _Transport({"detail": "nope"}, status=401)
    c = AgentCoreClient(
        cfg, base_url="https://example.invalid:15678",
        ca_file="", http=httpx.AsyncClient(transport=tr),
    )
    with pytest.raises(AgentCoreError):
        asyncio.run(c.verify())


class _ChunkedTransport(httpx.AsyncBaseTransport):
    """Serves a sizeable body WITHOUT a Content-Length so a true streaming byte
    cap must be enforced from the wire (not from a header)."""

    def __init__(self, body: bytes, status: int = 200):
        self.body = body
        self.status = status

    async def handle_async_request(self, request):
        # No content-length header: httpx must deliver via a stream.
        return httpx.Response(
            self.status,
            content=self.body,
            headers={},
            request=request,
        )


def test_stream_request_oversize_without_content_length():
    # A response with no Content-Length and more bytes than the limit must be
    # refused while streaming — it must never be buffered in full first.
    from ..clients_common import SecurityError, stream_request

    cfg = _client()
    cfg.max_response_bytes = 64
    big = b"x" * 4096
    tr = _ChunkedTransport(big)
    client = httpx.AsyncClient(transport=tr)
    with pytest.raises(SecurityError):
        asyncio.run(
            stream_request(
                client, "GET", "https://example.invalid/x",
                cfg.max_response_bytes,
            )
        )


def test_agent_core_oversize_response_fails_closed():
    # Even with no Content-Length header, an oversized Agent Core response is
    # refused (streaming byte cap), not parsed.
    cfg = _client()
    cfg.max_response_bytes = 64
    tr = _ChunkedTransport(b'{"code": 200, "data": "' + b"x" * 512 + b'"}')
    c = AgentCoreClient(
        cfg, base_url="https://example.invalid:15678",
        ca_file="", http=httpx.AsyncClient(transport=tr),
    )
    with pytest.raises(AgentCoreError):
        asyncio.run(c.driver_status("driver"))


def test_github_poll_prs_bounded_and_covers_closed():
    # The poller's PR enumeration must cover recently-updated closed/merged PRs
    # (so a production `/deploy` posted after merge is seen) and be bounded by the
    # initial lookback window; it never scans unbounded history.
    from ..github_client import GitHubClient
    from datetime import datetime, timezone, timedelta

    cfg = make_config(allow_private_http=False)
    cfg.github_token = "gh-token"
    cfg.poll_initial_lookback_hours = 24 * 7
    cfg.github_api_url = "https://api.github.com"

    now = datetime.now(timezone.utc)
    open_pr = {"number": 3, "updated_at": now.isoformat()}
    closed_pr = {
        "number": 5,
        "updated_at": (now - timedelta(hours=1)).isoformat(),
    }

    class FakeTransport(httpx.AsyncBaseTransport):
        def __init__(self, prs_by_page):
            self.prs_by_page = prs_by_page

        async def handle_async_request(self, request):
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(str(request.url)).query)
            st = qs.get("state", ["open"])[0]
            try:
                page = int(qs.get("page", ["1"])[0])
            except ValueError:
                page = 1
            batch = self.prs_by_page.get((st, page), [])
            return httpx.Response(200, json=batch, request=request)

    tr = FakeTransport({
        ("open", 1): [open_pr],
        ("closed", 1): [closed_pr],
    })
    client = httpx.AsyncClient(transport=tr)
    gh = GitHubClient(cfg, http=client)
    prs = asyncio.run(gh.poll_prs("org/repo"))
    nums = {p["number"] for p in prs}
    assert 3 in nums and 5 in nums, "poll_prs must cover open + recent closed PRs"


def test_within_cutoff_parses_github_timestamp():
    from ..github_client import _within_cutoff
    import time as _time
    cutoff = _time.time() - 3600
    # recent timestamp passes, old fails, empty fails closed
    import datetime as _dt
    recent = _dt.datetime.now(_dt.timezone.utc).isoformat()
    assert _within_cutoff(recent, cutoff) is True
    old = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=30)
    assert _within_cutoff(old.isoformat(), cutoff) is False
    assert _within_cutoff("", cutoff) is False
    assert _within_cutoff("not-a-date", cutoff) is False

def test_real_agent_core_list_envelopes_accept_list_data():
    """The real Agent Core wraps /api/drivers and /api/mcp as
    ``{"code":200,"data":[...]}`` (data is an ARRAY), while
    /api/drivers/<id>/status returns ``data`` as an OBJECT. The generic
    envelope check must accept both; each adapter validates its own shape."""
    cfg = _client()

    async def _scenario():
        out = []
        cases = [
            ({"code": 200, "data": []}, "list_drivers", []),
            ({"code": 200, "data": []}, "list_mcp", []),
            ({"code": 200, "data": {"status": "stopped", "running_image": ""}},
             "driver_status", {"running_image": ""}),
            ({"code": 200, "data": {"online": True, "tools": [{"name": "x"}]}},
             "mcp_ping", {"online": True, "tools": [{"name": "x"}]}),
        ]
        for payload, kind, expect in cases:
            tr = _Transport(payload)
            c = AgentCoreClient(
                cfg, base_url="https://example.invalid:15678",
                ca_file="", http=httpx.AsyncClient(transport=tr),
            )
            if kind == "list_drivers":
                got = await c.list_drivers()
            elif kind == "list_mcp":
                got = await c.list_mcp()
            elif kind == "driver_status":
                got = await c.driver_status("driver")
            else:
                got = await c.mcp_ping("mcp1")
            assert got == expect, (kind, got, expect)
            out.append(kind)
        return out

    assert asyncio.run(_scenario()) == [
        "list_drivers", "list_mcp", "driver_status", "mcp_ping",
    ]


def test_real_agent_core_registry_catalog_facets_contract():
    """/api/registry/catalog must be parsed into data/facets/filter with
    non-empty cpu_arch/acc_arch, and a real /api/drivers entry without a
    platform field must still parse as a list of driver dicts."""
    cfg = _client()

    async def _scenario():
        catalog_tr = _Transport({
            "code": 200,
            "data": {"repos": []},
            "cached": False,
            "facets": {
                "cpu_arch": "arm64",
                "acc_arch": "jetson-jp5",
            },
            "filter": {
                "applied": True,
            },
        })
        drivers_tr = _Transport({
            "code": 200,
            "data": [
                {
                    "id": "perception",
                    "name": "perception",
                    "image": "registry.example/repo/perception:rel-n5.11",
                    "port": "80",
                    "description": "",
                    "category": "perception",
                    "mcp_url": "",
                    "running_image": "",
                },
            ],
        })
        c = AgentCoreClient(
            cfg, base_url="https://example.invalid:15678",
            ca_file="", http=httpx.AsyncClient(
                transport=_TransportFromScenarios({
                    "/api/registry/catalog": catalog_tr,
                    "/api/drivers": drivers_tr,
                })
            ),
        )
        catalog = await c.registry_catalog()
        assert catalog["data"] == {"repos": []}
        assert catalog["facets"] == {
            "cpu_arch": "arm64", "acc_arch": "jetson-jp5",
        }
        assert catalog["filter"] == {"applied": True}
        drivers = await c.list_drivers()
        assert len(drivers) == 1
        # The REAL schema has no platform/required_platform field and that is
        # fine: the adapter must not require one to parse the entry.
        assert "platform" not in drivers[0]
        assert "required_platform" not in drivers[0]
        assert drivers[0]["id"] == "perception"

    asyncio.run(_scenario())


def test_registry_catalog_rejects_legacy_nested_facets_shape():
    """The legacy nested mock shape (facets/filter under data) is NOT the real
    /api/registry/catalog envelope and must fail closed, never be guessed."""
    cfg = _client()
    tr = _Transport({
        "code": 200,
        "data": {
            "facets": {
                "cpu_arch": "arm64",
                "acc_arch": "jetson-jp5",
            },
            "filter": {},
            "data": {},
        },
    })
    c = AgentCoreClient(
        cfg, base_url="https://example.invalid:15678",
        ca_file="", http=httpx.AsyncClient(transport=tr),
    )
    with pytest.raises(AgentCoreError):
        asyncio.run(c.registry_catalog())


def test_registry_catalog_rejects_missing_top_level_facets():
    """A top-level envelope without facets cannot prove host architecture and
    must fail closed (missing filter also fails closed)."""
    cfg = _client()
    tr = _Transport({
        "code": 200,
        "data": {"repos": []},
        "filter": {"applied": True},
    })
    c = AgentCoreClient(
        cfg, base_url="https://example.invalid:15678",
        ca_file="", http=httpx.AsyncClient(transport=tr),
    )
    with pytest.raises(AgentCoreError):
        asyncio.run(c.registry_catalog())


def test_registry_catalog_rejects_non_dict_top_level_filter():
    """filter is top-level in the real envelope; a malformed filter must fail
    closed instead of being silently replaced."""
    cfg = _client()
    tr = _Transport({
        "code": 200,
        "data": {"repos": []},
        "facets": {"cpu_arch": "arm64", "acc_arch": "jetson-jp5"},
        "filter": "applied",
    })
    c = AgentCoreClient(
        cfg, base_url="https://example.invalid:15678",
        ca_file="", http=httpx.AsyncClient(transport=tr),
    )
    with pytest.raises(AgentCoreError):
        asyncio.run(c.registry_catalog())


def test_registry_catalog_rejects_missing_filter_fail_closed():
    """The real API always supplies filter; a drift that drops it must fail
    closed, not be normalized to {}."""
    cfg = _client()
    tr = _Transport({
        "code": 200,
        "data": {"repos": []},
        "facets": {"cpu_arch": "arm64", "acc_arch": "jetson-jp5"},
    })
    c = AgentCoreClient(
        cfg, base_url="https://example.invalid:15678",
        ca_file="", http=httpx.AsyncClient(transport=tr),
    )
    with pytest.raises(AgentCoreError):
        asyncio.run(c.registry_catalog())


def test_registry_catalog_rejects_empty_cpu_or_acc_arch():
    """Empty cpu_arch/acc_arch cannot prove host architecture; fail closed."""
    cfg = _client()
    for cpu, acc in (("", "jetson-jp5"), ("arm64", " ")):
        tr = _Transport({
            "code": 200,
            "data": {"repos": []},
            "facets": {"cpu_arch": cpu, "acc_arch": acc},
            "filter": {"applied": True},
        })
        c = AgentCoreClient(
            cfg, base_url="https://example.invalid:15678",
            ca_file="", http=httpx.AsyncClient(transport=tr),
        )
        with pytest.raises(AgentCoreError):
            asyncio.run(c.registry_catalog())


def test_list_drivers_rejects_object_data_fail_closed():
    """If a node wrongly wraps /api/drivers as an object the adapter fails
    closed instead of guessing."""
    cfg = _client()
    tr = _Transport({"code": 200, "data": {"id": "perception"}})
    c = AgentCoreClient(
        cfg, base_url="https://example.invalid:15678",
        ca_file="", http=httpx.AsyncClient(transport=tr),
    )
    with pytest.raises(AgentCoreError):
        asyncio.run(c.list_drivers())


def test_deploy_driver_requires_immutable_digest_form():
    """The deploy POST adapter refuses a mutable tag: only
    repo@sha256:<64hex> may ever be sent to /deploy."""
    cfg = _client()
    for bad in ("registry.example/repo/perception:latest",
                "registry.example/repo/perception",
                "registry.example/repo/perception@sha256:abc",
                "registry.example/repo/perception@sha256:" + "z" * 64):
        tr = _Transport({"code": 200, "data": {}})
        c = AgentCoreClient(
            cfg, base_url="https://example.invalid:15678",
            ca_file="", http=httpx.AsyncClient(transport=tr),
        )
        with pytest.raises(AgentCoreError):
            asyncio.run(c.deploy_driver("drv", bad))

    class Capture(httpx.AsyncBaseTransport):
        def __init__(self):
            self.body = None

        async def handle_async_request(self, request):
            self.body = request.content
            return httpx.Response(200, json={"code": 200, "data": {}},
                                  request=request)

    tr = Capture()
    c = AgentCoreClient(
        cfg, base_url="https://example.invalid:15678",
        ca_file="", http=httpx.AsyncClient(transport=tr),
    )
    good = "registry.example/repo/perception@sha256:" + "a" * 64
    asyncio.run(c.deploy_driver("drv", good))
    assert b"@sha256:" in tr.body


# ── MCP strict schema: NO coercion of non-object tools ────────────────────

def test_mcp_health_rejects_non_object_tools_without_coercion():
    """A non-object tool (number/string/null) is a protocol violation and must
    FAIL the client's mcp_ping with AgentCoreError — never coerced into a fake
    ``{"name": "<str>"}`` tool. All of [123], ["foo"], [None] fail closed."""
    cfg = _client()
    for raw_tools in ([123], ["foo"], [None]):
        tr = _Transport({
            "code": 200,
            "data": {"online": True, "tools": raw_tools},
        })
        c = AgentCoreClient(
            cfg, base_url="https://example.invalid:15678",
            ca_file="", http=httpx.AsyncClient(transport=tr),
        )
        with pytest.raises(AgentCoreError):
            asyncio.run(c.mcp_ping("mcp1"))


# ── ReviewJobInfo: options.build_only missing must fail closed ────────────

def test_build_only_missing_fails_closed():
    """options={} (or a missing ``build_only`` key) must make review_complete()
    False — never treated as ``build_only=False``. Only an explicit JSON
    boolean False may pass the deploy gate; missing/null/string/number/True
    all fail closed."""
    from ..review_client import ReviewJobInfo

    base = {
        "id": "job1", "repo": "r", "pr_number": 1,
        "head_sha": "h" * 40, "build_ref_sha": "b" * 40,
        "status": "review_done", "review_text": "Review performed.",
        "build_results": [],
    }
    # missing options entirely / options={} / missing build_only key
    for raw in (
        {k: v for k, v in base.items() if k != "options"},
        {**base, "options": {}},
        # a full-detail job whose options dict lacks build_only
        {**base, "options": {"review_text": "x"}},
        # explicit non-boolean values are equally fail-closed (missing,
        # null, string, number, True all fail; only explicit False passes)
        {**base, "options": {"build_only": None}},
        {**base, "options": {"build_only": "false"}},
        {**base, "options": {"build_only": 0}},
        {**base, "options": {"build_only": True}},
    ):
        info = ReviewJobInfo(raw)
        if raw.get("options") == {"build_only": True}:
            assert info.build_only is True, raw  # explicit True is still not deployable
        else:
            assert info.build_only is None, raw
        assert info.review_complete() is False, raw
    # the explicit JSON boolean False is the ONLY passing form
    info = ReviewJobInfo({**base, "options": {"build_only": False}})
    assert info.build_only is False
    assert info.review_complete() is True
