"""Registry parse + policy tests (fully offline)."""

from __future__ import annotations

import pytest

import re

from ..registry_client import (
    DIGEST_RE,
    RegistryError,
    _is_manifest_index,
    _parse_challenge,
    _select_index_manifest,
    parse_reference,
)


def test_parse_valid_tag():
    assert parse_reference("registry.example/repo/perception:release.260531.x") == (
        "registry.example/repo/perception",
        "release.260531.x",
    )


def test_reject_latest():
    with pytest.raises(RegistryError):
        parse_reference("registry.example/repo/x:latest")


def test_reject_digest_immediately():
    with pytest.raises(RegistryError):
        parse_reference(f"registry.example/repo/x@{'a'*64}")


def test_reject_invalid_tag():
    with pytest.raises(RegistryError):
        parse_reference("registry.example/repo/x:has space")


def test_digest_regex():
    assert DIGEST_RE.fullmatch("sha256:" + "a" * 64)
    assert not DIGEST_RE.fullmatch("sha256:" + "b" * 63)


def test_parse_challenge_params():
    h = 'Bearer realm="https://auth",service="svc",scope="repo:x"'
    params = _parse_challenge(h)
    assert params["realm"] == "https://auth"
    assert params["service"] == "svc"
    assert params["scope"] == "repo:x"


def test_index_detected():
    idx = {
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "digest": "sha256:" + "a" * 64,
                "platform": {"os": "linux", "architecture": "arm64"},
            }
        ],
    }
    assert _is_manifest_index(idx) is True


def test_select_index_matches_platform():
    idx = {
        "manifests": [
            {
                "digest": "sha256:" + "a" * 64,
                "platform": {"os": "linux", "architecture": "amd64"},
            },
            {
                "digest": "sha256:" + "b" * 64,
                "platform": {"os": "linux", "architecture": "arm64"},
            },
        ]
    }
    chosen = _select_index_manifest(idx, "linux/arm64")
    assert chosen is not None and chosen["digest"] == "sha256:" + "b" * 64


def test_select_index_no_platform_match_returns_none():
    idx = {
        "manifests": [
            {
                "digest": "sha256:" + "a" * 64,
                "platform": {"os": "linux", "architecture": "amd64"},
            }
        ]
    }
    assert _select_index_manifest(idx, "linux/arm64") is None


def test_select_index_ambiguity_fails_closed():
    # Two entries for linux/arm64 (e.g. v7 and v8 of the same arch) — the
    # selection is ambiguous and must be refused rather than guessed.
    idx = {
        "manifests": [
            {
                "digest": "sha256:" + "a" * 64,
                "platform": {"os": "linux", "architecture": "arm64", "variant": "v7"},
            },
            {
                "digest": "sha256:" + "b" * 64,
                "platform": {"os": "linux", "architecture": "arm64", "variant": "v8"},
            },
        ]
    }
    with pytest.raises(RegistryError):
        _select_index_manifest(idx, "linux/arm64")


def test_select_index_specific_variant_picks_exact():
    idx = {
        "manifests": [
            {
                "digest": "sha256:" + "a" * 64,
                "platform": {"os": "linux", "architecture": "arm64", "variant": "v7"},
            },
            {
                "digest": "sha256:" + "b" * 64,
                "platform": {"os": "linux", "architecture": "arm64", "variant": "v8"},
            },
        ]
    }
    chosen = _select_index_manifest(idx, "linux/arm64/v8")
    assert chosen is not None and chosen["digest"] == "sha256:" + "b" * 64


# ── real httpx.MockTransport tests ──────────────────────────────────────────
# These actually exercise RegistryClient.resolve_tag over an in-memory transport
# (anonymous path, Basic auth, Bearer auth, single-arch and manifest-index). The
# platform must be read from the config blob, never guessed.

import asyncio
import hashlib
import httpx
import json

from ..config import Config
from ..registry_client import RegistryClient


# Config blob served as raw bytes; _DCFG is derived from those exact bytes so
# the production digest-byte verification passes on the happy path.
_blob_bytes = b'{"os": "linux", "architecture": "arm64"}'
_DCFG = "sha256:" + hashlib.sha256(_blob_bytes).hexdigest()


def _manifest_body(cfg_digest: str) -> bytes:
    """The exact bytes served for a single-arch manifest. The Docker-Content-
    Digest header must be sha256 of these same bytes, because the production
    client verifies manifest bytes against their digest."""
    return json.dumps(
        {"schemaVersion": 2, "config": {"digest": cfg_digest, "size": 10}},
        separators=(",", ":"),
    ).encode()


# Digest of the default single-arch manifest body served on the happy paths.
_DMAN = "sha256:" + hashlib.sha256(_manifest_body(_DCFG)).hexdigest()


def _reg_cfg(**kw) -> Config:
    defaults = dict(
        api_token="t",

        poll_enabled=False,
        allow_private_http=True,
        http_allowed_cidrs=[],
        agent_core_token="test-core-tok",
        registry_user_env="ARGUSER",
        registry_password_env="ARGPASS",
    )
    defaults.update(kw)
    return Config(**defaults)


def _blob(os_="linux", arch="arm64"):
    return {"os": os_, "architecture": arch}


def _blob_response():
    return httpx.Response(200, content=_blob_bytes, request=None)


def _manifest(cfg_digest=_DCFG):
    return {"schemaVersion": 2, "config": {"digest": cfg_digest, "size": 10}}


def _resolve(client, ref, allow, platform=""):
    return asyncio.run(client.resolve_tag(ref, allow, platform=platform))


def _single_arch_transport():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/manifests/v1"):
            return httpx.Response(
                200,
                headers={"Docker-Content-Digest": _DMAN},
                content=_manifest_body(_DCFG),
                request=request,
            )
        if request.url.path.endswith("/blobs/" + _DCFG):
            return httpx.Response(200, content=_blob_bytes, request=request)
        return httpx.Response(404, json={}, request=request)

    return handler


def test_resolve_tag_anonymous_reads_config_blob():
    client = RegistryClient(
        _reg_cfg(),
        http=httpx.AsyncClient(transport=httpx.MockTransport(_single_arch_transport())),
    )
    res = _resolve(client, "registry.example/repo/x:v1", ["registry.example/repo"])
    assert res.digest == _DMAN
    assert res.platform == "linux/arm64"
    assert res.family == "registry.example/repo/x"


def test_resolve_tag_rejects_family_prefix_escape():
    # "registry.example/repo-evil/x" must NOT be accepted by an allowlist that
    # only permits "registry.example/repo".
    client = RegistryClient(
        _reg_cfg(),
        http=httpx.AsyncClient(transport=httpx.MockTransport(_single_arch_transport())),
    )
    with pytest.raises(RegistryError):
        _resolve(client, "registry.example/repo-evil/app:v1", ["registry.example/repo"])


def test_resolve_tag_rejects_http_bearer_realm():
    state = {"basic_sent": False}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "auth.invalid":
            state["basic_sent"] = True
            return httpx.Response(200, json={"token": "abc"}, request=request)
        if request.url.path.endswith("/manifests/v1"):
            return httpx.Response(
                401,
                headers={"Www-Authenticate": 'Bearer realm="http://auth.example",service="svc"'},
                request=request,
            )
        return httpx.Response(404, json={}, request=request)

    client = RegistryClient(_reg_cfg(), http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    with pytest.raises(RegistryError):
        _resolve(client, "registry.example/repo/app:v1", ["registry.example/repo"])
    assert state["basic_sent"] is False


def test_resolve_tag_uses_bearer_token():
    state = {"used_bearer": False}
    # The Bearer realm host equals the manifest registry host (registry.example),
    # which is the allowed host for the anonymous Bearer flow (no SSRF).
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "registry.example" and request.url.path == "/token":
            return httpx.Response(200, json={"token": "tok123"}, request=request)
        if request.url.path.endswith("/manifests/v1"):
            if request.headers.get("authorization", "").startswith("Bearer "):
                state["used_bearer"] = True
                return httpx.Response(
                    200,
                    headers={"Docker-Content-Digest": _DMAN},
                    content=_manifest_body(_DCFG),
                    request=request,
                )
            return httpx.Response(
                401,
                headers={"Www-Authenticate": 'Bearer realm="https://registry.example/token",service="svc"'},
                request=request,
            )
        if request.url.path.endswith("/blobs/" + _DCFG):
            return httpx.Response(200, content=_blob_bytes, request=request)
        return httpx.Response(404, json={}, request=request)

    client = RegistryClient(_reg_cfg(), http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    res = _resolve(client, "registry.example/repo/app:v1", ["registry.example/repo"])
    assert res.digest == _DMAN
    assert state["used_bearer"] is True


def test_resolve_tag_rejects_anonymous_cross_origin_realm():
    # Even WITHOUT registry credentials, a Bearer realm pointing at a different
    # host than the manifest registry must be refused (no anonymous SSRF).
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/manifests/v1"):
            return httpx.Response(
                401,
                headers={"Www-Authenticate": 'Bearer realm="https://auth.other.example",service="s"'},
                request=request,
            )
        return httpx.Response(404, json={}, request=request)

    client = RegistryClient(_reg_cfg(), http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    with pytest.raises(RegistryError):
        _resolve(client, "registry.example/repo/app:v1", ["registry.example/repo"])


def test_resolve_tag_manifest_index_picks_platform():
    child_a = "sha256:" + "1" * 64
    child_body = json.dumps(
        {"schemaVersion": 2, "config": {"digest": _DCFG, "size": 10}},
        separators=(",", ":"),
    ).encode()
    child_b = "sha256:" + hashlib.sha256(child_body).hexdigest()
    cfg_b = _DCFG
    index = {
        "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
        "manifests": [
            {"digest": child_a, "platform": {"os": "linux", "architecture": "amd64"}},
            {"digest": child_b, "platform": {"os": "linux", "architecture": "arm64"}},
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/manifests/v1"):
            return httpx.Response(200, json=index, request=request)
        if request.url.path.endswith("/manifests/" + child_b):
            return httpx.Response(
                200,
                headers={"Docker-Content-Digest": child_b},
                content=child_body,
                request=request,
            )
        if request.url.path.endswith("/blobs/" + cfg_b):
            return httpx.Response(200, content=_blob_bytes, request=request)
        return httpx.Response(404, json={}, request=request)

    client = RegistryClient(_reg_cfg(), http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    res = _resolve(client, "registry.example/repo/app:v1",
                   ["registry.example/repo"], platform="linux/arm64")
    assert res.digest == child_b
    assert res.platform == "linux/arm64"


def test_resolve_tag_manifest_index_no_platform_fails():
    index = {
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {"digest": _DMAN, "platform": {"os": "linux", "architecture": "arm64"}}
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/manifests/v1"):
            return httpx.Response(200, json=index, request=request)
        return httpx.Response(404, json={}, request=request)

    client = RegistryClient(_reg_cfg(), http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    with pytest.raises(RegistryError):
        _resolve(client, "registry.example/repo/app:v1", ["registry.example/repo"])


def test_resolve_tag_rejects_non_json_manifest():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<html>not json</html>", request=request)

    client = RegistryClient(_reg_cfg(), http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    with pytest.raises(RegistryError):
        _resolve(client, "registry.example/repo/app:v1", ["registry.example/repo"])


def test_resolve_tag_refuses_no_config_blob():
    # A manifest without a verifiable config blob must be refused (no fallback to
    # the manifest's self-reported platform).
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/manifests/v1"):
            return httpx.Response(
                200,
                headers={"Docker-Content-Digest": _DMAN},
                json={"schemaVersion": 2, "config": {"digest": _DCFG}},
                request=request,
            )
        if request.url.path.endswith("/blobs/" + _DCFG):
            # serve a blob whose bytes do NOT match _DCFG digest
            return httpx.Response(200, json={"os": "linux", "architecture": "arm64"}, request=request)
        return httpx.Response(404, json={}, request=request)

    client = RegistryClient(_reg_cfg(), http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    with pytest.raises(RegistryError):
        _resolve(client, "registry.example/repo/app:v1", ["registry.example/repo"])


def test_resolve_tag_verifies_manifest_digest_bytes():
    # A Docker-Content-Digest header that does not match the actual body bytes
    # must be refused.
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/manifests/v1"):
            return httpx.Response(
                200,
                headers={"Docker-Content-Digest": "sha256:" + "f" * 64},
                content=_manifest_body(_DCFG),
                request=request,
            )
        if request.url.path.endswith("/blobs/" + _DCFG):
            return httpx.Response(200, content=_blob_bytes, request=request)
        return httpx.Response(404, json={}, request=request)

    client = RegistryClient(_reg_cfg(), http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    with pytest.raises(RegistryError):
        _resolve(client, "registry.example/repo/app:v1", ["registry.example/repo"])


def test_resolve_tag_rejects_cross_origin_bearer_with_credentials():
    # Cached REGISTRY credentials must only be sent to the manifest registry host
    # or an explicit allowlist; a cross-origin realm is refused.
    state = {"creds_sent": False}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "auth.other.example":
            if "Basic" in (request.headers.get("authorization") or ""):
                state["creds_sent"] = True
            return httpx.Response(200, json={"token": "t"}, request=request)
        if request.url.path.endswith("/manifests/v1"):
            return httpx.Response(
                401,
                headers={"Www-Authenticate": 'Bearer realm="https://auth.other.example",service="s"'},
                request=request,
            )
        return httpx.Response(404, json={}, request=request)

    import os
    os.environ["ARGUSER"] = "u"
    os.environ["ARGPASS"] = "p"
    try:
        client = RegistryClient(_reg_cfg(), http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        with pytest.raises(RegistryError):
            _resolve(client, "registry.example/repo/app:v1", ["registry.example/repo"])
        assert state["creds_sent"] is False
    finally:
        os.environ.pop("ARGUSER", None)
        os.environ.pop("ARGPASS", None)


def test_resolve_tag_allows_allowlisted_cross_origin_realm():
    import os
    os.environ["ARGUSER"] = "u"
    os.environ["ARGPASS"] = "p"
    state = {"used_bearer": False}
    try:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "auth.other.example":
                return httpx.Response(200, json={"token": "tok"}, request=request)
            if request.url.path.endswith("/manifests/v1"):
                if (request.headers.get("authorization") or "").startswith("Bearer "):
                    state["used_bearer"] = True
                    return httpx.Response(
                        200,
                        headers={"Docker-Content-Digest": _DMAN},
                        content=_manifest_body(_DCFG),
                        request=request,
                    )
                return httpx.Response(
                    401,
                    headers={"Www-Authenticate": 'Bearer realm="https://auth.other.example",service="s"'},
                    request=request,
                )
            if request.url.path.endswith("/blobs/" + _DCFG):
                return httpx.Response(200, content=_blob_bytes, request=request)
            return httpx.Response(404, json={}, request=request)
        cfg = _reg_cfg(registry_auth_host_allowlist=["auth.other.example"])
        client = RegistryClient(cfg, http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        res = _resolve(client, "registry.example/repo/app:v1", ["registry.example/repo"])
        assert res.digest == _DMAN
        assert state["used_bearer"] is True
    finally:
        os.environ.pop("ARGUSER", None)
        os.environ.pop("ARGPASS", None)


def test_resolve_tag_index_rejects_desc_mismatched_response():
    # TODO: descriptor digest A in the index, but the child manifest response
    # (both Docker-Content-Digest header and body) is B — must be refused, never
    # trust the response over the verified index descriptor.
    child_a = "sha256:" + "a" * 64
    child_b_body = json.dumps(
        {"schemaVersion": 2, "config": {"digest": _DCFG, "size": 10}},
        separators=(",", ":"),
    ).encode()
    child_b = "sha256:" + hashlib.sha256(child_b_body).hexdigest()
    index = {
        "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
        "manifests": [
            {"digest": child_a, "platform": {"os": "linux", "architecture": "arm64"}},
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/manifests/v1"):
            return httpx.Response(200, json=index, request=request)
        if request.url.path.endswith("/manifests/" + child_a):
            # descriptor says A, but the registry returns B (header AND body)
            return httpx.Response(
                200,
                headers={"Docker-Content-Digest": child_b},
                content=child_b_body,
                request=request,
            )
        return httpx.Response(404, json={}, request=request)

    client = RegistryClient(_reg_cfg(), http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    with pytest.raises(RegistryError):
        _resolve(client, "registry.example/repo/app:v1",
                 ["registry.example/repo"], platform="linux/arm64")


def test_resolve_tag_index_rejects_body_vs_desc_digest_mismatch():
    # descriptor says A, response body sha256 is B (even with NO Docker-Content-
    # Digest header) -> the pinned digest must remain descriptor A; mismatch is
    # refused.
    child_a = "sha256:" + "c" * 64
    child_b_body = json.dumps(
        {"schemaVersion": 2, "config": {"digest": _DCFG, "size": 10}},
        separators=(",", ":"),
    ).encode()
    child_b = "sha256:" + hashlib.sha256(child_b_body).hexdigest()
    index = {
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {"digest": child_a, "platform": {"os": "linux", "architecture": "arm64"}},
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/manifests/v1"):
            return httpx.Response(200, json=index, request=request)
        if request.url.path.endswith("/manifests/" + child_a):
            # body is B, but no Docker-Content-Digest header at all
            return httpx.Response(200, content=child_b_body, request=request)
        return httpx.Response(404, json={}, request=request)

    client = RegistryClient(_reg_cfg(), http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    with pytest.raises(RegistryError):
        _resolve(client, "registry.example/repo/app:v1",
                 ["registry.example/repo"], platform="linux/arm64")


# ── verify_digest: immutable reference provenance ──────────────────────────

def _vdigest(client, ref, allow):
    return asyncio.run(client.verify_digest(ref, allow))


def test_verify_digest_happy_immutable_manifest():
    # verify_digest fetches /v2/<repo>/manifests/<digest> (not the tag path).
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/manifests/" + _DMAN):
            return httpx.Response(
                200,
                headers={"Docker-Content-Digest": _DMAN},
                content=_manifest_body(_DCFG),
                request=request,
            )
        if request.url.path.endswith("/blobs/" + _DCFG):
            return httpx.Response(200, content=_blob_bytes, request=request)
        return httpx.Response(404, json={}, request=request)

    client = RegistryClient(
        _reg_cfg(),
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    res = _vdigest(client, "registry.example/repo/x@" + _DMAN, ["registry.example/repo"])
    assert res.digest == _DMAN
    assert res.platform == "linux/arm64"
    assert res.family == "registry.example/repo/x"


def test_verify_digest_rejects_mutable_tag_and_bad_digest():
    client = RegistryClient(
        _reg_cfg(),
        http=httpx.AsyncClient(transport=httpx.MockTransport(_single_arch_transport())),
    )
    with pytest.raises(RegistryError):
        _vdigest(client, "registry.example/repo/x:v1", ["registry.example/repo"])
    with pytest.raises(RegistryError):
        _vdigest(client, "registry.example/repo/x@sha256:" + "b" * 63, ["registry.example/repo"])


def test_verify_digest_rejects_wrong_family_and_index_digest():
    # The digest must live in the trusted family AND identify a single
    # immutable manifest — an index digest cannot prove one concrete platform
    # artifact.
    index = {
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {"digest": "sha256:" + "d" * 64, "platform": {"os": "linux", "architecture": "arm64"}},
        ],
    }
    index_body = json.dumps(index, separators=(",", ":")).encode()
    index_digest = "sha256:" + hashlib.sha256(index_body).hexdigest()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/manifests/" + index_digest):
            return httpx.Response(
                200, headers={"Docker-Content-Digest": index_digest},
                content=index_body, request=request,
            )
        return httpx.Response(404, json={}, request=request)

    client = RegistryClient(
        _reg_cfg(),
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(RegistryError):
        _vdigest(client, "registry.example/other/x@" + _DMAN, ["registry.example/repo"])
    with pytest.raises(RegistryError):
        _vdigest(client, "registry.example/repo/x@" + index_digest, ["registry.example/repo"])
