"""OCI / Docker Registry HTTP API client.

Pins a repository@sha256:<digest> from a user-facing tag, with allowlist
checks, Basic/Bearer auth (credentials only from env vars) and platform
validation. Never runs docker, shell or subprocess.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import urllib.parse as up
from dataclasses import dataclass

import httpx

from .config import Config
from .clients_common import (
    SecurityError,
    enforce_body_size,
    require_2xx,
    stream_request,
)

logger = logging.getLogger(__name__)


DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")
REPO_RE = re.compile(
    r"^[a-z0-9]+(?:(?:[._]|__+|[-]+)[a-z0-9]+)*"
    r"(?:/[a-z0-9]+(?:(?:[._]|__+|[-]+)[a-z0-9]+)*)*$"
)


@dataclass
class ResolvedImage:
    family: str  # "host/namespace/repository"
    tag: str
    digest: str  # "sha256:<hex>"
    platform: str  # "os/arch[/variant]"
    size: int


class RegistryError(Exception):
    pass


def parse_reference(ref: str) -> tuple[str, str]:
    """Split ``registry/repository:tag`` into (family, tag).

    - Digest references (``@sha256:...``) are rejected up front — the agent
      only accepts tags to pin to a digest itself.
    - ``latest`` and empty tags are rejected.
    """
    if not isinstance(ref, str) or not ref:
        raise RegistryError("empty image reference")
    if "@" in ref:
        raise RegistryError("digest references are not accepted as input")
    repo = ref
    tag = "latest"
    if ":" in ref:
        before, after = ref.rsplit(":", 1)
        if "/" in after or not before:
            raise RegistryError(f"malformed reference {ref!r}")
        repo, tag = before, after
    if tag in ("", "latest"):
        raise RegistryError("latest/empty tag is not allowed")
    if not TAG_RE.fullmatch(tag):
        raise RegistryError(f"invalid tag {tag!r}")
    if not REPO_RE.fullmatch(repo):
        raise RegistryError(f"invalid repository {repo!r}")
    return repo, tag


class RegistryClient:
    def __init__(self, config: Config, http: httpx.AsyncClient | None = None):
        self.config = config
        self.http = http or httpx.AsyncClient(
            timeout=httpx.Timeout(
                config.total_timeout,
                connect=config.connect_timeout,
                read=config.read_timeout,
                write=config.connect_timeout,
                pool=config.connect_timeout,
            ),
            follow_redirects=False,
        )

    async def resolve(
        self,
        ref: str,
        platform: str = "",
        allowed_prefixes: list[str] | None = None,
    ) -> ResolvedImage:
        """Resolve the exact Review Agent image tag to an immutable image.

        ``ref`` is the Review Agent source fact. The registry is only allowed to
        verify/resolve that exact image reference; it never chooses a different
        candidate. The repository portion of the resolved immutable reference
        must match the repository portion of ``ref``.
        """
        allowed_prefixes = allowed_prefixes or []
        if "@" in ref:
            family, _, digest = ref.rpartition("@")
            if not family or not digest:
                raise RegistryError(f"malformed reference {ref!r}")
            if not DIGEST_RE.fullmatch(digest):
                raise RegistryError(f"immutable reference {ref!r} has an invalid digest")
            resolved = await self.verify_digest(ref, allowed_prefixes)
        else:
            family, _tag = parse_reference(ref)
            resolved = await self.resolve_tag(ref, allowed_prefixes, platform=platform)
        if resolved.family != family:
            raise RegistryError(
                f"registry resolved repository {resolved.family!r} does not match source repository {family!r}"
            )
        return resolved

    async def resolve_tag(
        self,
        ref: str,
        allowed_prefixes: list[str],
        platform: str = "",
    ) -> ResolvedImage:
        """Resolve ``ref`` to an immutable digest, gated by allowlist.

        When the registry returns a manifest *index/list* (multi-arch), the
        entry matching ``platform`` is selected and its manifest fetched; the
        pinned digest is the platform-specific child, not the index digest. If
        ``platform`` is empty and the tag resolves to an index, that is treated
        as a policy error (we never guess an architecture).
        """
        family, tag = parse_reference(ref)
        if not any(
            family == p or family.startswith(p + "/") for p in allowed_prefixes
        ):
            raise RegistryError(
                f"image family {family!r} not in allowlist {sorted(allowed_prefixes)}"
            )

        headers = self._auth_headers(family)
        headers["Accept"] = _manifest_accept_header()
        scheme, host, path = self._endpoint(family)
        manifest_url = f"{scheme}://{host}/v2/{path}/manifests/{tag}"

        resp = await stream_request(
            self.http, "GET", manifest_url, self.config.max_response_bytes,
            headers=headers, timeout=self.config.total_timeout)
        resp = await enforce_body_size(resp, self.config.max_response_bytes)
        if resp.status_code == 401:
            bearer = await self._bearer(resp, scheme, host, family)
            if bearer:
                headers = {
                    "Accept": _manifest_accept_header(),
                    "Authorization": f"Bearer {bearer}",
                }
                resp = await stream_request(
            self.http, "GET", manifest_url, self.config.max_response_bytes,
            headers=headers, timeout=self.config.total_timeout)
                resp = await enforce_body_size(resp, self.config.max_response_bytes)

        try:
            require_2xx(resp.status_code, f"registry {_safe_display(manifest_url)}")
        except SecurityError as e:
            raise RegistryError(str(e)) from e

        manifest_body = await self._read_body_once(resp)
        content = _json_loads({}, manifest_body)
        _checked_manifest_digest(resp, content, manifest_body)

        if _is_manifest_index(content):
            child = _select_index_manifest(content, platform)
            if child is None:
                raise RegistryError(
                    f"no manifest index entry for platform {platform!r} "
                    f"(was {_index_platforms(content)})"
                )
            child_digest = child.get("digest", "")
            if not child_digest or not DIGEST_RE.fullmatch(child_digest):
                raise RegistryError("manifest index entry has an invalid digest")
            manifest_url2 = (
                f"{scheme}://{host}/v2/{path}/manifests/{child_digest}"
            )
            resp2 = await stream_request(
            self.http, "GET", manifest_url2, self.config.max_response_bytes,
            headers=headers, timeout=self.config.total_timeout)
            resp2 = await enforce_body_size(resp2, self.config.max_response_bytes)
            try:
                require_2xx(resp2.status_code, "registry index child")
            except SecurityError as e:
                raise RegistryError(str(e)) from e
            child_body = await self._read_body_once(resp2)
            child_content = _parse_json_bytes({}, child_body)
            # The pinned digest MUST be the index descriptor's child_digest. The
            # response body's sha256 must equal it, and if the registry returned
            # a Docker-Content-Digest header it must also equal it — so a chain
            # where the descriptor says A but the response returns B is refused
            # (no trusting a mismatched response over the verified index).
            header_digest = (
                resp2.headers.get("Docker-Content-Digest")
                or resp2.headers.get("docker-content-digest")
            )
            if header_digest and (
                not DIGEST_RE.fullmatch(header_digest)
                or header_digest != child_digest
            ):
                raise RegistryError(
                    "registry child response Docker-Content-Digest does not "
                    "match the index descriptor digest"
                )
            if _digest_of(child_body) != child_digest:
                raise RegistryError(
                    "registry child manifest body does not match its index "
                    "descriptor digest"
                )
            platform = await self._platform_from_manifest(
                child_content, scheme, host, path, headers
            )
            if not platform:
                raise RegistryError(
                    "manifest index child has no config-blob platform — refusing"
                )
            return ResolvedImage(
                family=family,
                tag=tag,
                digest=child_digest,
                platform=platform,
                size=int(child_content.get("size") or content.get("size") or 0),
            )

        # Single manifest (not an index).
        digest = _checked_digest(resp, manifest_body)
        if not digest:
            raise RegistryError(
                "registry did not return a valid Docker-Content-Digest"
            )
        if _digest_of(manifest_body) != digest:
            raise RegistryError(
                "registry manifest body does not match its digest"
            )
        platform = await self._platform_from_manifest(
            content, scheme, host, path, headers
        )
        if not platform:
            # No config blob platform: fail closed, never trust the manifest's
            # self-reported os/architecture.
            raise RegistryError(
                "registry manifest has no verifiable config platform — refusing"
            )
        return ResolvedImage(
            family=family,
            tag=tag,
            digest=digest,
            platform=platform,
            size=len(manifest_body),
        )

    async def verify_digest(
        self,
        ref: str,
        allowed_prefixes: list[str],
    ) -> ResolvedImage:
        """Verify an already-immutable ``repo@sha256:<64hex>`` reference by
        fetching ``/v2/<repo>/manifests/<digest>`` and proving:
        1. the reference format is valid,
        2. the manifest body sha256 equals the requested digest,
        3. a ``Docker-Content-Digest`` header (if present) equals it,
        4. the config blob digest/body are consistent,
        5. the concrete platform is verifiable,
        6. the repository is in the expected trusted family.

        An immutable repo@sha256 reference is required because a mutable tag
        cannot prove an exact artifact identity. Returns the verified
        immutable ResolvedImage (digest == requested)."""
        if not isinstance(ref, str) or "@" not in ref:
            raise RegistryError(
                f"immutable reference {ref!r} must use repo@sha256:<digest>"
            )
        family, _, digest = ref.rpartition("@")
        if not digest or not DIGEST_RE.fullmatch(digest):
            raise RegistryError(
                f"immutable reference {ref!r} has an invalid digest"
            )
        if not any(
            family == p or family.startswith(p + "/")
            for p in allowed_prefixes
        ):
            raise RegistryError(
                f"image family {family!r} not in allowlist "
                f"{sorted(allowed_prefixes)}"
            )
        headers = self._auth_headers(family)
        headers["Accept"] = _manifest_accept_header()
        scheme, host, path = self._endpoint(family)
        manifest_url = f"{scheme}://{host}/v2/{path}/manifests/{digest}"
        resp = await stream_request(
            self.http, "GET", manifest_url, self.config.max_response_bytes,
            headers=headers, timeout=self.config.total_timeout)
        resp = await enforce_body_size(resp, self.config.max_response_bytes)
        if resp.status_code == 401:
            bearer = await self._bearer(resp, scheme, host, family)
            if bearer:
                headers = {
                    "Accept": _manifest_accept_header(),
                    "Authorization": f"Bearer {bearer}",
                }
                resp = await stream_request(
                    self.http, "GET", manifest_url,
                    self.config.max_response_bytes,
                    headers=headers, timeout=self.config.total_timeout)
                resp = await enforce_body_size(
                    resp, self.config.max_response_bytes
                )
        try:
            require_2xx(resp.status_code, f"registry {_safe_display(manifest_url)}")
        except SecurityError as e:
            raise RegistryError(str(e)) from e
        manifest_body = await self._read_body_once(resp)
        if _digest_of(manifest_body) != digest:
            raise RegistryError(
                "registry manifest body does not match the requested digest"
            )
        header_digest = (
            resp.headers.get("Docker-Content-Digest")
            or resp.headers.get("docker-content-digest")
        )
        if header_digest and (
            not DIGEST_RE.fullmatch(header_digest)
            or header_digest != digest
        ):
            raise RegistryError(
                "registry Docker-Content-Digest does not match the requested "
                "digest"
            )
        content = _json_loads({}, manifest_body)
        if _is_manifest_index(content):
            # A digest must identify ONE immutable artifact. An index digest
            # does not prove which platform manifest was actually selected, so
            # it is refused here.
            raise RegistryError(
                "immutable reference digest is a manifest index — cannot prove "
                "the exact platform artifact"
            )
        platform = await self._platform_from_manifest(
            content, scheme, host, path, headers
        )
        if not platform:
            raise RegistryError(
                "immutable manifest has no verifiable config platform"
            )
        return ResolvedImage(
            family=family,
            tag="",
            digest=digest,
            platform=platform,
            size=len(manifest_body),
        )

    async def _read_body_once(self, resp: httpx.Response) -> bytes:
        """Read a response body that was already size-capped by
        ``enforce_body_size``. ``aread()`` returns the buffered content for a
        response that was fully read (mock or closed), or finishes streaming a
        live response."""
        body = await resp.aread()
        if len(body) > self.config.max_response_bytes:
            raise RegistryError("response body exceeds limit")
        return body

    async def _platform_from_manifest(
        self,
        content: dict,
        scheme: str,
        host: str,
        path: str,
        headers: dict,
    ) -> str:
        """Resolve the concrete platform for an image manifest from its config
        blob (the authoritative os/architecture/variant), never guessed from the
        manifest descriptor. Returns an empty string when there is no config blob
        to read (e.g. an image without config, which must be refused by the
        caller)."""
        config = content.get("config")
        if not isinstance(config, dict):
            return ""
        cfg_digest = config.get("digest", "")
        if not cfg_digest or not DIGEST_RE.fullmatch(cfg_digest):
            return ""
        cfg_url = f"{scheme}://{host}/v2/{path}/blobs/{cfg_digest}"
        cfg_resp = await stream_request(
            self.http, "GET", cfg_url, self.config.max_response_bytes,
            headers=headers, timeout=self.config.total_timeout)
        cfg_resp = await enforce_body_size(cfg_resp, self.config.max_response_bytes)
        try:
            require_2xx(cfg_resp.status_code, "registry config blob")
        except SecurityError as e:
            raise RegistryError(str(e)) from e
        cfg_body = await _read_checked(cfg_resp, self.config.max_response_bytes)
        if _digest_of(cfg_body) != cfg_digest:
            raise RegistryError(
                "registry config blob body does not match its digest"
            )
        try:
            cfg = cfg_resp.json()
        except ValueError:
            raise RegistryError("registry config blob was not JSON")
        if not isinstance(cfg, dict):
            raise RegistryError("registry config blob was not a JSON object")
        os_ = str(cfg.get("os") or "")
        arch = str(cfg.get("architecture") or "")
        if not arch:
            return ""
        variant = str(cfg.get("variant") or "")
        return _join2(os_, arch, variant)

    # ── auth ─────────────────────────────────────────────────────────────

    def _endpoint(self, family: str) -> tuple[str, str, str]:
        parts = family.split("/", 1)
        host = parts[0]
        path = parts[1] if len(parts) > 1 else ""
        return "https", host, path

    def _auth_headers(self, family: str) -> dict[str, str]:
        user = os.getenv("REGISTRY_USER", "")
        password = os.getenv("REGISTRY_PASSWORD", "")
        if not user:
            return {}
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        return {"Authorization": f"Basic {token}"}

    async def _bearer(
        self,
        resp: httpx.Response,
        scheme: str,
        host: str,
        family: str,
    ) -> str:
        challenge = resp.headers.get("Www-Authenticate") or resp.headers.get(
            "WWW-Authenticate"
        )
        if not challenge or "Bearer" not in challenge:
            return ""
        params = _parse_challenge(challenge)
        realm = params.get("realm", "")
        if not _verify_bearer_realm(realm):
            raise RegistryError("registry Bearer realm is not a verified HTTPS URL")
        realm_host = up.urlparse(realm).hostname or ""
        # The realm host must always be the manifest registry host or an
        # explicitly allowlisted host — including for the anonymous Bearer flow.
        # This prevents a malicious registry challenge from steering the agent
        # into contacting an arbitrary host (SSRF) even when no credentials are
        # sent.
        if not _realm_host_allowed(
            realm_host, host, self.config.registry_auth_host_allowlist
        ):
            raise RegistryError(
                f"registry Bearer realm host {realm_host!r} is not the "
                "registry host or in REGISTRY_AUTH_HOST_ALLOWLIST"
            )
        user = os.getenv("REGISTRY_USER", "")
        password = os.getenv("REGISTRY_PASSWORD", "")
        headers = {}
        if user:
            auth = base64.b64encode(f"{user}:{password}".encode()).decode()
            headers["Authorization"] = f"Basic {auth}"
        url = (
            f"{realm}?service={up.quote(params.get('service',''), safe='')}"
            f"&scope={up.quote(params.get('scope',''), safe='')}"
        )
        tok_resp = await stream_request(
            self.http, "GET", url, self.config.max_response_bytes,
            headers=headers, timeout=self.config.total_timeout)
        tok_resp = await enforce_body_size(tok_resp, self.config.max_response_bytes)
        try:
            require_2xx(tok_resp.status_code, "registry Bearer token fetch")
        except SecurityError as e:
            raise RegistryError(str(e)) from e
        try:
            data = tok_resp.json()
        except ValueError:
            raise RegistryError("registry Bearer token response was not JSON")
        if not isinstance(data, dict):
            raise RegistryError("registry Bearer token response was not a JSON object")
        token = str(data.get("token") or data.get("access_token") or "")
        if not token:
            raise RegistryError("registry Bearer token response had no token")
        return token


def _parse_challenge(header: str) -> dict[str, str]:
    idx = header.find(" ")
    if idx < 0:
        return {}
    rest = header[idx + 1 :]
    out: dict[str, str] = {}
    for part in _split_challenge(rest):
        if "=" not in part:
            continue
        k, _, v = part.partition("=")
        out[k.strip().lower()] = v.strip().strip('"')
    return out


def _verify_bearer_realm(realm: str) -> bool:
    """A registry Bearer realm must be an HTTPS URL with no credentials, no
    fragment, and no unexpected scheme. Anything else is refused (no Basic/Bearer
    credentials are ever sent to an unverified endpoint)."""
    if not realm:
        return False
    try:
        parsed = up.urlparse(realm)
    except ValueError:
        return False
    if parsed.scheme != "https":
        return False
    if parsed.username or parsed.password or parsed.fragment:
        return False
    if not parsed.hostname:
        return False
    return True


def _manifest_accept_header() -> str:
    """Accept both single manifests and multi-arch indexes/lists so the
    registry will actually return an index when the tag is multi-arch."""
    return (
        "application/vnd.oci.image.manifest.v1+json, "
        "application/vnd.docker.distribution.manifest.v2+json, "
        "application/vnd.oci.image.index.v1+json, "
        "application/vnd.docker.distribution.manifest.list.v2+json"
    )


def _split_challenge(s: str) -> list[str]:
    parts, buf, quoted = [], [], False
    for ch in s:
        if ch == '"':
            quoted = not quoted
            buf.append(ch)
        elif ch == "," and not quoted:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf).strip())
    return [p for p in parts if p]


def _manifest_platform(content: dict) -> str:
    cfg = content.get("config")
    if isinstance(cfg, dict):
        plat = cfg.get("platform")
        if isinstance(plat, dict):
            return _join2(
                plat.get("os", "linux"),
                plat.get("architecture", ""),
                plat.get("variant", ""),
            )
    os_ = content.get("os", "linux")
    arch = content.get("architecture", "")
    variant = content.get("variant", "")
    return _join2(os_, arch, variant)


_INDEX_MEDIA_TYPES = {
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
}


def _is_manifest_index(content: dict) -> bool:
    media = content.get("mediaType", "")
    if media in _INDEX_MEDIA_TYPES:
        return True
    # Content-type based detection as a fallback for registries that omit the
    # mediaType body field.
    manifests = content.get("manifests")
    return isinstance(manifests, list) and manifest_list(manifests)


def manifest_list(manifests: list) -> bool:
    return bool(manifests) and all(
        isinstance(m, dict) and m.get("digest") for m in manifests
    )


def _select_index_manifest(content: dict, platform: str) -> dict | None:
    """Return the single index entry matching ``platform`` (os/arch[/variant]).

    A platform without a variant is matched by os/arch only, but if more than
    one entry matches (e.g. two variants of the same architecture) the result is
    ambiguous and we fail closed rather than guess. Returns None only when there
    is no matching entry at all or ``platform`` is empty.
    """
    manifests = content.get("manifests") or []
    if not platform:
        return None
    want_os, want_arch, want_variant = _split_platform(platform)
    matches = []
    for m in manifests:
        p = m.get("platform") or {}
        if p.get("os") != want_os or p.get("architecture") != want_arch:
            continue
        variant = p.get("variant", "") or ""
        if want_variant:
            if variant == want_variant:
                matches.append(m)
            continue
        matches.append(m)
    if len(matches) == 1:
        return matches[0]
    if not matches:
        return None
    raise RegistryError(
        f"manifest index has {len(matches)} entries matching platform "
        f"{platform!r}; refusing ambiguous selection"
    )


def _index_platforms(content: dict) -> list[str]:
    out = []
    for m in content.get("manifests") or []:
        p = m.get("platform") or {}
        out.append(
            _join2(
                p.get("os", ""),
                p.get("architecture", ""),
                p.get("variant", ""),
            )
        )
    return out


def _split_platform(platform: str) -> tuple[str, str, str]:
    parts = platform.split("/")
    os_ = parts[0] if parts else ""
    arch = parts[1] if len(parts) > 1 else ""
    variant = parts[2] if len(parts) > 2 else ""
    return os_, arch, variant


def _join2(os_: str, arch: str, variant: str) -> str:
    base = f"{os_}/{arch}" if arch else os_
    return f"{base}/{variant}" if variant else base


def _safe_display(url: str) -> str:
    return up.unquote(url)

def _digest_of(body: bytes) -> str:
    """sha256:<hex>-of the raw body bytes (distribution digest)."""
    return "sha256:" + hashlib.sha256(body).hexdigest()


async def _read_checked(resp: httpx.Response, limit: int) -> bytes:
    """Read the (already size-capped) body, then re-count to be safe."""
    body = await resp.aread()
    if len(body) > limit:
        raise RegistryError(f"response body exceeds limit {limit}")
    return body


def _json_loads(default: dict, body: bytes) -> dict:
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return default
    if not isinstance(parsed, dict):
        # A parseable JSON value that is not an object (list/string/null/...) is
        # a registry protocol violation. Turn it into the fail-closed RegistryError
        # path rather than an AttributeError downstream.
        raise RegistryError(
            f"registry returned non-object JSON ({type(parsed).__name__})"
        )
    return parsed


def _parse_json_bytes(default: dict, body: bytes) -> dict:
    return _json_loads(default, body)


def _checked_digest(resp: httpx.Response, body: bytes) -> str:
    """Return the manifest digest from Docker-Content-Digest, verifying it is a
    valid sha256 reference that matches the actual body bytes."""
    digest = (
        resp.headers.get("Docker-Content-Digest")
        or resp.headers.get("docker-content-digest")
    )
    if not digest or not DIGEST_RE.fullmatch(digest):
        return ""
    return digest


def _checked_manifest_digest(resp, content, body: bytes) -> None:
    """Pre-check the top-level manifest digest: used so we never return a
    manifest whose digest header is inconsistent with its bytes. Raises on a
    missing/invalid/mismatching digest (index or single)."""
    digest = _checked_digest(resp, body)
    if (not content or _is_manifest_index(content)):
        # Indexes are validated per-child; the top-level digest may or may not
        # be present. If present, verify it.
        if digest and _digest_of(body) != digest:
            raise RegistryError(
                "registry manifest body does not match its digest"
            )
        return
    if not digest:
        raise RegistryError(
            "registry did not return a valid Docker-Content-Digest"
        )
    if _digest_of(body) != digest:
        raise RegistryError(
            "registry manifest body does not match its digest"
        )

def _realm_host_allowed(realm_host: str, registry_host: str, allowlist: list[str]) -> bool:
    """True only when the Bearer realm host equals the manifest registry host or
    is in the explicit REGISTRY_AUTH_HOST_ALLOWLIST."""
    if realm_host == registry_host:
        return True
    return realm_host in (allowlist or [])
