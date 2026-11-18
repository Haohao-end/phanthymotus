"""Persistent internal evidence records stored outside GitHub PR comments.

``GitHubStateProxy`` prefers the per-PR Git Notes ref. When the GitHub App
cannot write Git Data (HTTP 403), it appends the same records here instead of
degrading to user-visible PR comments.

Layout (append-only, content addressed, PR scoped):

    phanthymotus_pr/{repo-dir}/evidence-records-v1/pr-{pr}/
        {kind}/{identity_sha256}/head-{head_sha}/round-{round_id}/{sha256}.json

Every record is isolated by repository, PR, record kind, record key, HEAD and
round. The object listing is the index, so no mutable index object can be lost
by a concurrent writer, and one identity can be resolved by prefix. Every
object is created with ``x-cos-forbid-overwrite`` and must read back
byte-for-byte with a matching SHA256; otherwise the caller reports an explicit
persistence error and never reports success. Credentials come only from the
existing Controller COS secrets, and this module never presigns or logs a URL.

No method accepts a browser-supplied key or URL. SDK I/O runs in worker threads.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re

try:
    from qcloud_cos import cos_comm
    cos_comm.maplist.setdefault("ForbidOverwrite", "x-cos-forbid-overwrite")
except Exception:
    pass

_KINDS = frozenset({"round", "operation", "attachment"})
_RECORD_ROOT = "evidence-records-v1"
_RECORD_VERSION = 1
_MAX_RECORD_BYTES = 8 * 1024 * 1024
_MAX_RECORDS_PER_PR = 4096
_MAX_LIST_PAGES = 64

# Retry-only timestamps are not part of an immutable record's business fields.
_VOLATILE_FIELDS = frozenset({
    "created_at", "updated_at", "completed_at", "deleted_at",
    "invalidated_at", "archived_at", "ended_at",
})

# Tencent COS reports a bucket that never enabled versioning as an empty
# <VersioningConfiguration/>, which the SDK decodes to an explicit None value
# or an empty dict. Only these values prove versioning has never been enabled.
_VERSIONING_ENABLED_STATUSES = frozenset({"enabled", "suspended"})
_VERSIONING_DISABLED_STATUSES = frozenset({"off", "disabled", "none", "not-enabled"})


class EvidenceRecordBackendError(Exception):
    """A record could not be persisted or verified with the required guarantees."""


# Sentinel distinguishing "field absent" from a legitimate ``None`` value.
_ABSENT = object()


def canonical_evidence_data(data: dict) -> bytes:
    """Return the one canonical byte form used for digests and identity paths."""
    return json.dumps(data, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def same_evidence_record(kind: str, left: dict, right: dict) -> bool:
    """Compare immutable business fields, ignoring retry-only timestamps."""
    return ({key: value for key, value in left.items() if key not in _VOLATILE_FIELDS}
            == {key: value for key, value in right.items() if key not in _VOLATILE_FIELDS})


def _unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON key")
        result[name] = value
    return result


def _repo_directory(repo: str) -> str:
    from .cos_client import _repo_directory as directory
    return directory(repo)


class CosEvidenceRecordBackend:
    """Content-addressed internal record store in the configured COS bucket."""

    def __init__(self, config, client=None):
        self.config = config
        self._client = client
        self._slots = asyncio.Semaphore(2)
        self._versioning_verified = False

    def configured(self) -> bool:
        return all(
            isinstance(getattr(self.config, name, ""), str)
            and bool(getattr(self.config, name, "").strip())
            for name in ("cos_region", "cos_bucket", "cos_secret_id", "cos_secret_key")
        )

    def _sdk(self):
        if self._client is None:
            from qcloud_cos import CosConfig, CosS3Client, cos_comm
            import requests

            try:
                cos_comm.maplist.setdefault("ForbidOverwrite", "x-cos-forbid-overwrite")
                test_map = cos_comm.mapped({"ForbidOverwrite": "true"})
                if test_map.get("x-cos-forbid-overwrite") != "true":
                    raise EvidenceRecordBackendError(
                        "qcloud_cos SDK mapped() did not map ForbidOverwrite to x-cos-forbid-overwrite: true"
                    )
            except Exception as exc:
                raise EvidenceRecordBackendError(
                    f"qcloud_cos SDK does not support ForbidOverwrite parameter: {exc}"
                ) from exc

            class RecordSession(requests.Session):
                def request(self, method, url, **kwargs):
                    kwargs["timeout"] = (10, 30)
                    kwargs["verify"] = True
                    headers = kwargs.get("headers") or {}
                    if method.upper() == "PUT":
                        if headers.get("x-cos-forbid-overwrite") != "true":
                            raise EvidenceRecordBackendError(
                                "x-cos-forbid-overwrite: true header missing from PUT request"
                            )
                    return super().request(method, url, **kwargs)

            session = RecordSession()
            session.trust_env = False
            self._client = CosS3Client(CosConfig(
                Region=self.config.cos_region,
                SecretId=self.config.cos_secret_id,
                SecretKey=self.config.cos_secret_key,
                Scheme="https", Timeout=30, VerifySSL=True,
            ), retry=0, session=session)
        return self._client

    # ── identity ──

    @staticmethod
    def _identity_inputs(repo, pr_number):
        if not isinstance(repo, str) or "/" not in repo:
            raise EvidenceRecordBackendError("invalid evidence record repository")
        try:
            from .config import validate_repository_names
            canonical = validate_repository_names([repo])[0]
        except ValueError:
            raise EvidenceRecordBackendError("invalid evidence record repository") from None
        if canonical != repo:
            raise EvidenceRecordBackendError("evidence record repository is not canonical")
        if isinstance(pr_number, bool) or not isinstance(pr_number, int) or pr_number <= 0:
            raise EvidenceRecordBackendError("invalid evidence record PR identity")
        return repo, pr_number

    @staticmethod
    def _validate_kind_key(kind, key):
        if kind not in _KINDS:
            raise EvidenceRecordBackendError("invalid evidence record kind")
        if not isinstance(key, str) or not key or len(key) > 512:
            raise EvidenceRecordBackendError("invalid evidence record key")

    def _prefix(self, repo: str, pr_number: int) -> str:
        return f"phanthymotus_pr/{_repo_directory(repo)}/{_RECORD_ROOT}/pr-{pr_number}/"

    @staticmethod
    def _identity_digest(repo, pr_number, kind, key) -> str:
        raw = json.dumps(
            ["deploy-approval-evidence-record-v1", repo, pr_number, kind, key],
            ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def _identity_prefix(self, repo, pr_number, kind, key) -> str:
        return (f"{self._prefix(repo, pr_number)}{kind}/"
                f"{self._identity_digest(repo, pr_number, kind, key)}/")

    def _object_key(self, repo, pr_number, kind, key, head_sha, round_id, digest) -> str:
        # repo / pr / kind / record-key / HEAD / round / content are all fixed
        # path segments, so one PR or round can never read another's data.
        return (f"{self._identity_prefix(repo, pr_number, kind, key)}"
                f"head-{head_sha}/round-{round_id}/{digest}.json")

    # ── encoding ──

    @staticmethod
    def _validate_data(repo, pr_number, data) -> tuple[str, str, bytes, str]:
        if not isinstance(data, dict) or data.get("repo") != repo:
            raise EvidenceRecordBackendError("evidence record identity is invalid")
        if type(data.get("pr_number")) is not int or data.get("pr_number") != pr_number:
            raise EvidenceRecordBackendError("evidence record identity is invalid")
        head_sha, round_id = data.get("head_sha"), data.get("round_id")
        if (not isinstance(head_sha, str) or re.fullmatch(r"[0-9a-f]{40}", head_sha) is None
                or not isinstance(round_id, str)
                or re.fullmatch(re.escape(head_sha) + r"-[0-9]+", round_id) is None):
            raise EvidenceRecordBackendError("evidence record HEAD/round identity is invalid")
        try:
            raw = canonical_evidence_data(data)
        except (TypeError, ValueError, UnicodeEncodeError):
            raise EvidenceRecordBackendError("evidence record structure is invalid") from None
        if not 0 < len(raw) <= _MAX_RECORD_BYTES:
            raise EvidenceRecordBackendError("evidence record exceeds safe capacity")
        return head_sha, round_id, raw, hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _encode(repo, pr_number, kind, key, head_sha, round_id, digest, data) -> bytes:
        payload = {"version": _RECORD_VERSION, "repo": repo, "pr_number": pr_number,
                   "kind": kind, "key": key, "head_sha": head_sha,
                   "round_id": round_id, "sha256": digest, "data": data}
        try:
            return canonical_evidence_data(payload)
        except (TypeError, ValueError, UnicodeEncodeError):
            raise EvidenceRecordBackendError("evidence record envelope is invalid") from None

    def _decode(self, object_key, raw, repo, pr_number) -> dict:
        match = re.fullmatch(
            re.escape(self._prefix(repo, pr_number))
            + r"(round|operation|attachment)/([0-9a-f]{64})/"
              r"head-([0-9a-f]{40})/(round-[0-9a-f]{40}-[0-9]+)/([0-9a-f]{64})\.json",
            object_key if isinstance(object_key, str) else "",
        )
        if match is None:
            raise EvidenceRecordBackendError("evidence record layout is invalid")
        kind_segment, identity_digest, head_segment, round_segment, content_digest = \
            match.groups()
        if not isinstance(raw, bytes) or not 0 < len(raw) <= _MAX_RECORD_BYTES:
            raise EvidenceRecordBackendError("evidence record object is invalid")
        try:
            payload = json.loads(raw, object_pairs_hook=_unique_object)
        except (ValueError, UnicodeDecodeError):
            raise EvidenceRecordBackendError("evidence record JSON is invalid") from None
        required = {"version", "repo", "pr_number", "kind", "key", "head_sha",
                    "round_id", "sha256", "data"}
        if (not isinstance(payload, dict) or set(payload) != required
                or type(payload.get("version")) is not int
                or payload.get("version") != _RECORD_VERSION
                or payload.get("repo") != repo
                or type(payload.get("pr_number")) is not int
                or payload.get("pr_number") != pr_number):
            raise EvidenceRecordBackendError("evidence record identity is invalid")
        kind, key = payload.get("kind"), payload.get("key")
        self._validate_kind_key(kind, key)
        if kind != kind_segment:
            raise EvidenceRecordBackendError("evidence record kind does not match its path")
        head_sha, round_id, _data_raw, digest = self._validate_data(
            repo, pr_number, payload.get("data"))
        if (payload.get("head_sha") != head_sha or payload.get("round_id") != round_id
                or head_sha != head_segment or round_segment != f"round-{round_id}"):
            raise EvidenceRecordBackendError("evidence record envelope binding is invalid")
        if (payload.get("sha256") != digest or digest != content_digest
                or self._identity_digest(repo, pr_number, kind, key) != identity_digest):
            raise EvidenceRecordBackendError("evidence record digest or identity mismatch")
        if self._encode(repo, pr_number, kind, key, head_sha, round_id,
                        digest, payload["data"]) != raw:
            raise EvidenceRecordBackendError("evidence record is not canonically encoded")
        return {"kind": kind, "key": key, "data": payload["data"], "sha256": digest}

    # ── COS I/O ──

    async def _io(self, function, **kwargs):
        async with self._slots:
            return await asyncio.to_thread(function, **kwargs)

    def _list_all(self, prefix):
        client = self._sdk()
        keys, marker = [], ""
        for _ in range(_MAX_LIST_PAGES):
            try:
                response = client.list_objects(
                    Bucket=self.config.cos_bucket, Prefix=prefix,
                    Marker=marker, MaxKeys=1000,
                )
            except Exception:
                raise EvidenceRecordBackendError(
                    "evidence record listing is unavailable") from None
            if not isinstance(response, dict):
                raise EvidenceRecordBackendError("evidence record listing is malformed")
            contents = response.get("Contents", [])
            if isinstance(contents, dict):
                contents = [contents]
            if not isinstance(contents, list):
                raise EvidenceRecordBackendError("evidence record listing is malformed")
            for item in contents:
                name = item.get("Key") if isinstance(item, dict) else None
                if (not isinstance(name, str) or not name.startswith(prefix)
                        or "\\" in name or any(ord(c) < 32 for c in name)):
                    raise EvidenceRecordBackendError("evidence record listing is malformed")
                keys.append(name)
                if len(keys) > _MAX_RECORDS_PER_PR:
                    raise EvidenceRecordBackendError(
                        "evidence record count exceeds safe capacity")
            if str(response.get("IsTruncated", "false")).lower() != "true":
                return keys
            next_marker = response.get("NextMarker")
            if (not isinstance(next_marker, str) or not next_marker
                    or next_marker == marker):
                raise EvidenceRecordBackendError(
                    "evidence record listing pagination is malformed")
            marker = next_marker
        raise EvidenceRecordBackendError("evidence record listing exceeded its bound")

    def _get_object(self, object_key):
        try:
            response = self._sdk().get_object(
                Bucket=self.config.cos_bucket, Key=object_key)
            stream = response["Body"].get_raw_stream()
        except Exception:
            raise EvidenceRecordBackendError("evidence record object is unavailable") from None
        chunks, total = [], 0
        try:
            while True:
                block = stream.read(256 * 1024)
                if not block:
                    break
                total += len(block)
                if total > _MAX_RECORD_BYTES:
                    raise EvidenceRecordBackendError("evidence record object exceeds its bound")
                chunks.append(block)
        finally:
            stream.close()
        return b"".join(chunks)

    @staticmethod
    def _versioning_field(fields: dict, name: str):
        """Resolve one versioning field, stripping an XML namespace prefix.

        ``qcloud_cos`` 1.9.44 decodes the XML with ``xml_to_dict``, which only
        strips a fixed set of namespace URIs. The COS versioning namespace is
        not among them, so the same field can arrive either bare or wrapped as
        ``{<ns>}VersioningConfiguration``. Both spellings mean one field; two
        different spellings with conflicting values are ambiguous and fail
        closed.
        """
        values = [value for key, value in fields.items()
                  if isinstance(key, str)
                  and (key == name or key.rsplit("}", 1)[-1] == name)]
        if not values:
            return _ABSENT
        if any(value != values[0] for value in values[1:]):
            raise EvidenceRecordBackendError(
                "bucket versioning response contains conflicting fields")
        return values[0]

    def _verify_bucket_versioning(self):
        if getattr(self, "_versioning_verified", False):
            return
        client = self._sdk()
        versioning_reader = getattr(client, "get_bucket_versioning", None)
        if not callable(versioning_reader):
            raise EvidenceRecordBackendError(
                "qcloud_cos SDK does not support bucket versioning checks")
        try:
            resp = versioning_reader(Bucket=self.config.cos_bucket)
        except Exception as exc:
            raise EvidenceRecordBackendError(
                f"bucket versioning check failed: {type(exc).__name__}") from exc
        if not isinstance(resp, dict) or not resp:
            raise EvidenceRecordBackendError(
                "bucket versioning check returned no configuration")

        # cos-python-sdk-v5 1.9.44 renders a bucket that never enabled
        # versioning as an explicit ``VersioningConfiguration: None`` (or an
        # empty dict) because COS answers GET ?versioning with an empty
        # <VersioningConfiguration/> element. A populated element is hoisted
        # by the SDK to a flat top-level ``Status`` field. Versioning must be
        # provably off: once enabled (or suspended) COS ignores the
        # x-cos-forbid-overwrite header.
        configuration = self._versioning_field(resp, "VersioningConfiguration")
        if configuration is not _ABSENT and not isinstance(
                configuration, (dict, type(None))):
            raise EvidenceRecordBackendError(
                "bucket versioning configuration is malformed")

        status = self._versioning_field(resp, "Status")
        nested_status = (self._versioning_field(configuration, "Status")
                         if isinstance(configuration, dict) else _ABSENT)
        if status is _ABSENT:
            status = nested_status
        elif nested_status is not _ABSENT and nested_status != status:
            raise EvidenceRecordBackendError(
                "bucket versioning response contains conflicting status fields")

        # An explicit status is authoritative: Enabled or Suspended defeats
        # forbid-overwrite, and any unrecognized value is not proof of "off".
        if status is not _ABSENT and status is not None:
            if not isinstance(status, str) or not status.strip():
                raise EvidenceRecordBackendError(
                    "bucket versioning check did not confirm an explicit disabled status")
            normalized_status = status.strip().lower()
            if normalized_status in _VERSIONING_ENABLED_STATUSES:
                raise EvidenceRecordBackendError(
                    f"bucket versioning is {status}; forbid-overwrite semantics require versioning to be off"
                )
            if normalized_status not in _VERSIONING_DISABLED_STATUSES:
                raise EvidenceRecordBackendError(
                    f"bucket versioning status {status!r} is not a confirmed disabled status")
            # The status must belong to a present configuration; a bare status
            # with no VersioningConfiguration is not a trustworthy response.
            if configuration is _ABSENT:
                raise EvidenceRecordBackendError(
                    "bucket versioning response omitted VersioningConfiguration")
            self._versioning_verified = True
            return

        # No usable status. An absent field proves nothing and fails closed;
        # only a present-but-empty configuration is positive proof that
        # versioning was never enabled.
        if configuration is _ABSENT:
            raise EvidenceRecordBackendError(
                "bucket versioning response omitted VersioningConfiguration")
        if configuration is None or not configuration:
            self._versioning_verified = True
            return
        raise EvidenceRecordBackendError(
            "bucket versioning check did not confirm an explicit disabled status")

    def _put_object(self, object_key, body):
        # The ForbidOverwrite parameter maps to x-cos-forbid-overwrite: true
        # preventing accidental replacement. Bucket versioning must be off to
        # preserve forbid-overwrite semantics.
        self._verify_bucket_versioning()
        self._sdk().put_object(
            Bucket=self.config.cos_bucket, Key=object_key, Body=body,
            ContentType="application/json",
            ForbidOverwrite="true",
        )

    async def _read_object(self, object_key, repo, pr_number) -> dict:
        raw = await self._io(self._get_object, object_key=object_key)
        return self._decode(object_key, raw, repo, pr_number)

    async def _read_identity(self, repo, pr_number, kind, key) -> list[dict]:
        keys = await self._io(
            self._list_all, prefix=self._identity_prefix(repo, pr_number, kind, key))
        return [await self._read_object(object_key, repo, pr_number)
                for object_key in sorted(keys)]

    # ── public contract ──

    async def append(self, *, repo, pr_number, kind, key, data) -> dict:
        """Persist one immutable record, or return the identical stored one.

        A retry with only retry-timestamp differences resolves to the existing
        record. Any other content for the same identity fails closed; nothing is
        overwritten and nothing is reported as stored without a verified readback.
        """
        repo, pr_number = self._identity_inputs(repo, pr_number)
        self._validate_kind_key(kind, key)
        head_sha, round_id, _raw, digest = self._validate_data(repo, pr_number, data)

        existing = await self._read_identity(repo, pr_number, kind, key)
        matched = None
        for record in existing:
            if not same_evidence_record(kind, record["data"], data):
                raise EvidenceRecordBackendError("conflicting immutable evidence record")
            matched = matched or record
        if matched is not None:
            return matched

        body = self._encode(repo, pr_number, kind, key, head_sha, round_id, digest, data)
        object_key = self._object_key(
            repo, pr_number, kind, key, head_sha, round_id, digest)
        put_error = None
        try:
            await self._io(self._put_object, object_key=object_key, body=body)
        except Exception as exc:
            # Network write result uncertain -> read back first, never blindly overwrite
            put_error = exc
        try:
            record = await self._read_object(object_key, repo, pr_number)
        except EvidenceRecordBackendError:
            if put_error is not None:
                raise EvidenceRecordBackendError(
                    f"evidence record write could not be verified: {put_error}") from put_error
            raise EvidenceRecordBackendError(
                "evidence record write could not be verified") from None
        if record.get("sha256") != digest:
            raise EvidenceRecordBackendError("evidence record readback digest mismatch")

        # Double check identity to prevent concurrent conflicting writes
        all_for_identity = await self._read_identity(repo, pr_number, kind, key)
        for other in all_for_identity:
            if not same_evidence_record(kind, other["data"], data):
                raise EvidenceRecordBackendError("conflicting immutable evidence record")
        return record

    async def read(self, repo, pr_number) -> list[dict]:
        """Discover every stored record for one PR through its directory index."""
        repo, pr_number = self._identity_inputs(repo, pr_number)
        keys = await self._io(self._list_all, prefix=self._prefix(repo, pr_number))
        return [await self._read_object(object_key, repo, pr_number)
                for object_key in sorted(keys)]
