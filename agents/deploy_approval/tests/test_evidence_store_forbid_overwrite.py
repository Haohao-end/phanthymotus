"""Tests for COS forbid-overwrite header injection, signing, and fail-closed protections."""
from __future__ import annotations

import asyncio
import hashlib
import io
import re
from urllib.parse import parse_qsl, urlsplit

import pytest
import requests
from qcloud_cos.cos_exception import CosClientError

from ..config import Config
from ..evidence_store import (
    CosAttachmentStore,
    EvidenceOverwriteProtectionError,
    EvidenceStoreError,
    build_attachment_key,
)


def _make_config(**kwargs):
    defaults = {
        "cos_region": "ap-beijing",
        "cos_bucket": "test-bucket-1250000000",
        "cos_secret_id": "test-secret-id",
        "cos_secret_key": "test-secret-key-secret-key-secret",
        "evidence_max_file_bytes": 10 * 1024 * 1024,
        "evidence_part_bytes": 1024 * 1024,
        "evidence_max_note_bytes": 64 * 1024,
    }
    defaults.update(kwargs)
    return Config(**defaults)


def _valid_metadata():
    return {
        "repo": "4paradigm/phanthymotus",
        "pr_number": 42,
        "head_sha": "a" * 40,
        "round_id": "a" * 40 + "-1",
        "attachment_id": "att123",
        "created_at": "2026-11-20T12:00:00+08:00",
        "filename": "evidence.log",
    }


def _valid_key(metadata=None):
    m = metadata or _valid_metadata()
    return build_attachment_key(
        m["repo"],
        m["pr_number"],
        m["head_sha"],
        m["round_id"],
        m["attachment_id"],
        m["created_at"],
        m["filename"],
    )


class MockCosResponse(requests.Response):
    """Synthetic response generator for requests.Session interception."""

    def __init__(self, status_code=200, headers=None, content=b""):
        super().__init__()
        self.status_code = status_code
        self.headers = requests.structures.CaseInsensitiveDict(headers or {})
        self._content = content
        self.raw = io.BytesIO(content)


class StubCosTransport(requests.adapters.BaseAdapter):
    """Offline transport stand-in: records PreparedRequests, opens no socket."""

    def __init__(self, headers=None):
        super().__init__()
        self._headers = headers or {}
        self.requests = []

    def send(self, request, **kwargs):
        self.requests.append(request)
        response = MockCosResponse(200, headers=self._headers)
        response.request = request
        response.url = request.url
        return response

    def close(self):
        pass


def _signed_headers(request):
    """Return the lower-cased q-header-list COS signed for this request."""
    auth = request.headers.get("Authorization", "")
    if isinstance(auth, (bytes, bytearray)):
        auth = auth.decode("utf-8", errors="replace")
    params = dict(
        part.split("=", 1) for part in auth.split("&") if "=" in part
    )
    return {
        item.strip().lower()
        for item in params.get("q-header-list", "").split(";")
        if item.strip()
    }


def test_put_native_file_prepared_request_has_forbid_overwrite_header():
    """SDK-generated PreparedRequest for PUT contains x-cos-forbid-overwrite: true."""
    async def run():
        config = _make_config()
        store = CosAttachmentStore(config)

        captured_requests = []
        payload = b"audit-evidence-bytes"
        payload_sha256 = hashlib.sha256(payload).hexdigest()
        metadata = _valid_metadata()
        key = _valid_key(metadata)

        expected_head_headers = {
            "Content-Length": str(len(payload)),
            "x-cos-meta-repo": metadata["repo"],
            "x-cos-meta-pr-number": str(metadata["pr_number"]),
            "x-cos-meta-head-sha": metadata["head_sha"],
            "x-cos-meta-round-id": metadata["round_id"],
            "x-cos-meta-attachment-id": metadata["attachment_id"],
            "ETag": '"test-etag"',
        }

        class InterceptingSession(store._sdk()._session.__class__):
            def send(self, request, **kwargs):
                captured_requests.append(request)
                if request.method == "HEAD":
                    if len(captured_requests) == 1:
                        return MockCosResponse(404)
                    return MockCosResponse(200, headers=expected_head_headers)
                if request.method == "PUT":
                    return MockCosResponse(200, headers={"ETag": '"test-etag"'})
                if request.method == "GET":
                    return MockCosResponse(200, headers=expected_head_headers, content=payload)
                raise AssertionError(f"unexpected {request.method} {request.url}")

        session = InterceptingSession()
        session._evidence_forbid_overwrite_guard = True
        session.trust_env = False
        store._sdk()._session = session

        result = await store.put_native_file(
            key=key,
            metadata=metadata,
            size=len(payload),
            sha256=payload_sha256,
            body=io.BytesIO(payload),
        )

        assert result["verified"] is True
        assert result["sha256"] == payload_sha256

        put_requests = [r for r in captured_requests if r.method == "PUT"]
        assert len(put_requests) == 1
        put_req = put_requests[0]

        header_val = put_req.headers.get("x-cos-forbid-overwrite")
        if isinstance(header_val, bytes):
            header_val = header_val.decode("utf-8")
        assert header_val == "true"
        # The header must be part of the signed header list, not bolted on later.
        assert "x-cos-forbid-overwrite" in _signed_headers(put_req)

    asyncio.run(run())


def test_header_must_enter_before_signature_late_injection_rejected():
    """Header must be signed before request is sent; late injection in send() fails closed."""
    async def run():
        config = _make_config()
        store = CosAttachmentStore(config)
        client = store._sdk()

        class CheatingLateInjectionSession(client._session.__class__):
            def send(self, request, **kwargs):
                if CosAttachmentStore._requires_forbid_overwrite(request.method, request.url):
                    request.headers["x-cos-forbid-overwrite"] = "true"
                return super().send(request, **kwargs)

        cheating_session = CheatingLateInjectionSession()
        cheating_session._evidence_forbid_overwrite_guard = True
        cheating_session.trust_env = False
        transport = StubCosTransport()
        cheating_session.mount("https://", transport)
        cheating_session.mount("http://", transport)
        client._session = cheating_session

        with pytest.raises((EvidenceOverwriteProtectionError, CosClientError)) as exc_info:
            client.put_object(
                Bucket=config.cos_bucket,
                Key="test-key",
                Body=b"data",
            )
        err = exc_info.value
        cause = getattr(err, "__context__", None) or err
        assert "not included in request signature" in str(cause)

    asyncio.run(run())


def test_put_object_missing_header_fails_closed():
    """PUT request omitting x-cos-forbid-overwrite: true fails closed."""
    async def run():
        config = _make_config()
        store = CosAttachmentStore(config)
        client = store._sdk()

        class InterceptingSession(client._session.__class__):
            def send(self, request, **kwargs):
                return super().send(request, **kwargs)

        session = InterceptingSession()
        session._evidence_forbid_overwrite_guard = True
        session.trust_env = False
        transport = StubCosTransport()
        session.mount("https://", transport)
        session.mount("http://", transport)
        client._session = session

        with pytest.raises((EvidenceOverwriteProtectionError, CosClientError)) as exc_info:
            client.put_object(
                Bucket=config.cos_bucket,
                Key="test-key",
                Body=b"data",
            )
        err = exc_info.value
        cause = getattr(err, "__context__", None) or err
        assert "omitted x-cos-forbid-overwrite: true" in str(cause)

    asyncio.run(run())


def test_complete_multipart_upload_carries_header_and_is_signed():
    """complete_multipart_upload must send signed x-cos-forbid-overwrite: true."""
    async def run():
        config = _make_config()
        store = CosAttachmentStore(config)

        captured_requests = []
        payload = b"chunk1-content-and-chunk2-content"
        payload_sha256 = hashlib.sha256(payload).hexdigest()
        metadata = _valid_metadata()
        key = _valid_key(metadata)

        expected_head_headers = {
            "Content-Length": str(len(payload)),
            "x-cos-meta-repo": metadata["repo"],
            "x-cos-meta-pr-number": str(metadata["pr_number"]),
            "x-cos-meta-head-sha": metadata["head_sha"],
            "x-cos-meta-round-id": metadata["round_id"],
            "x-cos-meta-attachment-id": metadata["attachment_id"],
            "ETag": '"final-etag"',
        }

        complete_xml = (
            b"<CompleteMultipartUploadResult>"
            b"<Location>test-bucket-1250000000.cos.ap-beijing.myqcloud.com/key</Location>"
            b"<Bucket>test-bucket-1250000000</Bucket>"
            b"<Key>key</Key>"
            b'<ETag>"final-etag"</ETag>'
            b"</CompleteMultipartUploadResult>"
        )

        list_parts_xml = (
            b"<ListPartsResult>"
            b"<Bucket>test-bucket-1250000000</Bucket>"
            b"<Key>key</Key>"
            b"<UploadId>test-upload-id</UploadId>"
            b"<Part><PartNumber>1</PartNumber><ETag>\"part1-etag\"</ETag><Size>"
            + str(len(payload)).encode("ascii")
            + b"</Size></Part>"
            b"<IsTruncated>false</IsTruncated>"
            b"</ListPartsResult>"
        )

        class InterceptingSession(store._sdk()._session.__class__):
            def send(self, request, **kwargs):
                captured_requests.append(request)
                if request.method == "HEAD":
                    if len([r for r in captured_requests if r.method == "POST"]) == 0:
                        return MockCosResponse(404)
                    return MockCosResponse(200, headers=expected_head_headers)
                if request.method == "GET":
                    if "uploadId=" in request.url:
                        return MockCosResponse(200, content=list_parts_xml)
                    return MockCosResponse(200, headers=expected_head_headers, content=payload)
                if request.method == "POST":
                    return MockCosResponse(
                        200, headers={"ETag": '"final-etag"'}, content=complete_xml,
                    )
                raise AssertionError(f"unexpected {request.method} {request.url}")

        session = InterceptingSession()
        session._evidence_forbid_overwrite_guard = True
        session.trust_env = False
        store._sdk()._session = session

        result = await store.complete_upload(
            key=key,
            upload_id="test-upload-id",
            size=len(payload),
            metadata=metadata,
            sha256=payload_sha256,
            part_bytes=len(payload),
            probe_existing=True,
        )

        assert result["verified"] is True
        assert result["sha256"] == payload_sha256

        post_requests = [r for r in captured_requests if r.method == "POST" and "uploadId=" in r.url]
        assert len(post_requests) == 1
        complete_req = post_requests[0]

        header_val = complete_req.headers.get("x-cos-forbid-overwrite")
        if isinstance(header_val, bytes):
            header_val = header_val.decode("utf-8")
        assert header_val == "true"
        assert "x-cos-forbid-overwrite" in _signed_headers(complete_req)

    asyncio.run(run())


def test_multipart_part_upload_does_not_require_forbid_overwrite():
    """upload_part (PUT with uploadId & partNumber) is excluded from forbid-overwrite guard.

    Only the HTTP transport is replaced: the real COS SDK still builds and signs
    the PreparedRequest, so method, query parameters, and the signed header list
    are exactly what production would put on the wire.
    """
    async def run():
        config = _make_config()
        store = CosAttachmentStore(config)
        client = store._sdk()

        transport = StubCosTransport(headers={"ETag": '"part-etag"'})
        session = client._session
        session.trust_env = False
        session.mount("https://", transport)
        session.mount("http://", transport)

        resp = client.upload_part(
            Bucket=config.cos_bucket,
            Key="test-key",
            UploadId="test-upload-id",
            PartNumber=1,
            Body=b"part-data",
        )

        assert resp["ETag"] == '"part-etag"'
        assert len(transport.requests) == 1
        req = transport.requests[0]
        assert req.method == "PUT"
        parsed = dict(parse_qsl(urlsplit(req.url).query))
        assert parsed.get("uploadId") == "test-upload-id"
        assert parsed.get("partNumber") == "1"
        assert "x-cos-forbid-overwrite" not in req.headers
        assert "x-cos-forbid-overwrite" not in _signed_headers(req)

    asyncio.run(run())


def test_retry_cannot_overwrite_existing_object():
    """Retry must not overwrite an existing object; mismatched content fails closed."""
    async def run():
        config = _make_config()
        store = CosAttachmentStore(config)

        metadata = _valid_metadata()
        key = _valid_key(metadata)
        new_payload = b"new-payload-attempting-overwrite"
        new_sha256 = hashlib.sha256(new_payload).hexdigest()

        existing_payload = b"original-persisted-payload"
        existing_sha256 = hashlib.sha256(existing_payload).hexdigest()

        existing_head_headers = {
            "Content-Length": str(len(existing_payload)),
            "x-cos-meta-repo": metadata["repo"],
            "x-cos-meta-pr-number": str(metadata["pr_number"]),
            "x-cos-meta-head-sha": metadata["head_sha"],
            "x-cos-meta-round-id": metadata["round_id"],
            "x-cos-meta-attachment-id": metadata["attachment_id"],
            "ETag": '"existing-etag"',
        }

        class InterceptingSession(store._sdk()._session.__class__):
            def send(self, request, **kwargs):
                if request.method == "HEAD":
                    return MockCosResponse(200, headers=existing_head_headers)
                if request.method == "GET":
                    return MockCosResponse(200, headers=existing_head_headers, content=existing_payload)
                if request.method == "PUT":
                    return MockCosResponse(
                        409,
                        content=b"<Error><Code>FileAlreadyExists</Code><Message>Object already exists</Message></Error>",
                    )
                raise AssertionError(f"unexpected {request.method} {request.url}")

        session = InterceptingSession()
        session._evidence_forbid_overwrite_guard = True
        session.trust_env = False
        store._sdk()._session = session

        with pytest.raises(EvidenceStoreError, match="object (digest|size) mismatch"):
            await store.put_native_file(
                key=key,
                metadata=metadata,
                size=len(new_payload),
                sha256=new_sha256,
                body=io.BytesIO(new_payload),
            )

        idempotent_result = await store.put_native_file(
            key=key,
            metadata=metadata,
            size=len(existing_payload),
            sha256=existing_sha256,
            body=io.BytesIO(existing_payload),
        )
        assert idempotent_result["verified"] is True
        assert idempotent_result["sha256"] == existing_sha256

    asyncio.run(run())


def test_network_error_read_back_validates_full_object_identity():
    """Ambiguous network error after write relies strictly on full read-back verification."""
    async def run():
        config = _make_config()
        store = CosAttachmentStore(config)

        payload = b"network-recovery-test-data"
        payload_sha256 = hashlib.sha256(payload).hexdigest()
        metadata = _valid_metadata()
        key = _valid_key(metadata)

        matching_head_headers = {
            "Content-Length": str(len(payload)),
            "x-cos-meta-repo": metadata["repo"],
            "x-cos-meta-pr-number": str(metadata["pr_number"]),
            "x-cos-meta-head-sha": metadata["head_sha"],
            "x-cos-meta-round-id": metadata["round_id"],
            "x-cos-meta-attachment-id": metadata["attachment_id"],
            "ETag": '"recovered-etag"',
        }

        # Scenario A: PUT threw ConnectionError, but object actually landed safely on COS
        class LandedSession(store._sdk()._session.__class__):
            def __init__(self):
                super().__init__()
                self.put_attempted = False

            def send(self, request, **kwargs):
                if request.method == "HEAD":
                    if not self.put_attempted:
                        return MockCosResponse(404)
                    return MockCosResponse(200, headers=matching_head_headers)
                if request.method == "PUT":
                    self.put_attempted = True
                    raise requests.ConnectionError("Connection reset by peer after sending body")
                if request.method == "GET":
                    return MockCosResponse(200, headers=matching_head_headers, content=payload)
                raise AssertionError(f"unexpected {request.method} {request.url}")

        session_a = LandedSession()
        session_a._evidence_forbid_overwrite_guard = True
        session_a.trust_env = False
        store._sdk()._session = session_a

        recovered = await store.put_native_file(
            key=key,
            metadata=metadata,
            size=len(payload),
            sha256=payload_sha256,
            body=io.BytesIO(payload),
        )
        assert recovered["verified"] is True
        assert recovered["sha256"] == payload_sha256

        # Scenario B: PUT threw ConnectionError, and object did NOT land on COS (HEAD returns 404)
        class NotLandedSession(store._sdk()._session.__class__):
            def send(self, request, **kwargs):
                if request.method == "HEAD":
                    return MockCosResponse(404)
                if request.method == "PUT":
                    raise requests.ConnectionError("Connection aborted before server write")
                raise AssertionError(f"unexpected {request.method} {request.url}")

        session_b = NotLandedSession()
        session_b._evidence_forbid_overwrite_guard = True
        session_b.trust_env = False
        store._sdk()._session = session_b

        with pytest.raises(EvidenceStoreError):
            await store.put_native_file(
                key=key,
                metadata=metadata,
                size=len(payload),
                sha256=payload_sha256,
                body=io.BytesIO(payload),
            )

    asyncio.run(run())


def test_note_dispatch_carries_forbid_overwrite_and_verifies_identity():
    """dispatch(action='note') uses forbid-overwrite and exact SHA256 verification."""
    async def run():
        config = _make_config()
        store = CosAttachmentStore(config)

        note_text = "Verified deployment note"
        note_bytes = note_text.encode("utf-8")
        note_sha256 = hashlib.sha256(note_bytes).hexdigest()

        metadata = _valid_metadata()
        key = _valid_key(metadata)
        operation = {
            **metadata,
            "object_key": key,
            "size": len(note_bytes),
            "sha256": note_sha256,
        }

        matching_head_headers = {
            "Content-Length": str(len(note_bytes)),
            "x-cos-meta-repo": metadata["repo"],
            "x-cos-meta-pr-number": str(metadata["pr_number"]),
            "x-cos-meta-head-sha": metadata["head_sha"],
            "x-cos-meta-round-id": metadata["round_id"],
            "x-cos-meta-attachment-id": metadata["attachment_id"],
            "ETag": '"note-etag"',
        }

        captured_requests = []

        class NoteSession(store._sdk()._session.__class__):
            def send(self, request, **kwargs):
                captured_requests.append(request)
                if request.method == "HEAD":
                    return MockCosResponse(200, headers=matching_head_headers)
                if request.method == "PUT":
                    return MockCosResponse(200, headers={"ETag": '"note-etag"'})
                if request.method == "GET":
                    return MockCosResponse(200, headers=matching_head_headers, content=note_bytes)
                raise AssertionError(f"unexpected {request.method} {request.url}")

        session = NoteSession()
        session._evidence_forbid_overwrite_guard = True
        session.trust_env = False
        store._sdk()._session = session

        result = await store.dispatch(
            action="note",
            operation=operation,
            payload={"text": note_text},
        )

        assert result["verified"] is True
        assert result["sha256"] == note_sha256

        put_reqs = [r for r in captured_requests if r.method == "PUT"]
        assert len(put_reqs) == 1
        header_val = put_reqs[0].headers.get("x-cos-forbid-overwrite")
        if isinstance(header_val, bytes):
            header_val = header_val.decode("utf-8")
        assert header_val == "true"
        assert "x-cos-forbid-overwrite" in _signed_headers(put_reqs[0])

    asyncio.run(run())
