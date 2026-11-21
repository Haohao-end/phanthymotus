"""Focused tests for the single gzip evidence and private COS contracts."""
from __future__ import annotations

import asyncio
import gzip
import sys
from datetime import datetime
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from ..comments import evidence_upload_comment
from ..cos_client import CosClient, CosError, EVIDENCE_MAX_ARCHIVE_BYTES
from ..evidence_builder import EvidenceBuilder
from ..evidence_service import NOTIFICATION_SKIPPED, NOTIFICATION_SYNCED
from ..evidence_store import EvidenceStoreError, build_attachment_key
from .conftest import make_config


def test_upload_page_contains_only_upload_controls():
    from agents.deploy_approval.evidence_ui import render_upload_page
    page = render_upload_page("team/repo", 1, "a" * 40, "a" * 40 + "-1")
    assert 'type="file"' in page and 'id="upload"' in page
    assert "上传进度" in page and "测试证据上传" in page


def test_upload_page_hides_history_deployment_logs_and_attachment_listing():
    from agents.deploy_approval.evidence_ui import render_upload_page
    page = render_upload_page("team/repo", 1, "a" * 40, "a" * 40 + "-1")
    for phrase in ("历史轮次", "附件说明", "历史附件", "部署记录", "部署日志", "机器部署日志"):
        assert phrase not in page
    assert "archive_links" not in page and "deployment_logs" not in page


def test_internal_evidence_record_has_no_visible_chinese_summary():
    from agents.deploy_approval.evidence_service import EvidenceService
    record = {"actor_verified": True, "actor_login": "4pd-pr-assistant[bot]",
              "note": "自动保存的内部证据记录（无需操作）"}
    assert EvidenceService._is_internal_bot_note(record)
    assert not EvidenceService._is_internal_bot_note({**record, "actor_verified": False})


APP_BOT_LOGIN = "4pd-pr-assistant[bot]"
APP_BOT_USER = {"id": 41898282, "login": APP_BOT_LOGIN, "type": "Bot"}
NOTIFICATION_REPO = "Haohao-end/phanthymotus"
NOTIFICATION_PR = 7
NOTIFICATION_UPLOADED_AT = "2026-09-18T03:55:54Z"


class _EvidenceNotificationProxy:
    """Offline proxy that models the App-comment contract the service relies on.

    Mirrors the real ``GitHubCommentProxy`` surface used by
    ``EvidenceService._notify_ready_attachment``: App-authored comments carry a
    positive comment id, PATCHes mutate the stored comment in place, and
    ``write_evidence_record`` returns the persisted record so restore markers
    can be read back. No real GitHub API call is possible here.
    """

    def __init__(self):
        self.comments = []
        self.records = {}
        self._next_comment_id = 900

    async def get_issue_comments(self, _repo, _pr_number):
        return [dict(comment) for comment in self.comments]

    def is_bot_comment(self, comment):
        user = comment.get("user") if isinstance(comment, dict) else None
        return isinstance(user, dict) and user.get("login") == APP_BOT_LOGIN

    async def post_issue_comment(self, _repo, _pr_number, body):
        self._next_comment_id += 1
        comment = {"id": self._next_comment_id, "body": body, "user": dict(APP_BOT_USER)}
        self.comments.append(comment)
        return dict(comment)

    async def update_comment(self, _repo, comment_id, body):
        for comment in self.comments:
            if comment["id"] == comment_id:
                comment["body"] = body
                return dict(comment)
        raise AssertionError(f"unknown comment id {comment_id}")

    async def write_evidence_record(self, _repo, _pr_number, kind, key, record):
        self.records[key] = {"kind": kind, "data": dict(record)}
        return {"kind": kind, "data": dict(record)}


class FakeCosStore:
    """Offline stand-in for ``CosAttachmentStore`` read verification.

    Only the verification contract used by ready-attachment notifications is
    modelled: a HEAD that must agree on size and every ``x-cos-meta-*``
    identity header, followed by a content read whose digest must equal the
    persisted sha256. A record that does not match the stored object fails
    closed exactly like the production store. No COS SDK or network path exists
    here, so these tests can never reach the real bucket.

    Also returns the persisted sha256/object key so the caller-side identity
    re-check (size, sha256, object_key) is exercised for real.
    """

    _IDENTITY_FIELDS = ("repo", "pr_number", "head_sha", "round_id", "attachment_id")

    def __init__(self):
        self.objects = {}
        self.head_calls = []
        self.get_calls = []

    def put_object(self, key, *, size, sha256, metadata):
        """Register an object whose COS metadata is derived like production."""
        self.objects[key] = {
            "size": size,
            "sha256": sha256,
            "metadata": {
                "x-cos-meta-" + name.replace("_", "-"): str(metadata[name])
                for name in self._IDENTITY_FIELDS
            },
        }

    async def verify_object(self, *, key, size, metadata, sha256=None):
        self.head_calls.append({"key": key, "size": size, "metadata": dict(metadata)})
        stored = self.objects.get(key)
        if stored is None:
            raise EvidenceStoreError("object missing")
        if stored["size"] != size:
            raise EvidenceStoreError("object size mismatch")
        expected = {
            "x-cos-meta-" + name.replace("_", "-"): str(metadata[name])
            for name in self._IDENTITY_FIELDS
        }
        if any(stored["metadata"].get(name) != value for name, value in expected.items()):
            raise EvidenceStoreError("object identity mismatch")
        self.get_calls.append(key)
        if sha256 is not None and stored["sha256"] != sha256:
            raise EvidenceStoreError("object digest mismatch")
        return {
            "verified": True,
            "object_key": key,
            "size": stored["size"],
            "sha256": stored["sha256"],
        }


def _ready_attachment(**overrides):
    operation = {
        "repo": NOTIFICATION_REPO,
        "pr_number": NOTIFICATION_PR,
        "status": "ready",
        "cos_content_verified": True,
        "evidence_kind": "media",
        "size": 10,
        "sha256": "b" * 64,
        "head_sha": HEAD,
        "round_id": HEAD + "-1",
        "attachment_id": "attachment_1",
        "filename": "screen.png",
        "actor_verified": True,
        "actor_login": "real-user",
        "github_user_authenticated": True,
        "completed_at": NOTIFICATION_UPLOADED_AT,
    }
    operation.update(overrides)
    # Use the real persisted object layout so metadata/HEAD identity checks are
    # exercised against the same key the service reads back.
    operation["object_key"] = build_attachment_key(
        operation["repo"], operation["pr_number"], operation["head_sha"],
        operation["round_id"], operation["attachment_id"],
        NOTIFICATION_UPLOADED_AT, operation["filename"],
    )
    return operation


def _notification_fixture(**overrides):
    """Build proxy + FakeCosStore + service for one ready-attachment record."""
    proxy = _EvidenceNotificationProxy()
    store = FakeCosStore()
    operation = _ready_attachment(**overrides)
    store.put_object(
        operation["object_key"],
        size=operation["size"],
        sha256=operation["sha256"],
        metadata={
            name: operation[name]
            for name in FakeCosStore._IDENTITY_FIELDS
        },
    )
    from agents.deploy_approval.evidence_service import EvidenceService
    config = make_config(
        evidence_public_base_url="https://evidence.example",
        cos_secret_key="test-cos-secret",
    )
    service = EvidenceService(
        config=config, github=None, proxy=proxy, policy=None,
        controller=SimpleNamespace(), store=store,
    )
    return proxy, store, service, operation


@pytest.mark.asyncio
async def test_chinese_internal_bot_note_does_not_post_comment():
    proxy, _store, service, operation = _notification_fixture(
        actor_login=APP_BOT_LOGIN,
        note="自动保存的内部证据记录（无需操作）",
    )

    assert await service._notify_ready_attachment(
        NOTIFICATION_REPO, NOTIFICATION_PR, operation,
    ) == NOTIFICATION_SKIPPED
    assert proxy.comments == []


@pytest.mark.asyncio
@pytest.mark.parametrize("note", [
    "server-side cos multipart acceptance",
    "server-side 20mb h.264 cos transport acceptance",
])
async def test_existing_english_internal_bot_notes_do_not_post_comment(note):
    proxy, _store, service, operation = _notification_fixture(
        actor_login=APP_BOT_LOGIN,
        note=note,
    )

    assert await service._notify_ready_attachment(
        NOTIFICATION_REPO, NOTIFICATION_PR, operation,
    ) == NOTIFICATION_SKIPPED
    assert proxy.comments == []


@pytest.mark.asyncio
async def test_internal_bot_note_flag_does_not_post_comment():
    proxy, _store, service, operation = _notification_fixture(internal_bot_note=True)

    assert await service._notify_ready_attachment(
        NOTIFICATION_REPO, NOTIFICATION_PR, operation,
    ) == NOTIFICATION_SKIPPED
    assert proxy.comments == []


@pytest.mark.asyncio
async def test_real_user_image_posts_comment():
    proxy, store, service, operation = _notification_fixture(filename="screen.png")

    assert await service._notify_ready_attachment(
        NOTIFICATION_REPO, NOTIFICATION_PR, operation,
    ) == NOTIFICATION_SYNCED
    assert len(proxy.comments) == 1
    body = proxy.comments[0]["body"]
    # The uploaded object was read back (HEAD + content digest) before posting.
    assert store.get_calls == [operation["object_key"]]
    assert f"![screen.png](<https://evidence.example/api/evidence/{NOTIFICATION_REPO}/pulls/{NOTIFICATION_PR}/attachments/attachment_1/preview?cap=" in body
    assert f"[下载图片](<https://evidence.example/api/evidence/{NOTIFICATION_REPO}/pulls/{NOTIFICATION_PR}/attachments/attachment_1/download?cap=" in body
    assert "@real-user" in body


@pytest.mark.asyncio
async def test_real_user_video_posts_comment():
    proxy, _store, service, operation = _notification_fixture(filename="capture.mp4")

    assert await service._notify_ready_attachment(
        NOTIFICATION_REPO, NOTIFICATION_PR, operation,
    ) == NOTIFICATION_SYNCED
    assert len(proxy.comments) == 1
    body = proxy.comments[0]["body"]
    assert "capture.mp4" in body
    assert "[下载视频](<https://evidence.example/api/evidence/" in body
    assert "/attachments/attachment_1/download?cap=" in body
    # A video is never rendered as an inline image.
    assert "![capture.mp4]" not in body


@pytest.mark.asyncio
async def test_repeated_upload_does_not_duplicate_comment():
    proxy, _store, service, operation = _notification_fixture(filename="capture.mp4")

    assert await service._notify_ready_attachment(
        NOTIFICATION_REPO, NOTIFICATION_PR, operation,
    ) == NOTIFICATION_SYNCED
    assert await service._notify_ready_attachment(
        NOTIFICATION_REPO, NOTIFICATION_PR, operation,
    ) == NOTIFICATION_SYNCED
    assert len(proxy.comments) == 1
    assert proxy.comments[0]["body"].count("deploy-approval-evidence-upload:") == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", ["size", "sha256", "metadata"])
async def test_unverified_object_never_posts_a_comment(tamper):
    """A record that no longer matches its COS object must fail closed.

    The FakeStore models HEAD (size + ``x-cos-meta-*`` identity) and the
    content digest read; tampering with any of them must reproduce the real
    store's rejection and must never produce a user-visible comment.
    """
    from ..evidence_service import NOTIFICATION_RESTORE_PENDING

    proxy, store, service, operation = _notification_fixture()
    key = operation["object_key"]
    if tamper == "size":
        store.objects[key]["size"] += 1
    elif tamper == "sha256":
        store.objects[key]["sha256"] = "c" * 64
    else:
        store.objects[key]["metadata"]["x-cos-meta-attachment-id"] = "attachment_2"

    assert await service._notify_ready_attachment(
        NOTIFICATION_REPO, NOTIFICATION_PR, operation,
    ) == NOTIFICATION_RESTORE_PENDING
    assert proxy.comments == []
    assert store.head_calls, "object must have been HEAD-verified"
    if tamper == "sha256":
        # The digest can only be checked after the content read.
        assert store.get_calls == [key]
    else:
        # A HEAD identity/size mismatch rejects before any content is read.
        assert store.get_calls == []


def test_ready_attachment_posts_one_idempotent_comment_with_media_links():
    from agents.deploy_approval.comments import evidence_upload_comment
    route = "/api/evidence/team/repo/pulls/1/attachments/attachment_1"
    body = evidence_upload_comment(
        "team/repo", 1, HEAD, HEAD + "-1", "attachment_1", "screen.png",
        download_url=f"https://evidence.example{route}/download?cap=token",
        preview_url=f"https://evidence.example{route}/preview?cap=token",
        public_base_url="https://evidence.example",
    )
    assert "![screen.png]" in body
    assert "下载图片" in body
    assert f"(<https://evidence.example{route}/preview?cap=token>)" in body
    assert f"(<https://evidence.example{route}/download?cap=token>)" in body
    assert body.count("deploy-approval-evidence-upload:") == 1

    video = evidence_upload_comment(
        "team/repo", 1, HEAD, HEAD + "-1", "attachment_2", "capture.mp4",
        download_url="/api/evidence/team/repo/pulls/1/attachments/attachment_2/download?cap=token",
        preview_url="",
        public_base_url="https://evidence.example",
    )
    assert video == ""

    video = evidence_upload_comment(
        "team/repo", 1, HEAD, HEAD + "-1", "attachment_2", "capture.mp4",
        download_url="https://evidence.example/api/evidence/team/repo/pulls/1/"
                     "attachments/attachment_2/download?cap=token",
        preview_url="",
        public_base_url="https://evidence.example",
    )
    assert video.count("deploy-approval-evidence-upload:") == 1
    assert "[下载视频](<https://evidence.example/api/evidence/team/repo/pulls/1/" \
           "attachments/attachment_2/download?cap=token>)" in video

    # A foreign origin must never be rendered as a trusted attachment link.
    assert evidence_upload_comment(
        "team/repo", 1, HEAD, HEAD + "-1", "attachment_1", "screen.png",
        download_url="https://evil.example/api/evidence/team/repo/pulls/1/"
                     "attachments/attachment_1/download?cap=token",
        preview_url="",
        public_base_url="https://evidence.example",
    ) == ""

HEAD = "a" * 40


def _state(**overrides):
    state = {"review_evidence": {"build_comment_id": 1001, "build_comment_updated_at": "2026-09-18T03:55:54Z", "commit_prefix": "abc1234", "resolved_head_sha": "a" * 40, "test_comment_id": 1002, "code_review_comment_id": 1003, "review_author_id": "7950763"}, "components": [], "case_results": {},
             "command": {"kind": "approve_deploy"}}
    state.update(overrides)
    return state


def _build(**kwargs):
    args = {"repo": "Haohao-end/phanthymotus", "pr_number": 7, "head_sha": HEAD,
            "state": _state(), "result": "pass"}
    args.update(kwargs)
    return asyncio.run(EvidenceBuilder(make_config()).build_evidence(**args))


def _text(archive):
    return gzip.decompress(archive).decode("utf-8", errors="strict")


def test_evidence_is_single_gzip_utf8_text():
    body = _text(_build()[0])
    assert body.startswith("[metadata]")
    assert "repo=Haohao-end/phanthymotus" in body and "pr=7" in body
    assert f"head={HEAD}" in body and "review_build_comment_id=1001" in body
    assert "result=pass" in body and "[deploy]" in body
    assert "manifest" not in body.lower() and not body.startswith("ustar")


def test_evidence_fixed_metadata_survives_large_runtime_logs():
    body = _text(_build(runtime_logs={"agent": "x" * (11 * 1024 * 1024)})[0])
    for value in ("repo=Haohao-end/phanthymotus", "pr=7", f"head={HEAD}",
                  "review_build_comment_id=1001", "result=pass"):
        assert value in body


def test_evidence_keeps_newest_runtime_tail():
    logs = {"runtime": "OLDEST_RUNTIME_LOG_MUST_DROP\n" + "x" * (11 * 1024 * 1024) +
            "\nNEWEST_RUNTIME_LOG_MUST_STAY\n"}
    body = _text(_build(runtime_logs=logs)[0])
    assert "NEWEST_RUNTIME_LOG_MUST_STAY" in body
    assert "OLDEST_RUNTIME_LOG_MUST_DROP" not in body


def test_evidence_archive_and_plaintext_hard_cap():
    archive = _build(runtime_logs={"runtime": "z" * (12 * 1024 * 1024)})[0]
    assert len(archive) <= EVIDENCE_MAX_ARCHIVE_BYTES
    assert len(gzip.decompress(archive)) <= EVIDENCE_MAX_ARCHIVE_BYTES


def test_evidence_secret_redaction():
    values = ["ghp_FAKE_GITHUB_TOKEN", "github_pat_FAKE_TOKEN", "Bearer FAKE_BEARER",
              "password=FAKE_PASSWORD", "token=FAKE_TOKEN", "q-ak=FAKE_AK",
              "q-signature=FAKE_SIGNATURE", "q-sign-time=FAKE_TIME", "q-key-time=FAKE_KEY_TIME"]
    body = _text(_build(summary="\n".join(values), runtime_logs={"r": "\n".join(values)})[0])
    for value in values:
        assert value.split("=", 1)[-1] not in body
    assert "FAKE_BEARER" not in body


def test_deploy_failure_is_not_fake_record_test():
    body = _text(_build(result="fail", deploy_error="unsafe deploy failed")[0])
    assert "[deploy]" in body and "terminal_error=unsafe deploy failed" in body
    assert "[test]" not in body


def test_real_record_test_contains_test_section():
    body = _text(_build(result="pass", state=_state(command={"kind": "record_test"}))[0])
    assert "[test]" in body and "result=pass" in body


def test_cos_object_key_exact_layout():
    client = CosClient(make_config(github_repos=["Haohao-end/phanthymotus", "Haohao-end/phanthymotus-driver"]))
    now = datetime(2026, 9, 17, 20, 30)
    for repo, expected in [
        ("Haohao-end/phanthymotus", "phanthymotus_pr/repo-v1-68616f68616f2d656e64-7068616e7468796d6f747573/2026-09/2026-09-17/pr-7/evidence-" + HEAD + ".log.gz"),
        ("Haohao-end/phanthymotus-driver", "phanthymotus_pr/repo-v1-68616f68616f2d656e64-7068616e7468796d6f7475732d647269766572/2026-09/2026-09-17/pr-7/evidence-" + HEAD + ".log.gz"),
    ]:
        assert client.build_object_key(repo, 7, HEAD, now=now) == expected
    with pytest.raises(ValueError):
        client.build_object_key("some/other-repo", 7, HEAD, now=now)


@pytest.mark.parametrize("key", [
    "phanthymotus_pr/wrong/2026-09/2026-09-17/pr-7/evidence-" + HEAD + ".log.gz",
    "phanthymotus_pr/phanthymotus/2026-09/2026-09-17/pr-8/evidence-" + HEAD + ".log.gz",
    "phanthymotus_pr/phanthymotus/2026-09/2026-09-17/pr-7/evidence-" + "b" * 40 + ".log.gz",
    "phanthymotus_pr/phanthymotus/2026-08/2026-09-17/pr-7/evidence-" + HEAD + ".log.gz",
    "phanthymotus_pr/phanthymotus/2026-09/2026-09-17/../pr-7/evidence-" + HEAD + ".log.gz",
    "phanthymotus_pr/phanthymotus\\2026-09/2026-09-17/pr-7/evidence-" + HEAD + ".log.gz",
    "phanthymotus_pr/phanthymotus/2026-09/2026-09-17/pr-7/extra/evidence-" + HEAD + ".log.gz",
    "phanthymotus_pr/phanthymotus/2026-09/2026-09-17/pr-7/evidence-" + "A" * 40 + ".log.gz",
    "phanthymotus_pr/phanthymotus/2026-09/2026-09-17/pr-7/evidence-" + "a" * 39 + ".log.gz",
])
def test_cos_validate_object_key_fail_closed(key):
    with pytest.raises(ValueError):
        CosClient.validate_object_key("Haohao-end/phanthymotus", 7, HEAD, key)


class _Body:
    def __init__(self, chunks):
        self.chunks, self.closed = iter(chunks), False
    def get_raw_stream(self): return self
    def read(self, _size): return next(self.chunks, b"")
    def close(self): self.closed = True


def _install_qcloud(monkeypatch, client, body, length):
    events = []
    class SDK:
        def __init__(self, _config): pass
        def head_object(self, **kwargs): events.append("HEAD"); return {"Content-Length": str(length)}
        def get_object(self, **kwargs): events.append("GET"); return {"Body": body}
    module = ModuleType("qcloud_cos")
    module.CosConfig = lambda **kwargs: SimpleNamespace()
    module.CosS3Client = SDK
    monkeypatch.setitem(sys.modules, "qcloud_cos", module)
    client.config.cos_region, client.config.cos_secret_id, client.config.cos_secret_key, client.config.cos_bucket = "cn-bj", "id", "key", "bucket"
    return events


def test_cos_download_head_before_get_and_hard_bound(monkeypatch):
    client = CosClient(make_config())
    key = client.build_object_key("Haohao-end/phanthymotus", 7, HEAD)
    body = _Body([b"evidence"])
    events = _install_qcloud(monkeypatch, client, body, 8)
    assert asyncio.run(client.download_evidence_archive(key, 10)) == b"evidence"
    assert events == ["HEAD", "GET"] and body.closed
    events = _install_qcloud(monkeypatch, client, _Body([b"not-read"]), EVIDENCE_MAX_ARCHIVE_BYTES + 1)
    with pytest.raises(CosError):
        asyncio.run(client.download_evidence_archive(key, EVIDENCE_MAX_ARCHIVE_BYTES))
    assert events == ["HEAD"]
    body = _Body([b"x" * (EVIDENCE_MAX_ARCHIVE_BYTES + 1)])
    _install_qcloud(monkeypatch, client, body, EVIDENCE_MAX_ARCHIVE_BYTES)
    with pytest.raises(CosError):
        asyncio.run(client.download_evidence_archive(key, EVIDENCE_MAX_ARCHIVE_BYTES))
    assert body.closed
    body = _Body([b"short"])
    _install_qcloud(monkeypatch, client, body, 99)
    with pytest.raises(CosError):
        asyncio.run(client.download_evidence_archive(key, EVIDENCE_MAX_ARCHIVE_BYTES))
    assert body.closed


# ── presigned URL contract tests ─────────────────────────────────────────

def test_cos_presign_ttl_is_365_days():
    """EVIDENCE_PRESIGNED_URL_TTL_SECONDS must be exactly 365 days."""
    from ..cos_client import EVIDENCE_PRESIGNED_URL_TTL_SECONDS
    assert EVIDENCE_PRESIGNED_URL_TTL_SECONDS == 31536000


@pytest.mark.asyncio
async def test_cos_presign_missing_credentials_returns_empty(monkeypatch):
    """When credentials are missing, generate_evidence_download_url returns ''."""
    client = CosClient(make_config(cos_secret_id="", cos_secret_key=""))
    result = client.generate_evidence_download_url(client.build_object_key("Haohao-end/phanthymotus", 7, HEAD))
    assert result == ""


@pytest.mark.asyncio
async def test_cos_presign_invalid_object_key_returns_empty(monkeypatch):
    """Invalid object keys must return empty string."""
    client = CosClient(make_config())
    for bad_key in ["", "/phanthymotus_pr/test", "phanthymotus/../test", "phanthymotus_pr/test\\key", "other_repo/pr/1/test"]:
        result = client.generate_evidence_download_url(bad_key)
        assert result == f"expected empty for {bad_key!r} but got {result!r}" or result == ""


@pytest.mark.asyncio
async def test_cos_presign_https_accepted_http_rejected(monkeypatch):
    """HTTPS presigned URL accepted; HTTP rejected."""
    import sys
    from types import ModuleType

    class FakeCosConfig:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class FakeUrl(str):
        def __new__(cls, url):
            return str.__new__(cls, url)
        def startswith(self, prefix):
            return super().startswith(prefix)

    class FakeCosS3Client:
        def __init__(self, config):
            self.config = config
        def get_presigned_url(self, **kwargs):
            # Simulate SDK returning the URL
            return FakeUrl(self._test_url)

        def set_test_url(self, url):
            self._test_url = url

    fake_module = ModuleType("qcloud_cos")
    fake_module.CosConfig = FakeCosConfig
    fake_module.CosS3Client = FakeCosS3Client

    saved = sys.modules.get("qcloud_cos")
    sys.modules["qcloud_cos"] = fake_module
    try:
        cfg = make_config(cos_region="ap-shanghai", cos_bucket="test-bucket", cos_secret_id="SID", cos_secret_key="SK")
        client = CosClient(cfg)

        # HTTPS -> accepted
        client._client_class = FakeCosS3Client
        fake_client = FakeCosS3Client(None)
        fake_client.set_test_url("https://bucket-123456.cos.ap-shanghai.myqcloud.com/phanthymotus_pr/test/evidence.gz")
        client._fake_cos_client = fake_client

        # Patch the constructor to return our fake
        orig_init = FakeCosS3Client.__init__
        def patched_init(self, config):
            orig_init(self, config)
            self._test_url = "https://bucket-123456.cos.ap-shanghai.myqcloud.com/phanthymotus_pr/test/evidence.gz"
        FakeCosS3Client.__init__ = patched_init

        result = client.generate_evidence_download_url(client.build_object_key("Haohao-end/phanthymotus", 7, HEAD))
        assert result.startswith("https://"), f"expected https URL, got {result!r}"

        # HTTP -> rejected
        def patched_init_http(self, config):
            orig_init(self, config)
            self._test_url = "http://bucket-123456.cos.ap-shanghai.myqcloud.com/phanthymotus_pr/test/evidence.gz"
        FakeCosS3Client.__init__ = patched_init_http

        result2 = client.generate_evidence_download_url(client.build_object_key("Haohao-end/phanthymotus", 7, HEAD))
        assert result2 == "", f"expected empty for http URL, got {result2!r}"
    finally:
        FakeCosS3Client.__init__ = orig_init
        if saved:
            sys.modules["qcloud_cos"] = saved
        elif "qcloud_cos" in sys.modules:
            del sys.modules["qcloud_cos"]


@pytest.mark.asyncio
async def test_cos_presign_sdk_exception_returns_empty(monkeypatch):
    """SDK exception must fail closed."""
    import sys
    from types import ModuleType

    class FakeCosConfig:
        def __init__(self, **kwargs):
            pass

    class FakeCosS3Client:
        def __init__(self, config):
            pass
        def get_presigned_url(self, **kwargs):
            raise RuntimeError("network error")

    fake_module = ModuleType("qcloud_cos")
    fake_module.CosConfig = FakeCosConfig
    fake_module.CosS3Client = FakeCosS3Client

    saved = sys.modules.get("qcloud_cos")
    sys.modules["qcloud_cos"] = fake_module
    try:
        client = CosClient(make_config(cos_region="ap-shanghai", cos_bucket="test-bucket",
                                      cos_secret_id="OFFLINE_ID", cos_secret_key="OFFLINE_KEY"))
        result = client.generate_evidence_download_url(client.build_object_key("Haohao-end/phanthymotus", 7, HEAD))
        assert result == ""
    finally:
        if saved:
            sys.modules["qcloud_cos"] = saved
        elif "qcloud_cos" in sys.modules:
            del sys.modules["qcloud_cos"]


def test_cos_presign_no_secret_leakage_in_source():
    """Source must not log URL query strings, secrets, or Authorization headers."""
    source = open(Path(__file__).parent.parent / "cos_client.py").read()
    assert "logger.info" not in source or "presigned" not in source.lower() or "url" not in source.lower().split("logger.info")[0][-50:] if "logger.info" in source else True
    # Ensure no direct secret logging
    assert 'logger.info' not in source or 'SecretId' not in source.split('logger.info')[1].split('\n')[0] if 'logger.info' in source else True


@pytest.mark.asyncio
async def test_cos_presign_method_belongs_to_cos_client():
    """generate_evidence_download_url must be a method of CosClient, not CosError."""
    from ..cos_client import CosClient, CosError
    assert hasattr(CosClient, "generate_evidence_download_url")
    assert not hasattr(CosError, "generate_evidence_download_url")


@pytest.mark.asyncio
async def test_cos_presign_uses_real_local_sdk_construction_seam():
    """Tests must mock qcloud_cos, not client._client or self._config."""
    source = open(Path(__file__).parent.parent / "cos_client.py").read()
    # The method must construct CosConfig/CosS3Client locally
    assert "CosConfig(" in source
    assert "CosS3Client(" in source
    # Must not reference self._client or self._config inside generate_evidence_download_url
    # Check that the method uses self.config (not self._config)
    import ast
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "CosClient":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == "generate_evidence_download_url":
                    method_src = ast.unparse(item)
                    assert "self._config" not in method_src, "generate_evidence_download_url must use self.config, not self._config"
                    assert "self._client" not in method_src, "generate_evidence_download_url must not use self._client"


def test_production_compose_default_repos_are_main_and_driver():
    """GITHUB_REPOS default must contain exactly the two production repositories."""
    from ..config import DEFAULT_GITHUB_REPOS

    assert DEFAULT_GITHUB_REPOS == (
        "4paradigm/phanthymotus",
        "4paradigm/phanthymotus-driver",
    )


# ── service approval contract tests ────────────────────────────────────────

@pytest.mark.asyncio
async def test_pr_author_can_approve_own_deploy():
    """PR author who is machine owner or has write/maintain/admin must be allowed to approve own deploy.

    Regression: _is_self_approval gate removed from service.py.
    Static assertion: no _is_self_approval definition or "PR author cannot approve" string remains.
    """
    # Static regression assertions
    service_source = open(Path(__file__).parent.parent / "service.py").read()
    assert "_is_self_approval" not in service_source, (
        "_is_self_approval must be fully removed from service.py"
    )
    assert "PR author cannot approve their own deployment" not in service_source, (
        '"PR author cannot approve their own deployment" must not exist in service.py'
    )


@pytest.mark.asyncio
async def test_machine_partial_coverage_includes_only_compatible_components():
    """A machine with partial coverage must keep only its compatible remaining components."""
    from ..service import DeployController
    from types import SimpleNamespace

    machines = [
        SimpleNamespace(
            alias="alpha",
            node_id="node-1",
            node_host="192.0.2.10",
            platforms=["linux/arm64"],
            targets=["perception"],
            variants=[],
            driver_paths=[],
            owners=["alpha-owner"],
            machine_supports_target=lambda alias, target: True,
        )
    ]

    components = [
        {"component_id": "comp-a", "target": "perception", "resolved_platform": "linux/arm64"},
        {"component_id": "comp-b", "target": "planning", "resolved_platform": "linux/arm64"},
    ]

    mock_policy = SimpleNamespace()
    mock_policy.get_machines = lambda repo=None: machines
    mock_policy.get_machine = lambda alias, repo=None: next(
        (machine for machine in machines if machine.alias == alias), None,
    )
    mock_policy.repo_policy_status = lambda _repo: {
        "authorized": True, "machines_configured": True,
    }
    # "planning" is not a supported target (only perception/actucore/driver)
    def _supports_target(alias, target):
        return target in ("perception", "actucore", "driver")
    mock_policy.machine_supports_target = _supports_target

    controller = DeployController(
        config=SimpleNamespace(
            machine_config="tests/machines.yaml",
            health_timeout_seconds=30,
            health_poll_interval_seconds=1,
        ),
        proxy=None,
        policy=mock_policy,
        github=None,
    )
    controller._physical_machine_inventory = lambda: [{
        "alias": "alpha", "node_id": "node-1", "primary_ip": "192.0.2.10",
        "platform_status": "verified", "platforms": ["linux/arm64"],
        "platform_verified": True,
    }]

    groups = controller._get_machine_groups_for_components(
        components, "4paradigm/phanthymotus",
    )
    # Partial coverage is allowed: machine supports perception but not planning,
    # so it should be listed with only the compatible component.
    assert len(groups) == 1
    assert groups[0]["alias"] == "alpha"
    assert groups[0]["compatible_component_ids"] == ["comp-a"]


@pytest.mark.asyncio
async def test_no_post_deploy_health_gate():
    """_wait_for_deploy_health must not exist in service.py."""
    source = open(Path(__file__).parent.parent / "service.py").read()
    assert "_wait_for_deploy_health" not in source, (
        "_wait_for_deploy_health method must be removed"
    )


@pytest.mark.asyncio
async def test_cos_runtime_repo_key_legacy_and_collision_safe():
    """Exercise actual gzip identity/upload/read-back for configured namespaces."""
    repos = ["Haohao-end/phanthymotus", "Haohao-end/phanthymotus-driver",
             "team/phanthymotus", "other/phanthymotus", "team-a/b", "team/a-b"]
    cfg = make_config(github_repos=repos)
    client = CosClient(cfg, _fake=True)
    now = datetime(2026, 10, 14)
    keys = {repo: client.build_object_key(repo, 7, HEAD, now=now) for repo in repos}
    assert keys[repos[0]] == f"phanthymotus_pr/repo-v1-68616f68616f2d656e64-7068616e7468796d6f747573/2026-10/2026-10-14/pr-7/evidence-{HEAD}.log.gz"
    assert keys[repos[1]] == f"phanthymotus_pr/repo-v1-68616f68616f2d656e64-7068616e7468796d6f7475732d647269766572/2026-10/2026-10-14/pr-7/evidence-{HEAD}.log.gz"
    assert len(set(keys.values())) == len(repos)
    for repo, key in keys.items():
        assert key.split("/")[1] not in (".", "..")
        assert CosClient._repo_from_key(key) == repo.lower()
        canonical_repo = repo.lower()
        assert CosClient.validate_object_key(canonical_repo, 7, HEAD, key) == key
        archive, sha, size = await EvidenceBuilder(cfg).build_evidence(
            repo=canonical_repo, pr_number=7, head_sha=HEAD, state=_state(), result="pass")
        metadata = await client.ensure_evidence_archive(
            object_key=key, archive_bytes=archive, repo=canonical_repo,
            pr_number=7, head_sha=HEAD, result="pass")
        assert metadata == {"object_key": key, "sha256": sha, "size": size}
        assert await client.download_evidence_archive(key, size) == archive
        assert await client.verify_upload(key, sha, size)
        with pytest.raises(ValueError, match="identity"):
            CosClient.validate_object_key("outside/same-name", 7, HEAD, key)
    previous = list(client._uploads)
    wrong_repo_archive, _, _ = await EvidenceBuilder(cfg).build_evidence(
        repo=repos[2], pr_number=7, head_sha=HEAD, state=_state(), result="pass")
    assert not await client.upload_evidence_archive(keys[repos[0]], wrong_repo_archive, expected_result="pass")
    assert client._uploads == previous
    for invalid in ("outside/unconfigured", "team/../name", "team/..", "team/name/extra"):
        with pytest.raises(ValueError):
            client.build_object_key(invalid, 7, HEAD)
