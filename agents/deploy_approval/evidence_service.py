"""Attachment operations persisted as immutable, trusted Git Notes records.

Store adapter contract (B): async dispatch(action, *, operation, payload) -> dict.
init/note must be idempotent by operation_id; resume must locate an uncertain
initialization without creating another upload. complete/note return verified,
object_key, size, sha256 after bounded streaming verification. sign_part and
(download/log_download) return ephemeral URLs only. Tokens/URLs/file contents
are never accepted into durable records. C renders references via the watcher.
"""
from __future__ import annotations

import copy
import asyncio
import hashlib
import ipaddress
import json
import logging
import re
import socket
import tempfile
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import PurePosixPath
from urllib.parse import unquote, urljoin, urlsplit

from .evidence_auth import (
    DOWNLOAD_PURPOSE, PURPOSE, UPLOAD_MAX_BYTES, UPLOAD_MAX_FILES, UPLOAD_PURPOSE,
)
from .evidence_models import (
    EvidenceError, round_id_for_state, trusted_round_numbers, utc_now, validate_context,
)

UPLOAD_MAX_NOTES = 20
# Ready-attachment notification outcomes. An upload is verified and persisted
# independently of whether a visible GitHub comment can be posted: a failed or
# deferred announcement never invalidates the stored attachment.
NOTIFICATION_SYNCED = 'synced'
NOTIFICATION_PENDING = 'pending'
NOTIFICATION_RESTORE_PENDING = 'restore_pending'
NOTIFICATION_RESTORE_FAILED = 'restore_failed'
NOTIFICATION_SKIPPED = 'skipped'
NOTIFICATION_FAILED = 'failed'
_NOTIFICATION_ELIGIBLE = 'eligible'
NOTIFICATION_BACKFILL_INTERVAL_SECONDS = 300
NOTIFICATION_BACKFILL_MAX_PER_RUN = 10
_COMMENTABLE_MEDIA_SUFFIXES = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.mp4', '.webm'}
_CURRENT_CONTEXT_HISTORY_TIMEOUT_SECONDS = 8
logger = logging.getLogger(__name__)


class _NoopAsyncContext:
    async def __aenter__(self):
        return None

    async def __aexit__(self, exc_type, exc, tb):
        return False


class EvidenceService:
    @staticmethod
    def _is_internal_bot_note(row):
        if not isinstance(row, dict) or row.get('actor_verified') is not True:
            return False
        actor = row.get('actor_login') or row.get('actor')
        note = row.get('note')
        if not (isinstance(actor, str) and actor.casefold() == '4pd-pr-assistant[bot]'
                and isinstance(note, str)):
            return False
        normalized = ' '.join(
            unicodedata.normalize('NFKC', note).replace('\u200b', '').split(),
        ).casefold()
        templates = (
            'server-side cos multipart acceptance',
            'server-side 20mb h.264 cos transport acceptance',
            '自动保存的内部证据记录（无需操作）',
        )
        return any(normalized == template or
                   normalized.startswith(template) and
                   normalized[len(template):len(template) + 1] in
                   {' ', ':', ';', ',', '.', '!', '?', '(', '（', '-', '—'}
                   for template in templates)

    def __init__(self, *, config, github, proxy, policy, controller, store):
        self.config, self.github, self.proxy = config, github, proxy
        self.policy, self.controller, self.store = policy, controller, store
        self._used_auth_nonces = {}
        self._notification_backfill_runs = {}
        self._notification_backfill_cursor = {}
        self._notification_states = {}
        self._notification_lock = asyncio.Lock()
        self._ready_sync_scheduler = None
        controller.evidence_service = self

    @staticmethod
    def _require_pr_snapshot(pr, repo):
        """Distinguish a confirmed PR state from an incomplete/transient read."""
        if not isinstance(pr, dict) or pr.get('state') not in {'open', 'closed'}:
            raise EvidenceError('pr_status_unavailable', 503)
        base = pr.get('base')
        base_repository = base.get('repo') if isinstance(base, dict) else None
        base_repo = base_repository.get('full_name') if isinstance(base_repository, dict) else None
        if not isinstance(base_repo, str) or base_repo.casefold() != repo.casefold():
            raise EvidenceError('pr_repository_mismatch', 409)
        return pr

    async def _authorize(self, repo, principal, state, *, check_machine=True, pr=None):
        if (not self.config.auth_valid or repo not in self.config.github_repos
                or repo not in self.config.active_repos):
            raise EvidenceError('repository_not_authorized', 403)
        authorized = await self.github.list_installation_repositories()
        if repo not in authorized:
            raise EvidenceError('app_access_revoked', 403)
        if isinstance(principal.get('upload_invite'), dict):
            return False
        uid, login = principal.get('id'), principal.get('login')
        if type(uid) is not int or uid <= 0 or not isinstance(login, str) or not login:
            raise EvidenceError('identity_required', 401)
        if not self.config.auth_valid or repo not in self.config.active_repos:
            raise EvidenceError('app_access_revoked', 403)
        if not (principal.get('actor_verified') is True
                and principal.get('github_user_authenticated') is True):
            return False
        # Browser write identity is accepted only after the HTTP layer has
        # revalidated GitHub /user for this request. Authorization remains
        # tied to the live PR author, deployed machine owners, or repo ACL.
        author = (pr or {}).get('user', {})
        if (isinstance(author, dict) and
                type(author.get('id')) is int and author.get('id') == uid):
            return True
        deployed = {d.get('machine') for d in state.get('deployments', [])
                    if isinstance(d, dict) and d.get('phase') == 'deployed'}
        for alias in deployed:
            machine = self.policy.get_machine(alias) if isinstance(alias, str) else None
            if machine and any(isinstance(owner, str) and owner.lower() == login.lower()
                               for owner in (machine.owners or [])):
                return True
        try:
            permission = await self.proxy.collaborator_permission(repo, login)
        except Exception:
            permission = ''
        return self.policy.collaborator_can_approve(permission)

    @staticmethod
    def _validate_proof_context(principal, repo, pr_number, head_sha, round_id):
        """Require the HTTP layer's comment-proof identity to match this write."""
        proof = principal.get('evidence_auth')
        if (principal.get('actor_verified') is not True or not isinstance(proof, dict)
                or proof.get('repo') != repo or proof.get('pr_number') != pr_number
                or type(proof.get('comment_id')) is not int or proof['comment_id'] <= 0
                or proof.get('head_sha') != head_sha or proof.get('round_id') != round_id
                or not re.fullmatch(r'[0-9a-f]{64}', str(proof.get('proof', '')))
                or not re.fullmatch(r'[0-9a-f]{64}', str(proof.get('nonce', '')))):
            raise EvidenceError('evidence_authorization_invalid', 403)

    async def _consume_auth_nonce(self, principal):
        """Consume request replay protection in process memory, not GitHub comments.

        Business mutations remain idempotent through their durable operation IDs;
        short-lived per-request nonces must not create permanent records for every
        signed multipart part URL.
        """
        proof = principal['evidence_auth']
        nonce_key = hashlib.sha256(
            f"{principal['id']}:{proof['nonce']}".encode('utf-8')
        ).hexdigest()
        now = time.monotonic()
        for key, expires in list(self._used_auth_nonces.items()):
            if expires <= now:
                self._used_auth_nonces.pop(key, None)
        if nonce_key in self._used_auth_nonces:
            raise EvidenceError('evidence_request_replayed', 409)
        if len(self._used_auth_nonces) >= 100_000:
            raise EvidenceError('evidence_request_replay_cache_full', 503)
        self._used_auth_nonces[nonce_key] = now + 24 * 60 * 60

    async def _save(self, repo, pr_number, kind, operation, phase):
        operation['updated_at'] = utc_now()
        key = operation['operation_id'] + ':' + phase
        record = await self.proxy.write_evidence_record(repo, pr_number, kind, key, operation)
        canonical = copy.deepcopy(record['data'])
        operation.clear()
        operation.update(canonical)
        return record

    def _trusted_upload_notification(self, comment, marker):
        if not isinstance(comment, dict) or not callable(
                getattr(self.proxy, 'is_bot_comment', None)):
            return False
        body = comment.get('body')
        user = comment.get('user')
        if (not isinstance(body, str)
                or marker.strip() not in [line.strip() for line in body.splitlines()]
                or not self.proxy.is_bot_comment(comment)
                or not isinstance(user, dict)
                or isinstance(user.get('id'), bool)
                or not isinstance(user.get('id'), int) or user['id'] <= 0
                or not isinstance(user.get('login'), str) or not user['login']
                or user.get('type') not in (None, 'Bot')):
            return False
        return True

    async def _find_upload_notification(
        self, repo, pr_number, marker, *, expected_body=None, operation=None,
    ):
        comments = await self.proxy.get_issue_comments(repo, pr_number)
        if not isinstance(comments, list):
            raise EvidenceError('evidence_notification_read_failed', 503)
        return any(
            self._trusted_upload_notification(comment, marker)
            and (expected_body is None or self._notification_body_matches(
                comment.get('body'), expected_body, store=self.store,
                operation=operation,
            ))
            for comment in comments
        )

    async def _upload_notifications(self, repo, pr_number, marker):
        """Return every trusted App comment carrying this attachment marker."""
        comments = await self.proxy.get_issue_comments(repo, pr_number)
        if not isinstance(comments, list):
            raise EvidenceError('evidence_notification_read_failed', 503)
        return [comment for comment in comments
                if self._trusted_upload_notification(comment, marker)]

    async def _suppress_duplicate_upload_notifications(
        self, repo, matches, marker, keep_comment_id,
    ):
        """Hide any older duplicate success posts, preserving one trusted comment."""
        suppressed_body = (
            '<!-- deploy-approval-evidence-upload-duplicate-suppressed:'
            + hashlib.sha256(marker.encode('utf-8')).hexdigest() + ' -->'
        )
        for comment in matches:
            comment_id = comment.get('id') if isinstance(comment, dict) else None
            if comment_id == keep_comment_id:
                continue
            if (not isinstance(comment_id, int) or isinstance(comment_id, bool)
                    or comment_id <= 0):
                logger.error(
                    'evidence duplicate notification has invalid comment identity %s', repo,
                )
                return False
            if comment.get('body') == suppressed_body:
                continue
            try:
                updated = await self.proxy.update_comment(
                    repo, comment_id, suppressed_body,
                )
                if not isinstance(updated, dict) or updated.get('body') != suppressed_body:
                    updated = await self.proxy.get_comment(repo, comment_id)
            except Exception as exc:
                logger.error(
                    'evidence duplicate notification cleanup failed %s comment=%s exception=%s',
                    repo, comment_id, type(exc).__name__,
                )
                return False
            if (not isinstance(updated, dict) or updated.get('id') != comment_id
                    or updated.get('body') != suppressed_body):
                logger.error(
                    'evidence duplicate notification cleanup was not confirmed %s comment=%s',
                    repo, comment_id,
                )
                return False
        return True

    @classmethod
    def _notification_body_matches(cls, existing, desired, *, store=None, operation=None):
        """Compare comments ignoring per-signature query strings.

        COS signatures are time-dependent, so the same attachment renders a
        different URL query on each reconcile. Only the stable part of the
        link (host + decoded object path) decides whether a comment needs an
        in-place update; this prevents rewriting the same comment forever.
        When a store and operation are provided, any existing COS link that has
        expired or is within its 30-day renewal window is rejected so the
        comment is updated in place.
        """
        if not isinstance(existing, str) or not isinstance(desired, str):
            return False
        if "no description provided" in existing.lower():
            return False
        existing_visible = re.sub(r'<!--.*?-->', '', existing, flags=re.DOTALL).strip()
        if not existing_visible:
            return False
        pattern = re.compile(r'https://[^<>\s]+')

        def stable(match):
            return match.group(0).split('?', 1)[0]

        if pattern.sub(stable, existing) != pattern.sub(stable, desired):
            return False
        if store is not None and isinstance(operation, dict):
            object_key = operation.get('object_key')
            filename = operation.get('filename')
            attachment_id = operation.get('attachment_id')
            cos_host = getattr(store, 'projection_cos_host', '')
            if object_key and attachment_id and cos_host:
                now = int(time.time())
                for match in pattern.finditer(existing):
                    url = match.group(0)
                    if cos_host in url:
                        expiry = None
                        if callable(getattr(store, 'download_url_expiry', None)):
                            expiry = store.download_url_expiry(
                                url, key=object_key, filename=filename,
                                attachment_id=attachment_id,
                            )
                        if expiry is None and callable(getattr(store, 'projection_inline_url_expiry', None)):
                            expiry = store.projection_inline_url_expiry(
                                url, key=object_key, filename=filename,
                                attachment_id=attachment_id,
                            )
                        if expiry is None or expiry - now <= 30 * 24 * 3600:
                            return False
        return True

    def _notification_identity(self, operation):
        if not isinstance(operation, dict):
            return None
        head_sha, round_id = operation.get('head_sha'), operation.get('round_id')
        attachment_id = operation.get('attachment_id')
        if not all(isinstance(value, str) and value
                   for value in (head_sha, round_id, attachment_id)):
            return None
        return (operation.get('repo'), operation.get('pr_number'),
                head_sha, round_id, attachment_id)

    def _remember_notification(self, operation, state):
        identity = self._notification_identity(operation)
        if identity is None:
            return
        self._notification_states[identity] = state
        while len(self._notification_states) > 8192:
            self._notification_states.pop(next(iter(self._notification_states)))

    def notification_state_for(self, repo, pr_number, operation):
        """Return this process's last known display state for one attachment."""
        identity = self._notification_identity(operation)
        if identity is None or identity[0] != repo or identity[1] != pr_number:
            return None
        return self._notification_states.get(identity)

    def _rotate_notification_rows(self, repo, pr_number, rows):
        ordered = sorted(
            rows,
            key=lambda item: str(item.get('completed_at') or item.get('created_at') or ''),
        )
        cursor = self._notification_backfill_cursor.get((repo, pr_number))
        if cursor is None or not ordered:
            return ordered
        index = next((position for position, item in enumerate(ordered)
                      if item.get('attachment_id') == cursor), None)
        if index is None:
            return ordered
        return ordered[index + 1:] + ordered[:index + 1]

    def _remember_notification_cursor(self, repo, pr_number, operation):
        attachment_id = operation.get('attachment_id') if isinstance(operation, dict) else None
        if not isinstance(attachment_id, str) or not attachment_id:
            return
        key = (repo, pr_number)
        self._notification_backfill_cursor[key] = attachment_id
        while len(self._notification_backfill_cursor) > 4096:
            self._notification_backfill_cursor.pop(
                next(iter(self._notification_backfill_cursor)),
            )

    async def _verify_ready_attachment_object(self, operation):
        """Verify the exact persisted COS object before ready compensation or display."""
        if (not isinstance(operation, dict)
                or not isinstance(operation.get('object_key'), str)
                or not operation.get('object_key')
                or type(operation.get('size')) is not int
                or operation.get('size') <= 0
                or not isinstance(operation.get('sha256'), str)
                or re.fullmatch(r'[0-9a-f]{64}', operation['sha256']) is None):
            return False
        verifier = getattr(self.store, 'verify_object', None)
        if not callable(verifier):
            logger.error(
                'ready evidence COS verification unavailable %s#%s attachment=%s',
                operation.get('repo'), operation.get('pr_number'),
                operation.get('attachment_id'),
            )
            return False
        metadata = {
            name: operation.get(name)
            for name in ('repo', 'pr_number', 'head_sha', 'round_id', 'attachment_id')
        }
        try:
            result = await verifier(
                key=operation['object_key'], size=operation['size'],
                metadata=metadata, sha256=operation['sha256'],
            )
        except Exception as exc:
            logger.warning(
                'ready evidence COS object verification failed %s#%s attachment=%s exception=%s',
                operation.get('repo'), operation.get('pr_number'),
                operation.get('attachment_id'), type(exc).__name__,
            )
            return False
        if (not isinstance(result, dict) or result.get('verified') is not True
                or result.get('size') != operation['size']
                or result.get('sha256') != operation['sha256']
                or result.get('object_key') != operation['object_key']):
            logger.warning(
                'ready evidence COS object was not confirmed %s#%s attachment=%s',
                operation.get('repo'), operation.get('pr_number'),
                operation.get('attachment_id'),
            )
            return False
        return True

    @staticmethod
    def _restore_record_key(operation, state):
        identity = ':'.join(str(operation.get(name, '')) for name in (
            'repo', 'pr_number', 'head_sha', 'round_id', 'attachment_id',
        ))
        digest = hashlib.sha256(identity.encode('utf-8')).hexdigest()
        return f'cos-restore-{state}:{digest}'

    async def _record_ready_restore_state(self, repo, pr_number, operation, *, pending):
        """Persist a retry marker without rewriting the immutable ready record."""
        if (not isinstance(operation, dict)
                or operation.get('repo') != repo
                or operation.get('pr_number') != pr_number
                or not isinstance(operation.get('attachment_id'), str)
                or not operation.get('attachment_id')):
            logger.error(
                'ready evidence restore marker has invalid identity %s#%s', repo, pr_number,
            )
            return False
        record = copy.deepcopy(operation)
        if pending:
            record['cos_restore_pending'] = True
            # Keep this stable so a retry of the same immutable marker is idempotent.
            record['cos_restore_pending_reason'] = 'cos_object_not_verified'
        else:
            record['cos_restore_pending'] = False
            record.pop('cos_restore_pending_reason', None)
        record['updated_at'] = utc_now()
        marker_state = 'pending' if pending else 'verified'
        try:
            saved = await self.proxy.write_evidence_record(
                repo, pr_number, 'attachment',
                self._restore_record_key(operation, marker_state), record,
            )
        except Exception as exc:
            logger.error(
                'ready evidence restore marker persistence failed %s#%s attachment=%s pending=%s exception=%s',
                repo, pr_number, operation.get('attachment_id'), pending,
                type(exc).__name__,
            )
            return False
        if (not isinstance(saved, dict) or not isinstance(saved.get('data'), dict)
                or saved['data'].get('attachment_id') != operation.get('attachment_id')
                or saved['data'].get('cos_restore_pending') is pending):
            logger.error(
                'ready evidence restore marker readback failed %s#%s attachment=%s pending=%s',
                repo, pr_number, operation.get('attachment_id'), pending,
            )
            return False
        return True

    async def _prepare_ready_attachment_object(self, repo, pr_number, operation):
        """Return a notification state unless COS and its recovery marker are verified."""
        if not await self._verify_ready_attachment_object(operation):
            if await self._record_ready_restore_state(
                    repo, pr_number, operation, pending=True):
                return False, NOTIFICATION_RESTORE_PENDING
            return False, NOTIFICATION_RESTORE_FAILED
        if operation.get('cos_restore_pending') is True:
            if not await self._record_ready_restore_state(
                    repo, pr_number, operation, pending=False):
                return False, NOTIFICATION_FAILED
        return True, ''

    def _cos_display_links(self, repo, pr_number, operation, filename):
        """Return ``(download_url, preview_url, validator)`` or None.

        Used only while no durable public origin exists. Each URL is signed by
        the trusted store from the persisted object identity, never from
        browser input, and the validator re-checks the exact object key and
        signature window. Quick Tunnel hostnames can never pass because only
        the configured COS bucket host is accepted by the validator.
        """
        store = self.store
        sign = getattr(store, 'sign_summary_attachment', None)
        if not callable(sign):
            return None
        return store, sign

    async def _temporary_cos_notification_links(self, repo, pr_number, operation, filename):
        bound = self._cos_display_links(repo, pr_number, operation, filename)
        if bound is None:
            return None
        store, sign = bound
        try:
            download = await sign(repo=repo, pr_number=pr_number, operation=operation)
            preview = await sign(
                repo=repo, pr_number=pr_number, operation=operation, inline=True,
            )
        except Exception as exc:
            logger.warning(
                'evidence temporary COS display unavailable %s#%s exception=%s',
                repo, pr_number, type(exc).__name__,
            )
            return None
        object_key = operation.get('object_key')

        def validator(url, action):
            try:
                if action == 'preview':
                    expiry = store.projection_inline_url_expiry(
                        url, key=object_key, filename=filename,
                        attachment_id=operation.get('attachment_id'),
                    )
                else:
                    expiry = store.download_url_expiry(
                        url, key=object_key, filename=filename,
                        attachment_id=operation.get('attachment_id'),
                    )
            except (TypeError, ValueError, AttributeError):
                return False
            return expiry is not None and expiry > int(time.time())

        return download.get('url', ''), preview.get('url', ''), validator

    async def _ready_notification_context(self, repo, pr_number, operation):
        """Return ``(state, marker, body)`` for one ready attachment.

        ``state`` is ``_NOTIFICATION_ELIGIBLE`` when a comment can be posted,
        ``NOTIFICATION_PENDING`` when the attachment is verified but no usable
        display origin exists yet, ``NOTIFICATION_SKIPPED`` when this record
        will never produce a visible notification, or ``NOTIFICATION_FAILED``
        when the comment body cannot be built safely.

        A durable Controller origin is preferred. While only an ephemeral
        ingress exists, a strictly validated COS link is used for display so
        the already-verified file is never hidden or asked to be re-uploaded;
        the comment is updated in place when the durable origin appears.
        """
        if (not isinstance(operation, dict)
                or str(operation.get('repo', '')).casefold() != str(repo).casefold()
                or type(operation.get('pr_number')) is not int
                or type(pr_number) is not int
                or operation.get('pr_number') != pr_number
                or operation.get('status') != 'ready'
                or operation.get('cos_content_verified') is not True
                or operation.get('deleted_at')
                or operation.get('evidence_kind') == 'note'
                or operation.get('internal_bot_note') is True
                or self._is_internal_bot_note(operation)
                or not isinstance(operation.get('object_key'), str)
                or not operation['object_key']
                or type(operation.get('size')) is not int or operation['size'] <= 0
                or not isinstance(operation.get('sha256'), str)
                or re.fullmatch(r'[0-9a-f]{64}', operation['sha256']) is None):
            return NOTIFICATION_SKIPPED, '', ''
        head_sha, round_id = operation.get('head_sha'), operation.get('round_id')
        attachment_id = operation.get('attachment_id')
        filename = operation.get('filename')
        if (not isinstance(head_sha, str)
                or re.fullmatch(r'[0-9a-f]{40}', head_sha) is None
                or not isinstance(round_id, str)
                or re.fullmatch(re.escape(head_sha) + r'-[0-9]+', round_id) is None
                or not isinstance(attachment_id, str)
                or re.fullmatch(r'[A-Za-z0-9_-]{1,128}', attachment_id) is None
                or not isinstance(filename, str) or not filename.strip()):
            return NOTIFICATION_SKIPPED, '', ''
        if PurePosixPath(filename).suffix.lower() not in _COMMENTABLE_MEDIA_SUFFIXES:
            return NOTIFICATION_SKIPPED, '', ''

        from . import comments as comments_mod, evidence_auth
        from .config import is_stable_public_base_url
        public_base = getattr(self.config, 'evidence_public_base_url', '')
        try:
            if is_stable_public_base_url(public_base):
                capability = evidence_auth.issue_capability(
                    self.config, repo, pr_number, head_sha, round_id,
                    purpose=DOWNLOAD_PURPOSE,
                    resource='attachment:' + attachment_id,
                    expires_at=int(time.time()) + evidence_auth.DOWNLOAD_MAX_LIFETIME_SECONDS,
                )
                download_url = comments_mod.stable_attachment_url(
                    repo, pr_number, attachment_id, capability,
                    action='download', public_base_url=public_base,
                )
                preview_url = comments_mod.stable_attachment_url(
                    repo, pr_number, attachment_id, capability,
                    action='preview', public_base_url=public_base,
                )
                body = comments_mod.evidence_upload_comment(
                    repo, pr_number, head_sha, round_id, attachment_id, filename,
                    download_url=download_url, preview_url=preview_url,
                    public_base_url=public_base,
                )
            else:
                temporary = await self._temporary_cos_notification_links(
                    repo, pr_number, operation, filename,
                )
                if temporary is None:
                    return NOTIFICATION_PENDING, '', ''
                download_url, preview_url, validator = temporary
                body = comments_mod.evidence_upload_comment(
                    repo, pr_number, head_sha, round_id, attachment_id, filename,
                    download_url=download_url, preview_url=preview_url,
                    public_base_url='', cos_url_validator=validator,
                )
        except Exception as exc:
            logger.warning(
                'evidence ready notification link unavailable %s#%s exception=%s',
                repo, pr_number, type(exc).__name__,
            )
            return NOTIFICATION_PENDING, '', ''
        if not body:
            logger.warning(
                'evidence ready notification skipped %s#%s: attachment link unavailable',
                repo, pr_number,
            )
            return NOTIFICATION_PENDING, '', ''
        marker = next((line for line in body.splitlines()
                       if re.fullmatch(
                           r'<!-- deploy-approval-evidence-upload:[0-9a-f]{64} -->', line,
                       )), '')
        if not marker:
            return NOTIFICATION_FAILED, '', ''
        if f'(<{download_url}>)' not in body:
            logger.error(
                'evidence ready notification has no bound download link %s#%s attachment=%s',
                repo, pr_number, attachment_id,
            )
            return NOTIFICATION_FAILED, '', ''
        visible_text = re.sub(r'<!--.*?-->', '', body, flags=re.DOTALL).strip()
        if not visible_text or "no description provided" in visible_text.lower():
            logger.warning(
                'evidence ready notification skipped %s#%s: body lacks visible description',
                repo, pr_number,
            )
            return NOTIFICATION_FAILED, '', ''
        return _NOTIFICATION_ELIGIBLE, marker, body

    async def _notify_ready_attachment(
        self, repo, pr_number, operation, *, hint=True, object_verified=False,
    ):
        """Ensure exactly one visible success comment for one ready attachment.

        Returns a ``NOTIFICATION_*`` state. A deterministic marker plus a
        trusted App-authored comment keeps duplicate complete/resume calls, a
        Controller restart and the post-deploy reconcile idempotent. If an
        earlier comment exists it is updated in place (for example when the
        durable public origin or a renewed COS signature appears); a second
        visible comment is never created. When the POST outcome is unclear the
        comment is read back once and never blindly re-posted.
        """
        candidate = (
            isinstance(operation, dict)
            and operation.get('status') == 'ready'
            and operation.get('cos_content_verified') is True
            and not operation.get('deleted_at')
            and operation.get('evidence_kind') != 'note'
            and operation.get('internal_bot_note') is not True
            and not self._is_internal_bot_note(operation)
        )
        async with self._notification_lock:
            try:
                if candidate and not object_verified:
                    object_verified, state = await self._prepare_ready_attachment_object(
                        repo, pr_number, operation,
                    )
                    if not object_verified:
                        self._remember_notification(operation, state)
                    else:
                        state = await self._notify_ready_attachment_state(
                            repo, pr_number, operation,
                        )
                else:
                    state = await self._notify_ready_attachment_state(
                        repo, pr_number, operation,
                    )
            except Exception as exc:
                logger.warning(
                    'evidence ready notification failed %s#%s exception=%s',
                    repo, pr_number, type(exc).__name__,
                )
                state = NOTIFICATION_FAILED
        self._remember_notification(operation, state)
        if hint and state in (
                NOTIFICATION_SYNCED, NOTIFICATION_PENDING,
                NOTIFICATION_RESTORE_PENDING, NOTIFICATION_RESTORE_FAILED,
                NOTIFICATION_FAILED):
            # The watcher owns Summary projection. A ready event (or a still
            # deferred display, or a failed comment write) hands it one bounded
            # hint instead of relying on the PR updated_at refresh window.
            self._hint_ready_sync(repo, pr_number)
        return state

    async def _notify_ready_attachment_state(self, repo, pr_number, operation):
        state = await self._notify_ready_attachment_state_impl(
            repo, pr_number, operation,
        )
        self._remember_notification(operation, state)
        return state

    async def _notify_ready_attachment_state_impl(self, repo, pr_number, operation):
        state, marker, body = await self._ready_notification_context(
            repo, pr_number, operation,
        )
        if state == NOTIFICATION_PENDING:
            logger.info(
                'evidence ready notification deferred %s#%s: no display origin available',
                repo, pr_number,
            )
            return state
        if state != _NOTIFICATION_ELIGIBLE:
            return state

        try:
            matches = await self._upload_notifications(repo, pr_number, marker)
        except Exception as exc:
            logger.warning(
                'evidence ready notification dedupe read failed %s#%s exception=%s; not posting',
                repo, pr_number, type(exc).__name__,
            )
            return NOTIFICATION_FAILED

        if matches:
            comment = matches[0]
            existing_body = comment.get('body')
            comment_id = comment.get('id')
            if (not isinstance(comment_id, int) or isinstance(comment_id, bool)
                    or comment_id <= 0):
                return NOTIFICATION_FAILED
            if len(matches) > 1 and not await self._suppress_duplicate_upload_notifications(
                    repo, matches, marker, comment_id):
                return NOTIFICATION_FAILED
            if self._notification_body_matches(existing_body, body, store=self.store, operation=operation):
                return NOTIFICATION_SYNCED
            try:
                updated = await self.proxy.update_comment(repo, comment_id, body)
            except Exception as exc:
                # A lost PATCH response may still have applied. Re-read once.
                try:
                    rechecked = await self._upload_notifications(
                        repo, pr_number, marker,
                    )
                except Exception as read_exc:
                    logger.warning(
                        'evidence notification update outcome unknown %s#%s patch=%s read=%s',
                        repo, pr_number, type(exc).__name__, type(read_exc).__name__,
                    )
                    return NOTIFICATION_FAILED
                if any(self._notification_body_matches(item.get('body'), body, store=self.store, operation=operation)
                       for item in rechecked):
                    return NOTIFICATION_SYNCED
                logger.warning(
                    'evidence notification update not confirmed %s#%s exception=%s; not reposting',
                    repo, pr_number, type(exc).__name__,
                )
                return NOTIFICATION_FAILED
            if (self._trusted_upload_notification(updated, marker)
                    and self._notification_body_matches(
                        updated.get('body'), body, store=self.store,
                        operation=operation,
                    )):
                return NOTIFICATION_SYNCED
            try:
                rechecked = await self._upload_notifications(repo, pr_number, marker)
            except Exception as exc:
                logger.warning(
                    'evidence notification update confirmation read failed %s#%s exception=%s',
                    repo, pr_number, type(exc).__name__,
                )
                return NOTIFICATION_FAILED
            if any(self._notification_body_matches(item.get('body'), body, store=self.store, operation=operation)
                   for item in rechecked):
                return NOTIFICATION_SYNCED
            return NOTIFICATION_FAILED

        try:
            posted = await self.proxy.post_issue_comment(repo, pr_number, body)
        except Exception as exc:
            # A timeout can happen after GitHub accepted the POST. Confirm the
            # deterministic marker before reporting uncertainty; never retry
            # the POST from this request.
            try:
                confirmed = await self._find_upload_notification(
                    repo, pr_number, marker, expected_body=body,
                    operation=operation,
                )
            except Exception as read_exc:
                logger.warning(
                    'evidence ready notification outcome unknown %s#%s post=%s read=%s',
                    repo, pr_number, type(exc).__name__, type(read_exc).__name__,
                )
                return NOTIFICATION_FAILED
            if confirmed:
                return NOTIFICATION_SYNCED
            logger.warning(
                'evidence ready notification was not confirmed %s#%s exception=%s; not reposting',
                repo, pr_number, type(exc).__name__,
            )
            return NOTIFICATION_FAILED

        if (self._trusted_upload_notification(posted, marker)
                and self._notification_body_matches(
                    posted.get('body'), body, store=self.store,
                    operation=operation,
                )):
            return NOTIFICATION_SYNCED
        try:
            if await self._find_upload_notification(
                    repo, pr_number, marker, expected_body=body,
                    operation=operation):
                return NOTIFICATION_SYNCED
        except Exception as exc:
            logger.warning(
                'evidence ready notification confirmation failed %s#%s exception=%s',
                repo, pr_number, type(exc).__name__,
            )
            return NOTIFICATION_FAILED
        logger.warning(
            'evidence ready notification post was not confirmed %s#%s; not reposting',
            repo, pr_number,
        )
        return NOTIFICATION_FAILED

    def bind_ready_sync_scheduler(self, scheduler):
        """Bind the serial watcher's evidence-sync queue, when available.

        The watcher remains the only lifecycle writer. This service only hands
        it bounded hints; every hint is revalidated against persisted records
        and the live PR before anything is written.
        """
        self._ready_sync_scheduler = scheduler if callable(scheduler) else None

    def _hint_ready_sync(self, repo, pr_number):
        scheduler = self._ready_sync_scheduler
        if not callable(scheduler):
            logger.warning(
                'evidence ready sync hint has no scheduler %s#%s', repo, pr_number,
            )
            return False
        try:
            accepted = scheduler(repo, pr_number)
        except Exception as exc:
            logger.warning(
                'evidence ready sync hint failed %s#%s exception=%s',
                repo, pr_number, type(exc).__name__,
            )
            return False
        if accepted is False:
            logger.warning(
                'evidence ready sync hint was rejected %s#%s; watcher will retry on a later scan',
                repo, pr_number,
            )
            return False
        return True

    def schedule_ready_notification_backfill(self, repo, pr_number):
        """Ask the serial writer to reconcile ready attachments.

        Called from read-only paths (page poll, Summary projection) and from
        the ready event itself. It no longer requires a persistent origin:
        while only an ephemeral public ingress exists the visible comment and
        Summary use verified COS links, and both are updated in place when a
        durable origin appears. The interval throttle also prevents a
        projection from feeding itself through this read-only hook.
        """
        if not self._notification_backfill_due(repo, pr_number):
            return
        if callable(self._ready_sync_scheduler):
            self._hint_ready_sync(repo, pr_number)
            return
        task = asyncio.create_task(
            self._backfill_ready_notifications_once(repo, pr_number))

        def observe_backfill(done):
            if done.cancelled():
                return
            try:
                error = done.exception()
            except Exception as exc:
                error = exc
            if error is not None:
                logger.error(
                    'evidence notification backfill task failed %s#%s exception=%s',
                    repo, pr_number, type(error).__name__,
                )

        task.add_done_callback(observe_backfill)

    def _notification_backfill_due(self, repo, pr_number):
        """Bound the reconcile to once per interval per PR in this process."""
        key = (repo, pr_number)
        now = time.monotonic()
        last = self._notification_backfill_runs.get(key)
        if last is not None and now - last < NOTIFICATION_BACKFILL_INTERVAL_SECONDS:
            return False
        self._notification_backfill_runs[key] = now
        while len(self._notification_backfill_runs) > 4096:
            self._notification_backfill_runs.pop(
                next(iter(self._notification_backfill_runs)),
            )
        return True

    async def backfill_ready_notifications(self, repo, pr_number):
        """Throttled entry point for the ready-attachment reconcile."""
        if not self._notification_backfill_due(repo, pr_number):
            return 0
        return await self._backfill_ready_notifications_once(repo, pr_number)

    @staticmethod
    def _upload_notification_marker(operation):
        """Return the deterministic visible-comment marker for one attachment."""
        if not isinstance(operation, dict):
            return ''
        repo, pr_number = operation.get('repo'), operation.get('pr_number')
        head_sha, round_id = operation.get('head_sha'), operation.get('round_id')
        attachment_id = operation.get('attachment_id')
        if (not isinstance(repo, str) or not repo
                or type(pr_number) is not int or pr_number <= 0
                or not isinstance(head_sha, str) or not head_sha
                or not isinstance(round_id, str) or not round_id
                or not isinstance(attachment_id, str) or not attachment_id):
            return ''
        key = hashlib.sha256(
            f"{repo}:{pr_number}:{head_sha}:{round_id}:{attachment_id}".encode('utf-8')
        ).hexdigest()
        return f'<!-- deploy-approval-evidence-upload:{key} -->'

    @staticmethod
    def _summary_contains_attachment(visible, operation):
        """Whether the trusted Summary already exposes this exact attachment.

        A verified attachment link always carries its attachment id (either in
        the Controller route or inside the COS object path), so identity is
        decided by that id or the full object key; a filename alone is not
        enough to claim the row is projected.
        """
        if not isinstance(visible, str) or not visible:
            return False
        attachment_id = operation.get('attachment_id')
        object_key = operation.get('object_key')
        # COS URLs percent-encode spaces and non-ASCII filenames, so compare
        # against both the raw and decoded visible Summary text.
        candidates = {visible}
        try:
            candidates.add(unquote(visible))
        except (TypeError, ValueError):
            pass
        if isinstance(attachment_id, str) and attachment_id:
            if any(attachment_id in text for text in candidates):
                return True
        if isinstance(object_key, str) and object_key:
            if any(object_key in text for text in candidates):
                return True
        return False

    def _summary_link_valid(self, visible, operation):
        """Whether the Summary's display link for this attachment is currently valid.

        If a stable public origin is configured, the Summary should carry that
        origin; while only temporary ingress exists, any COS link in the
        Summary must pass validation and must not be inside the 30-day renewal
        window. A Quick Tunnel URL in the Summary is never considered valid.
        """
        if not isinstance(visible, str) or not visible:
            return False
        if not isinstance(operation, dict):
            return True
        attachment_id = operation.get('attachment_id')
        object_key = operation.get('object_key')
        if not attachment_id or not object_key:
            return True
        from .config import is_stable_public_base_url
        public_base = getattr(self.config, 'evidence_public_base_url', '')
        has_stable_base = is_stable_public_base_url(public_base)

        pattern = re.compile(r'<(?P<url>https://[^<>\s]+)>')
        matching_urls = []
        for match in pattern.finditer(visible):
            candidate = match.group('url')
            if attachment_id in candidate or object_key in candidate or unquote(candidate).find(object_key) >= 0:
                matching_urls.append(candidate)
        if not matching_urls:
            return False
        for url in matching_urls:
            if 'trycloudflare.com' in url:
                return False
            cos_host = getattr(self.store, 'projection_cos_host', '')
            if has_stable_base:
                if cos_host and cos_host in url:
                    return False
            elif cos_host and cos_host in url:
                now = int(time.time())
                expiry = None
                if callable(getattr(self.store, 'download_url_expiry', None)):
                    expiry = self.store.download_url_expiry(
                        url, key=object_key, filename=operation.get('filename'),
                        attachment_id=attachment_id,
                    )
                if expiry is None and callable(getattr(self.store, 'projection_inline_url_expiry', None)):
                    expiry = self.store.projection_inline_url_expiry(
                        url, key=object_key, filename=operation.get('filename'),
                        attachment_id=attachment_id,
                    )
                if expiry is None or expiry - now <= 30 * 24 * 3600:
                    return False
        return True

    async def reconcile_ready_evidence(self, repo, pr_number, *, notify=True):
        """Reconcile one PR's ready attachments: comment, links, Summary.

        Strictly bound to the live HEAD/round from the trusted lifecycle
        state. Returns bounded counters plus ``needs_projection`` so the
        serial watcher can re-project the Summary without relying on the PR
        ``updated_at`` version. No attachment is ever modified or deleted.
        """
        result = {
            'ready': 0, 'synced': 0, 'pending': 0, 'failed': 0,
            'restore_pending': 0, 'skipped': 0,
            'needs_projection': False, 'error': '',
        }
        try:
            records = await self.proxy.read_evidence_records(repo, pr_number)
        except Exception as exc:
            logger.warning(
                'evidence ready reconcile read failed %s#%s exception=%s',
                repo, pr_number, type(exc).__name__,
            )
            result['error'] = 'records_unavailable'
            return result
        if not isinstance(records, (list, tuple)):
            result['error'] = 'records_unavailable'
            return result
        try:
            state = await self.proxy.read_hidden_state(repo, pr_number)
        except Exception as exc:
            logger.warning(
                'evidence ready reconcile state failed %s#%s exception=%s',
                repo, pr_number, type(exc).__name__,
            )
            result['error'] = 'state_unavailable'
            return result
        if not isinstance(state, dict):
            result['error'] = 'state_unavailable'
            return result
        if state.get('status') not in {'testing', 'succeeded', 'failed'}:
            return result
        try:
            live_round = round_id_for_state(state)
        except (EvidenceError, TypeError, ValueError):
            result['error'] = 'round_unavailable'
            return result
        head_sha = state.get('head_sha')

        latest = {}
        for record in records:
            if not isinstance(record, dict) or record.get('kind') != 'attachment':
                continue
            row = record.get('data')
            if not isinstance(row, dict):
                continue
            if (str(row.get('repo', '')).casefold() != str(repo).casefold()
                    or row.get('pr_number') != pr_number
                    or row.get('round_id') != live_round
                    or row.get('head_sha') != head_sha):
                continue
            identity = row.get('attachment_id')
            if not isinstance(identity, str) or not identity:
                continue
            # Immutable history may retain earlier revisions; the newest
            # record for an attachment is authoritative.
            latest[identity] = row

        rows = [row for row in latest.values()
                if row.get('status') == 'ready'
                and row.get('cos_content_verified') is True
                and not row.get('deleted_at')
                and row.get('evidence_kind') != 'note'
                and not row.get('internal_bot_note')
                and not self._is_internal_bot_note(row)]
        result['ready'] = len(rows)
        if not rows:
            return result
        ordered_rows = self._rotate_notification_rows(repo, pr_number, rows)
        verified_rows = []
        for row in ordered_rows:
            object_verified, verify_state = await self._prepare_ready_attachment_object(
                repo, pr_number, row,
            )
            if object_verified:
                verified_rows.append(row)
            elif verify_state == NOTIFICATION_RESTORE_PENDING:
                result['pending'] += 1
                result['restore_pending'] += 1
                result['needs_projection'] = True
            else:
                result['failed'] += 1
                result['needs_projection'] = True
        if not verified_rows:
            return result

        try:
            comment = await self.proxy.find_trusted_lifecycle_comment(repo, pr_number)
        except Exception as exc:
            logger.warning(
                'evidence ready reconcile lifecycle comment read failed %s#%s exception=%s',
                repo, pr_number, type(exc).__name__,
            )
            result['error'] = 'lifecycle_comment_unavailable'
            return result
        from .github_state_proxy import HIDDEN_STATE_MARKER
        visible = ''
        if isinstance(comment, dict) and isinstance(comment.get('body'), str):
            visible = comment['body'].split(HIDDEN_STATE_MARKER, 1)[0]

        unattempted_notifications = 0
        attempted = 0
        for row in verified_rows:
            commentable = (
                PurePosixPath(str(row.get('filename') or '')).suffix.lower()
                in _COMMENTABLE_MEDIA_SUFFIXES
            )
            if notify and not commentable:
                result['skipped'] += 1
            elif notify and attempted < NOTIFICATION_BACKFILL_MAX_PER_RUN:
                attempted += 1
                self._remember_notification_cursor(repo, pr_number, row)
                try:
                    notification = await self._notify_ready_attachment(
                        repo, pr_number, row, hint=False, object_verified=True,
                    )
                except Exception as exc:
                    logger.warning(
                        'evidence ready reconcile notify failed %s#%s exception=%s',
                        repo, pr_number, type(exc).__name__,
                    )
                    notification = NOTIFICATION_FAILED
                if notification in result:
                    result[notification] += 1
            elif notify and commentable:
                unattempted_notifications += 1
            if not self._summary_contains_attachment(visible, row) or not self._summary_link_valid(visible, row):
                result['needs_projection'] = True
        if unattempted_notifications:
            result['pending'] += 1
        if result.get('ready') and result.get('needs_projection'):
            logger.info(
                'evidence ready reconcile needs Summary projection %s#%s ready=%d',
                repo, pr_number, result['ready'],
            )
        return result

    async def _backfill_ready_notifications_once(self, repo, pr_number):
        """Announce and re-project already-ready attachments, bounded.

        Discovery is driven by persisted evidence records, not by a fixed
        public origin and not by the PR ``updated_at``. This is the restart
        recovery path: an attachment verified before the process restarted
        gets its single visible comment and its Summary link without any
        re-upload. It is idempotent through the deterministic marker and
        never touches the stored attachment when a write fails.
        """
        try:
            records = await self.proxy.read_evidence_records(repo, pr_number)
        except Exception as exc:
            logger.warning(
                'evidence notification backfill read failed %s#%s exception=%s',
                repo, pr_number, type(exc).__name__,
            )
            return 0
        if not isinstance(records, (list, tuple)):
            logger.warning(
                'evidence notification backfill returned malformed records %s#%s',
                repo, pr_number,
            )
            return 0
        try:
            state = await self.proxy.read_hidden_state(repo, pr_number)
        except Exception as exc:
            logger.warning(
                'evidence notification backfill state read failed %s#%s exception=%s',
                repo, pr_number, type(exc).__name__,
            )
            return 0
        if not isinstance(state, dict):
            logger.warning(
                'evidence notification backfill returned malformed lifecycle state %s#%s',
                repo, pr_number,
            )
            return 0
        if state.get('status') not in {'testing', 'succeeded', 'failed'}:
            return 0
        try:
            live_round = round_id_for_state(state)
        except (EvidenceError, TypeError, ValueError) as exc:
            logger.warning(
                'evidence notification backfill round resolution failed %s#%s exception=%s',
                repo, pr_number, type(exc).__name__,
            )
            return 0

        latest = {}
        for record in records:
            if not isinstance(record, dict) or record.get('kind') != 'attachment':
                continue
            row = record.get('data')
            if not isinstance(row, dict):
                continue
            if str(row.get('repo', '')).casefold() != str(repo).casefold() or row.get('pr_number') != pr_number:
                continue
            if row.get('round_id') != live_round or row.get('head_sha') != state.get('head_sha'):
                continue
            identity = (row.get('head_sha'), row.get('round_id'), row.get('attachment_id'))
            if not all(isinstance(value, str) and value for value in identity):
                continue
            latest[identity] = row

        synced = attempted = 0
        eligible = [row for row in latest.values()
                    if row.get('status') == 'ready'
                    and row.get('cos_content_verified') is True
                    and not row.get('deleted_at')
                    and row.get('evidence_kind') != 'note'
                    and row.get('internal_bot_note') is not True
                    and not self._is_internal_bot_note(row)
                    and PurePosixPath(str(row.get('filename') or '')).suffix.lower()
                    in _COMMENTABLE_MEDIA_SUFFIXES]
        for row in self._rotate_notification_rows(repo, pr_number, eligible):
            if attempted >= NOTIFICATION_BACKFILL_MAX_PER_RUN:
                break
            attempted += 1
            self._remember_notification_cursor(repo, pr_number, row)
            notification = await self._notify_ready_attachment(
                repo, pr_number, row, hint=False,
            )
            if notification == NOTIFICATION_SYNCED:
                synced += 1
        if synced:
            logger.info(
                'evidence notification backfill synced %d attachment(s) for %s#%s',
                synced, repo, pr_number,
            )
        if len(eligible) > attempted:
            logger.info(
                'evidence notification backfill has %d attachment(s) remaining for %s#%s',
                len(eligible) - attempted, repo, pr_number,
            )
        return synced

    async def _store(self, action, operation, payload):
        if self.store is None or not callable(getattr(self.store, 'dispatch', None)):
            raise EvidenceError('store_adapter_unavailable', 503)
        result = await self.store.dispatch(action, operation=copy.deepcopy(operation), payload=payload)
        if not isinstance(result, dict):
            raise EvidenceError('store_result_invalid', 502)
        return result

    def _trusted_deployment_logs(self, snapshot, repo, pr_number, head_sha, round_id):
        """Return only verified deployment-log facts from a trusted snapshot."""
        logs = snapshot.get('deployment_logs', {}) if isinstance(snapshot, dict) else {}
        if not isinstance(logs, dict):
            return {}
        output = {}
        for alias, item in logs.items():
            if (not isinstance(alias, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', alias)
                    or '..' in alias
                    or not isinstance(item, dict) or item.get('head_sha') != head_sha
                    or item.get('round_id') != round_id
                    or item.get('status') not in {'pending', 'ready', 'unavailable'}):
                continue
            row = {'head_sha': head_sha, 'round_id': round_id, 'status': item['status']}
            for field in ('collected_at', 'size', 'sha256'):
                if field in item:
                    row[field] = item[field]
            if item['status'] == 'ready' and self.controller._valid_cos_metadata(
                    repo, pr_number, head_sha, item):
                # Internal object_key is needed only by the trusted download path.
                row['object_key'] = item['object_key']
                from . import evidence_auth
                row['capability'] = evidence_auth.issue_capability(
                    self.config, repo, pr_number, head_sha, round_id,
                    purpose=DOWNLOAD_PURPOSE,
                    resource='log:' + round_id + ':' + alias,
                )
                output[alias] = row
            elif item['status'] == 'ready':
                continue
            else:
                output[alias] = row
        return output

    async def _degraded_current_context(self, repo, pr_number, principal, pr, state, payload, active_round):
        """Return a read-only current snapshot after the bounded history read times out."""
        expected_head = state.get('head_sha')
        requested_head = payload.get('head_sha', expected_head)
        requested_round = payload.get('round_id', active_round)
        if requested_head != expected_head or requested_round != active_round:
            raise EvidenceError('evidence_context_mismatch', 409)
        live_head = pr.get('head')
        if not isinstance(live_head, dict) or live_head.get('sha') != expected_head:
            raise EvidenceError('round_changed', 409)
        authorized_writer = await self._authorize(repo, principal, state, pr=pr)
        validate_context(pr, state, expected_head, active_round, write=False)

        invite = principal.get('upload_invite')
        invite_allowed = bool(
            isinstance(invite, dict)
            and invite.get('purpose') == UPLOAD_PURPOSE
            and principal.get('auth_method') == 'signed_invite'
            and principal.get('upload_method') == 'signed_invite'
            and principal.get('actor_verified') is False
            and principal.get('github_user_authenticated') is False
            and type(principal.get('id')) is int
            and (principal['id'] > 0 or principal['id'] == 0)
            and invite.get('repo') == repo and invite.get('pr') == pr_number
            and invite.get('head') == expected_head and invite.get('round') == active_round
            and invite.get('status') == 'testing'
            and type(invite.get('expires_at')) is int
            and invite['expires_at'] > int(time.time())
            and not pr.get('merged') and not pr.get('draft')
            and pr.get('base', {}).get('repo', {}).get('full_name', '').casefold() == repo.casefold()
            and pr.get('head', {}).get('sha') == expected_head
            and state.get('head_sha') == expected_head
            and state.get('status') == 'testing'
            and round_id_for_state(state) == active_round
        )
        invite_read_context = bool(
            isinstance(invite, dict)
            and invite.get('purpose') == UPLOAD_PURPOSE
            and invite.get('repo') == repo and invite.get('pr') == pr_number
            and invite.get('head') == expected_head and invite.get('round') == active_round
            and state.get('head_sha') == expected_head
            and round_id_for_state(state) == active_round
            and (state.get('status') != 'testing'
                 or pr.get('head', {}).get('sha') != expected_head
                 or pr.get('state') != 'open' or pr.get('merged'))
        )
        capability = principal.get('capability')
        if not principal.get('github_user_authenticated'):
            claims = invite if invite_read_context else capability
            context_capability = (
                isinstance(capability, dict)
                and (capability.get('purpose') == PURPOSE and 'resource' not in capability
                     or capability.get('purpose') == DOWNLOAD_PURPOSE
                     and capability.get('resource') == 'page')
            )
            if (not invite_allowed and (not isinstance(claims, dict)
                    or claims.get('repo') != repo or claims.get('pr') != pr_number
                    or claims.get('head') != expected_head or claims.get('round') != active_round
                    or not (invite_read_context or context_capability))):
                raise EvidenceError('capability_context_mismatch', 403)

        return {
            'repo': repo, 'pr_number': pr_number,
            'head_sha': expected_head, 'round_id': active_round,
            'round_started_at': state.get('round_started_at'),
            'status': state.get('status'), 'authenticated': True, 'enabled': True,
            'pr_state': pr.get('state'), 'merged': pr.get('merged') is True,
            'draft': pr.get('draft') is True,
            'github_user_authenticated': bool(
                principal.get('actor_verified') is True
                and principal.get('github_user_authenticated') is True),
            'can_write': bool((authorized_writer or invite_allowed)
                              and state.get('status') == 'testing'
                              and pr.get('head', {}).get('sha') == expected_head
                              and not pr.get('merged') and not pr.get('draft')),
            'evidence_degraded': True,
            'upload_invite': invite_allowed,
            'auth_method': principal.get('auth_method', 'github_comment_proof'),
            'actor_verified': principal.get('actor_verified') is True,
            'upload_method': principal.get('upload_method', 'github_comment_proof'),
        }

    async def _verified_note_display(self, row, repo, pr_number, principal):
        """Read a note only through its exact, verified persisted attachment identity."""
        from .evidence_builder import _redact_secrets
        fallback = _redact_secrets(str(row.get('note') or ''))
        fallback = re.sub(
            r'(?i)((?:x-evidence-secret|x-evidence-client-key|evidence-capability|capability|cap)\s*[=:]\s*)[^\s&;]+',
            r'\1[REDACTED]', fallback)
        incomplete = fallback + ('\n\n[历史备注仅保存了摘要，内容不完整]' if fallback
                                 else '[历史备注内容不完整]')
        try:
            claims = (principal.get('upload_invite') or principal.get('capability')
                      or principal.get('evidence_auth'))
            if (row.get('evidence_kind') != 'note'
                    or row.get('repo') != repo or row.get('pr_number') != pr_number
                    or not isinstance(claims, dict) or claims.get('repo') != repo
                    or claims.get('pr', claims.get('pr_number')) != pr_number
                    or claims.get('head', claims.get('head_sha')) != row.get('head_sha')
                    or claims.get('round', claims.get('round_id')) != row.get('round_id')
                    or row.get('filename') != 'note.txt'
                    or not isinstance(row.get('head_sha'), str)
                    or not re.fullmatch(r'[0-9a-f]{40}', row['head_sha'])
                    or not isinstance(row.get('round_id'), str)
                    or not re.fullmatch(re.escape(row['head_sha']) + r'-[0-9]+', row['round_id'])
                    or not isinstance(row.get('attachment_id'), str)
                    or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', row['attachment_id'])
                    or type(row.get('size')) is not int
                    or not 1 <= row['size'] <= min(64 * 1024, self.config.evidence_max_note_bytes)
                    or not isinstance(row.get('sha256'), str)
                    or not re.fullmatch(r'[0-9a-f]{64}', row['sha256'])):
                return incomplete, False
            if row.get('status') == 'text':
                text = row.get('note')
                if (not isinstance(text, str) or len(text) > 5000
                        or type(row.get('source_comment_id')) is not int
                        or row['source_comment_id'] <= 0
                        or type(row.get('actor_id')) is not int or row['actor_id'] <= 0
                        or row.get('actor_verified') is not True
                        or row.get('size') != len(text.encode('utf-8'))
                        or hashlib.sha256(text.encode('utf-8')).hexdigest() != row['sha256']):
                    return incomplete, False
                text = _redact_secrets(text)
                text = re.sub(
                    r'(?i)((?:[?&])?(?:cap|capability|x-evidence-secret|x-evidence-client-key)[=:=])[^&#\s]+',
                    r'\1[REDACTED]', text)
                return text, True
            if (self.store is None or row.get('status') != 'ready'
                    or row.get('cos_content_verified') is not True):
                return incomplete, False
            key = self.store._operation_key(row)
            if row.get('object_key') != key:
                return incomplete, False
            metadata = self.store._identity_metadata(row)
            verified = await self.store.verify_object(
                key=key, size=row['size'], metadata=metadata, sha256=row['sha256'])
            if (verified.get('verified') is not True or verified.get('size') != row['size']
                    or verified.get('sha256') != row['sha256'] or verified.get('object_key') != key):
                return incomplete, False

            def read_exact_note():
                client = self.store._sdk()
                args = {'Bucket': self.config.cos_bucket, 'Key': self.store._key(key)}
                head = client.head_object(**args)
                lowered = {str(k).lower(): str(v) for k, v in head.items()}
                expected = self.store._metadata(metadata)
                if (int(lowered.get('content-length', '-1')) != row['size']
                        or any(lowered.get(name.lower()) != str(value)
                               for name, value in expected.items())):
                    raise ValueError('note object identity mismatch')
                etag = head.get('ETag', head.get('etag'))
                if etag:
                    args['IfMatch'] = etag
                response = client.get_object(**args)
                stream = response['Body'].get_raw_stream()
                chunks, count = [], 0
                digest = hashlib.sha256()
                try:
                    while True:
                        block = stream.read(16 * 1024)
                        if not block:
                            break
                        count += len(block)
                        if count > row['size'] or count > self.config.evidence_max_note_bytes:
                            raise ValueError('note object exceeds bounds')
                        digest.update(block)
                        chunks.append(block)
                finally:
                    stream.close()
                if count != row['size'] or digest.hexdigest() != row['sha256']:
                    raise ValueError('note object digest mismatch')
                return b''.join(chunks)

            body = await self.store._io(read_exact_note)
            text = body.decode('utf-8', errors='strict')
            if len(text) > 5000:
                return incomplete, False
            text = _redact_secrets(text)
            # Redact page/session capabilities and evidence request keys too;
            # note text is never echoed into logs or stored in Git Notes.
            text = re.sub(
                r'(?i)((?:[?&])?(?:cap|capability|x-evidence-secret|x-evidence-client-key)[=:=])[^&#\s]+',
                r'\1[REDACTED]', text)
            return text, True
        except Exception:
            # COS SDK errors and malformed historical records are not public.
            return incomplete, False

    @staticmethod
    def _native_asset_id(source_url):
        """Accept only GitHub's native PR attachment URL shapes."""
        parsed = urlsplit(source_url)
        if (parsed.scheme != 'https' or parsed.hostname != 'github.com'
                or parsed.port not in (None, 443) or parsed.username or parsed.password
                or parsed.query or parsed.fragment):
            raise EvidenceError('attachment_url_not_allowed', 400)
        if not parsed.path.startswith('/user-attachments/'):
            raise EvidenceError('attachment_url_not_allowed', 400)
        parts = [unquote(part) for part in parsed.path.split('/') if part]
        if len(parts) < 3 or parts[0] != 'user-attachments':
            raise EvidenceError('attachment_url_not_allowed', 400)
        kind = parts[1]
        if kind == 'assets' and len(parts) == 3 and re.fullmatch(r'[A-Fa-f0-9-]{16,}', parts[2]):
            asset_id = parts[2]
        elif (kind == 'files' and len(parts) == 4
              and re.fullmatch(r'[1-9][0-9]*', parts[2])
              and re.fullmatch(r'[A-Za-z0-9._~-]+', parts[3])):
            asset_id = parts[2]
        else:
            raise EvidenceError('attachment_url_not_allowed', 400)
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', asset_id):
            raise EvidenceError('attachment_url_not_allowed', 400)
        return asset_id

    @staticmethod
    def _attachment_urls(body):
        found = []
        for value in re.findall(r'https://github\.com/user-attachments/(?:assets|files)/[^\s<>\])]+', body):
            value = value.rstrip('.,;')
            try:
                EvidenceService._native_asset_id(value)
            except EvidenceError:
                continue
            if value not in found:
                found.append(value)
        return found

    @staticmethod
    def _safe_download_host(host):
        if host == 'github.com':
            return True
        if host == 'githubusercontent.com' or host.endswith('.githubusercontent.com'):
            return True
        return bool(re.fullmatch(
            r'github-production-user-asset-[0-9a-f]{6}\.s3\.amazonaws\.com', host))

    @classmethod
    def _download_native_asset(cls, source_url, target, limit):
        """Stream a public GitHub attachment without forwarding credentials."""
        import requests

        current = source_url
        session = requests.Session()
        session.trust_env = False
        total = 0
        digest = hashlib.sha256()
        filename = ''
        content_type = ''
        prefix = bytearray()
        from .evidence_store import safe_filename

        started = time.monotonic()
        try:
            for redirect_count in range(4):
                parsed = urlsplit(current)
                host = (parsed.hostname or '').lower()
                if (parsed.scheme != 'https' or not cls._safe_download_host(host)
                        or parsed.port not in (None, 443) or parsed.username or parsed.password):
                    raise EvidenceError('attachment_redirect_not_allowed', 400)
                try:
                    addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
                except OSError:
                    raise EvidenceError('attachment_download_unavailable', 502) from None
                if (not addresses or any(not ipaddress.ip_address(item[4][0]).is_global
                                         for item in addresses)):
                    raise EvidenceError('attachment_redirect_not_allowed', 400)
                response = session.get(current, stream=True, allow_redirects=False,
                                       timeout=(10, 30), headers={'User-Agent': 'Deploy-Approval-Evidence/1.0',
                                                                  'Accept': 'application/octet-stream'})
                if response.is_redirect or response.is_permanent_redirect:
                    location = response.headers.get('Location', '')
                    response.close()
                    if redirect_count >= 3 or not location:
                        raise EvidenceError('attachment_redirect_not_allowed', 400)
                    current = urljoin(current, location)
                    continue
                if response.status_code != 200:
                    response.close()
                    raise EvidenceError('attachment_download_unavailable', 502)
                length = response.headers.get('Content-Length')
                if length:
                    try:
                        declared_size = int(length)
                    except ValueError:
                        response.close()
                        raise EvidenceError('attachment_download_invalid', 502) from None
                    if declared_size > limit:
                        response.close()
                        raise EvidenceError('attachment_too_large', 413)
                disposition = response.headers.get('Content-Disposition', '')
                content_type = response.headers.get('Content-Type', '').split(';', 1)[0].strip().lower()
                try:
                    from email.message import Message
                    header = Message()
                    header['Content-Disposition'] = disposition
                    filename = header.get_filename() or ''
                except (TypeError, ValueError):
                    filename = ''
                if not filename:
                    filename = unquote(urlsplit(current).path.rsplit('/', 1)[-1])
                if not filename:
                    filename = unquote(urlsplit(source_url).path.rsplit('/', 1)[-1])
                try:
                    from .evidence_store import safe_filename
                    filename = safe_filename(filename)
                except (ValueError, TypeError):
                    filename = 'attachment-' + hashlib.sha256(source_url.encode()).hexdigest()[:12]
                try:
                    for chunk in response.iter_content(chunk_size=1024 * 1024):
                        if not chunk:
                            continue
                        total += len(chunk)
                        if total > limit:
                            raise EvidenceError('attachment_too_large', 413)
                        if time.monotonic() - started > 300:
                            raise EvidenceError('attachment_download_timeout', 502)
                        if len(prefix) < 4096:
                            prefix.extend(chunk[:4096 - len(prefix)])
                        target.write(chunk)
                        digest.update(chunk)
                finally:
                    response.close()
                if total < 1:
                    raise EvidenceError('attachment_empty', 400)
                sample = bytes(prefix).lstrip(b'\xef\xbb\xbf \t\r\n').lower()
                error_markers = (
                    b'accessdenied', b'access denied', b'signaturedoesnotmatch',
                    b'request has expired', b'nosuchkey', b'no such key',
                    b'403 forbidden', b'404 not found', b'502 bad gateway',
                    b'503 service unavailable', b'request blocked',
                    b'internal server error', b'<title>error', b'<error',
                )
                if (sample.startswith((b'<!doctype html', b'<html', b'<?xml'))
                        and any(marker in sample for marker in error_markers)):
                    raise EvidenceError('attachment_source_error_content', 400)
                if (sample.startswith((b'<!doctype html', b'<html'))
                        and content_type not in {'text/html', 'application/xhtml+xml'}):
                    raise EvidenceError('attachment_source_error_content', 400)
                if any(sample.startswith(marker) for marker in error_markers):
                    raise EvidenceError('attachment_source_error_content', 400)

                suffix = PurePosixPath(filename).suffix.lower()
                if (sample.startswith((b'<!doctype html', b'<html'))
                        and content_type in {'text/html', 'application/xhtml+xml'}
                        and suffix not in {'.html', '.htm'}):
                    raise EvidenceError('attachment_source_error_content', 400)
                webm_signature = bytes(prefix).startswith(b'\x1a\x45\xdf\xa3')
                ftyp_signature = len(prefix) >= 8 and prefix[4:8] == b'ftyp'
                mp4_declared = (content_type == 'video/mp4'
                                or (suffix == '.mp4' and content_type != 'video/webm'))
                is_mp4 = mp4_declared or ftyp_signature
                if mp4_declared and not ftyp_signature:
                    raise EvidenceError('attachment_video_invalid', 400)
                if is_mp4:
                    target.flush()
                    offset = 0
                    box_count = 0
                    has_ftyp = False
                    has_media = False
                    while offset < total and box_count < 10000:
                        target.seek(offset)
                        box_header = target.read(8)
                        if len(box_header) != 8:
                            raise EvidenceError('attachment_video_invalid', 400)
                        box_size = int.from_bytes(box_header[:4], 'big')
                        box_type = box_header[4:8]
                        header_size = 8
                        if box_size == 1:
                            extended_size = target.read(8)
                            if len(extended_size) != 8:
                                raise EvidenceError('attachment_video_invalid', 400)
                            box_size = int.from_bytes(extended_size, 'big')
                            header_size = 16
                        elif box_size == 0:
                            box_size = total - offset
                        if (box_size < header_size or box_size > total - offset
                                or (box_count == 0 and box_type != b'ftyp')):
                            raise EvidenceError('attachment_video_invalid', 400)
                        if box_type == b'ftyp':
                            target.seek(offset + header_size)
                            major_brand = target.read(4)
                            if (box_size < header_size + 8
                                    or (box_size - header_size - 8) % 4
                                    or len(major_brand) != 4
                                    or any(char < 0x20 or char > 0x7e for char in major_brand)):
                                raise EvidenceError('attachment_video_invalid', 400)
                            has_ftyp = True
                        if box_type == b'mdat':
                            if box_size <= header_size:
                                raise EvidenceError('attachment_video_invalid', 400)
                            has_media = True
                        offset += box_size
                        box_count += 1
                    if (offset != total or (box_count >= 10000 and offset < total)
                            or not has_ftyp or not has_media):
                        raise EvidenceError('attachment_video_invalid', 400)

                extension_by_type = {
                    'video/mp4': '.mp4', 'video/webm': '.webm',
                    'video/quicktime': '.mov', 'image/jpeg': '.jpg',
                    'image/png': '.png', 'image/gif': '.gif',
                    'image/webp': '.webp', 'text/plain': '.txt',
                    'application/pdf': '.pdf', 'audio/mpeg': '.mp3',
                    'audio/wav': '.wav', 'audio/ogg': '.ogg',
                }
                inferred_extension = (
                    '.mp4' if is_mp4 else '.webm' if webm_signature
                    else extension_by_type.get(content_type, '')
                )
                if inferred_extension and not suffix:
                    filename += inferred_extension
                elif (inferred_extension and suffix != inferred_extension
                      and (is_mp4 or webm_signature or content_type.startswith('video/'))):
                    filename = filename[:-len(suffix)] + inferred_extension
                filename = safe_filename(filename)
                target.flush()
                target.seek(0)
                return {'filename': filename, 'size': total, 'sha256': digest.hexdigest(),
                        'content_type': content_type}
            raise EvidenceError('attachment_redirect_not_allowed', 400)
        finally:
            session.close()

    async def _native_identity(self, repo, pr_number, comment_id, expected_id, expected_login,
                               expected_body_hash=''):
        comment = await self.proxy.get_comment(repo, comment_id)
        issue_url = comment.get('issue_url', '') if isinstance(comment, dict) else ''
        body = comment.get('body', '') if isinstance(comment, dict) else ''
        if (not isinstance(comment, dict) or comment.get('id') != comment_id
                or not isinstance(issue_url, str)
                or issue_url.rstrip('/').split('/')[-1] != str(pr_number)
                or not isinstance(body, str)
                or (expected_body_hash and hashlib.sha256(body.encode()).hexdigest() != expected_body_hash)):
            raise EvidenceError('comment_unavailable', 409)
        actor_id, actor_login = await self.proxy.comment_identity(repo, comment_id)
        if (not actor_id or not actor_login or str(actor_id) != str(expected_id)
                or actor_login.casefold() != expected_login.casefold()):
            raise EvidenceError('comment_identity_changed', 403)
        return comment, int(actor_id), actor_login

    async def _native_authorization(self, repo, pr_number, actor_id, actor_login):
        if (not self.config.auth_valid or repo not in self.config.github_repos
                or repo not in self.config.active_repos):
            raise EvidenceError('repository_not_authorized', 403)
        if repo not in await self.github.list_installation_repositories():
            raise EvidenceError('app_access_revoked', 403)
        pr = self._require_pr_snapshot(await self.proxy.get_pr(repo, pr_number), repo)
        state = await self.proxy.read_hidden_state(repo, pr_number)
        if not isinstance(state, dict):
            raise EvidenceError('state_unavailable', 503)
        author = pr.get('user', {})
        if isinstance(author, dict) and str(author.get('id', '')) == str(actor_id):
            return pr, state, 'pr_author', ''
        deployed = {row.get('machine') for row in state.get('deployments', [])
                    if isinstance(row, dict) and row.get('phase') == 'deployed'}
        for alias in deployed:
            machine = self.policy.get_machine(alias) if isinstance(alias, str) else None
            if machine and any(isinstance(owner, str) and owner.casefold() == actor_login.casefold()
                               for owner in (machine.owners or [])):
                return pr, state, 'machine_owner', alias
        permission = await self.proxy.collaborator_permission(repo, actor_login)
        if self.policy.collaborator_can_approve(permission):
            return pr, state, 'collaborator', permission
        raise EvidenceError('evidence_write_permission_required', 403)

    @staticmethod
    def _comment_created_at(comment):
        value = comment.get('created_at')
        if not isinstance(value, str):
            raise EvidenceError('comment_time_invalid', 409)
        try:
            stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
            if stamp.tzinfo is None:
                raise ValueError
            return stamp.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')
        except ValueError:
            raise EvidenceError('comment_time_invalid', 409) from None

    async def handle_native_comment(self, **kwargs):
        """Serialize native comment writes with the existing Evidence writer."""
        async with self.controller._evidence_lock:
            return await self._handle_native_comment_locked(**kwargs)

    async def _handle_native_comment_locked(self, *, repo, pr_number, comment_id, actor_id,
                                            actor_login, action, arguments, automatic=False):
        """Transfer native PR attachments and append immutable evidence documents."""
        if action not in {'submit_evidence', 'remove_evidence'}:
            raise EvidenceError('unknown_action', 400)
        if automatic and action != 'submit_evidence':
            raise EvidenceError('unknown_action', 400)
        if repo not in {'4paradigm/phanthymotus', '4paradigm/phanthymotus-driver'}:
            raise EvidenceError('repository_not_authorized', 403)
        comment, actor_id, actor_login = await self._native_identity(
            repo, pr_number, comment_id, actor_id, actor_login)
        pr, state, role, role_value = await self._native_authorization(
            repo, pr_number, actor_id, actor_login)
        body = comment.get('body', '')
        if not isinstance(body, str):
            raise EvidenceError('comment_unavailable', 409)
        if automatic:
            from .commands import command_starts_line_any
            if command_starts_line_any(body):
                raise EvidenceError('comment_command_changed', 409)
            arguments = {}
        else:
            from .commands import parse_command
            parsed = parse_command(body)
            if parsed.kind != action or parsed.evidence_args != arguments:
                raise EvidenceError('comment_command_changed', 409)
        body_hash = hashlib.sha256(body.encode()).hexdigest()
        if automatic:
            head_sha = state.get('head_sha', '')
            round_id = round_id_for_state(state)
            arguments = {
                'head': head_sha, 'round': round_id,
                'machine': role_value if role == 'machine_owner' else '',
                'note': '', 'replaces': '',
            }
        else:
            head_sha = arguments.get('head', '')
            round_id = arguments.get('round', '')
        if (not re.fullmatch(r'[0-9a-f]{40}', head_sha)
                or state.get('head_sha') != head_sha or pr.get('head', {}).get('sha') != head_sha
                or round_id_for_state(state) != round_id):
            raise EvidenceError('round_changed', 409)
        if state.get('status') != 'testing':
            raise EvidenceError('context_not_writable', 409)
        created_at = self._comment_created_at(comment)

        def require_current_round_comment(current_state):
            if not automatic:
                return
            try:
                started_at = current_state.get('round_started_at')
                started = datetime.fromisoformat(str(started_at).replace('Z', '+00:00'))
                created = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                if started.tzinfo is None or created.tzinfo is None or created <= started:
                    raise ValueError
            except (TypeError, ValueError):
                raise EvidenceError('comment_before_round', 409) from None

        require_current_round_comment(state)

        async def recheck_current():
            fresh_comment, fresh_id, fresh_login = await self._native_identity(
                repo, pr_number, comment_id, actor_id, actor_login, body_hash)
            if automatic and fresh_comment.get('created_at') != comment.get('created_at'):
                raise EvidenceError('comment_time_invalid', 409)
            fresh_pr, fresh_state, _, _ = await self._native_authorization(
                repo, pr_number, fresh_id, fresh_login)
            if (fresh_pr.get('head', {}).get('sha') != head_sha
                    or fresh_state.get('head_sha') != head_sha
                    or round_id_for_state(fresh_state) != round_id
                    or fresh_state.get('status') != 'testing'):
                raise EvidenceError('round_changed', 409)
            require_current_round_comment(fresh_state)
            return fresh_pr, fresh_state

        records = await self.proxy.read_evidence_records(repo, pr_number)
        latest = {}
        prepared_operations = {}
        for record in records:
            if record['kind'] == 'attachment':
                latest[record['data'].get('attachment_id')] = record['data']
            elif record['kind'] == 'operation':
                data = record['data']
                if data.get('native_attachment') is True:
                    prepared_operations[data.get('attachment_id')] = data
        if action == 'remove_evidence':
            target_id = arguments.get('id', '')
            target = latest.get(target_id)
            if (not target or target.get('round_id') != round_id or target.get('head_sha') != head_sha
                    or target.get('status') == 'deleted'):
                raise EvidenceError('attachment_not_found', 404)
            uploader = str(target.get('actor_id')) == str(actor_id)
            await recheck_current()
            if not uploader:
                permission = await self.proxy.collaborator_permission(repo, actor_login)
                if permission not in {'maintain', 'admin'}:
                    raise EvidenceError('evidence_delete_permission_required', 403)
            tombstone = {**target, 'status': 'deleted', 'deleted_at': created_at,
                         'deleted_by': actor_login, 'deleted_by_id': actor_id,
                         'deletion_comment_id': comment_id, 'updated_at': created_at}
            await self.proxy.write_evidence_record(
                repo, pr_number, 'attachment', 'native-delete:' + str(comment_id) + ':' + target_id,
                tombstone)
            return tombstone

        urls = self._attachment_urls(body)
        if len(urls) > 10:
            raise EvidenceError('too_many_attachments', 413)
        replaces = arguments.get('replaces', '')
        if replaces and (len(urls) != 1 or replaces not in latest
                         or latest[replaces].get('round_id') != round_id):
            raise EvidenceError('replacement_not_found', 404)
        if arguments.get('machine'):
            alias = arguments['machine']
            deployed = {row.get('machine') for row in state.get('deployments', [])
                        if isinstance(row, dict) and row.get('phase') == 'deployed'}
            if alias not in deployed or self.policy.get_machine(alias) is None:
                raise EvidenceError('machine_not_deployed', 409)
            machine = self.policy.get_machine(alias)
            if (role == 'machine_owner' and role_value != alias
                    and not any(owner.casefold() == actor_login.casefold()
                                for owner in machine.owners or [])):
                raise EvidenceError('machine_owner_mismatch', 403)
        if automatic:
            note = re.sub(
                r'!?\[[^\]]*\]\(\s*https://github\.com/user-attachments/(?:assets|files)/[^)]*\)',
                '', body)
            note = re.sub(
                r'https://github\.com/user-attachments/(?:assets|files)/[^\s<>\])]+',
                '', note,
            ).strip()
        else:
            note = arguments.get('note', '').strip()
        if not note and not automatic:
            remaining = body.split('\n', 1)[1] if '\n' in body else ''
            remaining = re.sub(
                r'!?\[[^\]]*\]\(\s*https://github\.com/user-attachments/(?:assets|files)/[^)]*\)',
                '', remaining)
            remaining = re.sub(r'https://github\.com/user-attachments/(?:assets|files)/[^\s<>\])]+', '', remaining)
            note = remaining.strip()
        if len(note.encode('utf-8')) > self.config.evidence_max_note_bytes:
            raise EvidenceError('note_too_large', 413)
        if not urls:
            if not note:
                raise EvidenceError('evidence_content_required', 400)
            attachment_id = 'note-' + hashlib.sha256(
                f'{repo}:{pr_number}:{comment_id}'.encode()).hexdigest()[:48]
            data = {'repo': repo, 'pr_number': pr_number, 'source_comment_id': comment_id,
                    'source_url': '', 'attachment_id': attachment_id, 'filename': 'note.txt',
                    'size': len(note.encode('utf-8')), 'sha256': hashlib.sha256(note.encode('utf-8')).hexdigest(),
                    'object_key': '', 'head_sha': head_sha, 'round_id': round_id,
                    'actor_id': actor_id, 'actor_login': actor_login, 'actor_verified': True,
                    'machine': arguments.get('machine', ''), 'note': note,
                    'created_at': created_at, 'updated_at': created_at, 'status': 'text'}
            existing = latest.get(attachment_id)
            if existing:
                if (existing.get('source_comment_id') != comment_id
                        or existing.get('head_sha') != head_sha or existing.get('round_id') != round_id
                        or existing.get('actor_id') != actor_id or existing.get('note') != note
                        or existing.get('status') != 'text'):
                    raise EvidenceError('attachment_identity_conflict', 409)
                await recheck_current()
                return existing
            await recheck_current()
            await self.proxy.write_evidence_record(
                repo, pr_number, 'attachment', 'native:' + attachment_id, data)
            return data

        limit = min(int(getattr(self.config, 'evidence_max_file_bytes', 100 * 1024 * 1024)),
                    100 * 1024 * 1024)
        completed = []
        for source_url in urls:
            asset_id = self._native_asset_id(source_url)
            attachment_id = 'native-' + hashlib.sha256(
                f'{repo}:{pr_number}:{comment_id}:{asset_id}'.encode()).hexdigest()[:48]
            existing = latest.get(attachment_id)
            if existing:
                if (existing.get('source_comment_id') != comment_id
                        or existing.get('source_url') != source_url
                        or existing.get('head_sha') != head_sha or existing.get('round_id') != round_id):
                    raise EvidenceError('attachment_identity_conflict', 409)
                if existing.get('status') == 'ready':
                    completed.append(existing)
                    continue
                if existing.get('status') in {'deleted', 'invalid'}:
                    continue
            prepared = prepared_operations.get(attachment_id)
            metadata = {'repo': repo, 'pr_number': pr_number, 'head_sha': head_sha,
                        'round_id': round_id, 'attachment_id': attachment_id}
            if prepared and (prepared.get('source_url') != source_url
                             or prepared.get('source_comment_id') != comment_id
                             or prepared.get('actor_id') != actor_id
                             or prepared.get('head_sha') != head_sha
                             or prepared.get('round_id') != round_id
                             or prepared.get('machine', '') != arguments.get('machine', '')
                             or prepared.get('note', '') != note
                             or prepared.get('replaces_id', '') != replaces):
                raise EvidenceError('attachment_identity_conflict', 409)
            if prepared:
                record = {k: v for k, v in prepared.items() if k not in {'native_attachment', 'operation_id'}}
                key, size, sha = record['object_key'], record['size'], record['sha256']
                try:
                    result = await self.store.verify_object(
                        key=key, size=size, metadata=metadata, sha256=sha)
                except Exception:
                    result = None
            else:
                record = None
                result = None
            if result is None:
                if not callable(getattr(self.store, 'put_native_file', None)):
                    raise EvidenceError('store_adapter_unavailable', 503)
                with tempfile.TemporaryFile() as temp:
                    facts = await asyncio.to_thread(
                        self._download_native_asset, source_url, temp, limit)
                    from .evidence_store import build_attachment_key
                    key = build_attachment_key(repo, pr_number, head_sha, round_id,
                                               attachment_id, created_at, facts['filename'])
                    record = {'repo': repo, 'pr_number': pr_number, 'source_comment_id': comment_id,
                              'source_url': source_url, 'attachment_id': attachment_id,
                              'filename': facts['filename'], 'size': facts['size'], 'sha256': facts['sha256'],
                              'object_key': key, 'head_sha': head_sha, 'round_id': round_id,
                              'actor_id': actor_id, 'actor_login': actor_login, 'actor_verified': True,
                              'machine': arguments.get('machine', ''), 'note': note,
                              'created_at': created_at, 'updated_at': created_at, 'status': 'prepared'}
                    if replaces:
                        record['replaces_id'] = replaces
                    if prepared and any(record.get(k) != prepared.get(k)
                                        for k in ('filename', 'size', 'sha256', 'object_key')):
                        raise EvidenceError('attachment_retry_conflict', 409)
                    if not prepared:
                        await recheck_current()
                        prepared_data = {**record, 'native_attachment': True,
                                         'operation_id': attachment_id}
                        await self.proxy.write_evidence_record(
                            repo, pr_number, 'operation', 'native:' + attachment_id + ':prepared',
                            prepared_data)
                    await recheck_current()
                    result = await self.store.put_native_file(
                        key=key, metadata=metadata, size=facts['size'],
                        sha256=facts['sha256'], body=temp)
            if (not isinstance(result, dict) or result.get('verified') is not True
                    or result.get('size') != record['size'] or result.get('sha256') != record['sha256']
                    or result.get('object_key') != record['object_key']):
                raise EvidenceError('object_not_verified', 409)
            await recheck_current()
            record.update(status='ready', updated_at=created_at)
            await self.proxy.write_evidence_record(
                repo, pr_number, 'attachment', 'native:' + attachment_id, record)
            completed.append(record)
        return {'attachments': completed}

    async def dispatch(self, action: str, *, repo: str, pr_number: int, principal: dict, payload: dict) -> dict:
        if action not in {'context', 'status', 'init', 'resume', 'sign_part', 'put_part', 'complete', 'note', 'delete', 'download', 'preview', 'log_download', 'machine_log_download'}:
            raise EvidenceError('unknown_action', 400)
        if type(pr_number) is not int or pr_number <= 0 or not isinstance(payload, dict) or not isinstance(principal, dict):
            raise EvidenceError('invalid_request', 400)
        if (not self.config.auth_valid or repo not in self.config.github_repos
                or repo not in self.config.active_repos):
            raise EvidenceError('repository_not_authorized', 403)
        # A process-local serialization lock is scheduling, not persistence.
        # Operation identities and recovery facts live in Git Notes records;
        # the lifecycle comment remains the sole business-state projection.
        lock_context = (
            self.controller._evidence_lock
            if action not in {'put_part', 'context'} else _NoopAsyncContext()
        )
        async with lock_context:
            pr = self._require_pr_snapshot(await self.proxy.get_pr(repo, pr_number), repo)
            state = await self.proxy.read_hidden_state(repo, pr_number)
            if not isinstance(state, dict):
                raise EvidenceError('state_unavailable', 409)
            active_round = round_id_for_state(state)
            payload = dict(payload)
            current_context_read = (
                action == 'context'
                and payload.get('head_sha', state.get('head_sha')) == state.get('head_sha')
                and payload.get('round_id', active_round) == active_round
            )
            if current_context_read:
                history_read = asyncio.create_task(
                    self.proxy.read_evidence_records(repo, pr_number))
                completed, _ = await asyncio.wait(
                    {history_read}, timeout=_CURRENT_CONTEXT_HISTORY_TIMEOUT_SECONDS)
                if not completed:
                    history_read.cancel()
                    def observe_history_read(task):
                        if task.cancelled():
                            return
                        try:
                            error = task.exception()
                        except Exception as exc:
                            error = exc
                        if error is not None:
                            logger.warning(
                                'evidence context history task failed %s#%s exception=%s',
                                repo, pr_number, type(error).__name__,
                            )
                    history_read.add_done_callback(observe_history_read)
                    return await self._degraded_current_context(
                        repo, pr_number, principal, pr, state, payload, active_round,
                    )
                try:
                    records = history_read.result()
                    if not isinstance(records, (list, tuple)):
                        raise EvidenceError('evidence_records_unavailable', 503)
                except Exception as exc:
                    logger.warning(
                        'evidence context history read failed %s#%s exception=%s',
                        repo, pr_number, type(exc).__name__,
                    )
                    return await self._degraded_current_context(
                        repo, pr_number, principal, pr, state, payload, active_round,
                    )
            else:
                records = await self.proxy.read_evidence_records(repo, pr_number)
            round_numbers = trusted_round_numbers(records, state, repo, pr_number)
            if action in {'context', 'status'}:
                # Attachments verified before the fixed public origin existed
                # are announced here, once per throttle window, without
                # delaying the response or taking the upload lock. The page
                # polls ``status`` while a file uploads, so a deploy that
                # switches to the fixed domain is reconciled on the next poll.
                self.schedule_ready_notification_backfill(repo, pr_number)
            if action in {'resume', 'status'}:
                upload_ref = payload.get('operation_id') or payload.get('upload_id')
                if not isinstance(upload_ref, str) or not 1 <= len(upload_ref) <= 128:
                    raise EvidenceError('invalid_upload_id', 400)
                source = next((r['data'] for r in reversed(records) if r['kind'] == 'operation'
                               and r['data'].get('upload_ref') == upload_ref), None)
                if not source:
                    raise EvidenceError('operation_not_found', 404)
                if (source.get('actor_id') != principal.get('id')
                        or isinstance(principal.get('upload_invite'), dict)
                        and source.get('upload_method') != 'signed_invite'):
                    raise EvidenceError('upload_owner_mismatch', 403)
                if source.get('repo') != repo or source.get('pr_number') != pr_number:
                    raise EvidenceError('operation_not_found', 404)
                # Both endpoints bind to the durable operation. A historical
                # upload remains readable in its archived round; only POST
                # resume may perform recovery or persist a new phase.
                payload.setdefault('head_sha', source['head_sha'])
                payload.setdefault('round_id', source['round_id'])
            if action == 'resume':
                payload.setdefault('idempotency_key', hashlib.sha256(('resume:' + source['upload_ref']).encode()).hexdigest())
            if action in {'init', 'sign_part', 'put_part', 'complete', 'note', 'delete'}:
                if 'head_sha' not in payload or 'round_id' not in payload:
                    raise EvidenceError('explicit_context_required', 400)
            if action in {'download', 'preview'} and 'round_id' not in payload:
                claims = principal.get('capability')
                attachment_resource = 'attachment:' + str(payload.get('attachment_id', ''))
                if (isinstance(claims, dict)
                        and claims.get('purpose') == DOWNLOAD_PURPOSE
                        and claims.get('resource') == attachment_resource):
                    payload.setdefault('head_sha', claims.get('head'))
                    payload['round_id'] = claims.get('round')
                else:
                    targets = [r['data'] for r in records if r['kind'] == 'attachment'
                               and r['data'].get('attachment_id') == payload.get('attachment_id')]
                    if targets:
                        payload.setdefault('head_sha', targets[-1].get('head_sha'))
                        payload['round_id'] = targets[-1].get('round_id')
            round_id = payload.get('round_id', active_round)
            selected = state
            if round_id != active_round:
                if round_id not in round_numbers:
                    raise EvidenceError('round_not_found', 404)
                archives = [r['data'] for r in records if r['kind'] == 'round' and r['data'].get('round_id') == round_id
                            and r['data'].get('repo') == repo and r['data'].get('pr_number') == pr_number]
                if not archives:
                    raise EvidenceError('round_not_found', 404)
                selected = archives[-1]['snapshot']
            expected_head = payload.get('head_sha', selected.get('head_sha'))
            authorized_writer = await self._authorize(repo, principal, selected, pr=pr)
            write = action in {'init', 'resume', 'sign_part', 'put_part', 'complete', 'note', 'delete'}
            invite = principal.get('upload_invite')

            def invite_context_matches(target_pr, target_state, target_round):
                return bool(
                    isinstance(invite, dict)
                    and invite.get('purpose') == UPLOAD_PURPOSE
                    and principal.get('auth_method') == 'signed_invite'
                    and principal.get('upload_method') == 'signed_invite'
                    and principal.get('actor_verified') is False
                    and principal.get('github_user_authenticated') is False
                    and type(principal.get('id')) is int
                    and (principal['id'] > 0 or action == 'context' and principal['id'] == 0)
                    and invite.get('repo') == repo and invite.get('pr') == pr_number
                    and invite.get('head') == expected_head
                    and invite.get('round') == target_round
                    and invite.get('status') == 'testing'
                    and type(invite.get('expires_at')) is int
                    and invite['expires_at'] > int(time.time())
                    and isinstance(target_pr, dict) and target_pr.get('state') in {'open', 'closed'}
                    and not target_pr.get('merged') and not target_pr.get('draft')
                    and target_pr.get('base', {}).get('repo', {}).get('full_name', '').lower() == repo.lower()
                    and target_pr.get('head', {}).get('sha') == expected_head
                    and target_state.get('head_sha') == expected_head
                    and target_state.get('status') == 'testing'
                    and round_id_for_state(target_state) == target_round
                )

            invite_allowed = (action in {'context', 'status'} or write) and invite_context_matches(
                pr, selected, round_id)
            write_context_allowed = bool(
                (authorized_writer or invite_allowed)
                and round_id == active_round
                and selected.get('status') == 'testing'
                and selected.get('head_sha') == pr.get('head', {}).get('sha')
                and pr.get('state') in {'open', 'closed'} and not pr.get('merged')
                and not pr.get('draft')
            )
            invite_read_context = bool(
                action == 'context' and isinstance(invite, dict)
                and invite.get('purpose') == UPLOAD_PURPOSE
                and invite.get('repo') == repo and invite.get('pr') == pr_number
                and invite.get('head') == expected_head and invite.get('round') == round_id
                and selected.get('head_sha') == expected_head
                and round_id_for_state(selected) == round_id
                and (round_id != active_round or selected.get('status') != 'testing'
                     or pr.get('head', {}).get('sha') != expected_head
                     or pr.get('state') != 'open' or pr.get('merged'))
            )
            if write and not (authorized_writer or invite_allowed):
                raise EvidenceError('evidence_write_permission_required', 403)
            validate_context(pr, selected, expected_head, round_id, write=write)
            if write and round_id != active_round:
                raise EvidenceError('round_changed', 409)
            if write and not invite_allowed:
                self._validate_proof_context(
                    principal, repo, pr_number, expected_head, round_id,
                )
            capability = principal.get('capability', {})
            resource = (('attachment:' + str(payload.get('attachment_id', '')))
                        if action in {'download', 'preview'} else ('log:' + round_id)
                        if action == 'log_download' else ('log:' + round_id + ':' + str(payload.get('machine_alias', ''))
                        if action == 'machine_log_download' else None))
            if not principal.get('github_user_authenticated'):
                purpose = capability.get('purpose')
                context_capability = (
                    action == 'context'
                    and (purpose == PURPOSE and 'resource' not in capability
                         or purpose == DOWNLOAD_PURPOSE
                         and capability.get('resource') == 'page'
                         or invite_read_context)
                )
                scoped_read_capability = (
                    action in {'download', 'preview', 'log_download', 'machine_log_download'}
                    and ((purpose == PURPOSE and 'resource' not in capability)
                         or (purpose == DOWNLOAD_PURPOSE
                             and capability.get('resource') == resource))
                )
                legacy_read_capability = (
                    action == 'status' and purpose == PURPOSE
                    and 'resource' not in capability
                )
                access_claims = invite if invite_read_context else capability
                if (not invite_allowed and (access_claims.get('repo') != repo or access_claims.get('pr') != pr_number
                        or access_claims.get('head') != expected_head
                        or access_claims.get('round') != round_id
                        or not (context_capability or scoped_read_capability
                                or legacy_read_capability))):
                    raise EvidenceError('capability_context_mismatch', 403)
            latest = {}
            latest_by_identity = {}
            operations = {}
            for record in records:
                data = record['data']
                if record['kind'] == 'attachment':
                    latest[data['attachment_id']] = data
                    latest_by_identity[(data.get('repo'), data.get('pr_number'),
                                        data.get('head_sha'), data.get('round_id'),
                                        data['attachment_id'])] = data
                if record['kind'] == 'operation':
                    operation_id = data.get('operation_id')
                    upload_ref = data.get('upload_ref')
                    head_sha = data.get('head_sha')
                    operation_round = data.get('round_id')
                    attachment_id = data.get('attachment_id')
                    native = data.get('native_attachment') is True
                    status = data.get('status')

                    # A one-time server-side diagnostic wrote these legacy
                    # records under a separate namespace without creating a
                    # resumable EvidenceService operation. Keep them out of
                    # the operation index while leaving attachment records
                    # (and their Summary projection) untouched.
                    legacy_server_operation = (
                        isinstance(record.get('key'), str)
                        and re.fullmatch(r'server:[A-Za-z0-9._:-]{1,128}', record['key']) is not None
                        and 'operation_id' not in data and 'upload_ref' not in data
                        and not native and data.get('repo') == repo
                        and data.get('pr_number') == pr_number
                        and isinstance(attachment_id, str)
                        and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', attachment_id) is not None
                        and isinstance(data.get('upload_id'), str)
                        and 1 <= len(data['upload_id']) <= 1024
                        and all(32 <= ord(char) < 127 for char in data['upload_id'])
                        and isinstance(head_sha, str)
                        and re.fullmatch(r'[0-9a-f]{40}', head_sha) is not None
                        and isinstance(operation_round, str)
                        and re.fullmatch(re.escape(head_sha) + r'-[0-9]+', operation_round) is not None
                        and isinstance(status, str)
                        and status in {'initializing', 'uploading', 'completing', 'verifying',
                                       'processing', 'ready', 'deleted', 'invalid'}
                    )
                    if legacy_server_operation:
                        continue

                    valid_attachment = (isinstance(attachment_id, str)
                                        and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', attachment_id) is not None)
                    valid_id = (valid_attachment and operation_id == attachment_id if native else
                                isinstance(operation_id, str)
                                and re.fullmatch(r'[0-9a-f]{64}', operation_id) is not None)
                    valid_context = (
                        data.get('repo') == repo and data.get('pr_number') == pr_number
                        and isinstance(head_sha, str)
                        and re.fullmatch(r'[0-9a-f]{40}', head_sha) is not None
                        and isinstance(operation_round, str)
                        and re.fullmatch(re.escape(head_sha) + r'-[0-9]+', operation_round) is not None
                    )
                    valid_status = (isinstance(status, str)
                                    and status in {'prepared', 'initializing', 'uploading',
                                                   'completing', 'verifying', 'processing',
                                                   'ready', 'deleted', 'invalid'})
                    valid_reference = (native and operation_id == attachment_id
                                       or not native and isinstance(upload_ref, str)
                                       and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', upload_ref) is not None)
                    if not (valid_id and valid_attachment and valid_context and valid_status
                            and valid_reference and data.get('native_attachment') in (None, True)):
                        raise EvidenceError('operation_record_invalid', 503)

                    previous = operations.get(operation_id)
                    if previous is not None and any(
                            previous.get(field) != data.get(field)
                            for field in ('repo', 'pr_number', 'head_sha', 'round_id',
                                          'attachment_id', 'upload_ref', 'actor_id')):
                        raise EvidenceError('operation_identity_conflict', 503)
                    operations[operation_id] = data

            archived_latest_by_identity = {}
            for record in records:
                if record['kind'] != 'round':
                    continue
                archive = record['data']
                if not isinstance(archive, dict):
                    continue
                archive_head = archive.get('head_sha')
                archive_round = archive.get('round_id')
                if (not isinstance(archive_head, str)
                        or not isinstance(archive_round, str)
                        or archive_round not in round_numbers
                        or archive.get('repo') != repo
                        or archive.get('pr_number') != pr_number
                        or not isinstance(archive.get('attachment_records'), list)):
                    continue
                for wrapper in archive['attachment_records']:
                    if not isinstance(wrapper, dict) or wrapper.get('kind') != 'attachment':
                        continue
                    data = wrapper.get('data')
                    attachment_id = data.get('attachment_id') if isinstance(data, dict) else None
                    if (not isinstance(data, dict)
                            or not isinstance(wrapper.get('key'), str)
                            or not isinstance(wrapper.get('sha256'), str)
                            or not re.fullmatch(r'[0-9a-f]{64}', wrapper['sha256'])
                            or data.get('repo') != repo
                            or type(data.get('pr_number')) is not int
                            or data.get('pr_number') != pr_number
                            or data.get('head_sha') != archive_head
                            or data.get('round_id') != archive_round
                            or not isinstance(attachment_id, str)
                            or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', attachment_id)):
                        continue
                    identity = (repo, pr_number, archive_head, archive_round, attachment_id)
                    archived_latest_by_identity[identity] = data
            # Live records win over their archived copies, especially for
            # deletion tombstones written after a round snapshot was captured.
            latest_by_identity = {**archived_latest_by_identity, **latest_by_identity}
            if action == 'put_part':
                ref = payload.get('operation_id')
                source = next((r['data'] for r in reversed(records)
                               if r['kind'] == 'operation'
                               and r['data'].get('upload_ref') == ref), None)
                if (not source or source.get('repo') != repo
                        or source.get('pr_number') != pr_number
                        or source.get('head_sha') != expected_head
                        or source.get('round_id') != round_id):
                    raise EvidenceError('operation_not_found', 404)
                if (source.get('actor_id') != principal.get('id')
                        or isinstance(principal.get('upload_invite'), dict)
                        and source.get('upload_method') != 'signed_invite'):
                    raise EvidenceError('upload_owner_mismatch', 403)
                saved = latest_by_identity.get((repo, pr_number, source.get('head_sha'),
                                                source.get('round_id'), source.get('attachment_id')))
                if (source.get('status') != 'uploading' or saved
                        and saved.get('status') in {'deleted', 'invalid'}):
                    raise EvidenceError('upload_not_writable', 409)
                if not source.get('object_key') or not source.get('upload_id'):
                    raise EvidenceError('upload_not_recoverable', 503)
                part = payload.get('part_number')
                chunk = source.get('part_bytes', self.config.evidence_part_bytes)
                if (type(part) is not int or not 1 <= part <= 10000
                        or type(chunk) is not int or not 1 <= chunk <= 8 * 1024 * 1024
                        or type(source.get('size')) is not int
                        or not 1 <= source['size'] <= min(
                            512 * 1024 * 1024, self.config.evidence_max_file_bytes)
                        or part > (source['size'] + chunk - 1) // chunk):
                    raise EvidenceError('invalid_part_request', 400)
                expected_length = min(chunk, source['size'] - (part - 1) * chunk)
                body_stream = payload.get('_body_stream')
                if not hasattr(body_stream, '__aiter__'):
                    raise EvidenceError('invalid_part_body', 400)

                nonce_consumed = False

                async def current_part():
                    nonlocal nonce_consumed
                    fresh_pr = self._require_pr_snapshot(
                        await self.proxy.get_pr(repo, pr_number), repo,
                    )
                    fresh_state = await self.proxy.read_hidden_state(repo, pr_number)
                    validate_context(fresh_pr, fresh_state, expected_head, round_id, write=True)
                    fresh_authorized = await self._authorize(repo, principal, fresh_state, pr=fresh_pr)
                    if not (fresh_authorized or invite_allowed and invite_context_matches(
                            fresh_pr, fresh_state, round_id)):
                        raise EvidenceError('evidence_write_permission_required', 403)
                    fresh_records = await self.proxy.read_evidence_records(repo, pr_number)
                    if not isinstance(fresh_records, (list, tuple)):
                        raise EvidenceError('evidence_records_unavailable', 503)
                    fresh_source = next((record['data'] for record in reversed(fresh_records)
                                         if record['kind'] == 'operation'
                                         and record['data'].get('upload_ref') == source.get('upload_ref')),
                                        None)
                    identity_fields = (
                        'operation_id', 'upload_ref', 'attachment_id', 'repo',
                        'pr_number', 'head_sha', 'round_id', 'actor_id',
                        'object_key', 'upload_id',
                    )
                    if (not fresh_source
                            or any(fresh_source.get(field) != source.get(field)
                                   for field in identity_fields)
                            or fresh_source.get('status') != 'uploading'):
                        raise EvidenceError('upload_not_writable', 409)
                    fresh_attachment = next((record['data'] for record in reversed(fresh_records)
                                             if record['kind'] == 'attachment'
                                             and (record['data'].get('repo'),
                                                  record['data'].get('pr_number'),
                                                  record['data'].get('head_sha'),
                                                  record['data'].get('round_id'),
                                                  record['data'].get('attachment_id'))
                                             == (repo, pr_number, expected_head, round_id,
                                                 source.get('attachment_id'))), None)
                    if (fresh_attachment
                            and fresh_attachment.get('status') in {'deleted', 'invalid', 'ready'}):
                        raise EvidenceError('upload_not_writable', 409)
                    if not nonce_consumed and not invite_allowed:
                        await self._consume_auth_nonce(principal)
                        nonce_consumed = True

                if not invite_allowed:
                    await self._consume_auth_nonce(principal)
                    nonce_consumed = True
                with tempfile.SpooledTemporaryFile(max_size=256 * 1024, mode='w+b') as body:
                    length = 0
                    async for block in body_stream:
                        if not isinstance(block, bytes):
                            raise EvidenceError('invalid_part_body', 400)
                        length += len(block)
                        if length > min(8 * 1024 * 1024, chunk):
                            raise EvidenceError('evidence_part_too_large', 413)
                        body.write(block)
                    if length != expected_length:
                        raise EvidenceError(
                            'evidence_part_too_large' if length > expected_length
                            else 'invalid_part_size',
                            413 if length > expected_length else 400)
                    body.seek(0)
                    await current_part()
                    result = await self._store('put_part', source, {
                        'part_number': part, 'body': body, 'content_length': length,
                    })
                if result.get('conflict') is True:
                    raise EvidenceError('part_conflict', 409)
                return {'uploaded': True, 'part_number': part, 'size': length}
            if action == 'context':
                note_display_cache = {}
                async def context_attachment(row):
                    # Internally generated bot notes remain in the trusted
                    # evidence store, but are never projected to this page.
                    if (row.get('internal_bot_note') is True
                            or self._is_internal_bot_note(row)):
                        return None
                    public_fields = {
                        'attachment_id', 'filename', 'size', 'sha256', 'note', 'evidence_kind',
                        'round_id', 'head_sha', 'status', 'created_at', 'updated_at',
                        'completed_at', 'deleted_at', 'replaces_id', 'actor', 'actor_login',
                        'actor_verified', 'cos_content_verified', 'submitter',
                        'upload_method',
                    }
                    value = {key: copy.deepcopy(item) for key, item in row.items()
                             if key in public_fields}
                    # This display hint is computed from the authenticated,
                    # persisted actor record. The browser never receives actor identity.
                    actor_login = row.get('actor_login')
                    note_text = str(row.get('note') or '').strip().replace('\n', ' ')
                    templates = ('server-side cos multipart acceptance',
                                 'server-side 20mb h.264 cos transport acceptance')
                    value['internal_bot_note'] = bool(
                        row.get('actor_verified') is True and isinstance(actor_login, str)
                        and actor_login.casefold() == '4pd-pr-assistant[bot]'
                        and any(note_text.casefold() == template or
                                note_text.casefold().startswith(template + ' ') for template in templates))
                    if row.get('upload_method') in ('signed_invite', 'github_comment_proof'):
                        # A display-safe enum only; actor IDs and proof/capability
                        # material stay private.
                        value['upload_method'] = row['upload_method']
                    note_row = (row.get('evidence_kind') == 'note'
                                or row.get('status') == 'text')
                    if note_row:
                        value['evidence_kind'] = 'note'
                        attachment_id = row.get('attachment_id')
                        if attachment_id not in note_display_cache:
                            note_source = {**row, 'evidence_kind': 'note'}
                            note_display_cache[attachment_id] = await self._verified_note_display(
                                note_source, repo, pr_number, principal)
                        display_note, complete = note_display_cache[attachment_id]
                        value.update(display_note=display_note,
                                     # Older page clients render `note`; retain that safe display alias.
                                     note=display_note)
                        value['display_note_complete'] = bool(complete)
                    value['can_delete'] = bool(
                        write_context_allowed
                        and (authorized_writer or invite_allowed
                             and row.get('actor_id') == principal['id']
                             and row.get('upload_method') == 'signed_invite'))
                    return value

                current_rows = [row for (row_repo, row_pr, row_head, row_round, _), row
                                in latest_by_identity.items()
                                if row_repo == repo and row_pr == pr_number
                                and row_head == selected.get('head_sha')
                                and row_round == round_id]
                current_attachments = await asyncio.gather(
                    *(context_attachment(row) for row in current_rows))
                current_attachments = [row for row in current_attachments if row is not None]

                # The upload page keeps only the current round's upload state.
                # Historical rounds, deployment records, machine logs and
                # attachment explanation tables are intentionally not projected
                # here; the Lifecycle Summary keeps the full trusted history.
                return {'repo': repo, 'pr_number': pr_number, 'head_sha': selected['head_sha'], 'round_id': round_id,
                        'round_number': round_numbers.get(round_id),
                        'round_started_at': selected.get('round_started_at'),
                        'status': selected['status'], 'authenticated': True, 'enabled': True,
                        'evidence_degraded': False,
                        'pr_state': pr.get('state'), 'merged': pr.get('merged') is True,
                        'draft': pr.get('draft') is True,
                        'github_user_authenticated': bool(
                            principal.get('actor_verified') is True
                            and principal.get('github_user_authenticated') is True),
                        'can_write': write_context_allowed,
                        'acceptance_pending': bool(
                            isinstance(selected.get('acceptance_request'), dict)
                            and selected['acceptance_request'].get('status') == 'pending'
                            and selected['acceptance_request'].get('head_sha') == selected.get('head_sha')
                            and selected['acceptance_request'].get('round_id') == round_id),
                        'upload_invite': bool(invite_allowed),
                        'auth_method': principal.get('auth_method', 'github_comment_proof'),
                        'actor_verified': principal.get('actor_verified') is True,
                        'upload_method': principal.get('upload_method', 'github_comment_proof'),
                        'upload_max_files': (UPLOAD_MAX_FILES if invite_allowed else None),
                        'upload_max_bytes': (UPLOAD_MAX_BYTES if invite_allowed else None),
                        'attachments': current_attachments,
                        'operations': [{k: v for k, v in r.items() if k != 'upload_id'}
                                       for r in operations.values()
                                       if r.get('internal_bot_note') is not True
                                       and not self._is_internal_bot_note(r)
                                       and not r.get('auth_nonce_marker')
                                       and not r.get('native_attachment')
                                       and r.get('head_sha') == selected.get('head_sha')
                                       and r.get('round_id') == round_id
                                       and r.get('actor_id') == principal['id']],
                        # Evidence history is projected from verified round data;
                        # storage comment URLs/IDs are intentionally not exposed.
                        'archive_links': []}
            if action == 'status':
                if source.get('head_sha') != expected_head or source.get('round_id') != round_id:
                    raise EvidenceError('round_changed', 409)
                if source.get('status') == 'invalid':
                    raise EvidenceError('round_changed', 409)
                saved = latest_by_identity.get((repo, pr_number, source.get('head_sha'),
                                                source.get('round_id'), source.get('attachment_id')))
                if saved and saved.get('status') == 'deleted':
                    raise EvidenceError('attachment_deleted', 410)
                operation = copy.deepcopy(saved if saved and saved.get('status') == 'ready' else source)
                result = {'uploaded_parts': []}
                # Status is a read-only reconciliation. In particular, an
                # uncertain complete is probed for the final object and then
                # the existing multipart upload; it is never submitted again.
                if operation.get('status') in {'completing', 'verifying', 'processing'}:
                    try:
                        result = await self.store.verify_object(
                            key=operation['object_key'], size=operation['size'],
                            metadata=self.store._identity_metadata(operation),
                            sha256=operation.get('sha256') or None,
                        )
                    except Exception:
                        if not operation.get('upload_id'):
                            result = {'uploaded_parts': [], 'completion_unknown': True}
                        else:
                            result = {'uploaded_parts': await self.store.list_parts(
                                key=operation['object_key'], upload_id=operation['upload_id']),
                                'completion_unknown': True}
                    else:
                        result = {**result, 'uploaded_parts': [], 'completion_unknown': False}
                elif operation.get('status') == 'uploading':
                    if not operation.get('object_key') or not operation.get('upload_id'):
                        result = {'uploaded_parts': [], 'initialization_pending': True}
                    else:
                        result = {'uploaded_parts': await self.store.list_parts(
                            key=operation['object_key'], upload_id=operation['upload_id'])}
                elif operation.get('status') == 'ready':
                    object_verified = await self._verify_ready_attachment_object(operation)
                    if not object_verified:
                        restore_pending = await self._record_ready_restore_state(
                            repo, pr_number, operation, pending=True,
                        )
                        result = {
                            'uploaded_parts': [], 'verified': False,
                            'restore_pending': True,
                            'restore_marker_persisted': restore_pending,
                            'sha256': operation.get('sha256'), 'size': operation.get('size'),
                        }
                    elif operation.get('cos_restore_pending') is True:
                        cleared = await self._record_ready_restore_state(
                            repo, pr_number, operation, pending=False,
                        )
                        result = {
                            'uploaded_parts': [], 'verified': cleared,
                            'restore_pending': not cleared,
                            'restore_marker_persisted': False,
                            'sha256': operation.get('sha256'), 'size': operation.get('size'),
                            'object_key': operation.get('object_key'),
                        }
                    else:
                        result = {
                            'uploaded_parts': [], 'verified': True,
                            'sha256': operation.get('sha256'), 'size': operation.get('size'),
                            'object_key': operation.get('object_key'),
                        }
                public_fields = {'attachment_id', 'filename', 'size', 'sha256', 'note',
                                 'round_id', 'head_sha', 'status', 'created_at',
                                 'completed_at', 'actor', 'actor_login', 'part_bytes',
                                 'cos_restore_pending'}
                value = {k: copy.deepcopy(v) for k, v in operation.items() if k in public_fields}
                value['upload_id'] = source.get('upload_ref', source['operation_id'])
                value['uploaded_parts'] = result.get('uploaded_parts', [])
                value['parts'] = value['uploaded_parts']
                value['historical'] = (round_id != active_round
                                       or pr.get('head', {}).get('sha') != expected_head)
                # Report this process's last known display state for the
                # attachment. ``status`` is read-only here; the display
                # reconcile itself belongs to the serial watcher.
                display_state = self.notification_state_for(repo, pr_number, operation)
                if result.get('restore_pending'):
                    display_state = (
                        NOTIFICATION_RESTORE_PENDING
                        if result.get('restore_marker_persisted') is True
                        else NOTIFICATION_RESTORE_FAILED
                    )
                    self._remember_notification(operation, display_state)
                if display_state is None and operation.get('status') == 'ready':
                    marker = self._upload_notification_marker(operation)
                    if marker:
                        try:
                            comments = await self.proxy.get_issue_comments(repo, pr_number)
                            if not isinstance(comments, list):
                                raise EvidenceError('evidence_notification_read_failed', 503)
                            if any(self._trusted_upload_notification(c, marker) for c in comments):
                                display_state = NOTIFICATION_SYNCED
                                self._remember_notification(operation, display_state)
                        except Exception as exc:
                            logger.warning(
                                'evidence status notification read failed %s#%s attachment=%s exception=%s',
                                repo, pr_number, operation.get('attachment_id'),
                                type(exc).__name__,
                            )
                            display_state = NOTIFICATION_FAILED
                            self._remember_notification(operation, display_state)
                            self._hint_ready_sync(repo, pr_number)
                if display_state is not None:
                    value['github_comment_synced'] = display_state == NOTIFICATION_SYNCED
                    value['github_comment_state'] = display_state
                    if display_state in {
                            NOTIFICATION_PENDING, NOTIFICATION_RESTORE_PENDING,
                            NOTIFICATION_RESTORE_FAILED}:
                        value['github_comment_pending'] = True
                if result.get('completion_unknown'):
                    value['completion_unknown'] = True
                if result.get('initialization_pending'):
                    value['initialization_pending'] = True
                if result.get('verified') is True:
                    attachment_persisted = bool(
                        saved and saved.get('status') == 'ready'
                        and saved.get('cos_content_verified') is True
                        and saved.get('head_sha') == source.get('head_sha')
                        and saved.get('round_id') == source.get('round_id')
                        and saved.get('attachment_id') == source.get('attachment_id')
                        and saved.get('sha256') == result.get('sha256', value.get('sha256'))
                        and saved.get('size') == source.get('size'))
                    if attachment_persisted:
                        value['status'] = 'ready'
                        value['sha256'] = result.get('sha256', value.get('sha256', ''))
                        value['verified'] = True
                        value['cos_restore_pending'] = False
                        value['github_record_persisted'] = True
                    else:
                        # COS may have the finished object while GitHub still
                        # lacks its ready attachment record. Keep it resumable,
                        # but never tell the uploader that it is complete yet.
                        value['status'] = 'verifying'
                        value['record_pending'] = True
                elif result.get('restore_pending'):
                    value.update(
                        status='verifying', verified=False,
                        restore_pending=True, cos_restore_pending=True,
                    )
                return value
            if action in {'download', 'preview', 'log_download', 'machine_log_download'}:
                if action in {'log_download', 'machine_log_download'}:
                    obj = selected.get('cos', {})
                    if action == 'machine_log_download':
                        machine_alias = payload.get('machine_alias')
                        logs = selected.get('deployment_logs', {})
                        obj = logs.get(machine_alias, {}) if isinstance(logs, dict) else {}
                        if (not isinstance(machine_alias, str)
                                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', machine_alias)
                                or '..' in machine_alias
                                or obj.get('status') != 'ready'
                                or obj.get('head_sha') != expected_head
                                or obj.get('round_id') != round_id
                                or not self.controller._valid_cos_metadata(repo, pr_number, expected_head, obj)):
                            raise EvidenceError('log_not_ready', 404)
                    if not self.controller._valid_cos_metadata(repo, pr_number, expected_head, obj):
                        raise EvidenceError('log_not_ready', 404)
                    operation = {'repo': repo, 'pr_number': pr_number, 'head_sha': expected_head, 'round_id': round_id, **obj}
                else:
                    operation = latest_by_identity.get((repo, pr_number, expected_head,
                                                        round_id, payload.get('attachment_id')))
                    if not operation:
                        raise EvidenceError('attachment_not_found', 404)
                    if operation['status'] == 'deleted':
                        raise EvidenceError('attachment_deleted', 410)
                    if operation['status'] != 'ready':
                        raise EvidenceError('attachment_not_ready', 409)
                # PR and lifecycle state were read and validated above.
                # Store may sign ONLY the server-loaded object, never payload key.
                result = await self._store(
                    'log_download' if action == 'machine_log_download' else action,
                    operation, {})
                fresh = self._require_pr_snapshot(
                    await self.proxy.get_pr(repo, pr_number), repo,
                )
                fresh_state = await self.proxy.read_hidden_state(repo, pr_number)
                if not isinstance(fresh_state, dict):
                    raise EvidenceError('state_unavailable', 503)
                if round_id == active_round:
                    validate_context(fresh, fresh_state, expected_head, round_id, write=False)
                await self._authorize(repo, principal, selected, pr=fresh)
                validate_context(fresh, selected, expected_head, round_id, write=False)
                if action in {'download', 'preview'}:
                    revisions = await self.proxy.read_evidence_records(repo, pr_number)
                    deleted = any(
                        r['kind'] == 'attachment'
                        and (r['data'].get('repo'), r['data'].get('pr_number'),
                             r['data'].get('head_sha'), r['data'].get('round_id'),
                             r['data'].get('attachment_id'))
                        == (repo, pr_number, expected_head, round_id,
                            operation['attachment_id'])
                        and r['data'].get('status') == 'deleted'
                        for r in revisions
                    )
                    if deleted:
                        raise EvidenceError('attachment_deleted', 410)
                return result
            idem = payload.get('idempotency_key')
            if not isinstance(idem, str) or not 1 <= len(idem) <= 128:
                raise EvidenceError('idempotency_key_required', 400)
            opid = hashlib.sha256(json.dumps([repo, pr_number, principal['id'], action, idem]).encode()).hexdigest()
            request_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
            existing = operations.get(opid)
            if existing and (existing.get('request_sha256') != request_hash
                             or existing.get('head_sha') != expected_head or existing.get('round_id') != round_id):
                raise EvidenceError('idempotency_conflict', 409)

            if invite_allowed and action in {'init', 'note'} and existing is None:
                invite_rows = {}
                round_rows = [row for (row_repo, row_pr, row_head, row_round, _), row
                              in latest_by_identity.items()
                              if row_repo == repo and row_pr == pr_number
                              and row_head == expected_head and row_round == round_id]
                for row in [*round_rows, *operations.values()]:
                    if (row.get('upload_method') != 'signed_invite' or row.get('round_id') != round_id
                            or not isinstance(row.get('attachment_id'), str)):
                        continue
                    row_kind = row.get('evidence_kind')
                    if row_kind not in {'file', 'note'}:
                        row_kind = 'file'
                    if row_kind != ('note' if action == 'note' else 'file'):
                        continue
                    attachment_id = row['attachment_id']
                    size = row.get('size', 0) if type(row.get('size')) is int else 0
                    invite_rows[attachment_id] = max(invite_rows.get(attachment_id, 0), size)

                if action == 'init':
                    requested_size = payload.get('size', 0)
                    if (type(requested_size) is not int
                            or not 1 <= requested_size <= 512 * 1024 * 1024):
                        raise EvidenceError('invalid_file_size', 413)
                    if len(invite_rows) >= UPLOAD_MAX_FILES:
                        raise EvidenceError('upload_invitation_file_quota_exceeded', 429)
                    if sum(invite_rows.values()) + requested_size > UPLOAD_MAX_BYTES:
                        raise EvidenceError('upload_invitation_byte_quota_exceeded', 413)
                else:
                    note_text = payload.get('text') or payload.get('note', '')
                    requested_size = len(note_text.encode('utf-8')) if isinstance(note_text, str) else 0
                    note_limit = int(self.config.evidence_max_note_bytes)
                    if len(invite_rows) >= UPLOAD_MAX_NOTES:
                        raise EvidenceError('upload_invitation_note_quota_exceeded', 429)
                    if (requested_size <= note_limit
                            and sum(invite_rows.values()) + requested_size > UPLOAD_MAX_BYTES):
                        raise EvidenceError('upload_invitation_note_byte_quota_exceeded', 413)

            def public(
                operation, result=None, *, attachment_persisted=False,
                notification=None,
            ):
                value = copy.deepcopy(operation)
                # HTTP upload_id is a stable operation reference, never a key
                # supplied by a browser. COS UploadId remains a recovery fact.
                value['upload_id'] = operation.get('upload_ref', operation['operation_id'])
                value['part_bytes'] = operation.get('part_bytes', self.config.evidence_part_bytes)
                value['uploaded_parts'] = (result or {}).get('uploaded_parts', [])
                value['parts'] = value['uploaded_parts']
                head_sha = operation.get('head_sha')
                round_id = operation.get('round_id')
                persisted_ready = (
                    operation.get('status') == 'ready'
                    and operation.get('cos_content_verified') is True
                    and operation.get('cos_restore_pending') is not True
                    and notification not in {
                        NOTIFICATION_RESTORE_PENDING, NOTIFICATION_RESTORE_FAILED,
                    }
                    and isinstance(operation.get('object_key'), str) and bool(operation['object_key'])
                    and type(operation.get('size')) is int and operation['size'] > 0
                    and isinstance(operation.get('sha256'), str)
                    and re.fullmatch(r'[0-9a-f]{64}', operation['sha256']) is not None
                    and isinstance(head_sha, str)
                    and re.fullmatch(r'[0-9a-f]{40}', head_sha) is not None
                    and isinstance(round_id, str)
                    and re.fullmatch(re.escape(head_sha) + r'-[0-9]+', round_id) is not None
                )
                if attachment_persisted:
                    value['github_record_persisted'] = True
                if attachment_persisted and ((result or {}).get('verified') is True or persisted_ready):
                    value['verified'] = True
                if notification is not None:
                    value['github_comment_synced'] = notification == NOTIFICATION_SYNCED
                    value['github_comment_state'] = notification
                    if notification in {
                            NOTIFICATION_PENDING, NOTIFICATION_RESTORE_PENDING,
                            NOTIFICATION_RESTORE_FAILED}:
                        value['github_comment_pending'] = True
                    if notification in {
                            NOTIFICATION_RESTORE_PENDING, NOTIFICATION_RESTORE_FAILED}:
                        value.update(
                            status='verifying', verified=False,
                            cos_restore_pending=True,
                            restore_pending=notification == NOTIFICATION_RESTORE_PENDING,
                        )
                return value

            nonce_consumed = False

            async def current():
                nonlocal nonce_consumed
                fresh_pr = self._require_pr_snapshot(
                    await self.proxy.get_pr(repo, pr_number), repo,
                )
                fresh_state = await self.proxy.read_hidden_state(repo, pr_number)
                validate_context(fresh_pr, fresh_state, expected_head, round_id, write=True)
                fresh_authorized = await self._authorize(repo, principal, fresh_state, pr=fresh_pr)
                if not (fresh_authorized or invite_allowed and invite_context_matches(
                        fresh_pr, fresh_state, round_id)):
                    raise EvidenceError('evidence_write_permission_required', 403)
                if not nonce_consumed and not invite_allowed:
                    await self._consume_auth_nonce(principal)
                    nonce_consumed = True

            if action == 'resume':
                if source.get('actor_id') != principal['id']:
                    raise EvidenceError('upload_owner_mismatch', 403)
                if source['status'] == 'invalid':
                    raise EvidenceError('round_changed', 409)
                saved = latest_by_identity.get((repo, pr_number, source.get('head_sha'),
                                                source.get('round_id'), source.get('attachment_id')))
                if saved and saved['status'] == 'deleted':
                    raise EvidenceError('attachment_deleted', 410)
                if saved and saved['status'] == 'ready' and saved.get('cos_content_verified') is True:
                    notification = await self._notify_ready_attachment(
                        repo, pr_number, saved,
                    )
                    return public(
                        saved, attachment_persisted=True,
                        notification=notification,
                    )
                if source['status'] == 'ready':
                    await current()
                    recovered = copy.deepcopy(source)
                    if recovered.get('cos_content_verified') is not True:
                        try:
                            result = await self.store.verify_object(
                                key=recovered['object_key'], size=recovered['size'],
                                metadata=self.store._identity_metadata(recovered),
                                sha256=recovered.get('sha256') or None,
                            )
                        except Exception as exc:
                            logger.warning(
                                'ready evidence compensation COS check failed %s#%s attachment=%s exception=%s',
                                repo, pr_number, recovered.get('attachment_id'),
                                type(exc).__name__,
                            )
                            result = None
                        sha = result.get('sha256') if isinstance(result, dict) else None
                        if (not isinstance(result, dict)
                                or result.get('verified') is not True
                                or result.get('object_key') != recovered.get('object_key')
                                or result.get('size') != recovered.get('size')
                                or not isinstance(sha, str)
                                or not re.fullmatch('[0-9a-f]{64}', sha)
                                or (recovered.get('sha256') and recovered['sha256'] != sha)):
                            logger.warning(
                                'ready evidence compensation COS object is not verified %s#%s attachment=%s',
                                repo, pr_number, recovered.get('attachment_id'),
                            )
                            marker_saved = await self._record_ready_restore_state(
                                repo, pr_number, recovered, pending=True,
                            )
                            restore_state = (
                                NOTIFICATION_RESTORE_PENDING if marker_saved
                                else NOTIFICATION_RESTORE_FAILED
                            )
                            pending = copy.deepcopy(recovered)
                            pending.update(status='verifying', cos_restore_pending=True)
                            value = public(
                                pending, attachment_persisted=False,
                                notification=restore_state,
                            )
                            value['restore_pending'] = marker_saved
                            return value
                        recovered.update(sha256=sha, cos_content_verified=True)
                        await self._save(repo, pr_number, 'operation', recovered, 'ready')
                    else:
                        object_verified, restore_state = await self._prepare_ready_attachment_object(
                            repo, pr_number, recovered,
                        )
                        if not object_verified:
                            pending = copy.deepcopy(recovered)
                            pending.update(status='verifying', cos_restore_pending=True)
                            value = public(
                                pending, attachment_persisted=False,
                                notification=restore_state,
                            )
                            value['restore_pending'] = restore_state == NOTIFICATION_RESTORE_PENDING
                            return value
                    await self._save(repo, pr_number, 'attachment', recovered, 'ready')
                    notification = await self._notify_ready_attachment(
                        repo, pr_number, recovered,
                    )
                    return public(
                        recovered, attachment_persisted=True,
                        notification=notification,
                    )
                await current()
                result = await self._store('resume', source, {})
                try:
                    await current()
                except ValueError as exc:
                    if isinstance(exc, EvidenceError) and exc.code not in {'round_changed', 'context_not_writable'}:
                        raise
                    fresh_pr = await self.proxy.get_pr(repo, pr_number)
                    if fresh_pr.get('state') == 'open' and not fresh_pr.get('merged'):
                        await self._save(repo, pr_number, 'operation',
                                         {**source, 'status': 'invalid', 'invalidated_at': utc_now()}, 'invalid')
                    raise EvidenceError('round_changed', 409) from None
                recovered = copy.deepcopy(source)
                for field in ('object_key', 'upload_id'):
                    if field in result:
                        value = result[field]
                        if (not isinstance(value, str) or not value or '://' in value
                                or value.startswith('/') or '\\' in value or '..' in value.split('/')
                                or '?' in value or '#' in value or any(ord(c) < 32 for c in value)
                                or (source.get(field) and source[field] != value)):
                            raise EvidenceError('store_recovery_conflict', 409)
                        recovered[field] = value
                notification = None
                if result.get('verified') is True:
                    sha = result.get('sha256')
                    if (not recovered.get('object_key') or type(result.get('size')) is not int
                            or result['size'] != source['size'] or not isinstance(sha, str)
                            or not re.fullmatch('[0-9a-f]{64}', sha)
                            or (source.get('sha256') and sha != source['sha256'])):
                        raise EvidenceError('object_not_verified', 409)
                    recovered.update(status='ready', sha256=sha, cos_content_verified=True,
                                     completed_at=utc_now())
                    await self._save(repo, pr_number, 'operation', recovered, 'ready')
                    await self._save(repo, pr_number, 'attachment', recovered, 'ready')
                    notification = await self._notify_ready_attachment(
                        repo, pr_number, recovered,
                    )
                else:
                    if not recovered.get('object_key') or not recovered.get('upload_id'):
                        raise EvidenceError('upload_not_recoverable', 502)
                    recovered['status'] = 'uploading'
                    await self._save(repo, pr_number, 'operation', recovered, 'uploading')
                return public(
                    recovered, result,
                    attachment_persisted=result.get('verified') is True,
                    notification=notification,
                )

            if existing and existing['status'] in {'ready', 'deleted', 'invalid'}:
                if existing['status'] == 'invalid':
                    raise EvidenceError('round_changed', 409)
                await current()
                if existing['status'] != 'ready':
                    await self._save(repo, pr_number, 'attachment', existing, existing['status'])
                notification = None
                if existing.get('status') == 'ready':
                    notification = await self._notify_ready_attachment(
                        repo, pr_number, existing,
                    )
                return public(
                    existing, attachment_persisted=existing.get('status') == 'ready',
                    notification=notification,
                )
            if action in {'init', 'note'}:
                text = payload.get('text') or payload.get('note', '')
                if action == 'note':
                    if not isinstance(text, str) or not text:
                        raise EvidenceError('text_required', 400)
                    if len(text) > 5000:
                        raise EvidenceError('text_too_large', 413)
                    body = text.encode('utf-8')
                    if len(body) > self.config.evidence_max_note_bytes:
                        raise EvidenceError('text_too_large', 413)
                    filename, size, sha = 'note.txt', len(body), hashlib.sha256(body).hexdigest()
                else:
                    filename, size, sha = payload.get('filename'), payload.get('size'), payload.get('sha256', '')
                    if sha and (not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{64}', sha)):
                        raise EvidenceError('invalid_sha256', 400)
                if (not isinstance(filename, str) or not filename or len(filename) > 255
                        or PurePosixPath(filename).name != filename or '\\' in filename or filename in {'.', '..'}
                        or any(ord(c) < 32 for c in filename)
                        or type(size) is not int or not 1 <= size <= self.config.evidence_max_file_bytes):
                    raise EvidenceError('invalid_file_metadata', 400)
                replaces = payload.get('replaces_id') or ''
                replacement = (latest_by_identity.get((repo, pr_number, expected_head,
                                                       round_id, replaces)) if replaces else None)
                if replaces and replacement is None:
                    raise EvidenceError('replacement_not_found', 404)
                if (invite_allowed and replaces
                        and replacement.get('actor_id') != principal['id']):
                    raise EvidenceError('upload_owner_mismatch', 403)
                from .evidence_builder import _redact_secrets
                note = payload.get('note', '')
                if not isinstance(note, str):
                    raise EvidenceError('invalid_note', 400)
                submitter = principal['login']
                operation = existing or {
                    'operation_id': opid, 'upload_ref': opid, 'attachment_id': opid, 'repo': repo, 'pr_number': pr_number,
                    'head_sha': expected_head, 'round_id': round_id, 'actor_id': principal['id'],
                    'actor_login': submitter, 'actor': 'shared-link' if invite_allowed else submitter,
                    'submitter': submitter,
                    'actor_verified': principal.get('actor_verified') is True,
                    'github_user_authenticated': principal.get('github_user_authenticated') is True,
                    'upload_method': ('signed_invite' if invite_allowed else 'github_comment_proof'),
                    'evidence_kind': 'note' if action == 'note' else 'file',
                    'upload_link_authorized': bool(invite_allowed),
                    'created_by': submitter,
                    'created_at': utc_now(), 'updated_at': utc_now(), 'filename': filename, 'size': size, 'sha256': sha,
                    'note': _redact_secrets(text if action == 'note' else note),
                    'replaces_id': replaces, 'status': 'initializing', 'request_sha256': request_hash,
                    'part_bytes': self.config.evidence_part_bytes,
                }
                if not existing:
                    await current()
                    await self._save(repo, pr_number, 'operation', operation, 'initializing')
                elif operation['status'] == 'uploading':
                    return public(operation)
                store_action = 'note' if action == 'note' else ('resume' if existing else action)
                store_payload = {'text': text} if action == 'note' else {}
            else:
                ref = payload.get('operation_id') or payload.get('upload_id')
                source = next((r['data'] for r in reversed(records) if r['kind'] == 'operation'
                               and r['data'].get('upload_ref') == ref), operations.get(ref))
                if action == 'delete':
                    source = latest_by_identity.get((repo, pr_number, expected_head,
                                                     round_id, payload.get('attachment_id')))
                if not source or source.get('round_id') != round_id or source.get('head_sha') != expected_head:
                    raise EvidenceError('operation_not_found', 404)
                current_attachment = latest_by_identity.get((repo, pr_number, expected_head,
                                                             round_id, source['attachment_id']))
                if source.get('status') == 'invalid':
                    raise EvidenceError('round_changed', 409)
                if current_attachment and current_attachment.get('status') == 'deleted':
                    raise EvidenceError('attachment_deleted', 410)
                if ((source.get('actor_id') != principal['id']
                     or invite_allowed and source.get('upload_method') != 'signed_invite')
                        and action != 'delete'):
                    raise EvidenceError('upload_owner_mismatch', 403)
                if (action != 'delete' and current_attachment
                        and current_attachment.get('status') == 'ready'):
                    notification = None
                    if action in {'complete', 'resume'}:
                        notification = await self._notify_ready_attachment(
                            repo, pr_number, current_attachment,
                        )
                    return public(
                        current_attachment,
                        attachment_persisted=True,
                        notification=notification,
                    )
                operation = existing or {**source, 'operation_id': opid,
                                         'source_operation_id': source['operation_id'], 'request_sha256': request_hash}
                if action == 'delete':
                    if (invite_allowed and (source.get('actor_id') != principal['id']
                                            or source.get('upload_method') != 'signed_invite')):
                        raise EvidenceError('upload_owner_mismatch', 403)
                    operation.update(status='deleted', deleted_at=utc_now(), deleted_by=principal['login'],
                                     deleted_by_login=principal['login'], deleted_by_id=principal['id'],
                                     actor_verified=principal.get('actor_verified') is True,
                                     github_user_authenticated=principal.get('github_user_authenticated') is True,
                                     updated_at=utc_now())
                    await current()
                    await self._save(repo, pr_number, 'operation', operation, 'deleted')
                    await self._save(repo, pr_number, 'attachment', operation, 'deleted')
                    return public(operation)
                if action == 'sign_part':
                    part = payload.get('part_number')
                    if type(part) is not int or not 1 <= part <= 10000 or source.get('status') != 'uploading':
                        raise EvidenceError('invalid_part_request', 409)
                    await current()
                    result = await self._store(action, source, {'part_number': part})
                    try:
                        await current()
                    except ValueError as exc:
                        if isinstance(exc, EvidenceError) and exc.code not in {'round_changed', 'context_not_writable'}:
                            raise
                        fresh_pr = await self.proxy.get_pr(repo, pr_number)
                        if fresh_pr.get('state') == 'open' and not fresh_pr.get('merged'):
                            await self._save(repo, pr_number, 'operation',
                                             {**operation, 'status': 'invalid', 'invalidated_at': utc_now()}, 'invalid')
                        raise EvidenceError('round_changed', 409) from None
                    return result
                if action == 'complete':
                    sha = payload.get('sha256')
                    if sha is not None and (not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{64}', sha)):
                        raise EvidenceError('invalid_sha256', 400)
                    if sha and source.get('sha256') and source['sha256'] != sha:
                        raise EvidenceError('sha256_conflict', 409)
                    if sha:
                        operation['sha256'] = sha
                    if not existing:
                        operation['status'] = 'completing'
                        await current()
                        await self._save(repo, pr_number, 'operation', operation, 'completing')
                store_action = ('resume' if existing or action == 'resume'
                                or source.get('status') in {'completing', 'verifying', 'processing', 'ready'}
                                else 'complete')
                store_payload = {}
            await current()
            result = await self._store(store_action, operation, store_payload)
            try:
                await current()
            except ValueError as exc:
                if isinstance(exc, EvidenceError) and exc.code not in {'round_changed', 'context_not_writable'}:
                    raise
                fresh_pr = await self.proxy.get_pr(repo, pr_number)
                invalid = {**operation, 'status': 'invalid', 'invalidated_at': utc_now()}
                if fresh_pr.get('state') == 'open' and not fresh_pr.get('merged'):
                    await self._save(repo, pr_number, 'operation', invalid, 'invalid')
                raise EvidenceError('round_changed', 409) from None
            # Only server-verified, whitelisted store facts enter GitHub.
            for key in ('object_key', 'upload_id'):
                if key in result:
                    value = result[key]
                    if (not isinstance(value, str) or not value or '\\' in value or '..' in value.split('/')
                            or value.startswith('/') or '://' in value or '?' in value or '#' in value
                            or any(ord(c) < 32 for c in value)):
                        raise EvidenceError('store_result_invalid', 502)
                    if operation.get(key) and operation[key] != value:
                        raise EvidenceError('store_object_conflict', 409)
                    operation[key] = value
            ready = result.get('verified') is True
            notification = None
            if action in {'complete', 'note'} or ready:
                actual_sha = result.get('sha256')
                if (not ready or not operation.get('object_key') or type(result.get('size')) is not int
                        or result['size'] != operation['size'] or not isinstance(actual_sha, str)
                        or not re.fullmatch('[0-9a-f]{64}', actual_sha)
                        or (operation.get('sha256') and actual_sha != operation['sha256'])):
                    raise EvidenceError('object_not_verified', 409)
                operation.update(status='ready', sha256=actual_sha, cos_content_verified=True,
                                 completed_at=utc_now())
                await self._save(repo, pr_number, 'operation', operation, 'ready')
                await self._save(repo, pr_number, 'attachment', operation, 'ready')
                notification = await self._notify_ready_attachment(
                    repo, pr_number, operation,
                )
            else:
                if not operation.get('upload_id') or not operation.get('object_key'):
                    raise EvidenceError('upload_not_recoverable', 502)
                operation['status'] = 'uploading'
                await self._save(repo, pr_number, 'operation', operation, 'uploading')
            return public(
                operation, result, attachment_persisted=ready,
                notification=notification,
            )
