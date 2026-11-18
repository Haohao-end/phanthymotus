"""Stable authenticated evidence HTTP contract; business mutations belong to A."""
from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from . import evidence_auth
from .config import validate_repository_names
from .evidence_store import EvidenceStoreError, safe_filename

router = APIRouter()
_PREFIX = '/api/evidence/{owner}/{repo}/pulls/{pr}'
_ID = re.compile(r'[A-Za-z0-9_-]{1,128}')
_BASE = {'head_sha', 'round_id', 'idempotency_key'}


def _identity(value, label):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise HTTPException(400, detail='invalid_' + label)
    return value


def _machine_alias(value):
    return (isinstance(value, str)
            and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', value) is not None
            and '..' not in value)


def _repo(owner, repo, pr):
    try:
        canonical = validate_repository_names([f'{owner}/{repo}'])[0]
    except ValueError:
        raise HTTPException(400, detail='invalid_repository') from None
    if pr < 1:
        raise HTTPException(400, detail='invalid_pr')
    return canonical


def _byte_length(value):
    try:
        return len(value.encode('utf-8'))
    except UnicodeError:
        raise HTTPException(400, detail='invalid_text_encoding') from None


def _validate(payload, action, config):
    extras = {'init': {'filename', 'size', 'content_type', 'note', 'replaces_id', 'sha256', 'submitter'},
              'complete': {'sha256', 'parts'}, 'note': {'text', 'note', 'replaces_id', 'submitter'}}.get(action, set())
    route_fields = {'status': {'upload_id'}, 'resume': {'upload_id'}, 'sign_part': {'upload_id', 'part_number'},
                    'put_part': {'upload_id', 'part_number'},
                    'complete': {'upload_id'}, 'download': {'attachment_id'},
                    'preview': {'attachment_id'},
                    'machine_log_download': {'machine_alias'},
                    'delete': {'attachment_id'}}.get(action, set())
    if not isinstance(payload, dict) or payload.keys() - (_BASE | extras | route_fields):
        raise HTTPException(400, detail='invalid_evidence_payload')
    if 'round_id' in payload:
        _identity(payload['round_id'], 'round_id')
    if action == 'machine_log_download':
        alias = payload.get('machine_alias')
        if not _machine_alias(alias):
            raise HTTPException(400, detail='invalid_machine')
    if 'head_sha' in payload:
        if not isinstance(payload.get('head_sha'), str) or not re.fullmatch('[0-9a-f]{40}', payload['head_sha']):
            raise HTTPException(400, detail='invalid_head_sha')
        _identity(payload.get('round_id'), 'round_id')

    if 'idempotency_key' in payload:
        idem = payload['idempotency_key']
        if not isinstance(idem, str) or not 1 <= len(idem) <= 1024 or any(ord(c) < 32 for c in idem):
            raise HTTPException(400, detail='invalid_idempotency_key')
        payload['idempotency_key'] = hashlib.sha256(idem.encode('utf-8')).hexdigest()
    if 'parts' in payload:
        # COS ListParts is authoritative; browser ETags are only bounded hints.
        if not isinstance(payload['parts'], list) or len(payload['parts']) > 10000:
            raise HTTPException(400, detail='invalid_parts')
        payload.pop('parts')
    if action == 'init':
        try:
            safe_filename(payload.get('filename'))
        except ValueError:
            raise HTTPException(400, detail='invalid_filename') from None
        size = payload.get('size')
        video_limit = getattr(config, 'evidence_max_video_bytes', config.evidence_max_file_bytes)
        is_video = isinstance(payload.get('content_type'), str) and payload['content_type'].lower().startswith('video/')
        limit = video_limit if is_video else config.evidence_max_file_bytes
        if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= limit:
            raise HTTPException(413, detail='invalid_file_size')
        content_type = payload.get('content_type')
        if not isinstance(content_type, str) or not re.fullmatch(r'[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+', content_type):
            raise HTTPException(400, detail='invalid_content_type')
    for field in ('note', 'text'):
        if field in payload and (not isinstance(payload[field], str) or
                               len(payload[field]) > 5000 or
                               _byte_length(payload[field]) > config.evidence_max_note_bytes):
            raise HTTPException(413, detail='invalid_note_size')
    if action == 'note' and not (payload.get('text') or payload.get('note')):
        raise HTTPException(400, detail='note_required')
    for field in ('upload_id', 'attachment_id', 'replaces_id'):
        if payload.get(field) is not None:
            _identity(payload[field], field)
    if 'sha256' in payload and (not isinstance(payload['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', payload['sha256'])):
        raise HTTPException(400, detail='invalid_sha256')
    if 'part_number' in payload and not 1 <= payload['part_number'] <= 10000:
        raise HTTPException(400, detail='invalid_part_number')
    if action == 'note':
        text = payload.get('text', '')
        note = payload.get('note', '')
        if note:
            text = (text + '\n\n' + note) if text else note
        if (not 1 <= len(text) <= 5000
                or _byte_length(text) > config.evidence_max_note_bytes):
            raise HTTPException(413, detail='invalid_note_size')
        payload.update(text=text, size=_byte_length(text),
                       sha256=hashlib.sha256(text.encode('utf-8')).hexdigest())
    return payload


async def _payload(request, action, **path):
    if request.method in ('POST', 'DELETE'):
        # Bound text input before parsing; uploads themselves go directly to COS.
        data = bytearray()
        async for chunk in request.stream():
            data.extend(chunk)
            if len(data) > 512 * 1024:
                raise HTTPException(413, detail='evidence_request_too_large')
        try:
            payload = json.loads(data) if data else {}
        except (ValueError, UnicodeError):
            raise HTTPException(400, detail='invalid_json') from None
    else:
        payload = dict(request.query_params)
        payload.pop('cap', None)
        payload.pop('read_view', None)
        if action == 'put_part' and payload.keys() - {'head_sha', 'round_id'}:
            raise HTTPException(400, detail='invalid_evidence_payload')
    if not isinstance(payload, dict) or any(field in payload for field in path):
        raise HTTPException(400, detail='invalid_evidence_payload')
    # Older browser JS sends this display-only value. It is discarded before
    # validation/dispatch and can never become a persisted actor identity.
    payload.pop('submitter', None)
    if request.method in ('POST', 'DELETE') and not _BASE <= payload.keys():
        raise HTTPException(400, detail='evidence_context_required')
    payload.update(path)
    return _validate(payload, action, request.app.state.config)


def _public_attachment(row, *, operation_context=None):
    allowed = {'attachment_id', 'filename', 'size', 'sha256', 'note', 'display_note',
               'display_note_complete', 'evidence_kind', 'round_id', 'head_sha',
               'status', 'created_at', 'updated_at', 'completed_at', 'deleted_at', 'replaces_id',
               'cos_content_verified', 'upload_method', 'download_capability', 'can_delete',
               'internal_bot_note', 'github_comment_synced', 'github_comment_state',
               'github_comment_pending'}
    result = {k: v for k, v in row.items() if k in allowed}
    upload_ref = row.get('upload_ref')
    if (operation_context is not None and isinstance(upload_ref, str)
            and _ID.fullmatch(upload_ref)
            and row.get('repo') == operation_context.get('repo')
            and row.get('pr_number') == operation_context.get('pr_number')
            and row.get('head_sha') == operation_context.get('head_sha')
            and row.get('round_id') == operation_context.get('round_id')):
        # This is the durable, scoped operation handle; the COS multipart
        # UploadId and other internal upload facts are never exposed.
        result['upload_id'] = upload_ref
    return result


async def _summary_updated(request, repo, pr, result):
    # This is a read-only comparison against the trusted lifecycle comment.
    # Store verification alone does not prove the watcher updated Summary.
    try:
        from .github_state_proxy import HIDDEN_STATE_MARKER, _extract_hidden_state
        comment = await request.app.state.proxy.find_trusted_lifecycle_comment(repo, pr)
        if comment is None:
            return False
        body = comment['body']
        state = _extract_hidden_state(body)
        if not state or state.get('head_sha') != result['head_sha']:
            return False
        visible = body.split(HIDDEN_STATE_MARKER, 1)[0].rstrip()
        expected = await request.app.state.controller._render_evidence_projection(repo, pr, state, visible)
        return expected == visible and '<!-- evidence-projection:start -->' in visible
    except Exception:
        return False


async def _trusted_summary_page_capability(request, repo, pr, *, target_head=None,
                                           target_round=None):
    """Mint a page-only read capability for a trusted current or archived round."""
    config = request.app.state.config
    if (not evidence_auth.public_https_ingress_ready(config)
            or not evidence_auth._configured_https_request(request)):
        return None
    if (target_head is None) != (target_round is None):
        return None
    if (target_head is not None
            and (not isinstance(target_head, str)
                 or not re.fullmatch(r'[0-9a-f]{40}', target_head)
                 or not isinstance(target_round, str)
                 or not re.fullmatch(re.escape(target_head) + r'-[0-9]+', target_round))):
        return None
    proxy = request.app.state.proxy
    try:
        comment = await proxy.find_trusted_lifecycle_comment(repo, pr)
    except Exception:
        raise HTTPException(503, detail='evidence_pr_unavailable') from None
    if not isinstance(comment, dict):
        return None
    expected_issue_url = (
        f'{config.github_api_url.rstrip("/")}/repos/{repo}/issues/{pr}'
    )
    if comment.get('issue_url') != expected_issue_url:
        return None
    body = comment.get('body')
    if not isinstance(body, str):
        return None
    from .github_state_proxy import HIDDEN_STATE_MARKER, _extract_hidden_state, _validate_hidden_state
    marker_pos = body.find(HIDDEN_STATE_MARKER)
    if marker_pos < 0:
        return None
    try:
        state = _validate_hidden_state(_extract_hidden_state(body))
    except Exception:
        raise HTTPException(503, detail='evidence_state_unavailable') from None
    if not isinstance(state, dict):
        raise HTTPException(503, detail='evidence_state_unavailable')
    try:
        current_pr = await proxy.get_pr(repo, pr)
    except Exception as exc:
        if getattr(exc, 'status_code', None) == 404:
            raise HTTPException(404, detail='evidence_pr_not_found') from None
        raise HTTPException(503, detail='evidence_pr_unavailable') from None
    if not isinstance(current_pr, dict) or current_pr.get('state') not in {'open', 'closed'}:
        raise HTTPException(503, detail='evidence_pr_status_unavailable')
    base = current_pr.get('base')
    base_repository = base.get('repo') if isinstance(base, dict) else None
    base_name = base_repository.get('full_name') if isinstance(base_repository, dict) else None
    if not isinstance(base_name, str) or base_name.casefold() != repo.casefold():
        raise HTTPException(409, detail='evidence_pr_context_changed')
    pr_head = current_pr.get('head')
    pr_head_sha = pr_head.get('sha') if isinstance(pr_head, dict) else None
    if not isinstance(pr_head_sha, str) or not re.fullmatch(r'[0-9a-f]{40}', pr_head_sha):
        raise HTTPException(503, detail='evidence_pr_status_unavailable')

    from .evidence_models import round_id_for_state, trusted_round_numbers
    try:
        current_head = state.get('head_sha')
        current_round = round_id_for_state(state)
    except Exception:
        raise HTTPException(503, detail='evidence_state_unavailable') from None
    if (not isinstance(current_head, str) or not re.fullmatch(r'[0-9a-f]{40}', current_head)
            or not isinstance(state.get('status'), str) or not state['status']):
        return None
    head, round_id = target_head, target_round
    if head is None:
        head, round_id = current_head, current_round
    is_current_round = (
        (head, round_id) == (current_head, current_round)
        and pr_head_sha == current_head
    )
    if not is_current_round:
        try:
            records = await proxy.read_evidence_records(repo, pr)
        except Exception:
            raise HTTPException(503, detail='evidence_history_unavailable') from None
        if not isinstance(records, (list, tuple)):
            raise HTTPException(503, detail='evidence_history_unavailable')
        round_numbers = trusted_round_numbers(records, state, repo, pr)
        if round_id not in round_numbers:
            return None
        archive_matches = any(
            isinstance(record, dict) and record.get('kind') == 'round'
            and isinstance(record.get('data'), dict)
            and record['data'].get('repo') == repo
            and record['data'].get('pr_number') == pr
            and record['data'].get('head_sha') == head
            and record['data'].get('round_id') == round_id
            and isinstance(record['data'].get('snapshot'), dict)
            and record['data']['snapshot'].get('head_sha') == head
            and (record['data']['snapshot'].get('repo') is None
                 or record['data']['snapshot'].get('repo') == repo)
            and (record['data']['snapshot'].get('pr_number') is None
                 or record['data']['snapshot'].get('pr_number') == pr)
            for record in records
        )
        if not archive_matches:
            return None
    try:
        token = evidence_auth.issue_capability(
            config, repo, pr, head, round_id,
            purpose=evidence_auth.DOWNLOAD_PURPOSE, resource='page',
        )
        evidence_auth.verify_capability(
            config, token, repo, pr,
            purpose=evidence_auth.DOWNLOAD_PURPOSE, resource='page',
        )
        return token
    except (TypeError, ValueError, HTTPException):
        return None


async def _dispatch(request, owner, repo, pr, action, **path):
    canonical = _repo(owner, repo, pr)
    purpose = (evidence_auth.DOWNLOAD_PURPOSE if action in {'download', 'preview', 'log_download', 'machine_log_download'}
               else evidence_auth.UPLOAD_PURPOSE if action in {
                   'context', 'status', 'init', 'resume', 'sign_part', 'put_part',
                   'complete', 'note', 'delete'} else evidence_auth.PURPOSE)
    resource = None
    if action in {'download', 'preview'}:
        resource = 'attachment:' + path.get('attachment_id', '')
    elif action == 'log_download':
        resource = 'log:' + path.get('round_id', '')
    elif action == 'machine_log_download':
        resource = 'log:' + path.get('round_id', '') + ':' + path.get('machine_alias', '')
    principal, _ = await evidence_auth.verified_principal(
        request, canonical, pr, write=request.method in ('POST', 'PUT', 'DELETE'),
        purpose=purpose, resource=resource)
    if request.method in ('POST', 'PUT', 'DELETE'):
        # Anti-abuse ceiling only: authorization is always the verified principal
        # above, never the counter.
        evidence_auth.enforce_write_rate_limit(principal, canonical, pr, action)
    # The EvidenceService reads and validates the live PR before any operation.
    # Do not double-fetch it here: additional GitHub calls delay uploads and
    # turn transient PR reads into misleading 'evidence_pr_unavailable' errors.
    payload = await _payload(request, action, **path)
    claims = principal.get('capability') or principal.get('upload_invite') or {
        'head': payload.get('head_sha'), 'round': payload.get('round_id')}
    if action == 'context':
        # The page capability selects the current round or a specific archived
        # round. The EvidenceService still validates that binding against the
        # trusted lifecycle snapshot before returning any records.
        if claims.get('head') and payload.get('head_sha') and payload['head_sha'] != claims['head']:
            raise HTTPException(409, detail='evidence_round_changed')
        if claims.get('round') and payload.get('round_id') and payload['round_id'] != claims['round']:
            raise HTTPException(409, detail='evidence_round_changed')
        if claims.get('head'):
            payload['head_sha'] = claims['head']
        if claims.get('round'):
            payload['round_id'] = claims['round']
    if 'upload_id' in payload:
        # The public upload handle is A's durable operation identity, rather
        # than an unauthenticated client-selected COS UploadId.
        payload['operation_id'] = payload.pop('upload_id')
    if action in {'download', 'preview'} and 'round_id' not in payload:
        records = await request.app.state.proxy.read_evidence_records(canonical, pr)
        candidates = [r['data'] for r in records if r['kind'] == 'attachment'
                      and r['data'].get('attachment_id') == payload['attachment_id']
                      and r['data'].get('head_sha') == claims.get('head')
                      and r['data'].get('round_id') == claims.get('round')]
        if candidates:
            row = candidates[-1]
            payload.update(head_sha=row['head_sha'], round_id=row['round_id'])
    if action in {'resume', 'download', 'preview', 'log_download', 'machine_log_download'}:
        if action == 'resume' and not _BASE <= payload.keys():
            raise HTTPException(400, detail='evidence_context_required')
    if action in {'init', 'resume', 'sign_part', 'put_part', 'complete', 'note', 'delete'}:
        if action == 'put_part' and not {'head_sha', 'round_id'} <= payload.keys():
            raise HTTPException(400, detail='evidence_context_required')
        if claims.get('head') and payload.get('head_sha') and payload['head_sha'] != claims['head']:
            raise HTTPException(409, detail='evidence_round_changed')
        if claims.get('round') and payload.get('round_id') and payload['round_id'] != claims['round']:
            raise HTTPException(409, detail='evidence_round_changed')
        if claims.get('head'):
            payload['head_sha'] = claims['head']
        if claims.get('round'):
            payload['round_id'] = claims['round']
        # Compatibility with the current browser UI: a display name is not
        # an identity source. The service records only the verified /user login.
        payload.pop('submitter', None)
        payload.pop('object_key', None)
    if action in {'download', 'preview', 'log_download', 'machine_log_download'}:
        payload.setdefault('idempotency_key', hashlib.sha256(
            json.dumps([action, path], sort_keys=True).encode()).hexdigest())
    try:
        if action == 'put_part':
            cap = min(8 * 1024 * 1024, request.app.state.config.evidence_part_bytes)
            content_length = request.headers.get('content-length')
            if content_length:
                try:
                    if int(content_length) > cap:
                        raise HTTPException(413, detail='evidence_part_too_large')
                except ValueError:
                    raise HTTPException(400, detail='invalid_content_length') from None
            payload['_body_stream'] = request.stream()
            result = await request.app.state.evidence_service.dispatch(
                action, repo=canonical, pr_number=pr, principal=principal, payload=payload)
        else:
            result = await request.app.state.evidence_service.dispatch(
                action, repo=canonical, pr_number=pr, principal=principal, payload=payload)
    except EvidenceStoreError:
        raise HTTPException(503, detail='evidence_object_unavailable') from None
    except Exception as exc:
        # Only the service's explicitly public error code crosses HTTP. SDK and
        # network diagnostics can contain signed URLs or authentication headers.
        from .evidence_models import EvidenceError
        if isinstance(exc, EvidenceError):
            raise HTTPException(exc.status_code, detail=exc.code) from None
        raise HTTPException(503, detail='evidence_operation_unavailable') from None
    if not isinstance(result, dict):
        raise HTTPException(503, detail='invalid_evidence_service_response')
    if action == 'context' and result.get('evidence_degraded') is True:
        verified_can_write = result.get('can_write') is True
        verified_upload_invite = result.get('upload_invite') is True
        verified_authenticated = result.get('authenticated') is True
        verified_enabled = result.get('enabled') is True
        if (type(result.get('can_write')) is not bool
                or type(result.get('upload_invite')) is not bool
                or not verified_authenticated or not verified_enabled):
            raise HTTPException(503, detail='invalid_degraded_evidence_context')
        head, round_id = result.get('head_sha'), result.get('round_id')
        if (not isinstance(head, str) or not re.fullmatch(r'[0-9a-f]{40}', head)
                or not isinstance(round_id, str)
                or not re.fullmatch(re.escape(head) + r'-[1-9][0-9]*', round_id)):
            raise HTTPException(503, detail='incomplete_degraded_evidence_context')
        current_logs = {}
        for alias, log in (result.get('deployment_logs', {}) or {}).items():
            if (not _machine_alias(alias) or not isinstance(log, dict)
                    or log.get('head_sha') != head or log.get('round_id') != round_id
                    or log.get('status') not in {'ready', 'pending', 'unavailable'}):
                continue
            item = {k: log[k] for k in ('status', 'collected_at', 'size', 'sha256') if k in log}
            if log.get('status') == 'ready':
                from .evidence_auth import issue_capability
                item['capability'] = issue_capability(
                    request.app.state.config, canonical, pr, head, round_id,
                    purpose=evidence_auth.DOWNLOAD_PURPOSE,
                    resource='log:' + round_id + ':' + alias)
            current_logs[alias] = item
        allowed = {'head_sha', 'round_id', 'round_number', 'round_started_at', 'status',
                   'acceptance_pending', 'display_deployments'}
        result = {k: result[k] for k in allowed if k in result}
        result.update({
            'can_write': verified_can_write,
            'evidence_degraded': True,
            'attachments': [], 'rounds': [], 'history': [], 'archive_links': [],
            'deployment_logs': current_logs,
            'authenticated': verified_authenticated, 'enabled': verified_enabled,
            'upload_invite': verified_upload_invite,
            'github_user_authenticated': bool(principal.get('github_user_authenticated')),
            'actor_verified': principal.get('actor_verified') is True,
            'auth_method': principal.get('auth_method', 'github_comment_proof'),
            'readiness': evidence_auth.readiness(
                request.app.state.config, request.app.state.evidence_service, request=request),
            'repo': canonical, 'pr_number': pr, 'summary_updated': None,
            'max_file_bytes': request.app.state.config.evidence_max_file_bytes,
            'part_bytes': request.app.state.config.evidence_part_bytes,
        })
        if not {'head_sha', 'round_id', 'status', 'can_write', 'evidence_degraded'} <= result.keys():
            raise HTTPException(503, detail='incomplete_degraded_evidence_context')
    # Internal recovery facts (COS keys, actor IDs) never need to reach the
    # browser. A durable operation ID is the only browser upload handle.
    if action in {'init', 'resume', 'complete', 'note'}:
        result = {**result, 'upload_id': path.get('upload_id') or result.get('source_operation_id', result.get('operation_id')),
                  'part_bytes': result.get('part_bytes', request.app.state.config.evidence_part_bytes),
                  'uploaded_parts': result.get('uploaded_parts', [])}
    if action == 'status':
        # Status is a deliberately small public projection. In particular, a
        # COS multipart UploadId and signed URLs are never public state. The
        # GitHub display fields must survive this projection: the page uses
        # them to distinguish "saved but not yet announced" from a failure.
        result = {k: result[k] for k in (
            'status', 'uploaded_parts', 'size', 'filename', 'head_sha', 'round_id',
            'verified', 'sha256', 'attachment_id', 'github_record_persisted',
            'record_pending', 'github_comment_synced', 'github_comment_state',
            'github_comment_pending', 'historical') if k in result}
        # A ready attachment with no recorded display state is reported as
        # pending, never as synced. It is also never reported as an upload
        # failure: the file is already saved and verified.
        if (result.get('status') == 'ready'
                and result.get('github_comment_synced') is not True
                and 'github_comment_state' not in result):
            result['github_comment_pending'] = True
    if action == 'context' and result.get('evidence_degraded') is not True:
        current_logs = {}
        for alias, log in (result.get('deployment_logs', {}) or {}).items():
            if not _machine_alias(alias) or not isinstance(log, dict):
                continue
            item = {k: log[k] for k in ('status', 'collected_at', 'size', 'sha256') if k in log}
            if log.get('status') == 'ready' and log.get('head_sha') == result.get('head_sha') and log.get('round_id') == result.get('round_id'):
                from .evidence_auth import issue_capability
                item['capability'] = issue_capability(
                    request.app.state.config, canonical, pr, result['head_sha'], result['round_id'],
                    purpose=evidence_auth.DOWNLOAD_PURPOSE,
                    resource='log:' + result['round_id'] + ':' + alias)
            current_logs[alias] = item
        result['deployment_logs'] = current_logs
        def scoped(rows):
            from .evidence_auth import issue_capability
            output = []
            for row in rows:
                item = dict(row)
                head = item.get('head_sha')
                round_value = item.get('round_id')
                digest = item.get('sha256')
                if (item.get('status') == 'ready' and not item.get('deleted_at')
                        and isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest)
                        and isinstance(head, str) and re.fullmatch(r'[0-9a-f]{40}', head)
                        and isinstance(round_value, str)
                        and re.fullmatch(re.escape(head) + r'-[0-9]+', round_value)
                        and isinstance(item.get('attachment_id'), str)
                        and _ID.fullmatch(item['attachment_id'])):
                    item['download_capability'] = issue_capability(
                        request.app.state.config, canonical, pr, head, round_value,
                        purpose=evidence_auth.DOWNLOAD_PURPOSE,
                        resource='attachment:' + item['attachment_id'],
                    )
                output.append(_public_attachment(item))
            return output
        rows = result.get('attachments', result.get('records', []))
        attachments = scoped(rows)
        rounds = []
        for row in result.get('rounds', []):
            machine_logs = {}
            for alias, log in (row.get('deployment_logs', {}) or {}).items():
                if (not _machine_alias(alias)
                        or not isinstance(log, dict) or log.get('status') not in {'ready', 'pending', 'unavailable'}):
                    continue
                public_log = {k: log.get(k) for k in ('status', 'collected_at', 'size', 'sha256') if k in log}
                if log.get('status') == 'ready' and log.get('head_sha') == row.get('head_sha') and log.get('round_id') == row.get('round_id'):
                    from .evidence_auth import issue_capability
                    public_log['capability'] = issue_capability(
                        request.app.state.config, canonical, pr, row['head_sha'], row['round_id'],
                        purpose=evidence_auth.DOWNLOAD_PURPOSE,
                        resource='log:' + row['round_id'] + ':' + alias)
                machine_logs[alias] = public_log
            round_value = {**{k: v for k, v in row.items() if k in {
                'head_sha', 'round_id', 'round_number', 'status', 'created_at', 'started_at',
                'round_started_at', 'ended_at', 'archived_at', 'acceptance_pending',
                'display_deployments'}},
                'attachments': scoped(row.get('attachments', [])),
                'log_available': bool(row.get('cos', {}).get('object_key')),
                'deployment_logs': machine_logs}
            head, round_id = round_value.get('head_sha'), round_value.get('round_id')
            if isinstance(head, str) and isinstance(round_id, str) and head == round_id.rsplit('-', 1)[0]:
                from .evidence_auth import issue_capability
                round_value['capability'] = issue_capability(
                    request.app.state.config, canonical, pr, head, round_id,
                    purpose=evidence_auth.DOWNLOAD_PURPOSE,
                    resource='log:' + round_id,
                )
            rounds.append(round_value)
        result['rounds'] = rounds
        operation_context = {key: result.get(key) for key in ('repo', 'pr_number', 'head_sha', 'round_id')}
        result['operations'] = [
            _public_attachment(row, operation_context=operation_context)
            for row in result.get('operations', [])
        ]
        # Summary synchronization is presentation-only; do not hold the page
        # response on a second GitHub comment read/render.
        result['summary_updated'] = None
        result = {**result, 'authenticated': True, 'enabled': True,
                  'github_user_authenticated': bool(principal.get('github_user_authenticated')),
                  'actor_verified': principal.get('actor_verified') is True,
                  'auth_method': principal.get('auth_method', 'github_comment_proof'),
                  'readiness': evidence_auth.readiness(
                      request.app.state.config, request.app.state.evidence_service, request=request),
                  'attachments': attachments, 'repo': canonical, 'pr_number': pr,
                  # PR state is returned from the EvidenceService's validated
                  # snapshot; no extra GitHub request is needed here.
                  'max_file_bytes': request.app.state.config.evidence_max_file_bytes,
                  'part_bytes': request.app.state.config.evidence_part_bytes}
        if not {'head_sha', 'round_id', 'status', 'can_write', 'attachments', 'archive_links'} <= result.keys():
            raise HTTPException(503, detail='incomplete_evidence_context')
    for name in ('object_key', 'upload_ref', 'operation_id', 'source_operation_id',
                 'actor_id', 'actor_login', 'deleted_by', 'records', 'request_sha256'):
        result.pop(name, None)
    return result


def _json(result):
    return JSONResponse(result, headers={'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
                                         'X-Content-Type-Options': 'nosniff'})


@router.get(_PREFIX + '/context')
async def context(request: Request, owner: str, repo: str, pr: int):
    return _json(await _dispatch(request, owner, repo, pr, 'context'))


@router.post(_PREFIX + '/uploads')
async def init(request: Request, owner: str, repo: str, pr: int):
    return _json(await _dispatch(request, owner, repo, pr, 'init'))


@router.get(_PREFIX + '/uploads/{upload_id}')
async def upload_status(request: Request, owner: str, repo: str, pr: int, upload_id: str):
    return _json(await _dispatch(request, owner, repo, pr, 'status', upload_id=upload_id))


@router.post(_PREFIX + '/uploads/{upload_id}/resume')
async def resume(request: Request, owner: str, repo: str, pr: int, upload_id: str):
    return _json(await _dispatch(request, owner, repo, pr, 'resume', upload_id=upload_id))


@router.post(_PREFIX + '/uploads/{upload_id}/parts/{part_number}/url')
async def sign_part(request: Request, owner: str, repo: str, pr: int, upload_id: str, part_number: int):
    return _json(await _dispatch(request, owner, repo, pr, 'sign_part', upload_id=upload_id, part_number=part_number))


@router.put(_PREFIX + '/uploads/{upload_id}/parts/{part_number}/data')
async def upload_part(request: Request, owner: str, repo: str, pr: int, upload_id: str, part_number: int):
    return _json(await _dispatch(request, owner, repo, pr, 'put_part', upload_id=upload_id, part_number=part_number))


@router.post(_PREFIX + '/uploads/{upload_id}/complete')
async def complete(request: Request, owner: str, repo: str, pr: int, upload_id: str):
    return _json(await _dispatch(request, owner, repo, pr, 'complete', upload_id=upload_id))


@router.post(_PREFIX + '/notes')
async def note(request: Request, owner: str, repo: str, pr: int):
    return _json(await _dispatch(request, owner, repo, pr, 'note'))


@router.delete(_PREFIX + '/attachments/{attachment_id}')
async def delete(request: Request, owner: str, repo: str, pr: int, attachment_id: str):
    return _json(await _dispatch(request, owner, repo, pr, 'delete', attachment_id=attachment_id))


async def _download(request, owner, repo, pr, action, **path):
    result = await _dispatch(request, owner, repo, pr, action, **path)
    url = result.get('url')
    if not isinstance(url, str) or not url.startswith('https://'):
        raise HTTPException(503, detail='evidence_download_unavailable')
    return RedirectResponse(url, status_code=303,
                            headers={'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer'})


@router.get(_PREFIX + '/attachments/{attachment_id}/download')
async def download(request: Request, owner: str, repo: str, pr: int, attachment_id: str):
    return await _download(request, owner, repo, pr, 'download', attachment_id=attachment_id)


@router.get(_PREFIX + '/attachments/{attachment_id}/preview')
async def preview(request: Request, owner: str, repo: str, pr: int, attachment_id: str):
    return await _download(request, owner, repo, pr, 'preview', attachment_id=attachment_id)


@router.get(_PREFIX + '/rounds/{round_id}/log/download')
async def log_download(request: Request, owner: str, repo: str, pr: int, round_id: str):
    return await _download(request, owner, repo, pr, 'log_download', round_id=round_id)


@router.get(_PREFIX + '/rounds/{round_id}/machines/{machine_alias}/log/download')
async def machine_log_download(request: Request, owner: str, repo: str, pr: int,
                               round_id: str, machine_alias: str):
    return await _download(request, owner, repo, pr, 'machine_log_download',
                           round_id=round_id, machine_alias=machine_alias)


@router.get('/evidence/{owner}/{repo}/pulls/{pr}', response_class=HTMLResponse)
async def page(request: Request, owner: str, repo: str, pr: int):
    """Permanent per-PR upload address.

    The public URL contains only the configured stable origin, repository and
    PR number. Upload authority is a short, server-signed session minted from
    trusted GitHub state on every visit and carried in an HttpOnly cookie; it
    never appears in the URL. Legacy ``?cap=`` links are redirected to the
    same fixed path so old Summary links keep working without exposing tokens.
    """
    headers = {'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
               'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY'}
    canonical = None
    try:
        evidence_auth.require_enabled(request)
        canonical = _repo(owner, repo, pr)
        if 'cap' in request.query_params:
            # Never honor, echo or proxy a legacy capability in the public link.
            clean_path = request.url.path
            if 'read' in request.query_params.getlist('view'):
                # Preserve read target if present, but strip cap
                params = {k: v for k, v in request.query_params.items() if k != 'cap'}
                clean_path += '?' + urllib.parse.urlencode(params)
            return RedirectResponse(clean_path, status_code=303,
                                    headers=headers)
        if 'read' not in request.query_params.getlist('view') and request.query_params:
            # The fixed upload page never carries query parameters (no cap, HEAD, round or token).
            return RedirectResponse(request.url.path, status_code=303,
                                    headers=headers)
        from . import evidence_ui
        if 'read' in request.query_params.getlist('view'):
            # Historical/read-only round view. Only the target round is resolved
            # here (current or archived); the fixed path itself grants nothing.
            if not await _installation_repo_authorized(request, canonical):
                raise HTTPException(403, detail='repository_not_authorized')
            target = _requested_read_target(request)
            read_capability = await _trusted_summary_page_capability(
                request, canonical, pr,
                target_head=target[0] if target else None,
                target_round=target[1] if target else None,
            )
            if not read_capability:
                raise HTTPException(403, detail='invalid_evidence_capability')
            claims = evidence_auth._verify_page_capability(
                request.app.state.config, read_capability, canonical, pr,
            )
            response = HTMLResponse(evidence_ui.render_upload_page(
                canonical, pr, claims['head'], claims['round'],
                read_only=True,
            ), headers=headers)
            evidence_auth.bind_read_session(response, request, read_capability)
            evidence_auth.drop_upload_session(response, request)
            return response

        context = await _trusted_page_context(request, canonical, pr)
        if context['writable']:
            session = evidence_auth.issue_upload_session(
                request.app.state.config, canonical, pr,
                context['head_sha'], context['round_id'],
            )
            claims = evidence_auth._verify_upload_capability(
                request.app.state.config, session, canonical, pr,
            )
            response = HTMLResponse(evidence_ui.render_upload_page(
                canonical, pr, claims['head'], claims['round'],
                read_only=False,
            ), headers=headers)
            evidence_auth.bind_upload_session(response, request, session)
        else:
            if not evidence_auth.public_https_ingress_ready(request.app.state.config):
                # Upload is optional; a missing public entry must not look like
                # a failed deployment or a closed PR.
                raise HTTPException(503, detail='evidence_public_entry_unavailable')
            # Outside a writable testing round the page is read-only. The read
            # capability is minted from the trusted Summary only after the
            # installation/PR/round checks above.
            read_capability = await _trusted_summary_page_capability(
                request, canonical, pr,
                target_head=context['head_sha'],
                target_round=context['round_id'],
            )
            if not read_capability:
                raise HTTPException(403, detail='invalid_evidence_capability')
            claims = evidence_auth._verify_page_capability(
                request.app.state.config, read_capability, canonical, pr,
            )
            response = HTMLResponse(evidence_ui.render_upload_page(
                canonical, pr, claims['head'], claims['round'],
                read_only=True,
            ), headers=headers)
            evidence_auth.bind_read_session(response, request, read_capability)
            evidence_auth.drop_upload_session(response, request)
        return response
    except HTTPException as exc:
        # Keep the authorization status and never echo exception detail,
        # capability input, cookies, or backend diagnostics into HTML.
        messages = {
            401: '附件链接身份验证失败，请从当前 PR Summary 重新打开。',
            403: '附件链接已失效或无权访问，请从当前 PR Summary 重新打开。',
            409: 'PR 或测试轮次已变化，请刷新当前 PR Summary 后重新打开。',
            503: '附件服务暂时不可用，请稍后从当前 PR Summary 重新打开。',
        }
        details = {
            'evidence_pr_unavailable': '暂时无法读取 GitHub PR 信息；这不代表 PR 已关闭。请稍后重试，或检查 GitHub API 连通性。',
            'evidence_pr_status_unavailable': '暂时无法确认 GitHub PR 状态或 HEAD；请稍后重试。',
            'evidence_history_unavailable': '历史附件记录暂时无法读取；请返回当前 PR Summary 查看最新状态，稍后再试历史附件。',
            'evidence_state_unavailable': '暂时无法验证当前 Lifecycle 状态；请稍后重试。',
            'evidence_public_entry_unavailable': '公共上传入口暂时不可用；测试视频或图片上传完全可选，不影响测试和验收。',
        }
        message = details.get(exc.detail, messages.get(
            exc.status_code, '附件链接暂不可用，请从当前 PR Summary 重新打开。'))
        summary_link = ('<p><a href="https://github.com/' + canonical + '/pull/' + str(pr)
                        + '">打开当前 PR Summary</a></p>') if canonical else ''
        html = ('<!doctype html><html lang="zh-CN"><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width,initial-scale=1">'
                '<title>附件链接不可用</title><main><h1>附件链接不可用</h1><p>'
                + message + '</p>' + summary_link + '</main></html>')
        return HTMLResponse(html, status_code=exc.status_code, headers=headers)


async def _installation_repo_authorized(request: Request, repo: str) -> bool:
    """Verify GitHub App installation access before exposing any PR state."""
    config = request.app.state.config
    if (not getattr(config, 'auth_valid', False)
            or repo not in getattr(config, 'github_repos', [])
            or repo not in getattr(config, 'active_repos', [])):
        return False
    try:
        authorized = await request.app.state.github.list_installation_repositories()
    except Exception:
        raise HTTPException(503, detail='evidence_pr_unavailable') from None
    return isinstance(authorized, (list, tuple)) and repo in {
        str(name).casefold() for name in authorized
    }


async def _trusted_page_context(request: Request, repo: str, pr: int) -> dict:
    """Load PR identity, latest HEAD, current round and Lifecycle from GitHub."""
    proxy = request.app.state.proxy
    if not await _installation_repo_authorized(request, repo):
        raise HTTPException(403, detail='repository_not_authorized')
    try:
        current_pr = await proxy.get_pr(repo, pr)
    except Exception as exc:
        if getattr(exc, 'status_code', None) == 404:
            raise HTTPException(404, detail='evidence_pr_not_found') from None
        raise HTTPException(503, detail='evidence_pr_unavailable') from None
    if not isinstance(current_pr, dict) or current_pr.get('state') not in {'open', 'closed'}:
        raise HTTPException(503, detail='evidence_pr_status_unavailable')
    base = current_pr.get('base')
    base_repository = base.get('repo') if isinstance(base, dict) else None
    base_name = base_repository.get('full_name') if isinstance(base_repository, dict) else None
    if not isinstance(base_name, str) or base_name.casefold() != repo.casefold():
        raise HTTPException(409, detail='evidence_pr_context_changed')
    head = current_pr.get('head')
    head_sha = head.get('sha') if isinstance(head, dict) else None
    if not isinstance(head_sha, str) or not re.fullmatch(r'[0-9a-f]{40}', head_sha):
        raise HTTPException(503, detail='evidence_pr_status_unavailable')
    state = await proxy.read_hidden_state(repo, pr)
    if not isinstance(state, dict):
        raise HTTPException(503, detail='evidence_state_unavailable')
    from .evidence_models import round_id_for_state
    try:
        round_id = round_id_for_state(state)
    except Exception:
        raise HTTPException(503, detail='evidence_state_unavailable') from None
    if (state.get('head_sha') != head_sha
            or not isinstance(round_id, str)
            or not re.fullmatch(re.escape(head_sha) + r'-[0-9]+', round_id)):
        raise HTTPException(409, detail='evidence_round_changed')
    ready = evidence_auth.readiness(
        request.app.state.config, request.app.state.evidence_service, request=request,
    )
    writable = bool(
        state.get('status') == 'testing'
        and current_pr.get('state') == 'open'
        and not current_pr.get('merged') and not current_pr.get('draft')
        and ready.get('BROWSER_UPLOAD_READY') is True
        and evidence_auth._configured_https_request(request)
    )
    return {
        'head_sha': head_sha, 'round_id': round_id,
        'status': state.get('status'), 'writable': writable,
    }


def _requested_read_target(request):
    head_values = request.query_params.getlist('head_sha')
    round_values = request.query_params.getlist('round_id')
    if not head_values and not round_values:
        return None
    if (len(head_values) != 1 or len(round_values) != 1
            or not re.fullmatch(r'[0-9a-f]{40}', head_values[0])
            or not re.fullmatch(re.escape(head_values[0]) + r'-[0-9]+', round_values[0])):
        raise HTTPException(400, detail='invalid_evidence_round')
    return head_values[0], round_values[0]


@router.get('/evidence/assets/app.js')
async def javascript(request: Request):
    evidence_auth.require_enabled(request)
    from . import evidence_ui
    return Response(evidence_ui.javascript_source(), media_type='application/javascript',
                    headers={'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})
