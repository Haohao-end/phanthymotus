"""Webhook HMAC/security tests (final alignment).
Signature verification is independent of workflow changes.
"""

from __future__ import annotations

import hmac
import hashlib

import pytest

from ..router_webhook import _verify_signature_impl as verify_signature


def test_valid_signature():
    secret = b"test-secret"
    body = b'{"action": "created"}'
    sig = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    assert verify_signature(body, sig, secret) is True


def test_wrong_signature_rejected():
    secret = b"test-secret"
    body = b'{"action": "created"}'
    wrong_sig = "sha256=" + "a" * 64
    assert verify_signature(body, wrong_sig, secret) is False


def test_missing_secret_fail_closed():
    secret = b""
    body = b'{"action": "created"}'
    sig = "sha256=" + hmac.new(b"anything", body, hashlib.sha256).hexdigest()
    assert verify_signature(body, sig, secret) is False


def test_wrong_algorithm_rejected():
    secret = b"test-secret"
    body = b'{"action": "created"}'
    sig = "md5=" + "a" * 32
    assert verify_signature(body, sig, secret) is False


def test_empty_sig_rejected():
    assert verify_signature(b"body", "", b"secret") is False
    assert verify_signature(b"body", None, b"secret") is False
