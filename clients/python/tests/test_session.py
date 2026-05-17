"""Tests for ARESSession wire format and token derivation.

End-to-end WS tests against a live server live in tests/test_e2e.py
(skipped unless ARES_TEST_SERVER is set).
"""

from __future__ import annotations

import pytest

from ares_client.session import WSMessage, _derive_ws_token, _ws_url


def test_token_matches_go_authmiddleware_format():
    # Same vector our Go AuthMiddleware.GenerateToken would emit.
    tok = _derive_ws_token("secret", "pseudo-A")
    # HMAC-SHA256("secret","pseudo-A") computed offline.
    # Verify by recomputing in pure stdlib to avoid hard-coding.
    import hashlib
    import hmac
    expected = hmac.new(b"secret", b"pseudo-A", hashlib.sha256).hexdigest()
    assert tok == expected


def test_token_dev_bypass_when_secret_empty():
    # Helper still returns a digest even with empty secret; callers
    # are expected to pass "" auth in dev mode.
    tok = _derive_ws_token("", "p")
    assert isinstance(tok, str) and len(tok) == 64


def test_ws_url_construction_http():
    url = _ws_url("http://localhost:8000", "p-1", "abc")
    assert url.startswith("ws://localhost:8000/v2/ws?")
    assert "pseudonym=p-1" in url
    assert "auth=abc" in url


def test_ws_url_construction_https_promotes_to_wss():
    url = _ws_url("https://api.fheya.de", "p-1", "abc")
    assert url.startswith("wss://api.fheya.de/v2/ws?")


def test_wsmessage_from_json_minimal():
    m = WSMessage.from_json({"type": "x"})
    assert m.type == "x"
    assert m.session_id == ""
    assert m.payload is None


def test_wsmessage_from_json_full():
    m = WSMessage.from_json({
        "type": "auction.bid",
        "session_id": "S1",
        "seq": 7,
        "payload": {"price": 99},
        "timestamp": "2026-05-17T01:00:00Z",
    })
    assert m.type == "auction.bid"
    assert m.session_id == "S1"
    assert m.seq == 7
    assert m.payload == {"price": 99}
