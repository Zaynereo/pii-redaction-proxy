"""Forwarding demo: SSRF guards and disabled mode."""

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import Settings, get_settings


def test_reject_upstream_in_body(client: TestClient) -> None:
    resp = client.post(
        "/v1/forward",
        json={"url": "http://evil.test", "payload": {"customer": {"email": "a@b.c"}}},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "upstream_override_forbidden"
    assert "a@b.c" not in resp.text


def test_reject_upstream_query(client: TestClient) -> None:
    resp = client.post(
        "/v1/forward?url=http://evil.test",
        json={"payload": {"customer": {"email": "x@example.test"}}},
    )
    assert resp.status_code == 400


def test_forwarding_disabled_returns_503_without_secrets(client: TestClient) -> None:
    get_settings.cache_clear()
    payload = {
        "payload": {
            "customer": {"email": "synthetic.user+demo@example.test"},
        }
    }
    resp = client.post("/v1/forward", json=payload)
    assert resp.status_code == 503
    body = resp.json()
    assert body["error"] == "forwarding_disabled"
    assert body["redacted_preview"]["customer"]["email"] == "[REDACTED_EMAIL]"
    assert "synthetic.user" not in resp.text


def test_forward_hits_fixed_upstream(monkeypatch: pytest.MonkeyPatch, client: TestClient) -> None:
    get_settings.cache_clear()
    monkeypatch.setenv("FORWARD_UPSTREAM_URL", "http://upstream-mock.local/v1/echo")
    get_settings.cache_clear()

    captured: dict = {}

    class MockTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            captured["json"] = json.loads(request.content.decode())
            return httpx.Response(200, json={"ok": True, "received_keys": list(captured["json"])})

    async def mock_forward(settings: Settings, payload: dict):
        url = settings.forward_upstream_url
        assert url == "http://upstream-mock.local/v1/echo"
        async with httpx.AsyncClient(transport=MockTransport(), follow_redirects=False) as c:
            r = await c.post(url, json=payload)
            return r.json()

    monkeypatch.setattr("app.main.forward_redacted_payload", mock_forward)

    resp = client.post(
        "/v1/forward",
        json={"payload": {"customer": {"email": "synthetic.user+demo@example.test"}}},
    )
    assert resp.status_code == 200
    assert captured["url"] == "http://upstream-mock.local/v1/echo"
    assert captured["json"]["customer"]["email"] == "[REDACTED_EMAIL]"
