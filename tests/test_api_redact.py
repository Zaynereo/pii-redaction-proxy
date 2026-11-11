"""HTTP tests for /v1/redact."""

from fastapi.testclient import TestClient

from app.config import get_settings


def test_redact_happy_path(client: TestClient, synthetic_customer: dict) -> None:
    resp = client.post("/v1/redact", json=synthetic_customer)
    assert resp.status_code == 200
    body = resp.json()
    assert body["redacted"]["customer"]["email"] == "[REDACTED_EMAIL]"
    assert "customer/email" in body["redacted_paths"]
    assert body["redacted"]["metadata"]["secretEmail"] == "hidden.leak@example.test"


def test_false_positive_order_id_unchanged(client: TestClient) -> None:
    payload = {"customer": {"email": "not-an-email"}, "orderId": "ORD-9988776655"}
    resp = client.post("/v1/redact", json=payload)
    assert resp.status_code == 200
    assert resp.json()["redacted"]["orderId"] == "ORD-9988776655"
    assert resp.json()["redacted_paths"] == []


def test_luhn_fail_on_allowlisted_path_unchanged(client: TestClient) -> None:
    payload = {"payment": {"cardNumber": "4111111111111112"}}
    resp = client.post("/v1/redact", json=payload)
    assert resp.status_code == 200
    assert resp.json()["redacted"]["payment"]["cardNumber"] == "4111111111111112"


def test_payload_too_large(client: TestClient) -> None:
    get_settings.cache_clear()
    settings = get_settings()
    limit = settings.max_request_bytes
    huge = b"x" * (limit + 1)
    resp = client.post(
        "/v1/redact",
        content=huge,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 413
    assert resp.json()["detail"]["error"] == "payload_too_large"


def test_error_response_does_not_echo_body_secret(client: TestClient) -> None:
    bad = b"{not json"
    resp = client.post("/v1/redact", content=bad, headers={"Content-Type": "application/json"})
    assert resp.status_code == 400
    assert "not json" not in resp.text


def test_unlisted_pii_unchanged(client: TestClient) -> None:
    payload = {"metadata": {"secretEmail": "hidden.leak@example.test"}}
    resp = client.post("/v1/redact", json=payload)
    assert resp.status_code == 200
    assert resp.json()["redacted"]["metadata"]["secretEmail"] == "hidden.leak@example.test"


def test_allowlisted_local_phone_format_unchanged(client: TestClient) -> None:
    payload = {"customer": {"phone": "(555) 123-4567"}}
    resp = client.post("/v1/redact", json=payload)
    assert resp.status_code == 200
    assert resp.json()["redacted"]["customer"]["phone"] == "(555) 123-4567"
    assert resp.json()["redacted_paths"] == []


def test_allowlist_endpoint(client: TestClient) -> None:
    resp = client.get("/v1/allowlist")
    assert resp.status_code == 200
    assert "customer/email" in resp.json()["paths"]
