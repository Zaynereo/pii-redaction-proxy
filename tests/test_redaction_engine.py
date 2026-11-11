"""Engine tests: allowlist-only redaction and depth."""

from app.redaction.engine import redact_json


def test_redacts_allowlisted_email_phone() -> None:
    data = {
        "customer": {
            "email": "synthetic.user+demo@example.test",
            "phone": "+15551234567",
        },
        "metadata": {"secretEmail": "hidden.leak@example.test"},
    }
    result = redact_json(data, max_depth=32)
    assert result.data["customer"]["email"] == "[REDACTED_EMAIL]"
    assert result.data["customer"]["phone"] == "[REDACTED_PHONE]"
    assert result.data["metadata"]["secretEmail"] == "hidden.leak@example.test"


def test_payment_pan_on_path_only() -> None:
    data = {
        "payment": {"cardNumber": "4111111111111111"},
        "notes": "4111111111111111",
    }
    result = redact_json(data, max_depth=32)
    assert result.data["payment"]["cardNumber"] == "[REDACTED_PAN]"
    assert result.data["notes"] == "4111111111111111"


def test_depth_limit() -> None:
    nested: dict = {"a": {}}
    current = nested
    for _ in range(40):
        current["a"] = {}
        current = current["a"]
    result = redact_json(nested, max_depth=5)
    assert result.depth_exceeded
