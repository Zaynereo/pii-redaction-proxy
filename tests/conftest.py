"""Shared fixtures — synthetic data only, no real credentials."""

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import app


@pytest.fixture
def client() -> TestClient:
    get_settings.cache_clear()
    return TestClient(app)


@pytest.fixture
def synthetic_customer() -> dict:
    return {
        "customer": {
            "email": "synthetic.user+demo@example.test",
            "phone": "+15551234567",
        },
        "orderId": "ORD-9988776655",
        "metadata": {
            "secretEmail": "hidden.leak@example.test",
        },
    }


# Visa test PAN (synthetic, industry-standard test number).
SYNTHETIC_LUHN_PAN = "4111111111111111"
LUHN_FAIL_PAN = "4111111111111112"
