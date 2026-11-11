"""Unit tests for matchers (true/false positives)."""

from app.redaction.luhn import luhn_valid
from app.redaction.patterns import matches_e164, matches_email, matches_pan, matches_us_ssn


def test_email_true_positive() -> None:
    assert matches_email("synthetic.user+demo@example.test")


def test_email_version_like_false_positive() -> None:
    assert not matches_email("release@2.0")


def test_e164_true_positive() -> None:
    assert matches_e164("+15551234567")


def test_e164_us_local_false_negative() -> None:
    assert not matches_e164("(555) 123-4567")


def test_ssn_true_positive() -> None:
    assert matches_us_ssn("987-65-4321")


def test_isbn_like_not_ssn() -> None:
    assert not matches_us_ssn("978-0-306-40615-7")


def test_pan_luhn_true() -> None:
    assert matches_pan("4111111111111111")


def test_pan_luhn_fail_not_redacted_pattern() -> None:
    assert not matches_pan("4111111111111112")


def test_order_id_digits_not_pan() -> None:
    assert not luhn_valid("998877665544332")


def test_luhn_helper() -> None:
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("123456789012345")
