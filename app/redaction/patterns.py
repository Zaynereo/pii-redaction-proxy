"""Conservative value patterns; applied only on allowlisted paths."""

import re

# Conservative email: requires an alphabetic TLD (filters version-like `user@2.0`).
EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z][a-zA-Z0-9-]{0,62}[a-zA-Z0-9]$"
)

# E.164: + followed by 8–15 digits (ITU-T E.164 max 15 digits).
E164_RE = re.compile(r"^\+[1-9]\d{7,14}$")

# US SSN: XXX-XX-XXXX or 9 digits (synthetic test fixtures only).
US_SSN_RE = re.compile(r"^(?:\d{3}-\d{2}-\d{4}|\d{9})$")

# PAN candidate: 13–19 digits, optional spaces/dashes between digit groups.
PAN_CANDIDATE_RE = re.compile(r"^[\d\s-]{13,23}$")


def digits_only(value: str) -> str:
    return re.sub(r"\D", "", value)


def matches_email(value: str) -> bool:
    if len(value) > 254:
        return False
    return EMAIL_RE.match(value) is not None


def matches_e164(value: str) -> bool:
    return E164_RE.match(value) is not None


def matches_us_ssn(value: str) -> bool:
    return US_SSN_RE.match(value) is not None


def matches_pan(value: str) -> bool:
    if not PAN_CANDIDATE_RE.match(value):
        return False
    d = digits_only(value)
    if len(d) < 13 or len(d) > 19:
        return False
    from app.redaction.luhn import luhn_valid

    return luhn_valid(d)
