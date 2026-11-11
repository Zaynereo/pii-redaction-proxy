"""Documented JSON pointer-style paths and redaction kinds.

Only values at these paths are candidates for pattern-based redaction.
All other fields are left unchanged (intentional false negatives).
"""

from enum import Enum


class RedactionKind(str, Enum):
    EMAIL = "email"
    PHONE_E164 = "phone_e164"
    US_SSN = "us_ssn"
    PAYMENT_PAN = "payment_pan"


# JSON Pointer paths (RFC 6901), without leading slash for ergonomics in docs.
ALLOWLIST: dict[str, RedactionKind] = {
    "customer/email": RedactionKind.EMAIL,
    "customer/contactEmail": RedactionKind.EMAIL,
    "user/email": RedactionKind.EMAIL,
    "profile/emailAddress": RedactionKind.EMAIL,
    "customer/phone": RedactionKind.PHONE_E164,
    "customer/mobile": RedactionKind.PHONE_E164,
    "user/phoneNumber": RedactionKind.PHONE_E164,
    "identity/ssn": RedactionKind.US_SSN,
    "taxpayer/ssn": RedactionKind.US_SSN,
    "payment/cardNumber": RedactionKind.PAYMENT_PAN,
    "billing/primaryAccountNumber": RedactionKind.PAYMENT_PAN,
}

PLACEHOLDERS: dict[RedactionKind, str] = {
    RedactionKind.EMAIL: "[REDACTED_EMAIL]",
    RedactionKind.PHONE_E164: "[REDACTED_PHONE]",
    RedactionKind.US_SSN: "[REDACTED_SSN]",
    RedactionKind.PAYMENT_PAN: "[REDACTED_PAN]",
}
