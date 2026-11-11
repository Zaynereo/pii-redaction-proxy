"""Logging helpers that avoid echoing request/response bodies."""

import logging

logger = logging.getLogger("pii_redaction_proxy")


def log_redact_request(*, redacted_count: int, depth_exceeded: bool) -> None:
    logger.info(
        "redact_complete",
        extra={
            "redacted_field_count": redacted_count,
            "depth_exceeded": depth_exceeded,
        },
    )


def log_forward_request(*, enabled: bool) -> None:
    logger.info("forward_invoked", extra={"forwarding_enabled": enabled})
