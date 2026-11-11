"""Redact allowlisted string fields in parsed JSON with a depth bound."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.redaction.allowlist import ALLOWLIST, PLACEHOLDERS, RedactionKind
from app.redaction.patterns import (
    matches_e164,
    matches_email,
    matches_pan,
    matches_us_ssn,
)


class JsonDepthExceededError(ValueError):
    pass


@dataclass
class RedactionResult:
    data: Any
    redacted_paths: list[str] = field(default_factory=list)
    depth_exceeded: bool = False


def _should_redact(kind: RedactionKind, value: str) -> bool:
    if kind is RedactionKind.EMAIL:
        return matches_email(value)
    if kind is RedactionKind.PHONE_E164:
        return matches_e164(value)
    if kind is RedactionKind.US_SSN:
        return matches_us_ssn(value)
    if kind is RedactionKind.PAYMENT_PAN:
        return matches_pan(value)
    return False


def _walk(
    node: Any,
    path_parts: list[str],
    max_depth: int,
    depth: int,
    out_paths: list[str],
) -> Any:
    if depth > max_depth:
        raise JsonDepthExceededError(f"JSON depth exceeds limit of {max_depth}")

    if isinstance(node, dict):
        result: dict[str, Any] = {}
        for key, child in node.items():
            child_path = path_parts + [key]
            pointer = "/".join(child_path)
            if isinstance(child, str) and pointer in ALLOWLIST:
                kind = ALLOWLIST[pointer]
                if _should_redact(kind, child):
                    result[key] = PLACEHOLDERS[kind]
                    out_paths.append(pointer)
                else:
                    result[key] = child
            else:
                result[key] = _walk(child, child_path, max_depth, depth + 1, out_paths)
        return result

    if isinstance(node, list):
        return [
            _walk(item, path_parts + [str(i)], max_depth, depth + 1, out_paths)
            for i, item in enumerate(node)
        ]

    return node


def redact_json(data: Any, max_depth: int) -> RedactionResult:
    paths: list[str] = []
    try:
        redacted = _walk(data, [], max_depth, 0, paths)
    except JsonDepthExceededError:
        return RedactionResult(data=data, redacted_paths=[], depth_exceeded=True)
    return RedactionResult(data=redacted, redacted_paths=paths, depth_exceeded=False)
