"""Optional demo forward to a single env-configured upstream (no request-controlled URL)."""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx
from fastapi import HTTPException

from app.config import Settings

logger = logging.getLogger(__name__)


class ForwardingDisabledError(Exception):
    pass


async def forward_redacted_payload(settings: Settings, payload: dict[str, Any]) -> Any:
    if not settings.forward_upstream_url:
        raise ForwardingDisabledError()

    url = settings.forward_upstream_url
    timeout = httpx.Timeout(settings.forward_timeout_seconds)
    limits = httpx.Limits(max_keepalive_connections=2, max_connections=4)

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=timeout,
        limits=limits,
    ) as client:
        try:
            response = await client.post(url, json=payload)
        except httpx.TimeoutException as exc:
            logger.warning("forward_timeout", extra={"upstream_host": httpx.URL(url).host})
            raise HTTPException(
                status_code=504,
                detail={"error": "upstream_timeout"},
            ) from exc
        except httpx.RequestError as exc:
            logger.warning("forward_error", extra={"kind": type(exc).__name__})
            raise HTTPException(
                status_code=502,
                detail={"error": "upstream_unreachable"},
            ) from exc

    raw = response.content
    if len(raw) > settings.forward_max_response_bytes:
        raise HTTPException(
            status_code=502,
            detail={"error": "upstream_response_too_large"},
        )

    if response.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail={
                "error": "upstream_error_status",
                "status_code": response.status_code,
            },
        )

    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=502,
            detail={"error": "upstream_invalid_json"},
        ) from exc
