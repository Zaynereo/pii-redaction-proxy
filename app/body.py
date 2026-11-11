"""Streaming request body read with a hard byte cap."""

from __future__ import annotations

from fastapi import HTTPException, Request

from app.config import Settings


async def read_body_bounded(request: Request, settings: Settings) -> bytes:
    """Read body until cap; reject with 413 if exceeded (ignores trusting Content-Length alone)."""
    limit = settings.max_request_bytes
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise HTTPException(
                status_code=413,
                detail={"error": "payload_too_large", "max_bytes": limit},
            )
        chunks.append(chunk)
    return b"".join(chunks)
