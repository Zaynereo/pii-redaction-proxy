"""FastAPI entry: local redaction and optional fixed-upstream forward demo."""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.body import read_body_bounded
from app.config import Settings, get_settings
from app.forwarding import ForwardingDisabledError, forward_redacted_payload
from app.logging_safe import log_forward_request, log_redact_request
from app.redaction import redact_json


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    _configure_logging(get_settings())
    yield


app = FastAPI(
    title="PII Redaction Proxy",
    description=(
        "Deterministic JSON field-path redaction. Not anonymization; not detect-all."
    ),
    version="0.1.0",
    lifespan=lifespan,
)


class RedactResponse(BaseModel):
    redacted: Any
    redacted_paths: list[str]
    depth_exceeded: bool = False


class ForwardBody(BaseModel):
    """Client JSON body only; upstream URL is never taken from the client."""

    payload: dict[str, Any] = Field(
        ...,
        description="JSON object to redact locally before optional forward",
    )


class UpstreamOverrideRejected(BaseModel):
    error: str = "upstream_override_forbidden"


def _configure_logging(settings: Settings) -> None:
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(levelname)s %(name)s %(message)s",
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/allowlist")
def get_allowlist() -> dict[str, Any]:
    from app.redaction.allowlist import ALLOWLIST, PLACEHOLDERS

    return {
        "paths": {k: v.value for k, v in ALLOWLIST.items()},
        "placeholders": {k.value: v for k, v in PLACEHOLDERS.items()},
        "note": "Values outside these paths are never scanned (false negatives by design).",
    }


@app.post("/v1/redact", response_model=RedactResponse)
async def redact_endpoint(request: Request) -> RedactResponse:
    settings = get_settings()
    raw = await read_body_bounded(request, settings)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail={"error": "invalid_json"}) from exc

    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail={"error": "root_must_be_object"})

    result = redact_json(data, settings.max_json_depth)
    if result.depth_exceeded:
        raise HTTPException(
            status_code=422,
            detail={"error": "json_depth_exceeded", "max_depth": settings.max_json_depth},
        )

    log_redact_request(
        redacted_count=len(result.redacted_paths),
        depth_exceeded=result.depth_exceeded,
    )
    return RedactResponse(
        redacted=result.data,
        redacted_paths=result.redacted_paths,
        depth_exceeded=result.depth_exceeded,
    )


@app.post("/v1/forward")
async def forward_endpoint(request: Request) -> JSONResponse:
    settings = get_settings()
    raw = await read_body_bounded(request, settings)

    # Reject any attempt to supply upstream via query or headers (SSRF guard).
    forbidden_query = {"url", "upstream", "target", "host", "endpoint"}
    for key in request.query_params:
        if key.lower() in forbidden_query:
            return JSONResponse(
                status_code=400,
                content=UpstreamOverrideRejected().model_dump(),
            )

    header_block = {"x-upstream-url", "x-forward-url", "x-target-url"}
    for name in request.headers:
        if name.lower() in header_block:
            return JSONResponse(
                status_code=400,
                content=UpstreamOverrideRejected().model_dump(),
            )

    try:
        envelope = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail={"error": "invalid_json"}) from exc

    if not isinstance(envelope, dict):
        raise HTTPException(status_code=400, detail={"error": "body_must_be_object"})

    if "upstream" in envelope or "url" in envelope or "target" in envelope:
        return JSONResponse(
            status_code=400,
            content=UpstreamOverrideRejected().model_dump(),
        )

    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail={"error": "missing_payload_object"})

    result = redact_json(payload, settings.max_json_depth)
    if result.depth_exceeded:
        raise HTTPException(
            status_code=422,
            detail={"error": "json_depth_exceeded", "max_depth": settings.max_json_depth},
        )

    log_redact_request(
        redacted_count=len(result.redacted_paths),
        depth_exceeded=False,
    )
    log_forward_request(enabled=settings.forward_upstream_url is not None)

    try:
        upstream_json = await forward_redacted_payload(settings, result.data)
    except ForwardingDisabledError:
        return JSONResponse(
            status_code=503,
            content={
                "error": "forwarding_disabled",
                "hint": "Set FORWARD_UPSTREAM_URL in the environment to enable.",
                "redacted_preview": result.data,
            },
        )

    return JSONResponse(
        content={
            "redacted_paths": result.redacted_paths,
            "upstream_response": upstream_json,
        }
    )
