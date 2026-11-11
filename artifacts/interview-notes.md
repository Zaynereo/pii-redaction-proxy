# Interview notes — PII redaction proxy

**Author context:** Portfolio demo for Habib Noor (privacy/security/backend). AI-assisted implementation; synthetic data only.

## Walkthrough (10 min)

1. **Problem framing** — Teams need to log or forward JSON without leaking *known* sensitive fields in *known* paths. This service is a **policy enforcer**, not a data anonymizer.
2. **API** — `POST /v1/redact` for local transforms; `POST /v1/forward` optionally posts redacted JSON to **`FORWARD_UPSTREAM_URL` only**.
3. **Core loop** — Stream body → parse → depth-bounded walk → for each allowlisted path, run a **small** matcher → swap to typed placeholder.
4. **Security** — Reject upstream overrides; no redirect follows; timeouts and response size caps; error JSON does not replay secrets.
5. **Tests** — True positives on allowlisted synthetic PII; false positive guards (order IDs, ISBN-shaped strings, `release@2.0`, Luhn-fail PAN); explicit false negatives; 413/422 paths.

## Tradeoffs

| Decision | Upside | Downside |
|----------|--------|----------|
| Allowlist vs scan-all | O(paths), predictable | Misses unknown fields |
| Placeholders vs hash | Debuggable, typed | Not anonymity |
| Luhn on PAN path | Cuts digit false positives | Fails on typos that look like PII |
| E.164 phone regex | International, strict | US local formats leak |
| 1 MiB cap | DoS resistance | Large batch ingest unsupported |

## Break experiments (do not run against prod)

1. **Unlisted email** — Put PII under `metadata/email`; observe unchanged output (documents false negative).
2. **Oversized body** — POST `MAX_REQUEST_BYTES + 1` bytes; expect **413** without server hang.
3. **SSRF attempt** — `?url=http://169.254.169.254` on `/v1/forward`; expect **400** `upstream_override_forbidden`.
4. **Deep JSON** — Nest objects beyond `MAX_JSON_DEPTH`; expect **422**.
5. **Luhn fail** — Put `4111111111111112` on `payment/cardNumber`; value retained.

## Proposed ownership changes (if this were a team service)

- Move allowlist to versioned config (`allowlist/v1.yaml`) with CI diff review.
- Add OpenAPI-driven contract tests with consumers.
- Ship OTel spans: `redacted_count`, `depth_exceeded`, never attribute values.
- Gate `/v1/forward` behind feature flag + egress firewall matching env URL host.
- Run periodic dependency audit (`pip-audit`) in CI.

## 30 Q&A (Word guide)

1. **What is this?** A FastAPI microservice that redacts specific JSON paths using explicit rules.
2. **What is it not?** Not DLP, not Presidio, not a reverse proxy for arbitrary URLs.
3. **Why allowlist?** Determinism and testability beat fuzzy recall in audit-heavy contexts.
4. **Why placeholders?** Preserve type semantics for downstream parsers without claiming crypto erasure.
5. **Is output anonymous?** No — same field type always maps to the same placeholder string.
6. **Which emails match?** Conservative RFC-like pattern on allowlisted paths only.
7. **Which phones match?** E.164 `+[1-9]\d{7,14}` only.
8. **Which SSNs match?** `XXX-XX-XXXX` or 9 digits — synthetic fixtures in tests.
9. **Which PANs match?** 13–19 digits passing Luhn on allowlisted payment paths.
10. **Why Luhn?** Reduces redacting order numbers / random digit strings on those paths.
11. **Example false positive avoided?** Order id `ORD-9988776655` — not on allowlist paths as email.
12. **Example pattern false positive avoided?** `release@2.0` fails email regex.
13. **Example PAN false positive avoided?** `4111111111111112` fails Luhn.
14. **Example false negative?** Email in `metadata/secretEmail` — path not allowlisted.
15. **Phone false negative?** `(555) 123-4567` on `customer/phone` — not E.164.
16. **How is body size enforced?** Streaming read with cumulative byte counter; **413** past 1 MiB.
17. **Why not trust Content-Length?** Clients can lie; streaming cap is authoritative.
18. **Depth limit?** Default 32; exceed → **422** `json_depth_exceeded`.
19. **SSRF controls?** No client upstream; env-only URL; redirects off; timeout/response caps.
20. **Can I set upstream in JSON?** No — `upstream_override_forbidden`.
21. **What gets logged?** Counts and flags — not bodies.
22. **Docker user?** Non-root `appuser` in Dockerfile.
23. **Dependencies?** Pinned in `requirements.txt` / `pyproject.toml`.
24. **How to extend allowlist?** Edit `app/redaction/allowlist.py` + tests + docs.
25. **Why FastAPI?** Typed models, OpenAPI, async body streaming.
26. **Forward demo purpose?** Shows redact-then-post pattern without building an open proxy.
27. **What breaks forwarding?** Missing env → **503** with redacted preview.
28. **CI coverage?** pytest, ruff, mypy, docker build.
29. **Real card numbers in repo?** No — only industry test PAN `4111111111111111`.
30. **AI disclosure?** README states AI-built portfolio piece; not employer-backed.

## File map

- `app/redaction/allowlist.py` — policy
- `app/redaction/patterns.py` — matchers
- `app/redaction/engine.py` — tree walk
- `app/body.py` — streaming cap
- `app/forwarding.py` — fixed upstream client
- `app/main.py` — routes and guards
