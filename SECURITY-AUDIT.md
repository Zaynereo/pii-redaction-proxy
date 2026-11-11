# Dependency security audit

This document records **pip-audit** results for pinned runtime dependencies in `requirements.txt`.

## Baseline (pre-remediation, `main` @ `bee4c238`)

FastAPI `0.115.6` constrained Starlette to `<0.42.0`, resolving **Starlette `0.41.3`**.

```text
Found 7 known vulnerabilities in 1 package
starlette 0.41.3  PYSEC-2026-161    fix 1.0.1
starlette 0.41.3  PYSEC-2026-249    fix 1.3.1
starlette 0.41.3  PYSEC-2026-248    fix 1.3.0
starlette 0.41.3  PYSEC-2026-1942   fix 0.49.1
starlette 0.41.3  PYSEC-2026-1941   fix 0.47.2
starlette 0.41.3  PYSEC-2026-2281   fix 1.1.0
starlette 0.41.3  PYSEC-2026-2280   fix 1.1.0
```

No single intermediate Starlette release clears **all seven** advisories; the maximum fix floor is **Starlette `1.3.1`**.

## Remediation (this branch)

| Package | Before | After | Notes |
|---------|--------|-------|-------|
| fastapi | 0.115.6 | 0.136.3 | Allows `starlette>=0.46.0` (no upper cap) |
| starlette | 0.41.3 (transitive) | **1.3.1 (explicit pin)** | Prevents silent downgrade via FastAPI bumps |

Post-remediation in a clean venv:

```text
No known vulnerabilities found
```

## CI gate

GitHub Actions runs `pip-audit -r requirements.txt --strict` and **fails the build** on any advisory in runtime dependencies. Dev-only tools (`requirements-dev.txt`) are installed for tests but are not part of the audit gate.

## Residual risk (explicit)

| Risk | Mitigation in this service |
|------|----------------------------|
| Starlette multipart / static-file CVE classes | We do not mount `StaticFiles`; primary surface is JSON `POST` bodies with a **1 MiB** cap |
| Host-header / `request.url` issues | No security decisions based on `request.url.host`; forward URL is **env-only** |
| Future transitive regressions | Explicit `starlette==1.3.1` pin + CI audit gate |
| Dev tooling advisories | Out of scope for runtime gate; revisit when upgrading pytest/ruff/mypy pins |

Reproduce locally:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install pip-audit==2.7.3 -r requirements.txt
pip-audit -r requirements.txt --strict
```
