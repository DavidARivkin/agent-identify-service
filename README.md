# Agent Identity Service

A production-oriented Rust implementation of a SPIFFE-style identity, authorization, and audit control plane for AI agents.

Each agent receives a stable SPIFFE ID and short-lived, audience-bound JWT-SVID. Access is default-deny and governed by explicit policies. Agent and token revocation, non-blocking asynchronous audit events, metrics, rate limiting, and operational health checks are included.

## Features

- **SPIFFE-Style Agent Identities**: Deterministic `spiffe://<trust-domain>/ns/agent-platform/agent/<UUID>` identifiers
- **Pluggable Storage Engine**: Defaults to embedded **DuckDB**, with support for **SQLite** and distributed **PostgreSQL**
- **Pluggable Revocation**: In-memory TTL revocation bucket (single-node) with zero external setup, or distributed **Redis**
- **Short-Lived RS256 JWT-SVIDs**: Strict token validation (`iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, `jti`) and algorithm pinning
- **Pluggable Signing & Key Rotation**: Multi-key JWKS support (`/.well-known/jwks.json`) with retirement grace periods, plus KMS/Vault driver abstraction
- **Non-Blocking Audit Pipeline**: Background asynchronous channel consumer preventing database write contention
- **Default-Deny Policy Engine**: Explicit fine-grained access control with wildcards
- **Fail-Closed Security**: Client certificate SAN / SPIFFE ID extraction for mTLS control-plane authentication, security headers (HSTS, nosniff, DENY, no-store), request timeouts, and token bucket rate limiting
- **Observability**: Prometheus metrics export (`/metrics`) and JSON logs with token / SPIFFE-ID redaction

## API

| Method | Path | Description |
|---|---|---|
| `GET` | `/healthz` | Liveness probe |
| `GET` | `/readyz` | Readiness probe (verifies DB & revocation connectivity) |
| `GET` | `/metrics` | Prometheus metrics |
| `GET` | `/.well-known/jwks.json` | Public JWKS |
| `POST` | `/v1/agents` | Register agent |
| `GET` | `/v1/agents/:agent_id` | Get agent details |
| `POST` | `/v1/agents/:agent_id/revoke` | Revoke agent |
| `POST` | `/v1/svids` | Issue audience-bound JWT-SVID |
| `POST` | `/v1/svids/revoke` | Revoke JWT-SVID by `jti` |
| `POST` | `/v1/policies` | Create access policy |
| `POST` | `/v1/authorize` | Authorize agent request |

## Quick Start (Zero External Dependencies)

By default, the service uses **DuckDB** and an in-memory revocation store. It requires no external database or Redis to start immediately:

```bash
# 1. Generate an RSA key for signing (if not using an existing one)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out dev-signing-key.pem

# 2. Start the service
DATABASE_URL=":memory:" cargo run
```

The service will listen on `http://localhost:8080`.

### Distributed Setup (PostgreSQL + Redis)

To run with PostgreSQL and Redis:

```bash
docker compose up --build
```

Or configure via environment variables:
```bash
DATABASE_BACKEND=postgres
DATABASE_URL=postgres://agent_identity:agent_identity@localhost:5432/agent_identity
REDIS_URL=redis://localhost:6379
cargo run
```

## Example Workflow

```bash
# 1. Register an Agent
curl -X POST http://localhost:8080/v1/agents \
  -H 'content-type: application/json' \
  -d '{"agent_name":"billing-agent","owner":"finance-platform","allowed_scopes":["invoices:read"]}'

# 2. Define Policy
curl -X POST http://localhost:8080/v1/policies \
  -H 'content-type: application/json' \
  -d '{
    "spiffe_id": "spiffe://example.org/ns/agent-platform/agent/<AGENT_ID>",
    "resource": "invoices",
    "action": "read",
    "effect": "allow"
  }'

# 3. Mint JWT-SVID
curl -X POST http://localhost:8080/v1/svids \
  -H 'content-type: application/json' \
  -d '{
    "agent_id": "<AGENT_ID>",
    "requested_scopes": ["invoices:read"],
    "audience": "agent-platform",
    "ttl_seconds": 300
  }'

# 4. Authorize Agent Action
curl -X POST http://localhost:8080/v1/authorize \
  -H 'content-type: application/json' \
  -H 'Authorization: Bearer <JWT_SVID>' \
  -d '{"resource": "invoices", "action": "read"}'
```

## Verification & Test Results

An automated end-to-end verification script is included in `tests/verify_e2e.sh`. Run it against a running instance:

```bash
./tests/verify_e2e.sh
```

### Verified Test Summary

| Test Scenario | Endpoint | Expected Result | Actual Result | Status |
|---|---|---|---|---|
| **Liveness Check** | `GET /healthz` | HTTP 200 OK | HTTP 200 OK | **PASS** |
| **Readiness Check** | `GET /readyz` | Ping DB & Revocation | `{"database":"duckdb","revocation":"memory","status":"ready"}` | **PASS** |
| **Public JWKS** | `GET /.well-known/jwks.json` | Valid RS256 JWKS | Key ID and modulus/exponent returned | **PASS** |
| **Register Agent** | `POST /v1/agents` | Status Active, SPIFFE ID assigned | Agent created with valid SPIFFE ID | **PASS** |
| **Create Policy** | `POST /v1/policies` | Policy UUID returned | Policy created | **PASS** |
| **Mint JWT-SVID** | `POST /v1/svids` | RS256 JWT with audience & scopes | Valid signed JWT returned | **PASS** |
| **Authorize (Allowed)** | `POST /v1/authorize` | Allowed = true | `{"allowed": true, "spiffe_id": "..."}` | **PASS** |
| **Default-Deny Policy** | `POST /v1/authorize` | HTTP 403 Forbidden | HTTP 403 Forbidden (`policy denied access`) | **PASS** |
| **Instant Revocation** | `POST /v1/agents/:id/revoke` | Agent revoked, future tokens denied | HTTP 401 Unauthorized (`agent revoked`) | **PASS** |

## License

Apache-2.0
