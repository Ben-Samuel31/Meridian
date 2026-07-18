# Meridian

Meridian is a self-hosted API observability MVP. It runs layered REST/GraphQL probes, correlates failures with signed deployment events, and exposes a GitHub Actions release gate.

## Run locally

```bash
cp .env.example .env
docker compose up --build
```

Open [http://localhost:5173](http://localhost:5173) and sign in with the values in `.env` (defaults: `admin@meridian.local` / `meridian-demo`). The API is at `http://localhost:8080`.

## Configure a target

Create a target in the dashboard. The dashboard saves a baseline config; use `PUT /targets/:id/config` to add a REST path or GraphQL query, expected shape, authentication settings, and L4 assertions.

Set **Recurring probe interval** on the target detail page to schedule continuous checks. `0` disables scheduling; the minimum enabled interval is 30 seconds. Scheduled runs use the same L1–L4 execution and incident attribution flow as manual runs, and Meridian prevents a target from running two scheduled probes concurrently.

Example REST config:

```json
{
  "l1": { "timeout_ms": 3000 },
  "l2": { "auth_type": "none" },
  "l3": { "method": "GET", "path": "/health", "expected_status": 200, "expected_shape": { "status": "string" } },
  "l4": { "assertions": [{ "field": "status", "rule": "equals", "value": "ok" }] }
}
```

For bearer authentication, configure `auth_type: "bearer"` and `token_env_var`. The API reads the value at runtime; it is never persisted.

## Deployment webhooks and CI

`POST /webhooks/deployments` requires `X-Meridian-Signature: sha256=<HMAC_SHA256(body)>`. The payload must provide `target_id`, `version`, and a unique `delivery_id`.

Use [`.github/workflows/meridian-gate.yml`](.github/workflows/meridian-gate.yml) as a GitHub Actions example. Set `MERIDIAN_URL`, `MERIDIAN_TOKEN`, `MERIDIAN_TARGET_ID`, and `MERIDIAN_WEBHOOK_SECRET` repository secrets. A failed/degraded gate returns HTTP 409, causing the workflow to fail.

## API endpoints

- `POST /auth/login`
- `POST`, `GET /targets`; `GET /targets/:id`; `PUT /targets/:id/config`; `PUT /targets/:id/schedule`
- `POST /targets/:id/probe`; `POST /targets/:id/gate`; `GET /targets/:id/runs`
- `GET /runs/:id`; `GET /incidents`
- `POST /webhooks/deployments`; `GET /healthz`, `/readyz`, `/metrics`
