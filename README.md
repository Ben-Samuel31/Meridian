# Meridian

Meridian is a self-hosted API reliability workspace. It continuously checks REST and GraphQL APIs, explains *which layer* failed, connects failures to recent deployments, opens incidents, sends alerts, and can block an unsafe release in CI.

It is designed for teams that want a clear answer to three questions:

1. Is this API working?
2. If it is not, what exactly failed?
3. Did a recent deployment probably cause it?

## OpenAI Build Week submission

**Category:** Developer Tools

### The problem

Teams frequently discover an API failure from a vague uptime alert, a failed deployment, or a customer report. The hard part is not merely knowing that a request failed; it is establishing whether the network, authentication, API contract, or returned business data is responsible, then getting the finding to the right person with enough context to act.

### The solution

Meridian turns an API check into an operational explanation. A target is evaluated through four progressive layers, correlated with recent deployments, represented as an incident, delivered through reliable notification channels, and measured against an SLO. The dashboard gives a team one shared place to investigate both the monitored API and the health of Meridian itself.

### Why it is different

Meridian is intentionally more than a request client and more specific than a generic uptime checker:

- **Layered diagnosis:** a failed run says whether the issue is reachability, credentials, contract, or data.
- **Deployment attribution:** failures are automatically compared with deployments from the preceding 30 minutes.
- **Actionable reliability:** incidents, acknowledgements, SLOs, error budgets, release gates, and alert delivery history connect detection to response.
- **Self-hosted and private-network ready:** private agents run checks inside a network without exposing internal APIs.
- **Secure by default:** SSRF protection, encrypted webhook storage, scoped automation tokens, sessions, MFA, and optional OIDC/SSO are built in.

### How Codex and GPT-5.6 were used

Meridian was built iteratively with Codex in ChatGPT using GPT-5.6 as a collaborative engineering partner. Codex accelerated the project by helping design and implement the Go API and React dashboard together, trace build and type errors, add migrations and security controls, create tests and CI automation, refine the UX through repeated feedback, and produce the operational documentation and demo flow. The resulting repository is a working, runnable product rather than a static prototype.

### Three-minute judge demo

1. Create or select a target, run a successful probe, and open its L1–L4 results.
2. Introduce a contract mismatch, run again, and open the resulting incident to show layer attribution and deployment context.
3. Open **Analytics** and the target SLO to show reliability trends and error budget.
4. Open **Administration → Alert rules**, use **Test send**, then show retry-aware **History**.
5. Open **Operations** to show Meridian’s own health and retention controls.
6. Open **Security** to show MFA; mention optional SSO and private-network agents.

## What Meridian includes

- REST and GraphQL targets
- Four-layer API probes: connectivity, authentication, contract, and data assertions
- Manual and scheduled probes
- Incident creation, acknowledgement, and resolution
- Deployment correlation and CI release gates
- Slack, Microsoft Teams, and SMTP email alerts
- Alert delivery history, retries, and test-send
- Reliability analytics, trends, layer-failure breakdowns, SLOs, and error budgets
- Private-network probe agents
- Transaction workflows
- Role-based access, sessions, password reset, MFA, scoped API tokens, audit history, and optional OIDC/SSO
- Operations health, data retention, and recovery guidance

---

## Quick start

### Requirements

- Docker Desktop with Docker Compose
- A free local port `5173` for the dashboard and `8080` for the API

### 1. Create local configuration

On macOS/Linux:

```bash
cp .env.example .env
```

On PowerShell:

```powershell
Copy-Item .env.example .env
```

For local evaluation, the defaults work. Before sharing Meridian or deploying it, replace the secret values in `.env`.

### 2. Start Meridian

```bash
docker compose up --build
```

Open:

| Service | Address |
|---|---|
| Dashboard | http://localhost:5173 |
| API | http://localhost:8080 |
| Health check | http://localhost:8080/healthz |

Default local sign-in:

```text
Email:    admin@meridian.local
Password: meridian-demo
```

Change `ADMIN_EMAIL` and `ADMIN_PASSWORD` in `.env` before using Meridian outside local development.

### 3. Your first successful probe

1. Open **Targets**.
2. Add a target such as `https://api.github.com` using the REST protocol.
3. Select the target and click **Run probe**.
4. Open the latest run to see the L1–L4 result.

For an API with a health endpoint, set the target configuration to the example in [Probe configuration](#probe-configuration), then run it again.

---

## How probes work: L1 to L4

Think of an API probe as checking a restaurant in four steps:

| Layer | What Meridian checks | Restaurant analogy |
|---|---|---|
| **L1 — Connectivity** | Can Meridian reach the host before the timeout? | Can you get to the restaurant? |
| **L2 — Authentication** | Is the configured authentication accepted? | Does your reservation or entry pass work? |
| **L3 — Contract** | Does the endpoint return the expected status and response shape? | Did you receive the meal you ordered? |
| **L4 — Data assertions** | Do specific response values meet business rules? | Is the meal actually correct and usable? |

Meridian stops after the first failed layer. Later layers are marked **skip**, because their result would not be reliable yet.

---

## Dashboard guide

### Overview

The landing page shows targets and their latest health. Select a target to configure it, run a probe, view recent runs, and inspect an individual L1–L4 result.

### Targets

Create REST or GraphQL targets, edit their configuration, set an SLO, and choose a recurring probe interval.

- `0` disables recurring probes.
- The minimum recurring interval is 30 seconds.
- **Pause scheduled probes** safely stops the scheduler for the selected target.
- **View all targets** supports multi-select deletion for administrators.

### Incidents

Meridian creates or updates an incident when a probe fails. An incident identifies the failed layer and notes whether a deployment was detected within the prior 30 minutes.

Use **Acknowledge** to assign ownership and **Resolve** after the underlying issue is fixed.

### Analytics

Analytics provides uptime, latency, target-level comparisons, trends, and a breakdown of L1–L4 failures. Choose 24 hours, 7 days, or 30 days and optionally filter by target.

### Workflows

Transaction workflows execute multiple HTTP steps in sequence. A step can save fields from a JSON response and reuse them in later paths or request bodies with `{{saved_name.field}}`.

### Administration

Administrators manage:

- Alert rules and notification delivery history
- Private agents
- Scoped API tokens for automation and CI
- Users and roles
- Audit history

### Operations

The **Operations** button in the header is available to administrators. It shows the health of PostgreSQL, MongoDB, the probe scheduler, alert configuration, private agents, and data retention. It also lets an administrator run data cleanup immediately.

### Security

Every signed-in user can open **Security** in the header to configure multi-factor authentication (MFA).

---

## Probe configuration

Use the **Probe configuration** editor on a selected target. Meridian validates JSON before saving it.

### REST example

```json
{
  "l1": {
    "timeout_ms": 3000
  },
  "l2": {
    "auth_type": "none"
  },
  "l3": {
    "type": "rest",
    "method": "GET",
    "path": "/health",
    "expected_status": 200,
    "expected_shape": {
      "status": "string"
    }
  },
  "l4": {
    "assertions": [
      {
        "field": "status",
        "rule": "equals",
        "value": "ok"
      }
    ]
  }
}
```

### GraphQL example

```json
{
  "l1": { "timeout_ms": 3000 },
  "l2": { "auth_type": "none" },
  "l3": {
    "type": "graphql",
    "method": "POST",
    "query": "{ __typename }",
    "expected_status": 200,
    "expected_shape": {
      "data": {
        "__typename": "string"
      }
    }
  },
  "l4": { "assertions": [] }
}
```

### Authentication

Meridian never stores bearer/header values in the target configuration. Instead, set `token_env_var` to the name of an environment variable available to the API or private-agent container.

```json
"l2": {
  "auth_type": "bearer",
  "token_env_var": "PAYMENTS_API_TOKEN"
}
```

Then set `PAYMENTS_API_TOKEN` through Docker, your orchestrator, or a secret manager. Do not place real credentials in JSON, Git, or screenshots.

### L4 assertion rules

Common assertion rules include:

- `exists`
- `non_empty`
- `equals`
- `greater_than`
- `less_than`

Use JSON paths such as `user.id`, `data.status`, or `items.0.id` in the `field` value.

---

## Alerts

Create alerts in **Administration → Alert rules**.

Each rule can send to:

- Slack webhook
- Microsoft Teams webhook
- SMTP email recipients

Meridian encrypts webhook URLs before storing them. The dashboard displays only a safe host hint after saving; the complete URL is never returned.

### Test an alert

1. Create and save an alert rule.
2. Click **Test send** beside the rule.
3. Wait a few seconds, then click **History**.

Delivery history records the channel, time, attempt number, HTTP status when available, and error message. Meridian retries failed webhook and SMTP deliveries up to three times with short backoff.

### SMTP configuration

Set these in `.env` to enable email:

```env
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=your-user
SMTP_PASSWORD=your-password
SMTP_FROM=meridian@example.com
```

---

## Incidents, deployments, and release gates

### Deployment webhook

Send a signed deployment event whenever your deployment completes:

```http
POST /webhooks/deployments
X-Meridian-Signature: sha256=<HMAC_SHA256_of_request_body>
Content-Type: application/json
```

Example body:

```json
{
  "target_id": "TARGET_UUID",
  "version": "2026.07.21.1",
  "deployed_by": "release-bot",
  "source": "github",
  "delivery_id": "a-unique-delivery-id",
  "deployed_at": "2026-07-21T10:00:00Z"
}
```

`delivery_id` must be unique. Meridian uses the deployment time to explain whether a failing incident is likely related to a recent deployment.

### GitHub Actions release gate

Use [`.github/workflows/meridian-gate.yml`](.github/workflows/meridian-gate.yml) as a starting point. Create a scoped API token in **Administration → API tokens**, with `gates:run` permission and, ideally, a target restriction and expiry.

Set these GitHub repository secrets:

```text
MERIDIAN_URL
MERIDIAN_TOKEN
MERIDIAN_TARGET_ID
MERIDIAN_WEBHOOK_SECRET
```

A failed or degraded release gate returns HTTP `409`, causing the workflow to fail.

---

## Reliability analytics and SLOs

For each target, set an uptime target and measurement window in the SLO section:

- 24 hours
- 7 days
- 30 days

Meridian calculates actual uptime and the remaining error budget. Use this to decide whether a service is within its reliability commitment, at risk, or breached.

---

## Private-network agents

Use a private agent when the API is reachable only inside a VPC, office network, or another private environment.

### Set up an agent

1. Open **Administration → Agents**.
2. Create an agent and copy its one-time enrollment key.
3. Assign a target to that agent.
4. Build the agent image:

```bash
docker build -f cmd/meridian-agent/Dockerfile -t meridian-agent .
```

5. Run it inside the private network:

```powershell
docker run --rm `
  -e MERIDIAN_URL=http://host.docker.internal:8080 `
  -e MERIDIAN_AGENT_KEY=meridian_agent_... `
  meridian-agent
```

For a remote Meridian deployment, replace `MERIDIAN_URL` with the publicly reachable Meridian API address.

The agent connects **outward** to Meridian. You do not need to open inbound firewall access to the private API.

---

## Users, sessions, MFA, and SSO

### Roles

| Role | Capabilities |
|---|---|
| Viewer | Read-only access to targets, runs, incidents, and analytics |
| Operator | Viewer access plus probes, release gates, and incident workflow actions |
| Admin | Full configuration, users, alerts, agents, tokens, operations, and audit history |

### Sessions

Each login creates a server-tracked session. `SESSION_HOURS` controls its lifetime (24 hours by default). Signing out or revoking a session makes its JWT unusable immediately.

### Password reset

When SMTP is configured, users can select **Forgot password?**. Reset links expire after 30 minutes, are single-use, and are stored only as hashes. Password reset revokes the user’s existing sessions.

Set `DASHBOARD_URL` to the dashboard address users actually open:

```env
DASHBOARD_URL=https://meridian.example.com
```

### MFA

Open **Security → Set up MFA**, add the displayed key to an authenticator app, confirm with a six-digit code, and save the recovery codes. Recovery codes are single-use and are only shown once.

Set a stable encryption key in production:

```env
MFA_ENCRYPTION_KEY=replace-with-a-long-random-value
```

### Optional SSO (OIDC)

SSO is optional. If the `OIDC_*` values are blank, Meridian continues to use normal email/password login and does not display **Sign in with SSO**.

Meridian supports generic OIDC providers such as Microsoft Entra ID, Okta, Google Workspace, and Keycloak.

```env
OIDC_AUTH_URL=https://provider.example.com/authorize
OIDC_TOKEN_URL=https://provider.example.com/token
OIDC_USERINFO_URL=https://provider.example.com/userinfo
OIDC_CLIENT_ID=meridian
OIDC_CLIENT_SECRET=replace-with-a-secret
OIDC_REDIRECT_URL=https://api.meridian.example.com/auth/oidc/callback
OIDC_AUTO_PROVISION=false
OIDC_DEFAULT_ROLE=viewer
```

Register `OIDC_REDIRECT_URL` with the provider. By default, only users already created in Meridian may use SSO. Set `OIDC_AUTO_PROVISION=true` to create verified-email users automatically with `OIDC_DEFAULT_ROLE`.

---

## Operations, retention, backup, and restore

Set data retention in `.env`:

```env
RETENTION_DAYS=90
```

Meridian runs cleanup daily. It removes historical probe runs, their linked incidents, workflow runs, audit events, and expired authentication records outside the retention window.

### Back up PostgreSQL

Back up persistent Docker volumes before upgrades or destructive maintenance. For a logical PostgreSQL backup:

```bash
docker compose exec -T postgres pg_dump -U meridian meridian > meridian-postgres.sql
```

### Restore PostgreSQL

Restore only into a stopped or new Meridian deployment after validating the backup:

```bash
docker compose exec -T postgres psql -U meridian meridian < meridian-postgres.sql
```

MongoDB stores probe configurations, so retain the `mongo-data` Docker volume alongside PostgreSQL backups.

---

## Configuration reference

Start from [`.env.example`](.env.example). Important settings:

| Variable | Purpose |
|---|---|
| `JWT_SECRET` | Signs Meridian user sessions; use a long random value |
| `WEBHOOK_SECRET` | Verifies deployment webhooks |
| `ALERT_WEBHOOK_ENCRYPTION_KEY` | Encrypts saved Slack/Teams webhook URLs; do not rotate while rules exist without a migration plan |
| `MFA_ENCRYPTION_KEY` | Encrypts stored MFA secrets |
| `SESSION_HOURS` | Session lifetime; default `24` |
| `RETENTION_DAYS` | Days to retain operational history; default `90` |
| `DASHBOARD_URL` | Public dashboard address used in password-reset links |
| `SMTP_*` | Optional email-alert and password-reset delivery |
| `OIDC_*` | Optional single sign-on configuration |

Never commit `.env`, API tokens, agent keys, SMTP passwords, webhook URLs, or deployment secrets.

---

## API overview

The dashboard is the recommended way to operate Meridian. The main API groups are:

| Area | Examples |
|---|---|
| Authentication | `POST /auth/login`, `POST /auth/logout`, password reset, MFA, OIDC |
| Targets and probes | `POST /targets`, `PUT /targets/:id/config`, `POST /targets/:id/probe` |
| Schedules and SLOs | `PUT /targets/:id/schedule`, `POST /targets/:id/pause`, `GET/PUT /targets/:id/slo` |
| Runs and incidents | `GET /targets/:id/runs`, `GET /runs/:id`, `GET /incidents` |
| Deployments and gates | `POST /webhooks/deployments`, `POST /targets/:id/gate` |
| Administration | Users, audit events, API tokens, agents, alert rules, and operations status |
| Health | `GET /healthz`, `GET /readyz`, `GET /metrics` |

Scoped automation tokens begin with `meridian_`. Their full value is shown once only. Give CI the minimum scope it needs, restrict it to a target where possible, set an expiry, and revoke it immediately if exposed.

---

## CI, tests, and Build Week demo

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) verifies Go tests, the dashboard production build, and Compose image builds on pull requests and main-branch pushes.

For a concise hackathon demo and architecture overview, see [Build Week submission guide](docs/BUILD_WEEK.md).

Run tests locally:

```bash
docker run --rm -v "$PWD:/app" -w /app golang:1.24-alpine go test ./...
```

On PowerShell, use:

```powershell
docker run --rm -v "${PWD}:/app" -w /app golang:1.24-alpine go test ./...
```

---

## Troubleshooting

### `Failed to fetch` in the dashboard

Confirm the API is running and available at port 8080:

```powershell
docker compose ps
docker compose logs api --tail=100
Invoke-WebRequest http://localhost:8080/healthz
```

### A dashboard feature returns `404`

The dashboard and API images are from different builds. Rebuild both:

```powershell
docker compose up --build
```

### Alert test shows failed delivery

Open **History** after a few seconds. Check the recorded error, webhook URL, firewall/proxy access, SMTP configuration, and recipient address.

### A private agent connects but does not run probes

Confirm the target is assigned to that agent, has a non-zero recurring interval, and the agent can reach `MERIDIAN_URL`. The agent logs the number of assigned targets each polling cycle.

### SSO button is missing

SSO is optional. It appears only when all required `OIDC_*` values are configured and the API has been rebuilt.

---

## Build Week quick demo

For the recommended three-minute demo sequence, architecture diagram, and submission checklist, open [docs/BUILD_WEEK.md](docs/BUILD_WEEK.md).
