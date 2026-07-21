# Meridian — Build Week submission guide

## What Meridian demonstrates

Meridian is a self-hosted API reliability workspace. Teams create REST or GraphQL targets and Meridian evaluates them in four human-readable layers: connectivity, authentication, contract, and data assertions. It ties failures to recent deployments, opens an incident, notifies the team, and can stop a release gate.

## Three-minute demo

1. Open **Overview** and select a target. Run a successful probe to show L1–L4 results.
2. Change the expected response shape or status, run again, and open the incident to show failure attribution and the layer breakdown.
3. Open **Analytics** for trend and per-layer reliability views; then show the target SLO and error budget.
4. Open **Administration → Alert rules**, use **Test send**, then open **History** to show reliable delivery tracking and retry attempts.
5. Open **Operations** to show the platform health, retention policy, and manual cleanup control.
6. Open **Security** to show MFA setup. Mention optional enterprise SSO through generic OIDC and private-network agents for internal APIs.

## Architecture

```text
Dashboard (React/Vite) ──> Meridian API (Go/Gin) ──> PostgreSQL
                                   │                    ├─ targets, runs, incidents
                                   │                    ├─ sessions, users, alerts
                                   │                    └─ analytics and audit records
                                   ├───────────────> MongoDB (probe configurations)
                                   ├───────────────> Slack / Teams / SMTP
                                   └───────────────> Private probe agents
```

## Submission evidence

- Layered probes, incident workflow, release gates, SLOs, and analytics are first-class product features.
- SSRF controls, encrypted webhooks, session revocation, password reset, MFA, scoped tokens, and optional OIDC demonstrate secure-by-default design.
- `Meridian CI` runs API tests, the dashboard production build, and both Compose image builds on every pull request and main-branch push.
