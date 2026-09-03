# Deploy Approval Agent — Stateless Alignment

An independent FastAPI service (the *Deploy Controller*) that manages the
deployment lifecycle of PRs across `4paradigm/phanthymotus` and
`4paradigm/phanthymotus-driver`. It does **not** build, review, or mutate code;
it only orchestrates the deploy approval process through GitHub PR comments.

## Architecture

```
Developer → GitHub PR → Review Agent → Deploy Controller → Agent Core → COS
```

- **Only persistence is the GitHub lifecycle comment hidden state.**
- No SQLite, no DeploymentStore, no DB_PATH, no persistence beyond GitHub.
- **GitHubCommandWatcher** polls PR comments using `POLL_INTERVAL_SECONDS` from the upstream environment. Default: 30 seconds.
- **GitHubStateProxy** reads/writes hidden state JSON in the lifecycle comment.
- **DeployController** is stateless between commands — it reads state from the lifecycle comment, validates, and writes back.

## State Machine (hidden state only)

```
review-required → reviewing → deploy-ready → deploy-requested → testing → succeeded | failed
Crash interruption: status remains deploy-requested, command.phase becomes uncertain; the next poll re-reads fresh hidden state before using the cursor
```

**Removed states:** `waiting-approval`, `waiting-machine-clean`, `deploying`, `deploy-failed`, `test-failed`, `rejected`, `cancelled`, `expired`, `rolling_back`, `rolled_back`, `rollback_failed`, `waiting_cleanup`.

## Commands

| Command | Actor | Description |
|---------|-------|-------------|
| `/request_deploy` | PR Author | Request deployment for current HEAD. Binds the latest exact review_done Job and ALL deployable components. |
| `/approve_deploy machine=<alias>` | Machine Owner or write/maintain/admin collaborator | Approve and bind to a machine. Runs a running_image-only clean gate before any deploy POST. |
| `/record_test result=pass|fail [summary="..."]` | Machine Owner or write/maintain/admin collaborator | Record overall test result. No machine parameter. |
| `/deploy_status` | Anyone | Read-only deployment status from hidden state. |
| `/deploy_help [topic]` | Anyone | Help for commands. |

**Legacy commands that are now `unknown`:** `/reject_deploy`, `/rollback_deploy`, `/cancel_deploy`, `/resume_deploy`.

## Key Contracts

- **Stateless:** No SQLite, no DB_PATH, no DeploymentStore. All state is in the GitHub lifecycle comment hidden state.
- **GitHub hidden lifecycle JSON is the ONLY authoritative persistent Deploy Approval business-state store.** Fresh facts come from Review Agent / Registry / Agent Core and are copied into hidden state to make the snapshot restart-safe.
- **Restart-safe, single-replica / single-writer:** Deploy Approval is intentionally restart-safe stateless, but only one `GitHubCommandWatcher` serially processes mutating commands. Multiple concurrent Deploy Controller replicas are unsupported because the current hidden-state protocol has no CAS/distributed lock, and replicas >1 would violate the at-most-once unsafe-side-effect model.
- **Polling:** PR comments are polled using `POLL_INTERVAL_SECONDS` from the upstream environment. Default: 30 seconds. No webhook required.
- **POLL_ENABLED must be true.** Webhook is supplementary only.
- **Hidden state JSON:** The lifecycle comment carries a `<!-- deploy-approval-state:v1\n{...}\n-->` marker with validated JSON state.
- **Trusted identity:** The lifecycle comment author must match the authenticated GitHub bot identity derived from `GITHUB_TOKEN` via `GET /user` at startup.
- **Top-level status labels:** only `review-required`, `reviewing`, `deploy-ready`, `deploy-requested`, `testing`, `succeeded`, `failed`.
- **Supported repos:** exactly `4paradigm/phanthymotus` and `4paradigm/phanthymotus-driver`. Unknown repos fail closed.
- **review_done lookup:** `/request_deploy` binds the latest exact `review_done` Job for repo + PR + full HEAD; Review Agent API does not receive a `pr_number` kwarg.
- **Source matrix:** Review Agent API is the sole source of job/build/target/image candidate facts; Registry only verifies/resolves that exact Review Agent image tag; Agent Core only supplies runtime identity, current `running_image`, and MCP evidence; GitHub persists the deployment snapshot.
- **Deployability:** `phanthymotus` deploys `perception` and `actucore`, not `CORE`; `phanthymotus-driver` deploys exact driver paths.
- **Variant contract:** perception variants are canonical `5.11` and `6.1`. Legacy `jetson-jp5.11` / `jetson-jp6.1` are normalized only at config load.
- **Clean gate:** `/approve_deploy` reads `running_image` for all selected components before any deploy POST. If any `running_image` is non-empty, zero deployment is performed and the owner must clear the occupied runtime image manually, then send a new `/approve_deploy`.
- **Agent Core no-container response:** the current compatibility shape normalizes to `running_image=""` only when `running_image` and `error` are absent, `status` key exists, and `logs` is a string. The `status` VALUE has zero CLEAN/health/case business influence. Error or malformed shapes fail closed.
- status VALUE has zero CLEAN/health/case business influence.
- error/malformed shapes fail closed.
- **unsafe deploy POST:** if the POST outcome is unknown after the unsafe attempt begins, the command becomes `command.phase=uncertain`, `status=deploy-requested`, `approve_attempt.outcome=uncertain`, and there is ZERO later POST.
- **review_done → deploy-ready only:** No automatic deployment is created.
- **PR Author only:** Only the GitHub PR author can run `/request_deploy`.
- **Authorization:** `/approve_deploy` requires the actor to be the selected machine owner OR a write/maintain/admin repo collaborator. `/record_test` requires the actor to be an owner of any actually deployed machine OR a write/maintain/admin repo collaborator. Self-approval is allowed if the actor satisfies the authorization rule.
- **Exact HEAD required:** GitHub HEAD is re-checked at each decision point; drift supersedes the deployment.
- **No rollback/reject/cancel/resume:** These commands are not supported.
- **COS evidence:** The default archive contains exactly `manifest.json` and `evidence.log`. Failed deployments, test results, and case logs are uploaded to private COS.

## Machine Owners Configuration

File: `deploy/deploy-approval/machines.example.yaml` (mount at `/run/deploy-approval/machines.yaml`)

```yaml
version: 1
machines:
  sh-g1-01:
    node_id: node-g1-01
    node_host: 10.0.1.101
    owners:
      - alice
      - bob
    targets:
      - perception
      - actucore
    platforms:
      - linux/arm64
    variants:
      - 5.11
      - 6.1
  sh-go2:
    node_id: node-go2
    node_host: 10.0.1.102
    owners:
      - bob
      - charlie
    targets:
      - driver
    driver_paths:
      - unitree/go2
    platforms:
      - linux/arm64
```

- `alias`: top-level key under `machines`, used in `/approve_deploy machine=<alias>`
- `node_id`: Deploy Approval machine-policy internal unique machine identifier
- `node_host`: used to reach the existing Agent Core API at `http://<node_host>:15678`
- `owners`: GitHub login list (case-insensitive, deduplicated)
- `targets`: explicit deployable targets for this machine
- `platforms`: canonical platform allowlist
- `variants`: canonical perception variants only (`5.11` / `6.1`)
- `driver_paths`: required for driver targets
- Missing/invalid file → startup fail closed

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
Deploy Approval does not define a new runtime env namespace.

It reuses the upstream existing keys below and fixed read-only files:

| Runtime input | Source |
| --- | --- |
| `GITHUB_TOKEN` | upstream existing env |
| `GITHUB_REPOS` | upstream existing env |
| `POLL_ENABLED` | upstream existing env |
| `POLL_INTERVAL_SECONDS` | upstream existing env |
| `WEBHOOK_ENABLED` | upstream existing env |
| `GITHUB_WEBHOOK_SECRET` | upstream existing env |
| `REGISTRY` | upstream existing env |
| `REGISTRY_USER` | upstream existing env |
| `REGISTRY_PASSWORD` | upstream existing env |
| `ACCESS_TOKEN` | upstream existing env from `/opt/phanthy-motus/.env` |
| `machines.yaml` | fixed read-only machine policy file |
| `secrets.yaml` | fixed read-only COS secrets file |
