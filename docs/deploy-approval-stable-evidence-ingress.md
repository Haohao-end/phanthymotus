# Deploy Approval Evidence — Stable Public Ingress

This runbook replaces the temporary Cloudflare Quick Tunnel with a fixed,
monitored, rollback-safe HTTPS entrance for Deploy Approval Evidence.

Scope of this document and its scripts:

| Path | Purpose |
|------|---------|
| `deploy/deploy-approval/stable-evidence-ingress.sh` | preflight / install / status / rollback |
| `deploy/deploy-approval/evidence-health-check.sh` | layered read-only health probe |
| `deploy/deploy-approval/nginx/evidence-ingress.conf.in` | loopback-only Nginx listener template |
| `deploy/deploy-approval/systemd/*.service|*.timer` | 5-minute health check units |

The Controller's existing image and Compose container are kept in place. The
procedure preserves the existing Compose mounts and updates the already-mounted
`secrets.yaml` file in place; it never runs `docker compose up` or replaces the
Controller container.

---

## 1. Architecture

```
GitHub PR Summary
   │  https://EVIDENCE_HOST/api/evidence/OWNER/REPO/pulls/N/...
   ▼
Cloudflare edge (TLS, the only public listener)
   │  Named Tunnel (token-authenticated, no inbound ports)
   ▼
cloudflared container (host network, restart=unless-stopped)
   │  http://127.0.0.1:25002
   ▼
Nginx 127.0.0.1:25002   (loopback only; forwards ONLY
   │                     /evidence/, /api/evidence/, /healthz; 404 elsewhere)
   ▼
Controller 127.0.0.1:25001  (deploy-approval, unchanged image, unchanged bind)
```

Lifecycle independence:

* Nginx is a host service (`nginx.service`), independent of Docker.
* The tunnel container restarts with Docker and the host reboot.
* The Controller keeps its own `restart: unless-stopped` policy.
* Stopping or restarting one layer never stops another.

Why the old domain broke: Quick Tunnel hostnames are allocated per process and
are not durable. `dawn-insurance-lamb-displaying.trycloudflare.com` no longer
resolves, while `secrets.yaml` still advertises it. A Named Tunnel bound to a
domain you own removes that failure mode, and `config.is_stable_public_base_url`
rejects `*.trycloudflare.com` so the Controller can never advertise one again.

---

## 2. One-time Cloudflare configuration

Do this once in the Cloudflare dashboard. The scripts never create tunnels,
DNS records or hostnames, and never invent a domain name.

1. **Add your domain to Cloudflare** and let the zone become *Active*.
2. **Create the Named Tunnel**
   * Zero Trust → Networks → Tunnels → *Create a tunnel* → *Cloudflared*.
   * Name it e.g. `deploy-approval-evidence`.
   * Choose the host running the Controller. The dashboard shows an install
     command containing `--token eyJ...`. Copy **only** the token value.
3. **Add the Public Hostname** (this is the *only* ingress for this tunnel):
   * Subdomain: `evidence` (or whatever you choose)
   * Domain: your zone, e.g. `yourcompany.com`
   * Path: leave empty
   * Service: `HTTP` → `127.0.0.1:25002`
   * Additional headers: none
   * Do not add a second hostname to this tunnel, and do not point another
     tunnel at the same hostname. One hostname ↔ one Evidence ingress.
4. **Write down the hostname** as it appears, e.g. `evidence.yourcompany.com`.
5. **Note the DNS record**: with a dashboard-created tunnel, Cloudflare writes a
   proxied `CNAME <tunnel-id>.cfargotunnel.com` for the hostname. Keep it
   proxied (orange cloud). Do not add an `A` record with a fixed IP.

The token is a credential. It authenticates this connector to that tunnel and
must not be shared, emailed, or stored in Git.

---

## 3. Inputs and Automatic Resource Discovery

The stable ingress install and status commands automatically discover existing
server resources before requiring manual configuration. The periodic health
check reads `EVIDENCE_HOST` from the configured environment file.

1. **`DEPLOY_APPROVAL_CONFIG_DIR`**: Automatically discovered from running Controller (`deploy-approval`) container bind mounts (`secrets.yaml`), candidate directories (`/opt/deploy-approval`, `/etc/deploy-approval`), or the script repository directory.
2. **`EVIDENCE_HOST`**: Automatically extracted from existing `secrets.yaml` (`evidence.public_base_url`), host Cloudflare Named Tunnel configuration (`/etc/cloudflared/config.yml`), or running container labels.
3. **`CF_TUNNEL_TOKEN_FILE`**: Automatically located from existing Named Tunnel container bind mounts (`/run/cloudflared-token/token`) or standard credential locations (`/etc/cloudflared/token`, `/etc/deploy-approval/cloudflared.token`).

The Controller's existing Compose bind mount targets
`/run/deploy-approval/secrets.yaml` inside the container. The installer reads
that mount's host source to discover the matching config directory.

If a local prerequisite is missing, the script prints which fixed hostname,
Controller secrets mount, Named Tunnel, or token credential needs attention
and exits before changing host state. DNS and tunnel reachability are checked
separately during preflight/install; failures are reported by layer, roll back
the temporary listener/connector, and never switch the Controller's URL.

* **Never generates ephemeral `trycloudflare.com` URLs.**
* **Never prompts for interactive keyboard input.**
* **Never rebuilds, pulls or replaces the Controller image or drops Compose mounts.**

### Explicit Inputs (Overrides)

When not auto-discovered, inputs can be supplied via environment variables or `/etc/deploy-approval/evidence-ingress.env`:

| Variable | Meaning |
|----------|---------|
| `EVIDENCE_HOST` | Fixed public HTTPS hostname, bare, e.g. `evidence.yourcompany.com` |
| `CF_TUNNEL_TOKEN_FILE` | Absolute path to a private file containing only the tunnel token |

Optional (defaults in parentheses):

| Variable | Meaning |
|----------|---------|
| `DEPLOY_APPROVAL_CONFIG_DIR` | Existing config dir with `machines.yaml`/`secrets.yaml` |
| `EVIDENCE_INGRESS_PORT` | Loopback Nginx port (`25002`) |
| `EVIDENCE_UPSTREAM_PORT` | Controller port (`25001`) |
| `EVIDENCE_TUNNEL_METRICS_PORT` | cloudflared metrics, loopback (`25003`) |
| `CF_IMAGE` | `cloudflare/cloudflared:2025.8.0` |
| `CF_TUNNEL_CONTAINER` | `deploy-approval-evidence-tunnel` |
| `EVIDENCE_PROBE_REPO` / `EVIDENCE_PROBE_PR` | Route probe target (`4paradigm/phanthymotus` / `1`) |
| `EVIDENCE_PUBLIC_TIMEOUT` | Seconds to wait for public health (`180`) |
| `EVIDENCE_ALLOW_PENDING_DNS` | `1` = install the tunnel but skip the switch while DNS propagates (`0`) |
| `EVIDENCE_HEALTH_TIMER` | `1` = install the systemd timer (`1`) |
| `EVIDENCE_ENV_FILE` | `/etc/deploy-approval/evidence-ingress.env` |

Place them in a root-owned env file so `status` and the timer can reuse them:

```bash
sudo install -d -m 0750 /etc/deploy-approval
sudo tee /etc/deploy-approval/evidence-ingress.env >/dev/null <<'EOF'
EVIDENCE_HOST=evidence.yourcompany.com
DEPLOY_APPROVAL_CONFIG_DIR=/var/lib/deploy-approval/config
CF_TUNNEL_CONTAINER=deploy-approval-evidence-tunnel
EVIDENCE_INGRESS_PORT=25002
EVIDENCE_UPSTREAM_PORT=25001
EVIDENCE_PROBE_REPO=4paradigm/phanthymotus
EVIDENCE_PROBE_PR=1
EVIDENCE_ALERT_COMMAND=
EOF
sudo chmod 0640 /etc/deploy-approval/evidence-ingress.env
```

### Token file

```bash
sudo install -d -m 0700 /etc/deploy-approval/secrets
sudo install -m 0600 /dev/null /etc/deploy-approval/secrets/cf-tunnel.token
sudoedit /etc/deploy-approval/secrets/cf-tunnel.token   # paste the token line only
export CF_TUNNEL_TOKEN_FILE=/etc/deploy-approval/secrets/cf-tunnel.token
```

Requirements enforced by `preflight`:

* absolute path, regular file, **not** a symlink
* owned by root or the invoking user
* mode without group/world bits (`0600`), size ≤ 8 KiB
* exactly one line, no whitespace, looks like a tunnel token, not a URL
* `trycloudflare` rejected — a Quick Tunnel URL is not a token

The token is passed to the container as a **file path** in `TUNNEL_TOKEN_FILE`,
never as an argument, so it does not appear in `docker inspect` or the process
table of the host. The script never prints token contents, never reads another
container's environment, and never extracts a token from a running container.

### Host validation

`EVIDENCE_HOST` must be a bare DNS name: no scheme, path, port, query or
wildcard; at least two labels; alphabetic TLD; no `localhost`/`.local`; and
never `*.trycloudflare.com`. IP literals are rejected.

---

## 4. Install

```bash
cd <repository-checkout>        # any checkout of this repository
export EVIDENCE_HOST=evidence.yourcompany.com
export CF_TUNNEL_TOKEN_FILE=/etc/deploy-approval/secrets/cf-tunnel.token
export DEPLOY_APPROVAL_CONFIG_DIR=/var/lib/deploy-approval/config

sudo -E bash deploy/deploy-approval/stable-evidence-ingress.sh preflight
sudo -E bash deploy/deploy-approval/stable-evidence-ingress.sh install
sudo    bash deploy/deploy-approval/stable-evidence-ingress.sh status
```

Run the script from the checkout; it reads its Nginx template and systemd units
relative to itself.

### What `install` does, in order

1. **Preflight** (read-only). Validates every input, the token file, the Nginx
   include directory, `nginx -t`, and that `nginx.service` is enabled. Confirms
   the Controller is running, answers `127.0.0.1:25001/healthz`, and publishes
   **only** on `127.0.0.1`. Confirms the running image supports fixed PR URLs
   and that the configured host passes `is_stable_public_base_url`.
   Any failure exits **before** touching the host.
2. **Backups.** Copies `secrets.yaml` and (if present) any previous listener
   file into `/var/lib/deploy-approval/stable-evidence-ingress/backups/`, and
   records an install state file with the previous `public_base_url`.
3. **Nginx listener.** Renders `nginx/evidence-ingress.conf.in` into a temp file
   in the include directory, `mv`s it into place, runs `nginx -t`, then
   `systemctl reload nginx.service`. Other sites are never edited.
4. **Tunnel container.** `docker run` with `--restart=unless-stopped`,
   `--network host`, read-only root, `--cap-drop ALL`, the token directory
   mounted read-only, and `TUNNEL_TOKEN_FILE` pointing inside that mount.
5. **Public verification.** Waits for the connector's local `/ready`, then for
   `https://EVIDENCE_HOST/healthz` to return HTTP 200 with JSON fields
   `status=ok` and `service=deploy-approval`, and for
   `/evidence/...` and `/api/evidence/...` to answer with their own
   authorization status. Also checks that a non-Evidence path (`/docs`) is 404.
   If this fails, `secrets.yaml` is **not** modified.
6. **Switch.** Rewrites `evidence.public_base_url` in the existing
   `secrets.yaml` **in place** (same inode, same mode) and restarts the existing
   Controller with `docker restart`. There is no `build`, no `pull` of the
   Controller image, no `docker compose up`, and no container replacement.
7. **Post-switch checks.** Confirms the Controller reports the new base URL and
   that public health still returns HTTP 200 with `status=ok` and
   `service=deploy-approval`.
8. **Health timer.** Installs `evidence-health-check.sh` to
   `/usr/local/sbin/`, installs and enables the systemd timer.
9. **State.** Writes `/var/lib/deploy-approval/stable-evidence-ingress/state.env`
   for `status` and `rollback`.

Any failure at step 3 or later restores the previous `secrets.yaml`, Nginx
configuration, Controller state and tunnel container before exiting non-zero.
The `ERR` trap performs the same recovery for unexpected errors.

### Why the in-place write matters

`secrets.yaml` is a **bind mount** into the running container. Replacing the
file (temp file + `mv`, `sed -i`, `install`) changes the inode; the container
keeps reading the old file through its original mount. The script opens the
existing file with `O_TRUNC`, writes the full new content, `fsync`s, and
restores the original mode, so the inode and the container's view stay aligned.
Rollback restores the backup the same way.

### Pending-DNS path

If the Cloudflare hostname is not yet resolvable, either wait (the script waits
up to `EVIDENCE_PUBLIC_TIMEOUT` seconds) or run with
`EVIDENCE_ALLOW_PENDING_DNS=1`. In that mode the listener and tunnel are
installed and verified locally, `secrets.yaml` is **not** touched, and the
script prints `INSTALL PARTIAL`. Re-run plain `install` once DNS resolves to
complete the switch.

---

## 5. Verify

```bash
sudo bash deploy/deploy-approval/stable-evidence-ingress.sh status
```

The status report is layered, and the first failing layer tells you which
component to look at:

| Layer | Meaning |
|-------|---------|
| L1 | Controller loopback `http://127.0.0.1:25001/healthz` |
| L2 | Nginx loopback `http://127.0.0.1:25002/healthz` |
| L3 | cloudflared local readiness `http://127.0.0.1:25003/ready` |
| L4 | public DNS for `EVIDENCE_HOST` (Cloudflare DoH) |
| L5 | public `https://EVIDENCE_HOST/healthz` |
| L6 | `/evidence/...`, `/api/evidence/...` routed; `/docs` returns 404 |

`status` exits non-zero if any layer fails, so it is safe to use as a gate.

### Confirming every PR uses the same stable domain

The advertised origin comes from one value, `evidence.public_base_url`, read
from the single `secrets.yaml` the one Controller is running. Nothing derives
it from a request `Host` header. So every PR uses the same host, and only the
PR-scoped path differs:

```
https://EVIDENCE_HOST/evidence/OWNER/REPO/pulls/NUMBER
https://EVIDENCE_HOST/api/evidence/OWNER/REPO/pulls/NUMBER/attachments/ID/download
```

The Summary's fixed upload URL ends at `/pulls/NUMBER`: it has no `cap`, HEAD,
round, or token query parameter. The server mints the current round's short
upload session after checking trusted GitHub state and stores it in an
HttpOnly cookie.

To confirm on the running host:

```bash
# What the Controller actually loaded
docker exec deploy-approval python3 -c \
  'from agents.deploy_approval.config import load_config; print(load_config().evidence_public_base_url)'

# Every Summary link must start with that origin
grep -o 'https://[^ )"]*api/evidence/[^ )"]*' <<<"$(gh pr view <N> --json comments -q '.comments[].body')" \
  | sed -E 's#(https://[^/]+).*#\1#' | sort -u
```

A single distinct origin for all PRs means the fixed domain is in effect. If
you see `*.trycloudflare.com`, `secrets.yaml` was not switched (pending-DNS
PARTIAL install) or the Controller was not restarted.

### Controller Ingress Health Probe & Failure Isolation

Inside the Controller, `evidence_auth.public_https_ingress_accessible()` validates that external clients can reach the fixed ingress:
1. **Real HTTPS Probe**: Outbound HTTPS probe to `https://<EVIDENCE_HOST>/healthz` with strict TLS certificate verification, redirects rejected, HTTP status exactly 200, and JSON fields `status=ok` and `service=deploy-approval`.
2. **No False Positives**: DNS resolution, local loopback listening ports (25002/25003), or environment overrides are never accepted as public health proof.
3. **Bounded & Non-Blocking**: Request handlers only read a fresh cache entry or schedule a probe. Network I/O runs in a two-worker bounded pool with a 3.5s socket timeout. Cache entries are isolated by `(host, port)`, have a 20s TTL, and the cache has a fixed size limit.
4. **Decoupled from Acceptance Workflow**:
   * If public ingress is degraded or unreachable, browser upload displays an informative notice (`公共上传入口暂时不可用；测试视频或图片上传完全可选，不影响测试和验收`).
   * `/request_acceptance`, `/approve_deploy`, and `/record_test` are completely independent and are never gated or blocked by public ingress or evidence-upload status.

---

## 6. Health monitoring

```bash
systemctl status deploy-approval-evidence-health.timer
systemctl list-timers deploy-approval-evidence-health.timer
sudo journalctl -u deploy-approval-evidence-health.service -n 50 --no-pager
sudo /usr/local/sbin/deploy-approval-evidence-health-check
```

Every 5 minutes (plus 3 minutes after boot) the timer runs the probe. It is
read-only by construction:

* no DNS changes, no `docker restart`, no writes to `secrets.yaml`
* no GitHub writes, no `/approve_deploy`, no PR modification
* no effect on `/request_acceptance` or `/record_test`
* no automatic hostname or domain change

Failure output prints each layer with `OK`/`FAIL`, plus diagnostics: container
state for L1, `nginx -t` output for L2, container state and the last log lines
(control characters stripped) for L3, the Cloudflare DoH answer versus the local
resolver for L4, and TLS verification status for L5.

### Wiring an existing alert channel

Set `EVIDENCE_ALERT_COMMAND` in `/etc/deploy-approval/evidence-ingress.env` to a
command that reads one line from stdin.

Use a small wrapper script rather than an inline one-liner. `EnvironmentFile`
parses `KEY=value` lines and does **not** support `\` line continuations, so a
multi-line `curl` invocation silently breaks; and the probe runs the value
unquoted, so embedded quotes and `$(...)` in the env file are not evaluated.
A wrapper keeps the JSON quoting, the webhook URL and the secret out of the
environment file:

```bash
sudo install -m 0700 /dev/null /usr/local/sbin/deploy-approval-evidence-alert
sudo tee /usr/local/sbin/deploy-approval-evidence-alert >/dev/null <<'EOF'
#!/usr/bin/env bash
# Reads one line from stdin and forwards it to the existing alert channel.
set -uo pipefail
read -r line || line="deploy-approval evidence probe produced no output"
payload="$(LINE="$line" python3 -c 'import json,os;print(json.dumps({"msg_type":"text","content":{"text":os.environ["LINE"]}}))')"
exec curl -fsS --max-time 10 -X POST \
  -H 'Content-Type: application/json' \
  --data "$payload" \
  'https://open.feishu.cn/open-apis/bot/v2/hook/XXXXXXXX'
EOF
sudo chmod 0700 /usr/local/sbin/deploy-approval-evidence-alert
```

Then set only the path:

```bash
EVIDENCE_ALERT_COMMAND=/usr/local/sbin/deploy-approval-evidence-alert
```

For Slack, keep the same wrapper and change the final `curl` to post
`{"text": ...}` to `https://hooks.slack.com/services/XXX/YYY/ZZZ`. Never put the
webhook URL in Git; the wrapper is mode `0700` on the host.

Alerts fire on state transitions (OK→FAIL, FAIL→OK) and once more after
`EVIDENCE_ALERT_REPEAT` (default 3) consecutive failures, so a flapping probe
does not spam the channel.

---

## 7. Rollback

```bash
sudo bash deploy/deploy-approval/stable-evidence-ingress.sh rollback
```

Rollback is driven by the install state file, not by the environment, so it
works even if `EVIDENCE_HOST` is unset:

1. disable and remove the systemd timer/units
2. stop and remove the tunnel container created by `install`
3. restore the previous Nginx file from backup, or delete the listener file if
   none existed, then `nginx -t` + reload
4. restore `secrets.yaml` from backup in place (same inode), preserving other
   keys; falls back to rewriting `public_base_url` if the backup is missing
5. `docker restart` the existing Controller (same image) and wait for health
6. archive the state file as `state.env.rolled-back-<timestamp>`

Rollback never touches `pr418-evidence-quicktunnel`. Other Nginx sites, the
Controller image, `machines.yaml`, COS secrets and the GitHub App key are not
altered.

`install` refuses to run with a different `EVIDENCE_HOST` while a state file
exists; run `rollback` first. This prevents silently leaving a previous tunnel
pointing at the same hostname.

---

## 8. Failure playbook

Isolate by layer first (`status`), then use the matching section.

### DNS (L4 fails, L3 OK)

* Symptom: no answer from Cloudflare DoH; `getent ahostsv4` also empty.
* Cause: the Public Hostname was never added, the zone is not Active, or the
  record was deleted.
* Fix: re-add the Public Hostname in the tunnel configuration (Service
  `HTTP://127.0.0.1:25002`). Wait for the proxied CNAME
  `<tunnel-id>.cfargotunnel.com` to appear. Do not add a manual `A` record.
* Do not change `EVIDENCE_HOST` to "make it work". Fix the record.

### TLS (L4 OK, L5 fails with a certificate or handshake error)

* Symptom: `ssl_verify_result` non-zero or `curl` reports a TLS error.
* Cause: Cloudflare Universal SSL not issued for the zone, or the request is
  bypassing the proxy (`DNS only`), or the hostname does not belong to the zone.
* Fix: confirm the record is proxied, check the zone's SSL/TLS mode is `Full`
  or `Full (strict)` (the connector is outbound-only; no origin certificate is
  needed), and wait for edge certificate issuance.
* Never disable TLS verification on the host to work around an edge problem.

### Tunnel (L3 fails, L1/L2 OK)

* Symptom: container running but `/ready` is not; logs show
  `failed to connect` / `unauthorized`.
* Cause: token rotated or deleted, tunnel deleted, outbound 7844 blocked, or
  container clock skew.
* Fix: verify egress DNS/HTTPS from the host, confirm the tunnel still exists in
  Zero Trust, regenerate the token if it was rotated, update the private token
  file (mode `0600`), then
  `docker restart deploy-approval-evidence-tunnel`.
* Check the container log for the exact error:
  `docker logs --tail 50 deploy-approval-evidence-tunnel`.
* Restarting the tunnel is safe: the Controller and Nginx are untouched.

### Nginx (L2 fails, L1 OK)

* Symptom: listener absent or reload failed.
* Fix: `nginx -t` for the exact error; check
  `/var/log/nginx/evidence-ingress.error.log`; confirm nothing else owns
  `127.0.0.1:25002` (`ss -ltnp 'sport = :25002'`). Re-running `install` won't
  help if the port is taken by an unrelated process — find and stop that
  process, or set `EVIDENCE_INGRESS_PORT` to a free loopback port and update
  the Cloudflare Public Hostname to match.
* Do not edit the generated listener by hand; the next `install` overwrites it.

### Controller (L1 fails)

* Symptom: `/healthz` non-200, or the port binds to `0.0.0.0`.
* Fix: `docker ps --filter name=deploy-approval`,
  `docker logs --tail 100 deploy-approval`, and confirm
  `DEPLOY_APPROVAL_BIND_IP=127.0.0.1`. Use `deploy.sh restart` for a supported
  restart; do not rebuild or replace the image to fix ingress.
* If L1 fails, L2 will fail too (Nginx has nothing to proxy to); always fix the
  innermost failing layer first.

### Evidence route (L5 OK, L6 fails)

* `/evidence/...` or `/api/evidence/...` returning 404 → the Nginx listener or
  Cloudflare hostname path mapping is wrong. Check `nginx -T | grep -A5 25002`
  and the Public Hostname service.
* Returning 502/504 → Nginx reached the upstream but the Controller was
  unreachable or timed out. Check L1.
* Returning 403 `evidence_origin_failed` → the Controller's configured origin
  and the `Host`/`Origin` seen on the request disagree; confirm
  `evidence.public_base_url` equals `https://EVIDENCE_HOST` exactly and that the
  Controller was restarted after the change.
* Returning 200 on a *credentialed* page is not expected; an unauthenticated
  page returns 403/401 by design, and those codes are treated as "routed".

### After a host reboot

Everything recovers on its own: `nginx.service` is enabled, the tunnel container
has `restart=unless-stopped` and is recreated by Docker, and the Controller has
its own restart policy. Verify with `status`; L3 through L6 may take a minute.

---

## 9. Security properties

* Only Cloudflare edge IPs ever reach the origin, and only to loopback
  `127.0.0.1:25002`.
* Nginx forwards exactly `/evidence/`, `/api/evidence/` and `/healthz`;
  everything else, including `/docs` and the webhook route, is 404.
* Nginx overwrites `Host`, `X-Forwarded-Proto`, `X-Forwarded-Host` and
  `X-Forwarded-Port` with static trusted values, so a client cannot spoof the
  origin or scheme.
* The Controller keeps `127.0.0.1:25001`. Its management API and webhook are
  not exposed.
* The tunnel container runs read-only, without added capabilities, with the
  token mounted read-only and passed by path.
* No secret is printed. `preflight` states that the token file is not read for
  display; only its shape, owner and mode are validated.
* The existing COS credentials, GitHub App key and machine policy are untouched.

---

## 10. Quick reference

```bash
# install
sudo -E bash deploy/deploy-approval/stable-evidence-ingress.sh preflight
sudo -E bash deploy/deploy-approval/stable-evidence-ingress.sh install

# status
sudo bash deploy/deploy-approval/stable-evidence-ingress.sh status

# rollback
sudo bash deploy/deploy-approval/stable-evidence-ingress.sh rollback
```
