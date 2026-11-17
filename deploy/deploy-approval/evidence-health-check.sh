#!/usr/bin/env bash
# evidence-health-check.sh — layered read-only health probe for the stable
# Deploy Approval Evidence entrance.
#
# Layers, in order:
#   L1 controller  http://127.0.0.1:$UPSTREAM_PORT/healthz
#   L2 nginx       http://127.0.0.1:$INGRESS_PORT/healthz
#   L3 tunnel      cloudflared metrics /ready on 127.0.0.1:$TUNNEL_METRICS_PORT
#   L4 dns         public A/CNAME answer for $EVIDENCE_HOST
#   L5 https       https://$EVIDENCE_HOST/healthz
#   L6 evidence    /evidence/... page + /api/evidence/... context answer with
#                  their own authorization status, and a non-Evidence path
#                  returns 404
#
# This probe never changes DNS, never edits a GitHub PR, never invokes
# /approve_deploy, and never touches /request_acceptance or /record_test.
# It only observes and reports.
#
# Configuration is read from, in order of precedence:
#   1. environment variables
#   2. $EVIDENCE_ENV_FILE (default /etc/deploy-approval/evidence-ingress.env)
#
# Optional alerting: set EVIDENCE_ALERT_COMMAND in the env file to a command
# that receives a single-line summary on stdin. It is invoked only when the
# health state changes or after EVIDENCE_ALERT_REPEAT consecutive failures.
set -uo pipefail

ENV_FILE="${EVIDENCE_ENV_FILE:-/etc/deploy-approval/evidence-ingress.env}"

load_env_defaults() {
    local file="$1" line key value
    [[ -f $file ]] || return 0
    while IFS= read -r line; do
        [[ $line =~ ^([A-Z][A-Z0-9_]*)=(.*)$ ]] || continue
        key="${BASH_REMATCH[1]}"
        value="${BASH_REMATCH[2]}"
        [[ -n ${!key+x} ]] || export "$key=$value"
    done <"$file"
}
load_env_defaults "$ENV_FILE"

EVIDENCE_HOST="${EVIDENCE_HOST:-}"
INGRESS_PORT="${EVIDENCE_INGRESS_PORT:-25002}"
UPSTREAM_PORT="${EVIDENCE_UPSTREAM_PORT:-25001}"
TUNNEL_METRICS_PORT="${EVIDENCE_TUNNEL_METRICS_PORT:-25003}"
TUNNEL_CONTAINER="${CF_TUNNEL_CONTAINER:-deploy-approval-evidence-tunnel}"
CONTROLLER_CONTAINER="${CONTROLLER_CONTAINER:-deploy-approval}"
PROBE_REPO="${EVIDENCE_PROBE_REPO:-4paradigm/phanthymotus}"
PROBE_PR="${EVIDENCE_PROBE_PR:-1}"
ALERT_COMMAND="${EVIDENCE_ALERT_COMMAND:-}"
NGINX_INGRESS_LOG="${EVIDENCE_NGINX_ERROR_LOG:-/var/log/nginx/evidence-ingress.error.log}"
ALERT_REPEAT="${EVIDENCE_ALERT_REPEAT:-3}"
STATE_DIR="${EVIDENCE_STATE_DIR:-/var/lib/deploy-approval/stable-evidence-ingress}"
PROBE_STATE="$STATE_DIR/health.state"

failures=()
reports=()

add_ok()   { reports+=("OK   $1"); }
add_fail() { reports+=("FAIL $1"); failures+=("$1"); }

http_code() {
    curl --noproxy '*' -o /dev/null -sS -w '%{http_code}' \
        --connect-timeout 5 --max-time "${2:-10}" "$1" 2>/dev/null || true
}

health_ok() {
    local url="$1" max_time="${2:-10}" response code body
    response="$(curl --noproxy '*' --silent --show-error --connect-timeout 5 \
        --max-time "$max_time" --max-filesize 4096 --write-out $'\n%{http_code}' \
        "$url" 2>/dev/null)" || return 1
    [[ $response == *$'\n'* ]] || return 1
    code="${response##*$'\n'}"
    body="${response%$'\n'*}"
    [[ $code == 200 ]] || return 1
    python3 -c '
import json, sys
try:
    payload = json.loads(sys.argv[1])
except (ValueError, TypeError):
    raise SystemExit(1)
raise SystemExit(0 if isinstance(payload, dict)
                 and payload.get("status") == "ok"
                 and payload.get("service") == "deploy-approval" else 1)
' "$body"
}

# L1 — Controller on loopback.
if health_ok "http://127.0.0.1:${UPSTREAM_PORT}/healthz"; then
    add_ok "L1 controller loopback"
else
    detail="HTTP $(http_code "http://127.0.0.1:${UPSTREAM_PORT}/healthz" 5)"
    add_fail "L1 controller loopback (127.0.0.1:${UPSTREAM_PORT}, ${detail:-no response})"
    if command -v docker >/dev/null 2>&1; then
        state="$(docker inspect -f '{{.State.Status}}' "$CONTROLLER_CONTAINER" 2>/dev/null || echo missing)"
        reports+=("     container ${CONTROLLER_CONTAINER}: ${state}")
    fi
fi

# L2 — Nginx loopback listener.
if health_ok "http://127.0.0.1:${INGRESS_PORT}/healthz"; then
    add_ok "L2 nginx loopback"
else
    detail="HTTP $(http_code "http://127.0.0.1:${INGRESS_PORT}/healthz" 5)"
    add_fail "L2 nginx loopback (127.0.0.1:${INGRESS_PORT}, ${detail:-no response})"
    if command -v systemctl >/dev/null 2>&1; then
        reports+=("     nginx.service: $(systemctl is-active nginx.service 2>/dev/null || echo unknown)")
        reports+=("     last nginx -t: $(nginx -t 2>&1 | tail -n1 || true)")
        if [[ -r $NGINX_INGRESS_LOG ]]; then
            while IFS= read -r line; do reports+=("     | $line"); done < <(
                tail -n 5 "$NGINX_INGRESS_LOG" 2>/dev/null | sed 's/[[:cntrl:]]//g' || true)
        fi
    fi
fi

# L3 — Tunnel connector readiness (local metrics only; no internet call).
if curl --noproxy '*' -fsS --max-time 5 \
    "http://127.0.0.1:${TUNNEL_METRICS_PORT}/ready" >/dev/null 2>&1; then
    add_ok "L3 tunnel connector"
else
    add_fail "L3 tunnel connector (127.0.0.1:${TUNNEL_METRICS_PORT}/ready)"
    if command -v docker >/dev/null 2>&1; then
        state="$(docker inspect -f '{{.State.Status}} restart={{.RestartCount}}' "$TUNNEL_CONTAINER" 2>/dev/null || echo missing)"
        reports+=("     container ${TUNNEL_CONTAINER}: ${state}")
        reports+=("     recent log tail follows")
        while IFS= read -r line; do reports+=("     | $line"); done < <(
            docker logs --tail 5 "$TUNNEL_CONTAINER" 2>&1 \
                | sed -e 's/[[:cntrl:]]//g' \
                      -e 's/eyJ[A-Za-z0-9._-]\{20,\}/<redacted-token>/g' || true)
    fi
fi

# L4 — Public DNS. Cloudflare DoH first; host resolver only for triage.
dns_answer() {
    curl --noproxy '*' -fsS --max-time 8 -H 'accept: application/dns-json' \
        "https://cloudflare-dns.com/dns-query?name=${EVIDENCE_HOST}&type=A" 2>/dev/null \
        | python3 -c '
import json, sys
try:
    payload = json.load(sys.stdin)
except ValueError:
    raise SystemExit(0)
for row in payload.get("Answer") or []:
    if row.get("type") in (1, 5):
        print(row.get("data", ""))
' 2>/dev/null || true
}
if [[ -z $EVIDENCE_HOST ]]; then
    add_fail "L4 public DNS (EVIDENCE_HOST is not configured)"
else
    v4="$(dns_answer | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | head -n1)"
    if [[ -n $v4 ]]; then
        add_ok "L4 public DNS (${EVIDENCE_HOST} -> ${v4})"
    else
        cname="$(dns_answer | grep -Ev '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | head -n1)"
        local_resolver="$(getent ahostsv4 "$EVIDENCE_HOST" 2>/dev/null | head -n1 || true)"
        add_fail "L4 public DNS (${EVIDENCE_HOST}: cloudflare DoH answer=${cname:-none}, local resolver=${local_resolver:-none})"
    fi
fi

# L5 — Public HTTPS health.
if [[ -n $EVIDENCE_HOST ]]; then
    if health_ok "https://${EVIDENCE_HOST}/healthz" 20; then
        add_ok "L5 public https health"
    else
        code="$(http_code "https://${EVIDENCE_HOST}/healthz" 20)"
        add_fail "L5 public https health (https://${EVIDENCE_HOST}/healthz, ${code:-no response}; requires HTTP 200, status=ok, service=deploy-approval)"
        if [[ -n $code && $code != 000 ]]; then
            tls="$(curl --noproxy '*' -sS -o /dev/null -w '%{ssl_verify_result}' \
                --connect-timeout 5 --max-time 15 "https://${EVIDENCE_HOST}/healthz" 2>/dev/null || true)"
            reports+=("     TLS verify result (0 means chain trusted locally): ${tls:-unknown}")
        fi
    fi

    # L6 — Evidence routes and isolation.
    # The Evidence app always sets X-Content-Type-Options: nosniff, while the
    # Nginx 404 fallback does not. That distinguishes "route reaches the
    # Controller but access is denied" from "route is not configured".
    probe() {
        local url="$1" headers status
        headers="$(curl --noproxy '*' -o /dev/null -sS -D - \
            --connect-timeout 5 --max-time 20 "$url" 2>/dev/null || true)"
        status="$(awk 'toupper($1) ~ /^HTTP\// {code=$2} END {print code}' <<<"$headers")"
        if grep -qi '^x-content-type-options:[[:space:]]*nosniff' <<<"$headers"; then
            printf '%s controller:yes' "${status:-000}"
        else
            printf '%s controller:no' "${status:-000}"
        fi
    }
    page="$(probe "https://${EVIDENCE_HOST}/evidence/${PROBE_REPO}/pulls/${PROBE_PR}")"
    api="$(probe "https://${EVIDENCE_HOST}/api/evidence/${PROBE_REPO}/pulls/${PROBE_PR}/context")"
    route_ok() { [[ $1 =~ ^(200|401|403|409|503)[[:space:]]controller:yes$ ]]; }
    if route_ok "$page"; then
        add_ok "L6 evidence page route (${page})"
    else
        add_fail "L6 evidence page route (https://${EVIDENCE_HOST}/evidence/${PROBE_REPO}/pulls/${PROBE_PR}, ${page:-no response})"
    fi
    if route_ok "$api"; then
        add_ok "L6 evidence api route (${api})"
    else
        add_fail "L6 evidence api route (https://${EVIDENCE_HOST}/api/evidence/${PROBE_REPO}/pulls/${PROBE_PR}/context, ${api:-no response})"
    fi
    blocked="$(http_code "https://${EVIDENCE_HOST}/docs" 15)"
    if [[ $blocked == 404 ]]; then
        add_ok "L6 non-evidence path blocked (HTTP 404)"
    else
        add_fail "L6 non-evidence path not isolated (/docs returned HTTP ${blocked:-no response})"
    fi
fi

printf 'deploy-approval evidence health @ %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '%s\n' "${reports[@]}"

if (( ${#failures[@]} == 0 )); then
    summary="OK"
else
    summary="FAIL layer=${failures[0]%% (*} count=${#failures[@]}"
fi

# Persist the last state so alerts fire on transitions, not on every probe.
mkdir -p "$STATE_DIR" 2>/dev/null || true
previous=""
[[ -r $PROBE_STATE ]] && previous="$(cat "$PROBE_STATE" 2>/dev/null || true)"
fail_count=0
[[ $previous =~ ^count=([0-9]+)$ ]] && fail_count="${BASH_REMATCH[1]}"
if (( ${#failures[@]} > 0 )); then
    fail_count=$(( fail_count + 1 ))
else
    fail_count=0
fi
printf 'summary=%s\ncount=%s\n' "$summary" "$fail_count" >"$PROBE_STATE.tmp" 2>/dev/null \
    && mv -f "$PROBE_STATE.tmp" "$PROBE_STATE" 2>/dev/null || true

if [[ -n $ALERT_COMMAND ]]; then
    was_ok=1
    [[ $previous == summary=FAIL* ]] && was_ok=0
    is_ok=0
    [[ $summary == OK ]] && is_ok=1
    notify=0
    if (( ! was_ok && is_ok )); then notify=1; fi
    if (( was_ok && ! is_ok )); then notify=1; fi
    if (( ! is_ok && fail_count == ALERT_REPEAT )); then notify=1; fi
    if (( notify )); then
        alert_line="[deploy-approval evidence] ${summary} host=${EVIDENCE_HOST:-unset}"
        # EVIDENCE_ALERT_COMMAND is a trusted root-owned config value.
        printf '%s\n' "$alert_line" | $ALERT_COMMAND >/dev/null 2>&1 || true
    fi
fi

(( ${#failures[@]} == 0 ))
