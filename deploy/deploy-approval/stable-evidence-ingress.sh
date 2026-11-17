#!/usr/bin/env bash
# stable-evidence-ingress.sh — persist the Deploy Approval Evidence ingress.
#
# Commands:
#   preflight   Validate every required input without changing the host.
#   install     Install the loopback-only Nginx listener and a Cloudflare Named
#               Tunnel connector, verify the public entrance, then update
#               evidence.public_base_url and restart the existing Controller.
#   status      Read-only report of every ingress layer.
#   rollback    Restore secrets.yaml, Nginx and the tunnel to the pre-install
#               state recorded by the last successful install.
#
# Required inputs (see docs/deploy-approval-stable-evidence-ingress.md):
#   EVIDENCE_HOST                Fixed public HTTPS hostname (no scheme/path).
#   CF_TUNNEL_TOKEN_FILE         Absolute path to a private 0600 tunnel token.
#   DEPLOY_APPROVAL_CONFIG_DIR   Directory containing machines.yaml/secrets.yaml.
#
# Optional inputs:
#   EVIDENCE_INGRESS_PORT        Loopback Nginx port (default 25002).
#   EVIDENCE_UPSTREAM_PORT       Controller port (default 25001).
#   CF_IMAGE                     cloudflared image (default cloudflare/cloudflared:2025.8.0).
#   CF_TUNNEL_CONTAINER          Tunnel container name (default deploy-approval-evidence-tunnel).
#   EVIDENCE_PROBE_REPO          owner/repo used for route probes (default 4paradigm/phanthymotus).
#   EVIDENCE_PROBE_PR            PR number used for route probes (default 1).
#   EVIDENCE_HEALTH_TIMER        1 to install/enable the systemd timer (default 1).
#   EVIDENCE_ALLOW_PENDING_DNS   1 to install the tunnel but skip the secrets switch
#                                while Cloudflare DNS is still propagating (default 0).
#   EVIDENCE_PUBLIC_TIMEOUT      Seconds to wait for public DNS/HTTPS (default 180).
#   EVIDENCE_TUNNEL_METRICS_PORT cloudflared metrics on loopback (default 25003).
#   EVIDENCE_STATE_DIR           Non-secret install record dir.
#   EVIDENCE_ENV_FILE            Defaults file (default /etc/deploy-approval/evidence-ingress.env).
#
# Safety properties:
#   * Never creates or changes Git branches/worktrees, never builds an image,
#     never rebuilds or replaces the Controller image.
#   * Never stops, removes or reconfigures pr418-evidence-quicktunnel.
#   * Never reads another container's environment or token.
#   * Never prints the tunnel token, COS keys or GitHub App key.
#   * Updates the bind-mounted secrets.yaml in place so the running container
#     keeps the same inode.
#
# Commands are not idempotent across different EVIDENCE_HOST values: run
# rollback before changing the hostname.

set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE_FILE="$SCRIPT_DIR/nginx/evidence-ingress.conf.in"
HEALTH_SCRIPT="$SCRIPT_DIR/evidence-health-check.sh"
UNIT_DIR="$SCRIPT_DIR/systemd"
ENV_FILE="${EVIDENCE_ENV_FILE:-/etc/deploy-approval/evidence-ingress.env}"
STATE_DIR="${EVIDENCE_STATE_DIR:-/var/lib/deploy-approval/stable-evidence-ingress}"
STATE_FILE="$STATE_DIR/state.env"
NGINX_CONF_NAME="deploy-approval-evidence-ingress.conf"
CONTROLLER_CONTAINER="deploy-approval"
HEALTH_TIMER="deploy-approval-evidence-health.timer"
HEALTH_SERVICE="deploy-approval-evidence-health.service"

INGRESS_PORT="${EVIDENCE_INGRESS_PORT:-25002}"
UPSTREAM_PORT="${EVIDENCE_UPSTREAM_PORT:-25001}"
CF_IMAGE="${CF_IMAGE:-cloudflare/cloudflared:2025.8.0}"
CF_TUNNEL_CONTAINER="${CF_TUNNEL_CONTAINER:-deploy-approval-evidence-tunnel}"
PROBE_REPO="${EVIDENCE_PROBE_REPO:-4paradigm/phanthymotus}"
PROBE_PR="${EVIDENCE_PROBE_PR:-1}"
INSTALL_TIMER="${EVIDENCE_HEALTH_TIMER:-1}"
ALLOW_PENDING_DNS="${EVIDENCE_ALLOW_PENDING_DNS:-0}"
PUBLIC_TIMEOUT="${EVIDENCE_PUBLIC_TIMEOUT:-180}"
TUNNEL_METRICS_PORT="${EVIDENCE_TUNNEL_METRICS_PORT:-25003}"

NGINX_CONF_DIR=""
NGINX_CONF=""
SECRETS_BACKUP=""
NGINX_BACKUP=""
NGINX_HAD_PRIOR=0
SECRETS_CHANGED=0
NGINX_CHANGED=0
TUNNEL_STARTED=0
CONTROLLER_RESTARTED=0

log()  { printf '%s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command missing: $1"
}

require_root() {
    [[ ${EUID:-$(id -u)} -eq 0 ]] || die "must run as root (Nginx, systemd and Docker state are modified)"
}

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

auto_detect_resources() {
    # 1. Auto-detect DEPLOY_APPROVAL_CONFIG_DIR from Docker inspect mounts or known host dirs
    if [[ -z ${DEPLOY_APPROVAL_CONFIG_DIR:-} ]]; then
        local candidate mount_src
        if command -v docker >/dev/null 2>&1; then
            # Inspect mount points of CONTROLLER_CONTAINER
            mount_src="$(docker inspect -f '{{range .Mounts}}{{if or (eq .Destination "/run/deploy-approval/secrets.yaml") (eq .Destination "/app/secrets.yaml") (eq .Destination "/secrets.yaml") (eq .Destination "/deploy-approval/secrets.yaml")}}{{.Source}}{{end}}{{end}}' "$CONTROLLER_CONTAINER" 2>/dev/null || true)"
            if [[ -n $mount_src && -f $mount_src ]]; then
                DEPLOY_APPROVAL_CONFIG_DIR="$(cd "$(dirname "$mount_src")" && pwd)"
            else
                mount_src="$(docker inspect -f '{{range .Mounts}}{{if eq .Type "bind"}}{{if .Source}}{{println .Source}}{{end}}{{end}}{{end}}' "$CONTROLLER_CONTAINER" 2>/dev/null | grep 'secrets\.yaml$' | head -n1 || true)"
                if [[ -n $mount_src && -f $mount_src ]]; then
                    DEPLOY_APPROVAL_CONFIG_DIR="$(cd "$(dirname "$mount_src")" && pwd)"
                fi
            fi
        fi
        if [[ -z ${DEPLOY_APPROVAL_CONFIG_DIR:-} ]]; then
            for candidate in "$SCRIPT_DIR" "$PWD" "/opt/deploy-approval" "/etc/deploy-approval"; do
                if [[ -f "$candidate/secrets.yaml" ]]; then
                    DEPLOY_APPROVAL_CONFIG_DIR="$(cd "$candidate" && pwd)"
                    break
                fi
            done
        fi
    fi

    # 2. Auto-detect EVIDENCE_HOST (persistent domain) from secrets.yaml, Named Tunnel configs, or state
    if [[ -z ${EVIDENCE_HOST:-} ]]; then
        local detected_host=""
        # Priority A: Check secrets.yaml if discovered
        if [[ -n ${DEPLOY_APPROVAL_CONFIG_DIR:-} && -f "$DEPLOY_APPROVAL_CONFIG_DIR/secrets.yaml" ]]; then
            detected_host="$(python3 - "$DEPLOY_APPROVAL_CONFIG_DIR/secrets.yaml" <<'PY' 2>/dev/null || true
import sys, yaml, urllib.parse
try:
    data = yaml.safe_load(open(sys.argv[1], encoding='utf-8'))
    base = (data.get('evidence') or {}).get('public_base_url', '').strip()
    parsed = urllib.parse.urlsplit(base)
    host = (parsed.hostname or '').lower()
    if host and 'trycloudflare' not in host and host not in ('localhost', '127.0.0.1') and '.' in host:
        print(host)
except Exception:
    pass
PY
)"
        fi
        # Priority B: Check Cloudflare Named Tunnel config on host
        if [[ -z $detected_host ]]; then
            for cf_cfg in /etc/cloudflared/config.yml /etc/cloudflared/config.yaml /root/.cloudflared/config.yml; do
                if [[ -f $cf_cfg ]]; then
                    detected_host="$(python3 - "$cf_cfg" <<'PY' 2>/dev/null || true
import sys, yaml
try:
    data = yaml.safe_load(open(sys.argv[1], encoding='utf-8'))
    for rule in data.get('ingress', []):
        host = (rule.get('hostname') or '').strip().lower()
        if host and 'trycloudflare' not in host and host not in ('localhost', '127.0.0.1') and '.' in host:
            print(host)
            break
except Exception:
    pass
PY
)"
                    [[ -n $detected_host ]] && break
                fi
            done
        fi
        # Priority C: Check existing tunnel container label
        if [[ -z $detected_host ]] && command -v docker >/dev/null 2>&1; then
            detected_host="$(docker inspect -f '{{index .Config.Labels "com.deploy-approval.evidence-host"}}' "$CF_TUNNEL_CONTAINER" 2>/dev/null || true)"
        fi
        # Priority D: Check state file
        if [[ -z $detected_host && -f $STATE_FILE ]]; then
            detected_host="$(state_value EVIDENCE_HOST 2>/dev/null || true)"
        fi
        if [[ -n $detected_host && $detected_host != *.trycloudflare.com ]]; then
            EVIDENCE_HOST="$detected_host"
        fi
    fi

    # 3. Auto-detect CF_TUNNEL_TOKEN_FILE (Named Tunnel config)
    if [[ -z ${CF_TUNNEL_TOKEN_FILE:-} ]]; then
        local detected_token=""
        # Priority A: Check existing Named Tunnel container bind mount
        if command -v docker >/dev/null 2>&1; then
            local tunnel_mount
            tunnel_mount="$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/run/cloudflared-token/token"}}{{.Source}}{{end}}{{end}}' "$CF_TUNNEL_CONTAINER" 2>/dev/null || true)"
            if [[ -n $tunnel_mount && -f $tunnel_mount ]]; then
                detected_token="$tunnel_mount"
            fi
        fi
        # Priority B: Check standard credential/token file locations
        if [[ -z $detected_token ]]; then
            local cand_token
            for cand_token in \
                "${DEPLOY_APPROVAL_CONFIG_DIR:-}/cloudflared.token" \
                "${DEPLOY_APPROVAL_CONFIG_DIR:-}/tunnel.token" \
                "/etc/cloudflared/token" \
                "/etc/cloudflared/tunnel-token" \
                "/etc/deploy-approval/cloudflared.token" \
                "/etc/deploy-approval/tunnel.token" \
                "/var/lib/deploy-approval/cloudflared.token" \
                "/var/lib/deploy-approval/tunnel.token"; do
                if [[ -f $cand_token && -s $cand_token ]]; then
                    detected_token="$cand_token"
                    break
                fi
            done
        fi
        if [[ -n $detected_token ]]; then
            CF_TUNNEL_TOKEN_FILE="$detected_token"
        fi
    fi
}

# ── Input validation ────────────────────────────────────────────────

require_common_inputs() {
    auto_detect_resources
    local missing=()
    [[ -n ${DEPLOY_APPROVAL_CONFIG_DIR:-} ]] || missing+=("Controller secrets bind mount at /run/deploy-approval/secrets.yaml (host directory via DEPLOY_APPROVAL_CONFIG_DIR)")
    [[ -n ${EVIDENCE_HOST:-} ]] || missing+=("fixed public DNS hostname/record (EVIDENCE_HOST; Cloudflare Public Hostname CNAME to the Named Tunnel)")
    [[ -n ${CF_TUNNEL_TOKEN_FILE:-} ]] || missing+=("Cloudflare Named Tunnel and its token credential (CF_TUNNEL_TOKEN_FILE)")

    if (( ${#missing[@]} > 0 )); then
        printf 'ERROR: Missing required server resources for stable evidence ingress:\n' >&2
        for item in "${missing[@]}"; do
            printf '  - %s\n' "$item" >&2
        done
        printf '\nRequired fixed ingress resources:\n' >&2
        printf '  - An existing Cloudflare zone DNS record/Public Hostname for the fixed hostname.\n' >&2
        printf '  - An existing Cloudflare Named Tunnel configured to route that hostname to 127.0.0.1:%s.\n' "$INGRESS_PORT" >&2
        printf '  - The Named Tunnel token in a protected local credential file.\n' >&2
        printf '  The script does not create DNS names, Cloudflare tunnels, or temporary domains.\n' >&2
        printf '\nAutomatic detection searched:\n' >&2
        printf '  - Docker container bind mounts for %s and %s\n' "$CONTROLLER_CONTAINER" "$CF_TUNNEL_CONTAINER" >&2
        printf '  - Controller bind mount /run/deploy-approval/secrets.yaml and existing secrets.yaml in %s, /opt/deploy-approval, /etc/deploy-approval\n' "$SCRIPT_DIR" >&2
        printf '  - Named Tunnel config in /etc/cloudflared/, /etc/deploy-approval/\n' >&2
        printf '\nRemediation:\n' >&2
        printf '  Provision the missing server resource or export the required environment variable:\n' >&2
        printf '    export EVIDENCE_HOST="<fixed-domain>"\n' >&2
        printf '    export CF_TUNNEL_TOKEN_FILE="/path/to/token"\n' >&2
        printf '    export DEPLOY_APPROVAL_CONFIG_DIR="/path/to/config"\n' >&2
        printf '  Note: Ephemeral trycloudflare domains and interactive prompts are strictly prohibited.\n' >&2
        exit 1
    fi
    require_rollback_inputs
}

require_rollback_inputs() {
    [[ -n ${DEPLOY_APPROVAL_CONFIG_DIR:-} ]] || die "DEPLOY_APPROVAL_CONFIG_DIR is required"
    [[ $DEPLOY_APPROVAL_CONFIG_DIR == /* ]] || die "DEPLOY_APPROVAL_CONFIG_DIR must be absolute"

    [[ $INGRESS_PORT =~ ^[1-9][0-9]{0,4}$ ]] || die "EVIDENCE_INGRESS_PORT must be a port number"
    [[ $UPSTREAM_PORT =~ ^[1-9][0-9]{0,4}$ ]] || die "EVIDENCE_UPSTREAM_PORT must be a port number"
    (( INGRESS_PORT >= 1024 && INGRESS_PORT <= 65535 )) || die "EVIDENCE_INGRESS_PORT must be >= 1024"
    (( UPSTREAM_PORT >= 1 && UPSTREAM_PORT <= 65535 )) || die "EVIDENCE_UPSTREAM_PORT is out of range"
    [[ $INGRESS_PORT != "$UPSTREAM_PORT" ]] || die "ingress and upstream ports must differ"
    [[ $PROBE_REPO =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "EVIDENCE_PROBE_REPO must be owner/repo"
    [[ $PROBE_PR =~ ^[1-9][0-9]*$ ]] || die "EVIDENCE_PROBE_PR must be a positive integer"
    [[ $PROBE_REPO != *..* ]] || die "EVIDENCE_PROBE_REPO must not contain '..'"
    [[ $PUBLIC_TIMEOUT =~ ^[1-9][0-9]{0,3}$ ]] || die "EVIDENCE_PUBLIC_TIMEOUT must be a positive integer"
    [[ $TUNNEL_METRICS_PORT =~ ^[1-9][0-9]{0,4}$ ]] || die "EVIDENCE_TUNNEL_METRICS_PORT must be a port number"
    (( TUNNEL_METRICS_PORT >= 1024 && TUNNEL_METRICS_PORT <= 65535 )) \
        || die "EVIDENCE_TUNNEL_METRICS_PORT must be >= 1024"
    [[ $TUNNEL_METRICS_PORT != "$INGRESS_PORT" && $TUNNEL_METRICS_PORT != "$UPSTREAM_PORT" ]] \
        || die "tunnel metrics port must differ from ingress and upstream ports"
    [[ $ALLOW_PENDING_DNS == 0 || $ALLOW_PENDING_DNS == 1 ]] || die "EVIDENCE_ALLOW_PENDING_DNS must be 0 or 1"
    [[ $INSTALL_TIMER == 0 || $INSTALL_TIMER == 1 ]] || die "EVIDENCE_HEALTH_TIMER must be 0 or 1"
}

lowercase() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

validate_evidence_host() {
    local host="$EVIDENCE_HOST" lower tld label
    [[ ${#host} -le 253 ]] || die "EVIDENCE_HOST is longer than 253 characters"
    [[ ${#host} -ge 4 ]] || die "EVIDENCE_HOST is too short"
    [[ $host != *://* && $host != */* && $host != *:* && $host != *\?* && $host != *\#* ]] \
        || die "EVIDENCE_HOST must be a bare hostname (no scheme, path, port or query)"
    [[ $host != \** && $host != *[[:space:]]* ]] || die "EVIDENCE_HOST must not be a wildcard or contain spaces"
    [[ $host =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]] \
        || die "EVIDENCE_HOST is not a valid DNS name"
    [[ $host =~ ^[0-9.]+$ ]] && die "EVIDENCE_HOST must be a DNS name, not an IP literal"
    lower="$(lowercase "$host")"
    [[ $lower != *..* && $lower != .* && $lower != *. ]] || die "EVIDENCE_HOST has an empty label"
    [[ $lower != trycloudflare.com && $lower != *.trycloudflare.com ]] \
        || die "ephemeral *.trycloudflare.com hostnames are not allowed"
    [[ $lower != localhost && $lower != *.localhost && $lower != *.local ]] \
        || die "EVIDENCE_HOST must be a public DNS name"
    tld="${lower##*.}"
    [[ $tld =~ ^[a-z]{2,63}$ ]] || die "EVIDENCE_HOST must end with an alphabetic TLD"
    for label in ${lower//./ }; do
        [[ $label != -* && $label != *- ]] || die "EVIDENCE_HOST contains a label starting or ending with '-'"
    done
}

validate_token_file() {
    local file="$CF_TUNNEL_TOKEN_FILE" owner expected current
    [[ $file == /* ]] || die "CF_TUNNEL_TOKEN_FILE must be an absolute path"
    [[ -f $file && ! -L $file ]] || die "CF_TUNNEL_TOKEN_FILE must be a regular file (not a symlink)"
    owner="$(stat -c '%u' "$file")" || die "cannot stat CF_TUNNEL_TOKEN_FILE"
    expected="${SUDO_UID:-$(id -u)}"
    current="$(id -u)"
    [[ $owner == "$expected" || $owner == "$current" || $owner == 0 ]] \
        || die "CF_TUNNEL_TOKEN_FILE must be owned by root or the invoking user"
    if (( 8#$(stat -c '%a' "$file") & 8#077 )); then
        die "CF_TUNNEL_TOKEN_FILE must not grant group/world permissions"
    fi
    [[ $(stat -c '%s' "$file") -le 8192 ]] || die "CF_TUNNEL_TOKEN_FILE is unexpectedly large"
    [[ $(basename "$file") =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] \
        || die "CF_TUNNEL_TOKEN_FILE basename must be a simple file name"
    python3 - "$file" <<'PY'
import re
import sys

data = open(sys.argv[1], 'rb').read()
if b'\x00' in data:
    raise SystemExit('CF_TUNNEL_TOKEN_FILE must be a text file')
try:
    text = data.decode('ascii')
except UnicodeDecodeError:
    raise SystemExit('CF_TUNNEL_TOKEN_FILE must be ASCII')
core = text.rstrip('\r\n')
if not core or core != core.strip() or any(ch.isspace() for ch in core):
    raise SystemExit('CF_TUNNEL_TOKEN_FILE must contain exactly one token line')
if not 64 <= len(core) <= 4096:
    raise SystemExit('CF_TUNNEL_TOKEN_FILE does not look like a tunnel token')
if not re.fullmatch(r'[A-Za-z0-9._+/=-]+', core):
    raise SystemExit('CF_TUNNEL_TOKEN_FILE contains unexpected characters')
if 'trycloudflare' in core.lower():
    raise SystemExit('CF_TUNNEL_TOKEN_FILE must be a Named Tunnel token, not a quick tunnel URL')
PY
}

validate_config_dir() {
    local dir="$DEPLOY_APPROVAL_CONFIG_DIR" file owner expected current
    [[ -d $dir && ! -L $dir ]] || die "DEPLOY_APPROVAL_CONFIG_DIR must be a real directory: $dir"
    file="$dir/secrets.yaml"
    [[ -f $file && ! -L $file ]] || die "secrets.yaml must be a regular file: $file"
    owner="$(stat -c '%u' "$file")"
    expected="${SUDO_UID:-$(id -u)}"
    current="$(id -u)"
    [[ $owner == "$expected" || $owner == "$current" || $owner == 0 ]] \
        || die "secrets.yaml must be owned by root or the invoking user"
    if (( 8#$(stat -c '%a' "$file") & 8#077 )); then
        die "secrets.yaml must not grant group/world permissions"
    fi
    python3 - "$file" <<'PY'
import sys
import yaml
try:
    data = yaml.safe_load(open(sys.argv[1], encoding='utf-8'))
except OSError:
    raise SystemExit('secrets.yaml is not readable')
except yaml.YAMLError:
    raise SystemExit('secrets.yaml is not valid YAML')
if not isinstance(data, dict) or data.get('version') != 1:
    raise SystemExit('secrets.yaml must be a version 1 mapping')
if not isinstance(data.get('cos'), dict):
    raise SystemExit('secrets.yaml cos section must be a mapping')
PY
}

ensure_host_not_changed_silently() {
    local previous=""
    [[ -f $STATE_FILE ]] || return 0
    previous="$(sed -n 's/^EVIDENCE_HOST=//p' "$STATE_FILE" | head -n1)"
    if [[ -n $previous && $previous != "$EVIDENCE_HOST" ]]; then
        die "a previous install at $previous exists; run rollback before changing EVIDENCE_HOST"
    fi
}

# ── Host checks ─────────────────────────────────────────────────────

health_json_ok() {
    python3 -c '
import json, sys
try:
    payload = json.loads(sys.stdin.read())
except (ValueError, TypeError):
    raise SystemExit(1)
raise SystemExit(0 if isinstance(payload, dict)
                 and payload.get("status") == "ok"
                 and payload.get("service") == "deploy-approval" else 1)
' <<<"$1"
}

controller_health_body() {
    curl --noproxy '*' -fsS --connect-timeout 3 --max-time 5 \
        "http://127.0.0.1:${UPSTREAM_PORT}/healthz" 2>/dev/null || true
}

wait_controller_health() {
    local deadline=$((SECONDS + ${1:-60}))
    while (( SECONDS < deadline )); do
        if health_json_ok "$(controller_health_body)"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

check_controller_loopback_binding() {
    local mapping
    mapping="$(docker port "$CONTROLLER_CONTAINER" "${UPSTREAM_PORT}/tcp" 2>/dev/null || true)"
    if [[ -z $mapping ]]; then
        warn "Controller does not publish ${UPSTREAM_PORT}/tcp"
        return 1
    fi
    while IFS= read -r line; do
        if [[ $line != 127.0.0.1:* ]]; then
            warn "Controller port is not loopback-bound: $line"
            return 1
        fi
    done <<<"$mapping"
    return 0
}

controller_supports_stable_urls() {
    docker exec -i "$CONTROLLER_CONTAINER" python3 - <<'PY'
from agents.deploy_approval.config import is_evidence_ingress_url, is_stable_public_base_url
from agents.deploy_approval import comments

assert is_stable_public_base_url('https://evidence.example.com')
assert not is_stable_public_base_url('https://demo.trycloudflare.com')
assert is_evidence_ingress_url('https://evidence.example.com')
assert comments._public_base('https://evidence.example.com/') == 'https://evidence.example.com'
built = comments.stable_attachment_url(
    'owner/repo', 1, 'attachment', 'capability',
    action='download', public_base_url='https://evidence.example.com',
)
assert built == ('https://evidence.example.com/api/evidence/owner/repo/'
                 'pulls/1/attachments/attachment/download?cap=capability'), built
print('STABLE_URL_SUPPORT_OK')
PY
}

file_public_base_url() {
    python3 - "$DEPLOY_APPROVAL_CONFIG_DIR/secrets.yaml" <<'PY'
import sys
import yaml
data = yaml.safe_load(open(sys.argv[1], encoding='utf-8')) or {}
evidence = data.get('evidence') or {}
print(evidence.get('public_base_url', '') if isinstance(evidence, dict) else '')
PY
}

listeners_on_port() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | awk -v port=":$port" '$4 ~ port"$"'
    elif command -v lsof >/dev/null 2>&1; then
        lsof -nP -iTCP:"${port}" -sTCP:LISTEN 2>/dev/null | tail -n +2
    else
        die "neither ss nor lsof is available"
    fi
}

port_in_use() {
    [[ -n $(listeners_on_port "$1") ]]
}

port_owned_by_nginx() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltnp 2>/dev/null | awk -v port=":$port" '$4 ~ port"$"' | grep -q '"nginx"'
    elif command -v lsof >/dev/null 2>&1; then
        lsof -nP -iTCP:"${port}" -sTCP:LISTEN 2>/dev/null | grep -q nginx
    else
        return 1
    fi
}

detect_nginx_conf_dir() {
    local candidate
    command -v nginx >/dev/null 2>&1 || die "nginx is not installed"
    systemctl is-enabled nginx.service >/dev/null 2>&1 \
        || die "nginx.service must be enabled"
    nginx -t >/dev/null 2>&1 || die "existing nginx configuration is invalid; fix it before installing"
    local rendered includes
    rendered="$(nginx -T 2>/dev/null || true)"
    includes="$(sed -n 's/^[[:space:]]*include[[:space:]]\+\([^;]*\);/\1/p' <<<"$rendered")"
    for candidate in /etc/nginx/conf.d /etc/nginx/default.d; do
        [[ -d $candidate ]] || continue
        if grep -Fxq "$candidate/*.conf" <<<"$includes"; then
            NGINX_CONF_DIR="$candidate"
            NGINX_CONF="$candidate/$NGINX_CONF_NAME"
            return 0
        fi
    done
    die "could not find an Nginx include directory (looked for /etc/nginx/conf.d or /etc/nginx/default.d in nginx -T); this script will not edit nginx.conf"
}

render_nginx_conf() {
    local out="$1"
    python3 - "$TEMPLATE_FILE" "$EVIDENCE_HOST" "$INGRESS_PORT" "$UPSTREAM_PORT" "$out" <<'PY'
import sys

template, host, ingress, upstream, out = sys.argv[1:6]
text = open(template, encoding='utf-8').read()
replacements = {
    '__EVIDENCE_HOST__': host,
    '__INGRESS_PORT__': ingress,
    '__UPSTREAM_PORT__': upstream,
}
for token, value in replacements.items():
    if token not in text:
        raise SystemExit(f'nginx template is missing {token}')
    text = text.replace(token, value)
for leftover in ('__EVIDENCE_HOST__', '__INGRESS_PORT__', '__UPSTREAM_PORT__'):
    if leftover in text:
        raise SystemExit(f'nginx template expansion failed for {leftover}')
open(out, 'w', encoding='utf-8').write(text)
PY
    chmod 0644 "$out"
}

loopback_health_body() {
    curl --noproxy '*' -fsS --connect-timeout 3 --max-time 5 \
        "http://127.0.0.1:${INGRESS_PORT}/healthz" 2>/dev/null || true
}

wait_loopback_health() {
    local deadline=$((SECONDS + ${1:-20}))
    while (( SECONDS < deadline )); do
        if health_json_ok "$(loopback_health_body)"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

ensure_cf_image() {
    docker image inspect "$CF_IMAGE" >/dev/null 2>&1 && return 0
    log "Pulling $CF_IMAGE ..."
    docker pull "$CF_IMAGE" >/dev/null
}

# ── State and backups ───────────────────────────────────────────────

state_value() {
    local key="$1"
    [[ -f $STATE_FILE ]] || return 0
    sed -n "s/^${key}=//p" "$STATE_FILE" | head -n1
}

write_state() {
    local previous_url="$1" prior_nginx="$2" installed_at
    installed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    mkdir -p "$STATE_DIR"
    chmod 0700 "$STATE_DIR"
    {
        printf 'EVIDENCE_HOST=%s\n' "$EVIDENCE_HOST"
        printf 'EVIDENCE_INGRESS_PORT=%s\n' "$INGRESS_PORT"
        printf 'EVIDENCE_UPSTREAM_PORT=%s\n' "$UPSTREAM_PORT"
        printf 'CF_TUNNEL_CONTAINER=%s\n' "$CF_TUNNEL_CONTAINER"
        printf 'CF_IMAGE=%s\n' "$CF_IMAGE"
        printf 'NGINX_CONF=%s\n' "$NGINX_CONF"
        printf 'NGINX_WAS_PRESENT=%s\n' "$prior_nginx"
        printf 'SECRETS_FILE=%s\n' "$DEPLOY_APPROVAL_CONFIG_DIR/secrets.yaml"
        printf 'SECRETS_BACKUP=%s\n' "$SECRETS_BACKUP"
        printf 'NGINX_BACKUP=%s\n' "$NGINX_BACKUP"
        printf 'PREVIOUS_PUBLIC_BASE_URL=%s\n' "$previous_url"
        printf 'INSTALLED_AT=%s\n' "$installed_at"
        printf 'HEALTH_TIMER=%s\n' "$INSTALL_TIMER"
    } >"$STATE_FILE.tmp"
    chmod 0600 "$STATE_FILE.tmp"
    mv -f "$STATE_FILE.tmp" "$STATE_FILE"
    chmod 0600 "$STATE_FILE"
}

backup_inputs() {
    local stamp
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$STATE_DIR/backups"
    chmod 0700 "$STATE_DIR" "$STATE_DIR/backups"

    SECRETS_BACKUP="$STATE_DIR/backups/secrets.yaml.$stamp"
    cp -p "$DEPLOY_APPROVAL_CONFIG_DIR/secrets.yaml" "$SECRETS_BACKUP"
    chmod 0600 "$SECRETS_BACKUP"
    cmp -s "$DEPLOY_APPROVAL_CONFIG_DIR/secrets.yaml" "$SECRETS_BACKUP" \
        || die "secrets.yaml backup verification failed"

    NGINX_BACKUP="$STATE_DIR/backups/nginx-$NGINX_CONF_NAME.$stamp"
    if [[ -f $NGINX_CONF ]]; then
        NGINX_HAD_PRIOR=1
        cp -p "$NGINX_CONF" "$NGINX_BACKUP"
        cmp -s "$NGINX_CONF" "$NGINX_BACKUP" || die "Nginx configuration backup verification failed"
    else
        NGINX_HAD_PRIOR=0
        : >"$NGINX_BACKUP.disabled-target"
    fi
}

# ── secrets.yaml: in-place update that preserves the bind-mount inode ──

secrets_set_public_base_url() {
    local file="$1" value="$2" mode
    mode="$(stat -c '%a' "$file")"
    python3 - "$file" "$value" <<'PY'
import os
import re
import sys

path, value = sys.argv[1], sys.argv[2]
with open(path, 'r', encoding='utf-8') as fh:
    text = fh.read()

if re.search(r'\r', text):
    raise SystemExit('secrets.yaml uses CRLF; refusing an in-place rewrite')

lines = text.splitlines(keepends=True)
section_re = re.compile(r'^evidence:\s*(?:#.*)?$')
key_re = re.compile(r'^(\s+)public_base_url\s*:')

section_index = None
for index, line in enumerate(lines):
    if section_re.match(line.rstrip('\n')):
        if section_index is not None:
            raise SystemExit('secrets.yaml contains more than one top-level evidence section')
        section_index = index

if section_index is None:
    if lines and not lines[-1].endswith('\n'):
        lines[-1] += '\n'
    lines.extend(['\n', 'evidence:\n', '  public_base_url: "' + value + '"\n'])
else:
    end = len(lines)
    for index in range(section_index + 1, len(lines)):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith('#'):
            continue
        if not lines[index].startswith((' ', '\t')):
            end = index
            break
    indent = '  '
    for index in range(section_index + 1, end):
        child = lines[index]
        if not child.strip() or child.strip().startswith('#'):
            continue
        indent = child[:len(child) - len(child.lstrip(' \t'))]
        break
    value_line = indent + 'public_base_url: "' + value + '"\n'
    replaced = False
    for index in range(section_index + 1, end):
        if key_re.match(lines[index]):
            if replaced:
                raise SystemExit('secrets.yaml evidence section repeats public_base_url')
            lines[index] = value_line
            replaced = True
    if not replaced:
        lines.insert(section_index + 1, value_line)

updated = ''.join(lines)

import yaml
pre = yaml.safe_load(text) or {}
post = yaml.safe_load(updated)
if not isinstance(post, dict) or post.get('version') != 1:
    raise SystemExit('rewritten secrets.yaml lost its version')
evidence = post.get('evidence') or {}
if not isinstance(evidence, dict) or evidence.get('public_base_url') != value:
    raise SystemExit('rewritten secrets.yaml does not contain the new public base URL')

def without_evidence(data):
    clone = dict(data)
    clone.pop('evidence', None)
    return clone

if without_evidence(pre) != without_evidence(post):
    raise SystemExit('rewritten secrets.yaml changed unrelated settings')

# Same inode: truncate and rewrite the existing file, never replace it.
fd = os.open(path, os.O_WRONLY | os.O_TRUNC)
try:
    os.write(fd, updated.encode('utf-8'))
    os.fsync(fd)
finally:
    os.close(fd)
PY
    chmod "$mode" "$file"
    python3 - "$file" "$value" <<'PY'
import sys
import yaml
data = yaml.safe_load(open(sys.argv[1], encoding='utf-8')) or {}
evidence = data.get('evidence') or {}
if not isinstance(evidence, dict) or evidence.get('public_base_url') != sys.argv[2]:
    raise SystemExit('secrets.yaml public_base_url verification failed')
print('SECRETS_UPDATED')
PY
}

restore_secrets_from_backup() {
    local backup="$1" file="$2" mode
    [[ -f $backup && -f $file ]] || return 1
    mode="$(stat -c '%a' "$file")"
    # Stream into the existing file so the bind mount keeps its inode.
    if ! cat "$backup" >"$file"; then
        return 1
    fi
    chmod "$mode" "$file"
    cmp -s "$backup" "$file" || return 1
}

# ── Nginx ───────────────────────────────────────────────────────────

install_nginx_listener() {
    local tmp
    tmp="$(mktemp "$NGINX_CONF_DIR/.${NGINX_CONF_NAME}.XXXXXX")"
    render_nginx_conf "$tmp"
    mv -f "$tmp" "$NGINX_CONF"
    chmod 0644 "$NGINX_CONF"
    if ! nginx -t >/dev/null 2>&1; then
        warn "new Nginx listener failed validation; restoring previous configuration"
        restore_nginx_listener
        die "Nginx rejected the Evidence listener; no changes were applied"
    fi
    NGINX_CHANGED=1
    systemctl reload nginx.service
}

restore_nginx_listener() {
    local prior="${1:-$NGINX_HAD_PRIOR}"
    if [[ $prior == 1 && -f ${NGINX_BACKUP:-} ]]; then
        cp -p "$NGINX_BACKUP" "$NGINX_CONF"
        chmod 0644 "$NGINX_CONF"
    else
        rm -f "$NGINX_CONF"
    fi
    nginx -t >/dev/null 2>&1 && systemctl reload nginx.service || warn "Nginx reload after restore failed"
    NGINX_CHANGED=0
}

# ── Tunnel container ────────────────────────────────────────────────

tunnel_container_ours() {
    local name="$1"
    docker inspect -f '{{ index .Config.Labels "com.deploy-approval.evidence-ingress" }}' "$name" 2>/dev/null \
        | grep -qx '1'
}

start_tunnel_container() {
    # Only the token file itself is mounted, never its directory. The connector
    # needs no other host state and runs in an otherwise read-only container.
    if docker inspect "$CF_TUNNEL_CONTAINER" >/dev/null 2>&1; then
        if tunnel_container_ours "$CF_TUNNEL_CONTAINER"; then
            docker rm -f "$CF_TUNNEL_CONTAINER" >/dev/null
        else
            die "container $CF_TUNNEL_CONTAINER exists and is not managed by this script; refusing to replace it"
        fi
    fi
    ensure_cf_image
    docker run -d \
        --name "$CF_TUNNEL_CONTAINER" \
        --restart=unless-stopped \
        --network host \
        --user 0:0 \
        --read-only \
        --tmpfs /tmp:rw,noexec,nosuid,size=16m \
        --cap-drop ALL \
        --security-opt no-new-privileges:true \
        --label com.deploy-approval.evidence-ingress=1 \
        --label "com.deploy-approval.evidence-host=$EVIDENCE_HOST" \
        -e HOME=/tmp \
        -e TUNNEL_TOKEN_FILE=/run/cloudflared-token/token \
        --mount "type=bind,src=$CF_TUNNEL_TOKEN_FILE,dst=/run/cloudflared-token/token,readonly" \
        "$CF_IMAGE" \
        tunnel --no-autoupdate --metrics "127.0.0.1:${TUNNEL_METRICS_PORT}" run >/dev/null
    TUNNEL_STARTED=1
}

stop_tunnel_container() {
    if docker inspect "$CF_TUNNEL_CONTAINER" >/dev/null 2>&1; then
        if tunnel_container_ours "$CF_TUNNEL_CONTAINER"; then
            docker rm -f "$CF_TUNNEL_CONTAINER" >/dev/null
        else
            warn "container $CF_TUNNEL_CONTAINER is not managed by this script; leaving it untouched"
        fi
    fi
    TUNNEL_STARTED=0
}

connector_log_tail() {
    docker logs --tail "${1:-40}" "$CF_TUNNEL_CONTAINER" 2>&1 \
        | sed -e 's/[[:cntrl:]]//g' \
              -e 's/eyJ[A-Za-z0-9._-]\{20,\}/<redacted-token>/g'
}

tunnel_connector_ready() {
    curl --noproxy '*' -fsS --max-time 3 "http://127.0.0.1:${TUNNEL_METRICS_PORT}/ready" >/dev/null 2>&1
}

# ── Public verification ─────────────────────────────────────────────

public_dns_addresses() {
    curl --noproxy '*' -fsS --max-time 8 \
        -H 'accept: application/dns-json' \
        "https://cloudflare-dns.com/dns-query?name=${EVIDENCE_HOST}&type=A" 2>/dev/null \
        | python3 -c '
import json, sys
payload = json.load(sys.stdin)
rows = payload.get("Answer") or []
print("\n".join(row["data"] for row in rows if row.get("type") in (1, 5)))
' || true
}

public_dns_ok() {
    local answers
    answers="$(public_dns_addresses)"
    if [[ -n $answers ]] && grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' <<<"$answers"; then
        return 0
    fi
    # Fall back to the host resolver only to distinguish "not configured"
    # from "Cloudflare DoH unreachable".
    getent ahostsv4 "$EVIDENCE_HOST" >/dev/null 2>&1
}

public_https_health() {
    local response http_code body
    response="$(curl --noproxy '*' --silent --show-error --connect-timeout 8 --max-time 15 \
        --max-filesize 4096 --write-out $'\n%{http_code}' \
        "https://${EVIDENCE_HOST}/healthz" 2>/dev/null)" || return 1
    [[ $response == *$'\n'* ]] || return 1
    http_code="${response##*$'\n'}"
    body="${response%$'\n'*}"
    [[ $http_code == 200 ]] || return 1
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

# Returns "<status> <controller:yes|no>". "controller:yes" means the response
# came from the Evidence app (it sets X-Content-Type-Options: nosniff), not
# from the Nginx 404 fallback. That distinguishes "route works, access denied"
# from "route not configured".
probe_route() {
    local url="$1" headers status
    headers="$(curl --noproxy '*' -o /dev/null -sS -D - \
        --connect-timeout 8 --max-time 20 "$url" 2>/dev/null || true)"
    status="$(awk 'toupper($1) ~ /^HTTP\// {code=$2} END {print code}' <<<"$headers")"
    if grep -qi '^x-content-type-options:[[:space:]]*nosniff' <<<"$headers"; then
        printf '%s controller:yes' "${status:-000}"
    else
        printf '%s controller:no' "${status:-000}"
    fi
}

public_route_status() {
    probe_route "https://${EVIDENCE_HOST}/evidence/${PROBE_REPO}/pulls/${PROBE_PR}"
}

public_api_status() {
    probe_route "https://${EVIDENCE_HOST}/api/evidence/${PROBE_REPO}/pulls/${PROBE_PR}/context"
}

# A route is healthy when the Evidence app answered, even with 401/403/409/503.
route_healthy() {
    [[ $1 =~ ^(200|401|403|409|503)\ controller:yes$ ]]
}

public_management_blocked() {
    local status
    status="$(curl --noproxy '*' -o /dev/null -sS -w '%{http_code}' \
        --connect-timeout 8 --max-time 15 "https://${EVIDENCE_HOST}/docs" 2>/dev/null || true)"
    [[ $status == 404 ]]
}

wait_public_entrance() {
    local deadline=$((SECONDS + PUBLIC_TIMEOUT)) route api
    while (( SECONDS < deadline )); do
        if public_https_health && tunnel_connector_ready; then
            route="$(public_route_status)"
            api="$(public_api_status)"
            if route_healthy "$route" && route_healthy "$api"; then
                return 0
            fi
        fi
        sleep 3
    done
    return 1
}

# ── Controller restart (no rebuild, no image replacement) ───────────

restart_controller_only() {
    local image_before image_after
    image_before="$(docker inspect -f '{{.Image}}' "$CONTROLLER_CONTAINER")"
    docker restart "$CONTROLLER_CONTAINER" >/dev/null
    CONTROLLER_RESTARTED=1
    image_after="$(docker inspect -f '{{.Image}}' "$CONTROLLER_CONTAINER")"
    if [[ $image_before != "$image_after" ]]; then
        warn "Controller image identity changed across restart"
        return 1
    fi
    wait_controller_health 120 || { warn "Controller did not become healthy after restart"; return 1; }
    check_controller_loopback_binding || return 1
}

controller_effective_public_base_url() {
    docker exec "$CONTROLLER_CONTAINER" python3 -c \
        'from agents.deploy_approval.config import load_config; print(load_config().evidence_public_base_url)' \
        2>/dev/null | tail -n1
}

# ── Health timer ────────────────────────────────────────────────────

install_health_timer() {
    local unit_dir="/etc/systemd/system" script_target="/usr/local/sbin/deploy-approval-evidence-health-check"
    [[ -f $HEALTH_SCRIPT ]] || die "health check script missing: $HEALTH_SCRIPT"
    install -o root -g root -m 0755 "$HEALTH_SCRIPT" "$script_target"
    install -d -m 0755 /usr/local/share/doc/deploy-approval
    if [[ -f "$SCRIPT_DIR/../../docs/deploy-approval-stable-evidence-ingress.md" ]]; then
        install -o root -g root -m 0644 \
            "$SCRIPT_DIR/../../docs/deploy-approval-stable-evidence-ingress.md" \
            /usr/local/share/doc/deploy-approval/stable-evidence-ingress.md
    fi
    install -o root -g root -m 0644 "$UNIT_DIR/$HEALTH_SERVICE" "$unit_dir/$HEALTH_SERVICE"
    install -o root -g root -m 0644 "$UNIT_DIR/$HEALTH_TIMER" "$unit_dir/$HEALTH_TIMER"
    mkdir -p "$(dirname "$ENV_FILE")"
    chmod 0750 "$(dirname "$ENV_FILE")"
    if [[ ! -f $ENV_FILE ]]; then
        {
            printf 'EVIDENCE_HOST=%s\n' "$EVIDENCE_HOST"
            printf 'EVIDENCE_INGRESS_PORT=%s\n' "$INGRESS_PORT"
            printf 'EVIDENCE_UPSTREAM_PORT=%s\n' "$UPSTREAM_PORT"
            printf 'EVIDENCE_PROBE_REPO=%s\n' "$PROBE_REPO"
            printf 'EVIDENCE_PROBE_PR=%s\n' "$PROBE_PR"
            printf 'EVIDENCE_TUNNEL_METRICS_PORT=%s\n' "$TUNNEL_METRICS_PORT"
            printf 'CF_TUNNEL_CONTAINER=%s\n' "$CF_TUNNEL_CONTAINER"
            printf 'CONTROLLER_CONTAINER=%s\n' "$CONTROLLER_CONTAINER"
            printf '# Optional: command invoked on failure. Receives one-line summary on stdin.\n'
            printf 'EVIDENCE_ALERT_COMMAND=\n'
        } >"$ENV_FILE.tmp"
        chmod 0640 "$ENV_FILE.tmp"
        chown root:root "$ENV_FILE.tmp"
        mv -f "$ENV_FILE.tmp" "$ENV_FILE"
    fi
    systemctl daemon-reload
    systemctl enable --now "$HEALTH_TIMER" >/dev/null
}

remove_health_timer() {
    systemctl disable --now "$HEALTH_TIMER" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/$HEALTH_TIMER" "/etc/systemd/system/$HEALTH_SERVICE"
    rm -f "/usr/local/sbin/deploy-approval-evidence-health-check"
    systemctl daemon-reload || true
}

# ── Rollback machinery ──────────────────────────────────────────────

rollback_to_values() {
    local previous_url="$1" prior_nginx="$2"
    local failed=0

    # Restore the file whenever it no longer matches the previous value, even
    # if the Controller never picked the new value up.
    local file_url=""
    if [[ -n ${DEPLOY_APPROVAL_CONFIG_DIR:-} ]]; then
        file_url="$(file_public_base_url 2>/dev/null || true)"
    fi
    if (( CONTROLLER_RESTARTED )) && [[ $file_url != "$previous_url" ]]; then
        local secrets_file="$DEPLOY_APPROVAL_CONFIG_DIR/secrets.yaml"
        if [[ -n ${SECRETS_BACKUP:-} ]] && restore_secrets_from_backup "$SECRETS_BACKUP" "$secrets_file"; then
            :
        elif [[ -n $previous_url ]]; then
            if ! secrets_set_public_base_url "$secrets_file" "$previous_url" >/dev/null 2>&1; then
                warn "could not restore the previous evidence.public_base_url from the live secrets.yaml"
                failed=1
            fi
        else
            if ! secrets_remove_public_base_url "$secrets_file"; then
                warn "could not remove the newly added evidence.public_base_url"
                failed=1
            fi
        fi
        if ! docker restart "$CONTROLLER_CONTAINER" >/dev/null 2>&1; then
            warn "could not restart the Controller during rollback"
            failed=1
        fi
        if ! wait_controller_health 120; then
            warn "Controller is not healthy after rollback"
            failed=1
        fi
    fi

    if (( NGINX_CHANGED )); then
        restore_nginx_listener "$prior_nginx" || failed=1
    fi

    if (( TUNNEL_STARTED )); then
        stop_tunnel_container || failed=1
    fi

    return $failed
}

secrets_remove_public_base_url() {
    local file="$1" mode
    [[ -f $file ]] || return 0
    mode="$(stat -c '%a' "$file")"
    python3 - "$file" <<'PY'
import os
import re
import sys
import yaml

path = sys.argv[1]
original = open(path, encoding='utf-8').read()
lines = original.splitlines(keepends=True)
section_re = re.compile(r'^evidence:\s*(?:#.*)?$')
key_re = re.compile(r'^\s+public_base_url\s*:')

section = next((i for i, line in enumerate(lines)
                if section_re.match(line.rstrip('\n'))), None)
if section is None:
    raise SystemExit(0)

end = len(lines)
for index in range(section + 1, len(lines)):
    stripped = lines[index].strip()
    if not stripped or stripped.startswith('#'):
        continue
    if not lines[index].startswith((' ', '\t')):
        end = index
        break

kept = lines[:section + 1] + [line for line in lines[section + 1:end]
                              if not key_re.match(line)] + lines[end:]
# Drop the section header too when nothing but comments/blank lines remain,
# so a rollback of a previously absent evidence section restores the file.
body = [line for line in kept[section + 1:section + 1 + (end - section - 1)
                              - (end - section - 1 - len([line for line in lines[section + 1:end]
                                                          if key_re.match(line)]))]
        if line.strip() and not line.strip().startswith('#')]
if not body:
    del kept[section]
    if section > 0 and kept[section - 1].strip() == '':
        del kept[section - 1]
updated = ''.join(kept)

pre = yaml.safe_load(original) or {}
data = yaml.safe_load(updated) or {}
if data.get('version') != 1:
    raise SystemExit('rewritten secrets.yaml lost its version')
evidence = data.get('evidence')
if isinstance(evidence, dict):
    evidence.pop('public_base_url', None)


def strip_evidence(doc):
    clone = dict(doc or {})
    clone.pop('evidence', None)
    return clone


if strip_evidence(pre) != strip_evidence(data):
    raise SystemExit('rewriting secrets.yaml would change unrelated settings')

fd = os.open(path, os.O_WRONLY | os.O_TRUNC)
try:
    os.write(fd, updated.encode('utf-8'))
    os.fsync(fd)
finally:
    os.close(fd)
PY
    chmod "$mode" "$file"
    python3 - "$file" <<'PY'
import sys
import yaml
data = yaml.safe_load(open(sys.argv[1], encoding='utf-8')) or {}
evidence = data.get('evidence') or {}
if isinstance(evidence, dict) and evidence.get('public_base_url'):
    raise SystemExit('secrets.yaml still contains a public_base_url')
PY
}

# ── Commands ────────────────────────────────────────────────────────

cmd_preflight() {
    require_root
    need_cmd python3
    need_cmd curl
    need_cmd docker
    need_cmd nginx
    need_cmd systemctl
    require_common_inputs
    validate_evidence_host
    validate_token_file
    validate_config_dir
    ensure_host_not_changed_silently
    detect_nginx_conf_dir

    log "== Inputs =="
    log "EVIDENCE_HOST            : $EVIDENCE_HOST"
    log "CF_TUNNEL_TOKEN_FILE     : $CF_TUNNEL_TOKEN_FILE (validated, never printed)"
    log "DEPLOY_APPROVAL_CONFIG_DIR: $DEPLOY_APPROVAL_CONFIG_DIR"
    log "Ingress listener         : 127.0.0.1:${INGRESS_PORT} -> 127.0.0.1:${UPSTREAM_PORT}"
    log "Tunnel container         : $CF_TUNNEL_CONTAINER ($CF_IMAGE)"
    log "Nginx include directory  : $NGINX_CONF_DIR"

    log "== Controller =="
    docker inspect "$CONTROLLER_CONTAINER" >/dev/null 2>&1 \
        || die "Controller container $CONTROLLER_CONTAINER does not exist"
    [[ $(docker inspect -f '{{.State.Running}}' "$CONTROLLER_CONTAINER") == true ]] \
        || die "Controller container $CONTROLLER_CONTAINER is not running"
    wait_controller_health 15 \
        || die "Controller is not healthy on 127.0.0.1:${UPSTREAM_PORT}/healthz"
    check_controller_loopback_binding \
        || die "Controller must publish ${UPSTREAM_PORT}/tcp on 127.0.0.1 only"
    log "Controller loopback health: OK"

    log "== Stable URL support =="
    if controller_supports_stable_urls >/dev/null 2>&1; then
        log "Fixed PR URL support: OK"
    else
        die "the running Controller image does not provide stable public URLs; deploy the reviewed version first"
    fi

    log "== Nginx =="
    if port_in_use "$INGRESS_PORT"; then
        if port_owned_by_nginx "$INGRESS_PORT"; then
            log "Port $INGRESS_PORT already served by nginx (reinstall path)"
        else
            die "port $INGRESS_PORT is already used by a non-nginx process"
        fi
    else
        log "Port $INGRESS_PORT is free"
    fi

    log "== Public DNS (informational) =="
    if public_dns_ok; then
        log "DNS resolves for $EVIDENCE_HOST"
    elif (( ALLOW_PENDING_DNS )); then
        log "DNS does not resolve yet; install will configure the tunnel and skip the switch"
    else
        log "DNS does not resolve yet; install will wait up to ${PUBLIC_TIMEOUT}s after starting the tunnel"
    fi

    log "PREFLIGHT PASSED"
}

on_install_error() {
    local code=$?
    trap - ERR
    warn "unexpected failure during install (exit ${code}); restoring previous state"
    if (( SECRETS_CHANGED )) && [[ -n ${SECRETS_BACKUP:-} ]]; then
        if restore_secrets_from_backup "$SECRETS_BACKUP" "$DEPLOY_APPROVAL_CONFIG_DIR/secrets.yaml"; then
            SECRETS_CHANGED=0
        else
            warn "could not restore secrets.yaml from $SECRETS_BACKUP"
        fi
    fi
    if (( CONTROLLER_RESTARTED )); then
        docker restart "$CONTROLLER_CONTAINER" >/dev/null 2>&1 || true
        wait_controller_health 120 || warn "Controller is not healthy after recovery restart"
        CONTROLLER_RESTARTED=0
    fi
    if (( NGINX_CHANGED )); then
        restore_nginx_listener "${NGINX_HAD_PRIOR:-0}" || true
    fi
    if (( TUNNEL_STARTED )); then
        stop_tunnel_container || true
    fi
    exit "$code"
}

cmd_install() {
    cmd_preflight
    local previous_url prior_nginx

    log "== Backups =="
    local original_url
    if [[ -f $STATE_FILE ]]; then
        # Re-install for the same host: keep the original pre-install state so
        # rollback still returns to the state before the FIRST install.
        local recorded_host
        recorded_host="$(state_value EVIDENCE_HOST)"
        original_url="$(state_value PREVIOUS_PUBLIC_BASE_URL)"
        if [[ $recorded_host == "$EVIDENCE_HOST" && -n $(state_value SECRETS_BACKUP) \
              && -f $(state_value SECRETS_BACKUP) ]]; then
            SECRETS_BACKUP="$(state_value SECRETS_BACKUP)"
            NGINX_BACKUP="$(state_value NGINX_BACKUP)"
            NGINX_HAD_PRIOR="$(state_value NGINX_WAS_PRESENT)"
            log "Re-install detected; preserving the original pre-install backup"
        else
            backup_inputs
            original_url="$(file_public_base_url)"
        fi
    else
        backup_inputs
        original_url="$(file_public_base_url)"
    fi
    previous_url="$original_url"
    prior_nginx="$NGINX_HAD_PRIOR"
    log "Backed up secrets.yaml and Nginx state to $STATE_DIR/backups"
    write_state "$previous_url" "$prior_nginx"
    trap on_install_error ERR

    log "== Installing loopback Nginx listener =="
    install_nginx_listener
    local listener_ok=0
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if health_json_ok "$(loopback_health_body)"; then listener_ok=1; break; fi
        sleep 1
    done
    if (( ! listener_ok )); then
        warn "loopback listener did not return health"
        rollback_to_values "$previous_url" "$prior_nginx" || true
        die "Nginx listener failed; previous state restored"
    fi
    log "Loopback listener verified on 127.0.0.1:${INGRESS_PORT}"

    log "== Starting Cloudflare Named Tunnel connector =="
    start_tunnel_container
    local connector_ok=0
    for _ in $(seq 1 30); do
        if tunnel_connector_ready; then connector_ok=1; break; fi
        sleep 2
    done
    if (( ! connector_ok )); then
        connector_log_tail 40 >&2 || true
        rollback_to_values "$previous_url" "$prior_nginx" || true
        die "Cloudflare Named Tunnel connector did not become ready; confirm the Named Tunnel exists, the hostname is attached to it, and CF_TUNNEL_TOKEN_FILE contains its valid credential. Previous state was restored."
    fi
    log "Tunnel connector reports ready"

    if (( ALLOW_PENDING_DNS )); then
        log "Skipping public verification and the secrets switch (EVIDENCE_ALLOW_PENDING_DNS=1)"
        if (( INSTALL_TIMER )); then
            install_health_timer
            log "Health timer installed"
        fi
        trap - ERR
        write_state "$previous_url" "$prior_nginx"
        log "INSTALL PARTIAL: tunnel and listener are ready; Controller still advertises the previous URL"
        log "Re-run install without EVIDENCE_ALLOW_PENDING_DNS once ${EVIDENCE_HOST} resolves"
        return 0
    fi

    log "== Verifying public entrance =="
    if ! public_dns_ok; then
        connector_log_tail 20 >&2 || true
        rollback_to_values "$previous_url" "$prior_nginx" || true
        die "the fixed DNS record/Public Hostname for ${EVIDENCE_HOST} is missing or not propagated; secrets.yaml was NOT changed and the listener/tunnel were removed. Create or repair the Cloudflare DNS CNAME to the existing Named Tunnel, then re-run install (or use EVIDENCE_ALLOW_PENDING_DNS=1 to stage the connector while DNS propagates)."
    fi
    if ! wait_public_entrance; then
        connector_log_tail 60 >&2 || true
        rollback_to_values "$previous_url" "$prior_nginx" || true
        die "public entrance https://${EVIDENCE_HOST}/healthz did not return HTTP 200 with status=ok and service=deploy-approval; verify the fixed DNS record, Named Tunnel hostname route, and Controller health. secrets.yaml was NOT changed and the listener/tunnel were removed."
    fi
    if ! public_management_blocked; then
        rollback_to_values "$previous_url" "$prior_nginx" || true
        die "public entrance exposes non-Evidence paths; previous state restored"
    fi
    log "Public HTTPS health, Evidence page/API routing and 404 isolation verified"

    log "== Updating evidence.public_base_url =="
    SECRETS_CHANGED=1
    secrets_set_public_base_url "$DEPLOY_APPROVAL_CONFIG_DIR/secrets.yaml" \
        "https://${EVIDENCE_HOST}" >/dev/null

    log "== Restarting the existing Controller (same image) =="
    if ! restart_controller_only; then
        warn "Controller restart failed; rolling back"
        rollback_to_values "$previous_url" "$prior_nginx" || true
        die "Controller restart failed; previous configuration restored"
    fi
    if [[ $(controller_effective_public_base_url) != "https://${EVIDENCE_HOST}" ]]; then
        warn "Controller did not pick up the new public base URL"
        rollback_to_values "$previous_url" "$prior_nginx" || true
        die "Controller configuration did not take effect; previous configuration restored"
    fi
    if ! public_https_health; then
        warn "public health regressed after the Controller restart"
        rollback_to_values "$previous_url" "$prior_nginx" || true
        die "public health regressed; previous configuration restored"
    fi

    if (( INSTALL_TIMER )); then
        log "== Installing health timer =="
        install_health_timer
        log "Health timer installed"
    else
        log "Skipping health timer (EVIDENCE_HEALTH_TIMER=0)"
    fi

    trap - ERR
    write_state "$previous_url" "$prior_nginx"
    cat <<EOF
INSTALLED
EVIDENCE_PUBLIC_BASE_URL=https://${EVIDENCE_HOST}
INGRESS_LISTENER=127.0.0.1:${INGRESS_PORT}
TUNNEL_CONTAINER=${CF_TUNNEL_CONTAINER}
PREVIOUS_PUBLIC_BASE_URL=${previous_url:-<empty>}
PR_EVIDENCE_PATH=https://${EVIDENCE_HOST}/evidence/OWNER/REPO/pulls/NUMBER
EOF
}

cmd_status() {
    need_cmd python3
    need_cmd curl
    command -v docker >/dev/null 2>&1 || warn "docker is not available; L1/L3 container details are limited"
    local ok=0 url answers
    log "== Configuration =="
    log "EVIDENCE_HOST             : ${EVIDENCE_HOST:-<unset>}"
    log "Ingress listener          : 127.0.0.1:${INGRESS_PORT}"
    log "Tunnel container          : ${CF_TUNNEL_CONTAINER}"
    if [[ -f $STATE_FILE ]]; then
        log "Last installed at         : $(state_value INSTALLED_AT)"
        log "Previous public base URL  : $(state_value PREVIOUS_PUBLIC_BASE_URL)"
    else
        log "Install record            : absent"
    fi
    if [[ -n ${DEPLOY_APPROVAL_CONFIG_DIR:-} ]]; then
        url="$(file_public_base_url 2>/dev/null || true)"
        log "secrets.yaml base URL     : ${url:-<empty>}"
    else
        log "secrets.yaml base URL     : <DEPLOY_APPROVAL_CONFIG_DIR unset>"
    fi

    log "== L1 Controller (localhost) =="
    if health_json_ok "$(controller_health_body)"; then
        log "L1 Controller            : OK"
    else
        log "L1 Controller            : FAIL (127.0.0.1:${UPSTREAM_PORT}/healthz)"
        ok=1
    fi

    log "== L2 Nginx loopback listener =="
    if health_json_ok "$(loopback_health_body)"; then
        log "L2 Nginx listener        : OK"
    else
        log "L2 Nginx listener        : FAIL (127.0.0.1:${INGRESS_PORT}/healthz)"
        ok=1
    fi

    log "== L3 Tunnel connector =="
    if docker inspect -f '{{.State.Running}}' "$CF_TUNNEL_CONTAINER" 2>/dev/null | grep -qx true; then
        if tunnel_connector_ready; then
            log "L3 Tunnel connector      : OK"
        else
            log "L3 Tunnel connector      : FAIL (connector has no ready Named Tunnel connection; verify the existing Named Tunnel and its token credential)"
            ok=1
        fi
    else
        log "L3 Tunnel connector      : FAIL (Named Tunnel connector is absent or stopped; verify the existing Named Tunnel and CF_TUNNEL_TOKEN_FILE credential)"
        ok=1
    fi

    log "== L4 Public DNS =="
    if [[ -z ${EVIDENCE_HOST:-} ]]; then
        log "L4 Public DNS            : FAIL (fixed hostname/DNS resource is missing; configure EVIDENCE_HOST and its Cloudflare Public Hostname CNAME to the Named Tunnel)"
        ok=1
    else
        answers="$(public_dns_addresses)"
        if [[ -n $answers ]]; then
            log "L4 Public DNS            : OK (${answers//$'\n'/, })"
        else
            log "L4 Public DNS            : FAIL (no A/AAAA/CNAME answer for ${EVIDENCE_HOST})"
            ok=1
        fi
    fi

    if [[ -n ${EVIDENCE_HOST:-} ]]; then
        log "== L5 Public HTTPS =="
        if public_https_health; then
            log "L5 Public HTTPS health   : OK"
        else
            log "L5 Public HTTPS health   : FAIL (https://${EVIDENCE_HOST}/healthz)"
            ok=1
        fi
        log "== L6 Evidence route =="
        local route api management
        route="$(public_route_status)"
        api="$(public_api_status)"
        management="$(curl --noproxy '*' -o /dev/null -sS -w '%{http_code}' \
            --connect-timeout 8 --max-time 15 "https://${EVIDENCE_HOST}/docs" 2>/dev/null || true)"
        log "L6 Evidence page         : ${route:-no-response}"
        log "L6 Evidence API          : ${api:-no-response}"
        log "L6 Non-Evidence path     : ${management:-no-response} (expected 404)"
        route_healthy "$route" || ok=1
        route_healthy "$api" || ok=1
        [[ $management == 404 ]] || ok=1
    fi

    log "== Health timer =="
    if systemctl is-active --quiet "$HEALTH_TIMER" 2>/dev/null; then
        log "Timer                    : active"
        systemctl list-timers --no-pager "$HEALTH_TIMER" 2>/dev/null | sed -n '2p'
    else
        log "Timer                    : inactive"
    fi

    return $ok
}

cmd_rollback() {
    require_rollback_inputs
    [[ -f $STATE_FILE ]] \
        || die "no install record at $STATE_FILE; nothing was installed by this script"
    local previous_url prior_nginx
    previous_url="$(state_value PREVIOUS_PUBLIC_BASE_URL)"
    NGINX_CONF="$(state_value NGINX_CONF)"
    NGINX_BACKUP="$(state_value NGINX_BACKUP)"
    NGINX_HAD_PRIOR="$(state_value NGINX_WAS_PRESENT)"
    SECRETS_BACKUP="$(state_value SECRETS_BACKUP)"
    prior_nginx="${NGINX_HAD_PRIOR:-0}"

    # The host recorded at install time is authoritative; rollback must work
    # even when EVIDENCE_HOST is no longer exported.
    local recorded_host
    recorded_host="$(state_value EVIDENCE_HOST)"
    if [[ -z ${EVIDENCE_HOST:-} ]]; then
        EVIDENCE_HOST="$recorded_host"
    elif [[ -n $recorded_host && $EVIDENCE_HOST != "$recorded_host" ]]; then
        warn "EVIDENCE_HOST ($EVIDENCE_HOST) differs from the recorded install host ($recorded_host); using the recorded host"
        EVIDENCE_HOST="$recorded_host"
    fi
    if [[ -z $NGINX_CONF || ! -d $(dirname "$NGINX_CONF") ]]; then
        detect_nginx_conf_dir
    fi

    log "== Removing health timer =="
    remove_health_timer
    log "== Stopping tunnel connector =="
    TUNNEL_STARTED=1
    stop_tunnel_container
    log "== Restoring Nginx configuration =="
    restore_nginx_listener "$prior_nginx"
    NGINX_CHANGED=0
    log "== Restoring Controller configuration =="
    CONTROLLER_RESTARTED=1
    rollback_to_values "$previous_url" "$prior_nginx" \
        || die "rollback finished with errors; inspect manually"

    mv -f "$STATE_FILE" "$STATE_FILE.rolled-back-$(date -u +%Y%m%dT%H%M%SZ)"
    log "ROLLED_BACK"
    log "Previous evidence.public_base_url: ${previous_url:-<empty>}"
    log "The pre-existing pr418-evidence-quicktunnel container was not touched."
}

usage() {
    sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

main() {
    local command="${1:-}"
    case "$command" in
        preflight|install|status|rollback) ;;
        -h|--help|help|"") usage; exit 0 ;;
        *) usage >&2; die "unknown command: $command" ;;
    esac
    # The env file provides defaults only; explicit environment variables win.
    load_env_defaults "$ENV_FILE"
    auto_detect_resources
    case "$command" in
        preflight) cmd_preflight ;;
        install) cmd_install ;;
        status) cmd_status ;;
        rollback) cmd_rollback ;;
    esac
}

main "$@"
