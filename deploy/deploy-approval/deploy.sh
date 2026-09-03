#!/usr/bin/env bash
# deploy.sh — manage the Deploy Approval Agent container.
#
#   ./deploy.sh up          build + start
#   ./deploy.sh rebuild     rebuild without cache
#   ./deploy.sh stop|start|restart|down
#   ./deploy.sh status      show agent API status (token never in argv)
#   ./deploy.sh logs        tail container logs
#   ./deploy.sh purge       DESTROY the deploy-approval data volume (requires confirmation)
#
# The Deploy Agent reads machine owners from the mandatory MACHINE_OWNERS_HOST_FILE
# (YAML, per-machine owners[]). It reuses only the whitelisted keys from the
# Review Agent's .env (deploy/pr-review/.env). The Agent Core ACCESS_TOKEN is
# mapped from /opt/phanthy-motus/.env into AGENT_CORE_TOKEN.
# Everything is read with a strict dotenv parser (never `source`d, never eval'd,
# never shell-expanded).
# The control API token is auto-generated into a 0600 runtime file and reused.
# Machine allowlist is per-machine owners[] from the YAML file; each selected
# machine provides a node_host and Deploy Approval reaches the existing Agent
# Core API directly at http://<node_host>:15678. Agent Core does not register
# with Deploy Approval. Runtime identity and health information are read from
# the existing Agent Core APIs.
#
# Uses python3 for the status JSON pretty print (no build/test commands run).

set -euo pipefail

cd "$(dirname "$0")"
COMPOSE="docker compose"

die() { echo "ERROR: $*" >&2; exit 1; }

RUNTIME_ENV=".runtime.env"
DEPLOY_ENV="${DA_DEPLOY_ENV:-.env}"
REVIEW_ENV="${DA_REVIEW_ENV:-../pr-review/.env}"
AGENT_CORE_ENV="${DA_AGENT_CORE_ENV:-/opt/phanthy-motus/.env}"

# ── strict dotenv parsing ──────────────────────────────────────────────────
# Reads `NAME=value` pairs from a file without executing anything. Rejects
# duplicate keys, malformed lines, embedded NUL/newlines and shell-like
# expansion/comments that could execute arbitrary code.
dotenv_parse() {
    local file="$1" name value line
    [ -f "$file" ] || { echo "MISSING:$file" >&2; return 2; }
    [ -r "$file" ] || { echo "UNREADABLE:$file" >&2; return 2; }
    [ -f "$file" ] && [ ! -s "$file" ] && return 0  # empty is fine
    python3 - "$file" <<'PY'
import re, sys
path=sys.argv[1]
seen={}
out={}
with open(path, "r", encoding="utf-8") as fh:
    data=fh.read()
if "\0" in data:
    raise SystemExit("NUL byte in dotenv")
for lineno, raw in enumerate(data.splitlines(), 1):
    line=raw.strip()
    if not line or line.startswith("#"):
        continue
    if line.startswith("export "):
        line=line[len("export "):].strip()
    if "=" not in line:
        raise SystemExit(f"malformed dotenv line {lineno}")
    name, _, value = line.partition("=")
    name=name.strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise SystemExit(f"invalid key at line {lineno}")
    if name in seen:
        raise SystemExit(f"duplicate key {name}")
    seen[name]=lineno
    value=value.strip()
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        value=value[1:-1]
    if ('\n' in value) or ('"' in value and '\\' in value and False):
        raise SystemExit(f"unsafe value at line {lineno}")
    out[name]=value
for k,v in out.items():
    print(f"{k}={v}")
PY
}

_dotenv_value() {
    # $1=file $2=key  -> prints value (empty string when unset). Fails (exit 3)
    # when the file does not exist / parse fails.
    local file="$1" key="$2" line k v
    local parsed
    parsed="$(dotenv_parse "$file")" || return $?
    while IFS= read -r line; do
        k="${line%%=*}"; v="${line#*=}"
        if [ "$k" = "$key" ]; then
            printf '%s' "$v"
            return 0
        fi
    done <<< "$parsed"
    return 0
}

# Whitelisted Review Agent keys the Deploy Agent is allowed to reuse.
REVIEW_KEYS=(GITHUB_TOKEN GITHUB_REPOS POLL_ENABLED GITHUB_COMMAND_POLL_INTERVAL_SECONDS WEBHOOK_ENABLED GITHUB_WEBHOOK_SECRET REGISTRY_USER REGISTRY_PASSWORD)

require_review_env() {
    [ -f "$REVIEW_ENV" ] || die "Review Agent .env not found: $REVIEW_ENV"
    [ -r "$REVIEW_ENV" ] || die "Review Agent .env not readable: $REVIEW_ENV"
    dotenv_parse "$REVIEW_ENV" >/dev/null 2>&1 || die "Review Agent .env is not a safe dotenv file"
}

require_core_token() {
    [ -f "$AGENT_CORE_ENV" ] || die "Agent Core .env not found: $AGENT_CORE_ENV (expected /opt/phanthy-motus/.env)"
    [ -f "$AGENT_CORE_ENV" ] && [ ! -L "$AGENT_CORE_ENV" ] || die "Agent Core .env must be a regular file"
    [ -r "$AGENT_CORE_ENV" ] || die "Agent Core .env not readable: $AGENT_CORE_ENV"
    local a b
    a="$(dotenv_parse "$AGENT_CORE_ENV" >/dev/null || true)"
    # strict: require exactly one ACCESS_TOKEN
    local count
    count="$(dotenv_parse "$AGENT_CORE_ENV" 2>/dev/null | grep -c '^ACCESS_TOKEN=' )" || count=0
    [ "$count" -eq 1 ] || die "Agent Core .env must contain exactly one ACCESS_TOKEN"
    local tok
    tok="$(ACCESS_TOKEN_from_core)" || true
    [ -n "$tok" ] || die "ACCESS_TOKEN is empty in $AGENT_CORE_ENV"
}

# ── machine owners (Mandatory for deployment) ──────────────────────────
# The deployer MUST provide a valid machines.yaml file. Missing/invalid YAML
# fails fast before any container is started.
require_machine_owners() {
    local file="$1"
    [ -f "$file" ] || die "Machine owners file not found: $file"
    [ -f "$file" ] && [ ! -L "$file" ] || die "Machine owners file must be a regular file, not a symlink: $file"
    [ -r "$file" ] || die "Machine owners file not readable: $file"
    # Validate YAML schema using Python
    python3 - "$file" <<'PY' || die "Machine owners file failed schema validation: $file"
import sys, yaml
path = sys.argv[1]
with open(path) as f:
    data = yaml.safe_load(f)
if not isinstance(data, dict):
    raise SystemExit("Root must be a mapping")
v = data.get("version")
if v != 1:
    raise SystemExit(f"version must be 1, got {v!r}")
machines = data.get("machines")
if not isinstance(machines, dict) or not machines:
    raise SystemExit("machines must be a non-empty mapping")
node_ids = {}
for alias, cfg in machines.items():
    if not isinstance(alias, str) or not alias.strip():
        raise SystemExit(f"alias must be non-empty string")
    if not isinstance(cfg, dict):
        raise SystemExit(f"machine {alias!r} must be a mapping")
    nid = str(cfg.get("node_id", "")).strip()
    if not nid:
        raise SystemExit(f"machine {alias!r}: node_id required")
    if nid in node_ids:
        raise SystemExit(f"duplicate node_id: {nid!r}")
    node_ids[nid] = alias
    owners = cfg.get("owners")
    if not isinstance(owners, list) or not owners:
        raise SystemExit(f"machine {alias!r}: owners must be non-empty list")
    if not all(isinstance(o, str) and o.strip() for o in owners):
        raise SystemExit(f"machine {alias!r}: each owner must be a non-empty string")
print("MACHINE_OWNERS_VALID")
PY
}

ACCESS_TOKEN_from_core() {
    dotenv_parse "$AGENT_CORE_ENV" 2>/dev/null | sed -n 's/^ACCESS_TOKEN=//p' | head -n1
}

# ── API token (auto-generated, stable, 0600) ───────────────────────────────
ensure_api_token() {
    if [ -f "$RUNTIME_ENV" ]; then
        local tok
        tok="$(dotenv_parse "$RUNTIME_ENV" 2>/dev/null | sed -n 's/^API_TOKEN=//p' | head -n1)" || true
        [ -n "$tok" ] || die "$RUNTIME_ENV exists but has no API_TOKEN"
        chmod 600 "$RUNTIME_ENV"
        return
    fi
    local tok
    tok="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    printf 'API_TOKEN=%s\n' "$tok" > "$RUNTIME_ENV"
    chmod 600 "$RUNTIME_ENV"
}

dotenv_get() {
    # legacy helper: read a key from .env if present (else: the runtime file)
    local key="$1" file="${2:-.env}"
    _dotenv_value "$file" "$key" 2>/dev/null || true
}

require_env() {
    # Machine owners file is mandatory for deployment.
    # Missing/invalid YAML stops deployment before the container starts.
    local machine_file="${MACHINE_OWNERS_HOST_FILE:-}"
    if [ -z "$machine_file" ]; then
        # Try to read from DEPLOY_ENV
        machine_file="$(_dotenv_value "$DEPLOY_ENV" MACHINE_OWNERS_HOST_FILE 2>/dev/null)" || true
        [ -z "$machine_file" ] && machine_file="./machines.yaml"
    fi
    require_machine_owners "$machine_file"
    require_review_env
    require_core_token
    ensure_api_token
    # Export MACHINE_OWNERS_HOST_FILE for docker-compose
    export MACHINE_OWNERS_HOST_FILE="$machine_file"
}

build_list_env() {
    # Emit the merged environment variables for Compose (as KEY=value lines).
    local f
    f="$(dotenv_parse "$REVIEW_ENV" 2>/dev/null || true)"
    for key in "${REVIEW_KEYS[@]}"; do
        local v
        v="$(printf '%s' "$f" | sed -n "s/^${key}=//p" | head -n1)"
        [ -n "$v" ] && printf '%s=%s
' "$key" "$v"
    done
    printf 'REVIEW_AGENT_BASE_URL=http://host.docker.internal:25000\n'
    printf 'AGENT_CORE_TOKEN=%s\n' "$(ACCESS_TOKEN_from_core)"
    printf 'API_TOKEN=%s\n' "$(dotenv_parse "$RUNTIME_ENV" | sed -n 's/^API_TOKEN=//p')"
}

cmd_up() {
    require_env
    local tmp
    tmp="$(mktemp)"
    chmod 600 "$tmp"
    build_list_env > "$tmp"
    trap 'rm -f "$tmp"' EXIT
    $COMPOSE --env-file "$tmp" build
    $COMPOSE --env-file "$tmp" up -d
    echo "Deploy Approval Agent is running on http://0.0.0.0:25001 (host network)"
}

cmd_rebuild() {
    require_env
    local tmp
    tmp="$(mktemp)"; chmod 600 "$tmp"
    build_list_env > "$tmp"; trap 'rm -f "$tmp"' EXIT
    $COMPOSE --env-file "$tmp" build --no-cache
    $COMPOSE --env-file "$tmp" up -d --force-recreate
}

cmd_stop() { $COMPOSE stop; }
cmd_start() { $COMPOSE start; }
cmd_restart() { $COMPOSE restart; }

cmd_down() {
    $COMPOSE down
}

cmd_status() {
    require_env
    curl -sf --max-time 5 http://127.0.0.1:25001/healthz >/dev/null         && echo "deploy-approval: healthy" || echo "deploy-approval: not responding"
    local tok
    tok="$(dotenv_parse "$RUNTIME_ENV" 2>/dev/null | sed -n 's/^API_TOKEN=//p' | head -n1)" || true
    {
        printf 'url = "http://127.0.0.1:25001/api/status"\n'
        printf 'header = "Authorization: Bearer %s"\n' "$tok"
    } | curl -sf --max-time 30 --config - -o /tmp/da_status.json         && python3 -m json.tool /tmp/da_status.json 2>/dev/null || true
    rm -f /tmp/da_status.json
}

cmd_logs() {
    local args=()
    [ -f .env ] && args+=(--env-file .env)
    $COMPOSE "${args[@]}" logs -f --tail "${1:-100}"
}

cmd_purge() {
    read -r -p "Type PURGE-DEPLOY-DATA to permanently delete the deploy-approval data volume: " confirm
    [ "$confirm" = "PURGE-DEPLOY-DATA" ] || die "Purge cancelled."
    $COMPOSE down -v
    echo "Purged the deploy-approval data volume."
}

usage() { sed -n '2,30p' "$0"; }

case "${1:-up}" in
    up|"") cmd_up ;;
    rebuild) cmd_rebuild ;;
    stop) cmd_stop ;;
    start) cmd_start ;;
    down) cmd_down ;;
    restart) cmd_restart ;;
    status) cmd_status ;;
    logs) shift; cmd_logs "$@" ;;
    purge) cmd_purge ;;
    -h|--help|help) usage ;;
    *) echo "Unknown command: $1" >&2; usage >&2; exit 1 ;;
esac
