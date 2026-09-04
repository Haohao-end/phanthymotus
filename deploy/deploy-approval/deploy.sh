#!/usr/bin/env bash
# deploy.sh — manage the Deploy Approval Agent container.
#
# Commands:
#   ./deploy.sh up|rebuild|start|stop|restart|down|status|logs
#
# Fixed inputs:
#   review env: ../pr-review/.env
#   agent core env: /opt/phanthy-motus/.env
#   machine policy: ./machines.yaml
#   COS secrets: ./secrets.yaml
#
# No purge mode, no runtime API token, no env indirection for file locations.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PATH="$SCRIPT_DIR/deploy.sh"
cd "$SCRIPT_DIR"
COMPOSE="docker compose"
REVIEW_ENV="../pr-review/.env"
AGENT_CORE_ENV="/opt/phanthy-motus/.env"
MACHINES_FILE="./machines.yaml"
SECRETS_FILE="./secrets.yaml"
TMP_ENV=""

die() { echo "ERROR: $*" >&2; exit 1; }

dotenv_parse() {
    local file="$1"
    [ -f "$file" ] || { echo "MISSING:$file" >&2; return 2; }
    [ -r "$file" ] || { echo "UNREADABLE:$file" >&2; return 2; }
    python3 - "$file" <<'PY'
import re, sys
path = sys.argv[1]
seen = set()
with open(path, "r", encoding="utf-8") as fh:
    data = fh.read()
if "\0" in data:
    raise SystemExit("NUL byte in dotenv")
for lineno, raw in enumerate(data.splitlines(), 1):
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    if line.startswith("export "):
        line = line[len("export "):].strip()
    if "=" not in line:
        raise SystemExit(f"malformed dotenv line {lineno}")
    name, _, value = line.partition("=")
    name = name.strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise SystemExit(f"invalid key at line {lineno}")
    if name in seen:
        raise SystemExit(f"duplicate key {name}")
    seen.add(name)
    value = value.strip()
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        value = value[1:-1]
    if "\n" in value:
        raise SystemExit(f"unsafe value at line {lineno}")
    print(f"{name}={value}")
PY
}

dotenv_value() {
    local file="$1" key="$2"
    dotenv_parse "$file" | sed -n "s/^${key}=//p" | head -n1
}

dotenv_has_key() {
    local file="$1" key="$2"
    dotenv_parse "$file" | awk -F= -v key="$key" '$1 == key { found = 1 } END { exit(found ? 0 : 1) }'
}

require_env_value() {
    local file="$1" key="$2" label="$3"
    dotenv_has_key "$file" "$key" || die "$label is missing from $file"
    local value
    value="$(dotenv_value "$file" "$key")"
    [ -n "$value" ] || die "$label is empty in $file"
    printf '%s\n' "$value"
}

require_review_env() {
    [ -f "$REVIEW_ENV" ] && [ ! -L "$REVIEW_ENV" ] || die "Review Agent .env must be a regular file: $REVIEW_ENV"
    [ -r "$REVIEW_ENV" ] || die "Review Agent .env not readable: $REVIEW_ENV"
    dotenv_parse "$REVIEW_ENV" >/dev/null
    require_env_value "$REVIEW_ENV" GITHUB_TOKEN "GITHUB_TOKEN" >/dev/null
}

require_core_env() {
    [ -f "$AGENT_CORE_ENV" ] && [ ! -L "$AGENT_CORE_ENV" ] || die "Agent Core .env must be a regular file: $AGENT_CORE_ENV"
    [ -r "$AGENT_CORE_ENV" ] || die "Agent Core .env not readable: $AGENT_CORE_ENV"
    dotenv_parse "$AGENT_CORE_ENV" >/dev/null
    require_env_value "$AGENT_CORE_ENV" ACCESS_TOKEN "ACCESS_TOKEN" >/dev/null
}

require_machine_policy() {
    [ -f "$MACHINES_FILE" ] && [ ! -L "$MACHINES_FILE" ] || die "Machine policy file must be a regular file: $MACHINES_FILE"
    [ -r "$MACHINES_FILE" ] || die "Machine policy file not readable: $MACHINES_FILE"
    python3 - "$MACHINES_FILE" <<'PY'
import sys, yaml
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    data = yaml.safe_load(fh)
if not isinstance(data, dict) or data.get("version") != 1:
    raise SystemExit("machine policy must be a version 1 mapping")
machines = data.get("machines")
if not isinstance(machines, dict) or not machines:
    raise SystemExit("machines must be a non-empty mapping")
seen_node_ids = set()
for alias, machine in machines.items():
    if not isinstance(alias, str) or not alias.strip():
        raise SystemExit("machine aliases must be non-empty strings")
    if not isinstance(machine, dict):
        raise SystemExit(f"machine {alias!r} must be a mapping")
    node_id = machine.get("node_id")
    if not isinstance(node_id, str) or not node_id.strip():
        raise SystemExit(f"machine {alias!r} must define a non-empty node_id")
    if node_id in seen_node_ids:
        raise SystemExit(f"duplicate node_id {node_id!r}")
    seen_node_ids.add(node_id)
    owners = machine.get("owners")
    if not isinstance(owners, list) or not owners:
        raise SystemExit(f"machine {alias!r} must define a non-empty owners list")
    for owner in owners:
        if not isinstance(owner, str) or not owner.strip():
            raise SystemExit(f"machine {alias!r} has an invalid owner entry")
print("MACHINE_POLICY_OK")
PY
}

require_secrets() {
    [ -f "$SECRETS_FILE" ] && [ ! -L "$SECRETS_FILE" ] || die "COS secrets file must be a regular file: $SECRETS_FILE"
    [ -r "$SECRETS_FILE" ] || die "COS secrets file not readable: $SECRETS_FILE"
    python3 - "$SECRETS_FILE" <<'PY'
import sys, yaml
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    data = yaml.safe_load(fh)
if not isinstance(data, dict):
    raise SystemExit("secrets file must be a mapping")
if data.get("version") != 1:
    raise SystemExit("secrets file must be version 1")
cos = data.get("cos", {})
if cos is None:
    cos = {}
if not isinstance(cos, dict):
    raise SystemExit("cos section must be a mapping")
for key in ("region", "bucket", "secret_id", "secret_key", "session_token"):
    value = cos.get(key, "")
    if value is not None and not isinstance(value, str):
        raise SystemExit(f"cos.{key} must be a string")
prefix = cos.get("prefix", "deploy-approval")
if not isinstance(prefix, str) or not prefix.strip():
    raise SystemExit("cos.prefix must be a non-empty string")
ttl = cos.get("signed_url_ttl_seconds", 604800)
if isinstance(ttl, bool) or not isinstance(ttl, int):
    raise SystemExit("cos.signed_url_ttl_seconds must be an integer")
if ttl < 1 or ttl > 604800:
    raise SystemExit("cos.signed_url_ttl_seconds must be 1..604800")
print("SECRETS_OK")
PY
}

require_runtime_inputs() {
    require_review_env
    require_core_env
    require_machine_policy
    require_secrets
}

build_env_file() {
    local tmp
    tmp="$(mktemp)"
    chmod 600 "$tmp"
    {
        printf 'GITHUB_TOKEN=%s\n' "$(require_env_value "$REVIEW_ENV" GITHUB_TOKEN GITHUB_TOKEN)"
        printf 'ACCESS_TOKEN=%s\n' "$(require_env_value "$AGENT_CORE_ENV" ACCESS_TOKEN ACCESS_TOKEN)"
        for key in GITHUB_REPOS POLL_ENABLED POLL_INTERVAL_SECONDS WEBHOOK_ENABLED GITHUB_WEBHOOK_SECRET REGISTRY REGISTRY_USER REGISTRY_PASSWORD; do
            if dotenv_has_key "$REVIEW_ENV" "$key"; then
                value="$(dotenv_value "$REVIEW_ENV" "$key")"
                if [ -n "$value" ]; then
                    printf '%s=%s\n' "$key" "$value"
                fi
            fi
        done
    } > "$tmp"
    echo "$tmp"
}

cmd_up() {
    require_runtime_inputs
    TMP_ENV="$(build_env_file)"
    trap 'rm -f "$TMP_ENV"' EXIT
    $COMPOSE --env-file "$TMP_ENV" build
    $COMPOSE --env-file "$TMP_ENV" up -d
    echo "Deploy Approval Agent is running on http://127.0.0.1:25001"
}

cmd_rebuild() {
    require_runtime_inputs
    TMP_ENV="$(build_env_file)"
    trap 'rm -f "$TMP_ENV"' EXIT
    $COMPOSE --env-file "$TMP_ENV" build --no-cache
    $COMPOSE --env-file "$TMP_ENV" up -d --force-recreate
}

cmd_stop() { $COMPOSE stop; }
cmd_start() { $COMPOSE start; }
cmd_restart() { $COMPOSE restart; }
cmd_down() { $COMPOSE down; }

cmd_status() {
    curl -sf --max-time 5 http://127.0.0.1:25001/healthz >/dev/null \
        && echo "deploy-approval: healthy" || echo "deploy-approval: not responding"
    $COMPOSE ps
}

cmd_logs() {
    $COMPOSE logs -f --tail "${1:-100}"
}

usage() { sed -n '1,22p' "$SCRIPT_PATH"; }

case "${1:-up}" in
    up|"") cmd_up ;;
    rebuild) cmd_rebuild ;;
    stop) cmd_stop ;;
    start) cmd_start ;;
    restart) cmd_restart ;;
    down) cmd_down ;;
    status) cmd_status ;;
    logs) shift; cmd_logs "$@" ;;
    -h|--help|help) usage ;;
    *) echo "Unknown command: $1" >&2; usage >&2; exit 1 ;;
esac
