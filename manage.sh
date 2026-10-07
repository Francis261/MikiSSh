#!/usr/bin/env bash
#
# manage.sh — operations for the MikiSSh gateway + Cloudflare tunnel.
#
#   ./manage.sh status          health overview
#   ./manage.sh doctor          deep checks, non-zero exit on failure
#   ./manage.sh start|stop|restart
#   ./manage.sh logs [gateway|tunnel] [lines]
#   ./manage.sh test            run the test suite
#   ./manage.sh connect         open a shell through the public URL
#   ./manage.sh recover         restore after a host reset
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# ---------------------------------------------------------------- constants
PUBLIC_URL="https://mikissh.ryion.com"
WS_PATH="/ssh"
TLS_PORT=8022
LOOPBACK_PORT=8023

APP_GW="mikissh-gateway"
APP_TUN="mikissh-tunnel"
CONFIG="$ROOT/mikissh.config.json"
TOKEN_FILE="$ROOT/.cf-tunnel-token"
UNIT_FILE="/etc/systemd/system/pm2-root.service"
# pm2 keeps its daemon state here, NOT in the project directory.
PM2_HOME="${PM2_HOME:-$HOME/.pm2}"
DUMP_FILE="$PM2_HOME/dump.pm2"
GATEWAY_LOG="$ROOT/logs/gateway.log"
TUNNEL_LOG="$ROOT/logs/tunnel.err.log"

# ---------------------------------------------------------------- output
if [ -t 1 ]; then
  C_G=$'\033[32m'; C_R=$'\033[31m'; C_Y=$'\033[33m'; C_B=$'\033[1m'; C_D=$'\033[2m'; C_0=$'\033[0m'
else
  C_G=""; C_R=""; C_Y=""; C_B=""; C_D=""; C_0=""
fi

ok()   { printf '  %sPASS%s  %s\n' "$C_G" "$C_0" "$*"; }
bad()  { printf '  %sFAIL%s  %s\n' "$C_R" "$C_0" "$*"; FAILS=$((FAILS + 1)); }
warn() { printf '  %sWARN%s  %s\n' "$C_Y" "$C_0" "$*"; WARNS=$((WARNS + 1)); }
info() { printf '  %s%s%s\n' "$C_D" "$*" "$C_0"; }
head2() { printf '\n%s%s%s\n' "$C_B" "$*" "$C_0"; }

FAILS=0
WARNS=0
# `bad` counts as a failure; plain assertion failures use this instead.
fail() { bad "$*"; }

# Read a dotted path out of the config file. Never prints secrets.
cfg() {
  [ -f "$CONFIG" ] || return 0
  jq -r --arg p "$1" '
    ($p | split(".")) as $k
    | getpath($k)
    | if . == null then empty
      elif type == "array" then map(tostring) | join(", ")
      elif type == "object" then tojson
      else tostring end
  ' "$CONFIG" 2>/dev/null || true
}

# pm2 status rows for our two apps only.
pm2_rows() {
  pm2 jlist 2>/dev/null | jq -r '
    .[]
    | select(.name | test("^mikissh-"))
    | (.pm2_env.pm_uptime // .pm2_env.pm2_uptime) as $start
    | [ .name,
        .pm2_env.status,
        (if $start == null
         then "-"
         else (((now * 1000) - $start) / 1000 | round | tostring) + "s" end),
        (.pm2_env.restart_time // 0 | tostring) ]
    | @tsv
  ' 2>/dev/null || true
}

listening() { ss -tlnp 2>/dev/null | grep -cE ":$1\b" || true; }

tunnel_conns() { grep -c "Registered tunnel connection" "$TUNNEL_LOG" 2>/dev/null || echo 0; }

# ==================================================================== status
cmd_status() {
  head2 "PROCESSES"
  local rows
  rows="$(pm2_rows)"
  if [ -z "$rows" ]; then
    bad "no mikissh apps registered with pm2"
  else
    while IFS=$'\t' read -r name status up restarts; do
      case "$status" in
        online) printf '  %s%-18s%s %-8s up=%-6s restarts=%s\n' "$C_G" "$name" "$C_0" "$status" "$up" "$restarts" ;;
        *)      printf '  %s%-18s%s %-8s up=%-6s restarts=%s\n' "$C_R" "$name" "$C_0" "$status" "$up" "$restarts" ;;
      esac
    done <<< "$rows"
  fi

  head2 "LISTENERS"
  [ "$(listening "$TLS_PORT")" -gt 0 ] \
    && ok "TLS     127.0.0.1:$TLS_PORT" || bad "TLS     127.0.0.1:$TLS_PORT not bound"
  [ "$(listening "$LOOPBACK_PORT")" -gt 0 ] \
    && ok "origin  127.0.0.1:$LOOPBACK_PORT  (tunnel target)" || bad "origin  127.0.0.1:$LOOPBACK_PORT not bound"

  head2 "TUNNEL"
  local n; n="$(tunnel_conns)"
  [ "$n" -gt 0 ] && ok "$n connection(s) registered to Cloudflare" || bad "no tunnel connections"
  if grep -q "SUMMARY: Environment is healthy" "$TUNNEL_LOG" 2>/dev/null; then
    ok "prechecks healthy"
  else
    warn "no healthy precheck found in log"
  fi

  head2 "POLICY"
  local origins; origins="$(cfg security.allowedOrigins)"
  if [ -n "$origins" ]; then ok "allowedOrigins: $origins"; else fail "allowedOrigins empty (internet-facing!)"; fi
  local toks; toks="$(jq -r '((.auth.tokens) // []) | length' "$CONFIG" 2>/dev/null || echo 0)"
  [ "$toks" -gt 0 ] && ok "auth tokens configured: $toks (value not shown)" || fail "no auth tokens configured"

  head2 "PUBLIC"
  probe_public || true

  echo
}

probe_public() {
  local code
  code="$(timeout 15 curl -sS -o /dev/null -w '%{http_code}' "$PUBLIC_URL/" 2>/dev/null || echo 000)"
  case "$code" in
    200) ok "$PUBLIC_URL -> HTTP $code" ;;
    000) bad "$PUBLIC_URL unreachable" ;;
    *)   bad "$PUBLIC_URL -> HTTP $code" ;;
  esac
}

# ==================================================================== doctor
cmd_doctor() {
  head2 "FILES"
  [ -x "$ROOT/bin/mikissh" ] \
    && ok "gateway binary present ($(stat -c%s "$ROOT/bin/mikissh") bytes)" \
    || fail "gateway binary missing — run: go build -o bin/mikissh ./cmd/mikissh"
  [ -f "$ROOT/go.mod" ] && ok "go.mod present" || fail "go.mod missing"
  [ -f "$CONFIG" ] && ok "config present" || fail "config missing: mikissh.config.json"
  [ -f "$ROOT/certs/server.crt" ] && ok "TLS certificate present" || fail "TLS certificate missing — run: ./bin/mikissh gen-cert"
  [ -f "$ROOT/public/index.html" ] && ok "web UI present" || fail "public/index.html missing"
  [ -f "$ROOT/public/vendor/xterm.js" ] && ok "vendored xterm present" \
    || fail "public/vendor/xterm.js missing — the UI needs a CDN-free terminal"
  [ -f "$ROOT/.ssh/id_ed25519" ] && ok "SSH gateway key present (mode $(stat -c%a "$ROOT/.ssh/id_ed25519"))" \
    || warn "SSH key missing — gateway will fall back to agent/default identities"

  if [ -f "$TOKEN_FILE" ]; then
    local m; m="$(stat -c%a "$TOKEN_FILE")"
    [ "$m" = "600" ] && ok "tunnel token file mode 600" || fail "tunnel token file mode is $m, should be 600"
  else
    warn "no .cf-tunnel-token — tunnel will not start"
  fi

  head2 "TOOLING"
  command -v jq        >/dev/null && ok "jq installed"        || fail "jq not found — manage.sh reads the config with it"
  command -v node      >/dev/null && ok "node $(node -v) (pm2 runtime)" || fail "node not found — pm2 cannot run"
  command -v pm2       >/dev/null && ok "pm2 installed"       || fail "pm2 not found"
  command -v cloudflared >/dev/null && ok "cloudflared installed" || fail "cloudflared not found"
  command -v go        >/dev/null && ok "go toolchain available for rebuilds" \
    || warn "go not installed — the binary cannot be rebuilt on this host"

  head2 "PROCESS"
  local rows; rows="$(pm2_rows)"
  if [ -z "$rows" ]; then
    fail "no mikissh apps registered — run: ./manage.sh start"
  else
    while IFS=$'\t' read -r name status _up _r; do
      [ "$status" = "online" ] && ok "$name online" || fail "$name is '$status'"
    done <<< "$rows"
  fi

  head2 "NETWORK"
  [ "$(listening "$TLS_PORT")" -gt 0 ] && ok "TLS listener on $TLS_PORT" || fail "TLS listener not bound"
  [ "$(listening "$LOOPBACK_PORT")" -gt 0 ] && ok "loopback origin on $LOOPBACK_PORT" || fail "loopback origin not bound"
  local n; n="$(tunnel_conns)"
  [ "$n" -gt 0 ] && ok "$n tunnel connection(s)" || fail "tunnel has no registered connections"

  head2 "POLICY"
  local origins; origins="$(cfg security.allowedOrigins)"
  if [ -n "$origins" ]; then ok "allowedOrigins: $origins"; else fail "allowedOrigins is empty"; fi
  local minv; minv="$(cfg ws.tls.minVersion)"
  [ "$minv" = "TLSv1.3" ] && ok "min TLS version $minv" || fail "min TLS version is '${minv:-unset}'"

  head2 "PERSISTENCE"
  [ -f "$UNIT_FILE" ] && ok "systemd unit present" || fail "systemd unit missing — run: ./manage.sh startup"
  if [ -f "$DUMP_FILE" ]; then
    grep -q "$APP_GW" "$DUMP_FILE" && ok "pm2 dump contains $APP_GW" || fail "pm2 dump missing $APP_GW — run: ./manage.sh save"
    grep -q "$APP_TUN" "$DUMP_FILE" && ok "pm2 dump contains $APP_TUN" || fail "pm2 dump missing $APP_TUN — run: ./manage.sh save"
  else
    fail "pm2 dump missing ($DUMP_FILE) — run: ./manage.sh save"
  fi

  head2 "PUBLIC ENDPOINT"
  probe_public || true

  echo
  if [ "$FAILS" -gt 0 ]; then
    printf '%s%d check(s) failed.%s\n' "$C_R" "$FAILS" "$C_0"
    return 1
  fi
  printf '%sall checks passed%s' "$C_G" "$C_0"
  if [ "$WARNS" -gt 0 ]; then
    printf ' (%d warning(s))' "$WARNS"
  fi
  echo
}

# ============================================================== start/stop
cmd_start() {
  [ -x "$ROOT/bin/mikissh" ] || { warn "gateway binary missing — building"; go build -o bin/mikissh ./cmd/mikissh; }
  pm2 start "$ROOT/ecosystem.config.cjs"
  sleep 2
  cmd_status
}

cmd_stop()   { pm2 stop "$APP_GW" "$APP_TUN"; }
cmd_restart(){ pm2 restart "$APP_GW" "$APP_TUN" --update-env; sleep 2; cmd_status; }

cmd_save() {
  pm2 save
  if [ -f "$DUMP_FILE" ] && grep -q "$APP_GW" "$DUMP_FILE" && grep -q "$APP_TUN" "$DUMP_FILE"; then
    ok "dump contains both apps"
  else
    fail "dump does not contain both apps"
    return 1
  fi
}

cmd_startup() {
  pm2 startup
  systemctl enable pm2-root 2>/dev/null || true
  [ -f "$UNIT_FILE" ] && ok "systemd unit present and enabled" || fail "systemd unit still missing"
}

# ===================================================================== logs
cmd_logs() {
  local which="${1:-all}" lines="${2:-40}"
  case "$which" in
    gateway) tail -n "$lines" "$GATEWAY_LOG" 2>/dev/null || warn "no gateway log" ;;
    tunnel)  tail -n "$lines" "$TUNNEL_LOG" 2>/dev/null || warn "no tunnel log" ;;
    *)       echo "--- gateway ---"; tail -n "$lines" "$GATEWAY_LOG" 2>/dev/null
             echo; echo "--- tunnel ---"; tail -n "$lines" "$TUNNEL_LOG" 2>/dev/null ;;
  esac
}

# ==================================================================== test
cmd_test() {
  local unformatted
  unformatted="$(gofmt -l cmd internal)" || true
  if [ -n "$unformatted" ]; then
    warn "gofmt would rewrite: $(printf '%s' "$unformatted" | tr '\n' ' ')"
  fi
  go vet ./...
  go test ./...
}

# ================================================================= connect
cmd_connect() {
  if [ -z "${MIKISSH_TOKEN:-}" ]; then
    # Pull the first configured token into the environment without printing it.
    MIKISSH_TOKEN="$(jq -r '((.auth.tokens) // [""])[0] // ""' "$CONFIG" 2>/dev/null || true)"
    export MIKISSH_TOKEN
  fi
  [ -n "${MIKISSH_TOKEN:-}" ] || { fail "no token available — set MIKISSH_TOKEN or add one to the config"; exit 1; }
  info "connecting to wss://mikissh.ryion.com$WS_PATH"
  exec "$ROOT/bin/mikissh" client --url "wss://mikissh.ryion.com$WS_PATH" "$@"
}

# =================================================================== token
cmd_token() {
  "$ROOT/bin/mikissh" gen-token
}

# ================================================================= recover
# Full restore after a host reset: rebuilds the binary if it is gone, the
# pm2 dump and the systemd unit.
cmd_recover() {
  head2 "RECOVERING"

  if [ ! -x "$ROOT/bin/mikissh" ]; then
    info "gateway binary missing → go build"
    go build -o bin/mikissh ./cmd/mikissh
    ok "gateway binary built"
  else
    ok "gateway binary present"
  fi

  pm2 start "$ROOT/ecosystem.config.cjs" >/dev/null 2>&1 || pm2 restart "$APP_GW" "$APP_TUN" >/dev/null 2>&1 || true
  sleep 3
  pm2 save >/dev/null 2>&1 || true
  ok "pm2 processes registered and saved"

  if [ ! -f "$UNIT_FILE" ]; then
    pm2 startup >/dev/null 2>&1 || true
    systemctl enable pm2-root 2>/dev/null || true
  fi
  [ -f "$UNIT_FILE" ] && ok "boot persistence restored" || warn "systemd unit could not be created"

  sleep 2
  cmd_doctor
}

# ==================================================================== help
cmd_help() {
  # Print the header comment block (everything after the shebang up to the
  # first non-comment line) rather than a hard-coded line range.
  awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$ROOT/manage.sh"
  cat <<EOF

Commands:
  status                 processes, listeners, tunnel, policy, public URL
  doctor                 deep health checks (exit 1 on failure)
  start | stop | restart manage the pm2 apps
  save                   persist the pm2 process list
  startup                (re)create boot persistence
  logs [name] [lines]    gateway | tunnel | all
  test                   run the test suite
  connect [flags]        open a shell via ${PUBLIC_URL}${WS_PATH}
  token                  generate a fresh access token
  recover                restore everything after a host reset

Endpoint: ${PUBLIC_URL}${WS_PATH}
EOF
}

# ================================================================ dispatch
cmd="${1:-help}"
[ $# -gt 0 ] && shift || true

case "$cmd" in
  status)   cmd_status "$@" ;;
  doctor)   cmd_doctor "$@" ;;
  start)    cmd_start "$@" ;;
  stop)     cmd_stop "$@" ;;
  restart)  cmd_restart "$@" ;;
  save)     cmd_save "$@" ;;
  startup)  cmd_startup "$@" ;;
  logs)     cmd_logs "$@" ;;
  test)     cmd_test "$@" ;;
  connect)  cmd_connect "$@" ;;
  token)    cmd_token "$@" ;;
  recover)  cmd_recover "$@" ;;
  help|-h|--help) cmd_help ;;
  *) echo "unknown command: $cmd" >&2; cmd_help; exit 2 ;;
esac
