#!/usr/bin/env bash
#
# dev-sandbox.sh — bring up a complete NurProxy stack in dry-run / sandbox mode
# (#93) and seed it with a working topology, so the whole control plane runs
# locally with NO external DNS or ACME calls and NO privileges.
#
# It starts a dry-run orchestrator + N dry-run agents, then seeds a provider
# (dummy token), a zone, a Proxmox discovery source (dry-run fixture), and one
# server + central-TLS domain per agent. The
# orchestrator simulates every DNS/ACME call; the agents simulate their reverse
# proxy in memory (no Caddy process, no :80/:443). The result is a fully
# populated, "live"-looking environment you can open in the dashboard.
#
# Usage:
#   scripts/dev-sandbox.sh             # build, launch, seed, keep running (Ctrl-C stops)
#   AGENTS=3 scripts/dev-sandbox.sh    # 3 agents
#   PORT=9000 scripts/dev-sandbox.sh   # orchestrator on :9000
#   KEEP=0 scripts/dev-sandbox.sh      # tear everything down once seeded (smoke test)
#   PROFILE=live scripts/dev-sandbox.sh  # agents run a REAL Caddy on loopback ports
#
# Live profile (PROFILE=live, #96): the orchestrator stays dry (no external DNS
# or ACME), but each agent runs a real Caddy bound to 127.0.0.1 on unprivileged
# ports and proxies to a small fake upstream the script starts, so real HTTP and
# TLS flow end to end. Needs a caddy binary (CADDY_BIN or PATH); no root.
#
# Env knobs:
#   PORT      orchestrator HTTP port            (default 8099)
#   AGENTS    number of agents                  (default 1)
#   WORKDIR   sandbox data/log directory        (default ./.dev-sandbox)
#   ORCH_BIN  orchestrator binary               (default ./nurproxy, falls back to ./nurproxy-headless)
#   AGENT_BIN agent binary                      (default ./nurproxy-agent)
#   PASSWORD  admin password (min 8 chars)      (default sandbox123)
#   KEEP      1 = keep running, 0 = exit + tear down after seeding (default 1)
#   PROFILE   dry (proxy simulated in memory) | live (real Caddy)   (default dry)
# Live profile only (agent n adds 10*(n-1) to each Caddy port):
#   CADDY_BIN      caddy binary                 (default: caddy on PATH)
#   UPSTREAM_BIN   fake upstream binary         (default ./nurproxy-sandbox-upstream)
#   HTTP_PORT      Caddy plain HTTP port        (default 18080)
#   HTTPS_PORT     Caddy HTTPS port             (default 18443)
#   ADMIN_PORT     Caddy admin API port         (default 12019)
#   UPSTREAM_PORT  fake upstream port           (default 18081)
#   LISTEN_HOST    address Caddy binds          (default 127.0.0.1)
set -euo pipefail

PORT="${PORT:-8099}"
AGENTS="${AGENTS:-1}"
WORKDIR="${WORKDIR:-$(pwd)/.dev-sandbox}"
PASSWORD="${PASSWORD:-sandbox123}"
KEEP="${KEEP:-1}"
BASE="http://localhost:${PORT}"
ZONE="${ZONE:-sandbox.test}"
PROFILE="${PROFILE:-dry}"

ORCH_BIN="${ORCH_BIN:-}"
AGENT_BIN="${AGENT_BIN:-./nurproxy-agent}"

HTTP_PORT="${HTTP_PORT:-18080}"
HTTPS_PORT="${HTTPS_PORT:-18443}"
ADMIN_PORT="${ADMIN_PORT:-12019}"
UPSTREAM_PORT="${UPSTREAM_PORT:-18081}"
LISTEN_HOST="${LISTEN_HOST:-127.0.0.1}"
UPSTREAM_BIN="${UPSTREAM_BIN:-./nurproxy-sandbox-upstream}"
CADDY_BIN="${CADDY_BIN:-}"

case "$PROFILE" in
  dry|live) : ;;
  *) echo "error: PROFILE must be dry or live (got '$PROFILE')" >&2; exit 1 ;;
esac

PIDS=()
cleanup() {
  echo
  echo "--> stopping sandbox..."
  # SIGTERM first: a live agent stops its own Caddy on shutdown.
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [[ "$PROFILE" == "live" ]]; then
    # Backstop: no Caddy may outlive the sandbox, even if an agent died first.
    for n in $(seq 1 "$AGENTS"); do
      curl -fsS -X POST "http://127.0.0.1:$((ADMIN_PORT + (n - 1) * 10))/stop" >/dev/null 2>&1 || true
    done
  fi
  echo "--> sandbox stopped (data left in ${WORKDIR})"
}
trap cleanup EXIT

# --- resolve binaries -------------------------------------------------------
if [[ -z "$ORCH_BIN" ]]; then
  if [[ -x ./nurproxy ]]; then ORCH_BIN=./nurproxy
  elif [[ -x ./nurproxy-headless ]]; then ORCH_BIN=./nurproxy-headless
  else echo "error: no orchestrator binary (build with 'make build' or 'make build-headless')" >&2; exit 1
  fi
fi
[[ -x "$AGENT_BIN" ]] || { echo "error: agent binary $AGENT_BIN missing (build with 'make build-agent')" >&2; exit 1; }

port_free() { # port_free PORT — true when nothing accepts connections on 127.0.0.1:PORT
  ! (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

if [[ "$PROFILE" == "live" ]]; then
  if [[ -z "$CADDY_BIN" ]]; then CADDY_BIN=$(command -v caddy || true); fi
  [[ -n "$CADDY_BIN" && -x "$CADDY_BIN" ]] || {
    echo "error: PROFILE=live needs a caddy binary (set CADDY_BIN or put caddy on PATH)" >&2; exit 1; }
  [[ -x "$UPSTREAM_BIN" ]] || {
    echo "error: fake upstream $UPSTREAM_BIN missing (build with 'make build-sandbox-upstream')" >&2; exit 1; }
  CADDY_BIN=$(cd "$(dirname "$CADDY_BIN")" && pwd)/$(basename "$CADDY_BIN")
  ports=("$UPSTREAM_PORT")
  for n in $(seq 1 "$AGENTS"); do
    off=$(((n - 1) * 10))
    ports+=("$((HTTP_PORT + off))" "$((HTTPS_PORT + off))" "$((ADMIN_PORT + off))")
  done
  for p in "${ports[@]}"; do
    if (( p < 1024 )); then echo "error: port $p is privileged; the live sandbox runs unprivileged" >&2; exit 1; fi
    port_free "$p" || { echo "error: port $p is already in use" >&2; exit 1; }
  done
fi

# Guard the rm -rf: WORKDIR is env-overridable, so refuse to wipe anything that
# doesn't look like a sandbox dir — either its basename starts with .dev-sandbox
# (the default) or it carries the marker file a previous run left behind.
MARKER=".nurproxy-dev-sandbox"
if [[ -e "$WORKDIR" ]]; then
  case "$(basename "$WORKDIR")" in
    .dev-sandbox*) : ;;
    *)
      if [[ ! -e "$WORKDIR/$MARKER" ]]; then
        echo "error: refusing to rm -rf $WORKDIR — not a sandbox directory" >&2
        echo "       (expected a basename starting with .dev-sandbox, or a $MARKER marker file from a previous run)" >&2
        exit 1
      fi
      ;;
  esac
fi

rm -rf "$WORKDIR"; mkdir -p "$WORKDIR/orch"
touch "$WORKDIR/$MARKER"
echo "==> NurProxy dev sandbox (profile=$PROFILE) — orchestrator=$ORCH_BIN agent=$AGENT_BIN"

api() { # api METHOD PATH [JSON]
  local method=$1 path=$2 body=${3:-}
  curl -fsS -X "$method" \
    -H "Authorization: Bearer ${API_KEY:-}" -H 'Content-Type: application/json' \
    ${body:+-d "$body"} "${BASE}${path}"
}

jget() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }

wait_for() { # wait_for URL DESC
  # A fresh-DB cold boot runs every migration before /health answers; on a slow
  # disk that is tens of seconds, so wait up to ~60s (300 * 0.2s) rather than 10s.
  local url=$1 desc=$2
  for _ in $(seq 1 300); do curl -fsS "$url" >/dev/null 2>&1 && return 0; sleep 0.2; done
  echo "error: timed out waiting for $desc ($url)" >&2; return 1
}

# --- orchestrator -----------------------------------------------------------
echo "--> starting dry-run orchestrator on :${PORT}"
NP_DRY_RUN=true "$ORCH_BIN" -port "$PORT" -data-dir "$WORKDIR/orch" >"$WORKDIR/orch.log" 2>&1 &
PIDS+=($!)
wait_for "${BASE}/api/v1/health" "orchestrator"

export NP_API_URL="$BASE"
# The workdir is wiped on every run, so the DB is always fresh — auth setup
# must succeed. Capture its output and surface it on failure instead of masking
# the real error behind an eventual empty API_KEY.
if ! setup_out=$("$ORCH_BIN" auth setup --password "$PASSWORD" 2>&1); then
  echo "error: auth setup failed:" >&2
  echo "$setup_out" >&2
  cat "$WORKDIR/orch.log" >&2
  exit 1
fi
API_KEY=$("$ORCH_BIN" apikey create --password "$PASSWORD" 2>&1 | grep -oE 'np_ak_[a-f0-9]+' | head -1)
[[ -n "$API_KEY" ]] || { echo "error: could not create API key" >&2; cat "$WORKDIR/orch.log" >&2; exit 1; }
export API_KEY
echo "    API key: ${API_KEY:0:14}…"

# --- provider + zone (dummy creds; dry-run mocks validation) ----------------
echo "--> seeding provider (dummy token) + zone ${ZONE}"
PROVIDER_ID=$(api POST /api/v1/providers '{"type":"cloudflare","name":"CF-dry","config":{"api_token":"dummy-dry-token"}}' | jget "d['id']")
ZONE_ID=$(api POST /api/v1/zones "{\"provider_id\":\"$PROVIDER_ID\",\"name\":\"$ZONE\"}" | jget "d['id']")
echo "    provider=$PROVIDER_ID zone=$ZONE_ID ($ZONE)"

# --- server discovery source (dry-run returns a fixed Proxmox cluster) -------
echo "--> seeding Proxmox discovery source (dry-run fixture)"
SOURCE_ID=$(api POST /api/v1/discovery/sources '{"type":"proxmox","name":"pve-dry","config":{"url":"https://pve.sandbox.test:8006","token_id":"nurproxy@pve!dry","token_secret":"dummy-dry-secret","verify_tls":true}}' | jget "d['id']")
api POST "/api/v1/discovery/sources/${SOURCE_ID}/run" >/dev/null
echo "    discovery source=$SOURCE_ID (Servers → Discover from Proxmox VE)"
# --- live profile: fake upstream + caddy on the agents' PATH -----------------
server_body='{"name":"app","address":"10.0.0.5:8080"}'
domain_port=8080
domain_extra=''
if [[ "$PROFILE" == "live" ]]; then
  mkdir -p "$WORKDIR/bin"
  # The agent looks Caddy up as "caddy" on PATH, whatever CADDY_BIN is called.
  ln -sf "$CADDY_BIN" "$WORKDIR/bin/caddy"
  echo "--> starting fake upstream on 127.0.0.1:${UPSTREAM_PORT} (caddy: $CADDY_BIN)"
  "$UPSTREAM_BIN" -listen "127.0.0.1:${UPSTREAM_PORT}" -name app >"$WORKDIR/upstream.log" 2>&1 &
  PIDS+=($!)
  wait_for "http://127.0.0.1:${UPSTREAM_PORT}/" "fake upstream"
  server_body='{"name":"app","address":"127.0.0.1"}'
  domain_port=$UPSTREAM_PORT
  domain_extra=',"proxy_config":{"force_https":true}'
fi

# --- agents -----------------------------------------------------------------
for n in $(seq 1 "$AGENTS"); do
  fqdn="edge${n}.${ZONE}"
  apiport=$((8780 + n))
  ddir="$WORKDIR/agent${n}"
  mkdir -p "$ddir"
  if [[ "$PROFILE" == "live" ]]; then
    off=$(((n - 1) * 10))
    echo "--> starting live agent ${n}: ${fqdn} (api :${apiport}, caddy ${LISTEN_HOST}:$((HTTP_PORT + off))/$((HTTPS_PORT + off)), admin :$((ADMIN_PORT + off)))"
    # Caddy's own state (autosave, storage) goes into the agent's data dir.
    PATH="$WORKDIR/bin:$PATH" HOME="$ddir/caddy-home" \
      XDG_DATA_HOME="$ddir/caddy-home/data" XDG_CONFIG_HOME="$ddir/caddy-home/config" \
      "$AGENT_BIN" -orchestrator "$BASE" -fqdn "$fqdn" -api-port "$apiport" -data-dir "$ddir" \
      -caddy-admin-port "$((ADMIN_PORT + off))" -caddy-listen-host "$LISTEN_HOST" \
      -caddy-http-port "$((HTTP_PORT + off))" -caddy-https-port "$((HTTPS_PORT + off))" \
      >"$WORKDIR/agent${n}.log" 2>&1 &
  else
    echo "--> starting dry-run agent ${n}: ${fqdn} (api :${apiport})"
    "$AGENT_BIN" -dry-run -orchestrator "$BASE" -fqdn "$fqdn" -api-port "$apiport" -data-dir "$ddir" \
      >"$WORKDIR/agent${n}.log" 2>&1 &
  fi
  PIDS+=($!)

  # wait for the agent to register, then adopt it onto the zone
  agent_id=""
  for _ in $(seq 1 50); do
    agent_id=$(api GET /api/v1/agents | jget "next((a['id'] for a in d if a['fqdn']=='$fqdn'), '')" 2>/dev/null || echo "")
    [[ -n "$agent_id" ]] && break; sleep 0.2
  done
  [[ -n "$agent_id" ]] || { echo "error: agent ${fqdn} never registered" >&2; cat "$WORKDIR/agent${n}.log" >&2; exit 1; }
  api PUT "/api/v1/agents/${agent_id}/adopt" "{\"name\":\"edge${n}\",\"zone_ids\":[\"$ZONE_ID\"]}" >/dev/null
  echo "    adopted ${agent_id}"

  # server + central-TLS domain → triggers simulated DNS-01 issuance + route push.
  # Each agent gets a unique subdomain (app${n}) so multi-agent runs don't collide
  # on the same FQDN.
  sub="app${n}"
  server_id=$(api POST "/api/v1/agents/${agent_id}/servers" "$server_body" | jget "d['id']")
  api POST /api/v1/domains \
    "{\"subdomain\":\"$sub\",\"zone_id\":\"$ZONE_ID\",\"server_id\":\"$server_id\",\"port\":${domain_port},\"ssl_mode\":\"central\"${domain_extra}}" >/dev/null
  echo "    domain ${sub}.${ZONE} → server ${server_id} (central TLS)"
done

# --- wait for convergence ---------------------------------------------------
echo "--> waiting for domains to converge..."
for _ in $(seq 1 50); do
  active=$(api GET /api/v1/domains | jget "sum(1 for x in d if x['status']=='active')" 2>/dev/null || echo 0)
  [[ "$active" -ge "$AGENTS" ]] && break; sleep 0.4
done

served=0
if [[ "$PROFILE" == "live" ]]; then
  # Real traffic: each app<n> must answer through its agent's Caddy with the
  # fake upstream's body over HTTPS, and redirect plain HTTP.
  echo "--> checking real traffic through Caddy..."
  for n in $(seq 1 "$AGENTS"); do
    off=$(((n - 1) * 10)); host="app${n}.${ZONE}"
    hs=$((HTTPS_PORT + off)); hp=$((HTTP_PORT + off))
    ok=0
    for _ in $(seq 1 150); do
      if curl -fsS -k --max-time 3 --resolve "${host}:${hs}:${LISTEN_HOST}" "https://${host}:${hs}/" 2>/dev/null \
        | grep -q nurproxy-sandbox-upstream; then ok=1; break; fi
      sleep 0.4
    done
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 --resolve "${host}:${hp}:${LISTEN_HOST}" "http://${host}:${hp}/" || true)
    if [[ "$ok" == 1 && "$code" == 30? ]]; then
      served=$((served + 1)); echo "    ${host}: HTTPS → upstream ok, HTTP → ${code}"
    else
      echo "    ${host}: NOT serving (https ok=${ok}, http status ${code}) — see ${WORKDIR}/agent${n}.log" >&2
    fi
  done
fi

echo
echo "===================================================================="
if [[ "$PROFILE" == "live" ]]; then
  echo " NurProxy dev sandbox is UP (live — real Caddy, dry DNS/ACME)"
else
  echo " NurProxy dev sandbox is UP (dry-run — no external DNS/ACME calls)"
fi
echo "   Dashboard / API : ${BASE}"
if [[ "$PROFILE" == "live" ]]; then
  echo "   Agents          : ${AGENTS} (real Caddy on ${LISTEN_HOST}, fake upstream :${UPSTREAM_PORT})"
else
  echo "   Agents          : ${AGENTS} (dry-run, in-memory proxy)"
fi
echo "   Domains active  : ${active:-0}/${AGENTS}"
if [[ "$PROFILE" == "live" ]]; then
  echo "   Serving traffic : ${served}/${AGENTS}"
  echo "   Try             : curl -k --resolve app1.${ZONE}:${HTTPS_PORT}:${LISTEN_HOST} https://app1.${ZONE}:${HTTPS_PORT}/"
fi
echo "   Logs            : ${WORKDIR}/{orch,agent*}.log"
echo "===================================================================="
api GET /api/v1/audit-log'?limit=6' | jget "'\n'.join('   audit  %-18s source=%-7s %s' % (e['action'], e['source'], e['details'][:46]) for e in d.get('entries', []))" 2>/dev/null || true
echo

if [[ "$KEEP" == "0" ]]; then
  echo "--> KEEP=0: seeded, tearing down."
  if [[ "$PROFILE" == "live" && "$served" -lt "$AGENTS" ]]; then
    echo "error: only ${served}/${AGENTS} agents served real traffic" >&2
    exit 1
  fi
  exit 0
fi
echo "--> running. Press Ctrl-C to stop."
wait
