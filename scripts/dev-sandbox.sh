#!/usr/bin/env bash
#
# dev-sandbox.sh — bring up a complete NurProxy stack in dry-run / sandbox mode
# (#93) and seed it with a working topology, so the whole control plane runs
# locally with NO external DNS or ACME calls and NO privileges.
#
# It starts a dry-run orchestrator + N dry-run agents, then seeds a provider
# (dummy token), a zone, and one server + central-TLS domain per agent. The
# orchestrator simulates every DNS/ACME call; the agents simulate their reverse
# proxy in memory (no Caddy process, no :80/:443). The result is a fully
# populated, "live"-looking environment you can open in the dashboard.
#
# Usage:
#   scripts/dev-sandbox.sh             # build, launch, seed, keep running (Ctrl-C stops)
#   AGENTS=3 scripts/dev-sandbox.sh    # 3 agents
#   PORT=9000 scripts/dev-sandbox.sh   # orchestrator on :9000
#   KEEP=0 scripts/dev-sandbox.sh      # tear everything down once seeded (smoke test)
#
# Env knobs:
#   PORT      orchestrator HTTP port            (default 8099)
#   AGENTS    number of dry-run agents          (default 1)
#   WORKDIR   sandbox data/log directory        (default ./.dev-sandbox)
#   ORCH_BIN  orchestrator binary               (default ./nurproxy, falls back to ./nurproxy-headless)
#   AGENT_BIN agent binary                      (default ./nurproxy-agent)
#   PASSWORD  admin password (min 8 chars)      (default sandbox123)
#   KEEP      1 = keep running, 0 = exit + tear down after seeding (default 1)
set -euo pipefail

PORT="${PORT:-8099}"
AGENTS="${AGENTS:-1}"
WORKDIR="${WORKDIR:-$(pwd)/.dev-sandbox}"
PASSWORD="${PASSWORD:-sandbox123}"
KEEP="${KEEP:-1}"
BASE="http://localhost:${PORT}"
ZONE="${ZONE:-sandbox.test}"

ORCH_BIN="${ORCH_BIN:-}"
AGENT_BIN="${AGENT_BIN:-./nurproxy-agent}"

PIDS=()
cleanup() {
  echo
  echo "--> stopping sandbox..."
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
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

rm -rf "$WORKDIR"; mkdir -p "$WORKDIR/orch"
echo "==> NurProxy dev sandbox (dry-run) — orchestrator=$ORCH_BIN agent=$AGENT_BIN"

api() { # api METHOD PATH [JSON]
  local method=$1 path=$2 body=${3:-}
  curl -fsS -X "$method" \
    -H "Authorization: Bearer ${API_KEY:-}" -H 'Content-Type: application/json' \
    ${body:+-d "$body"} "${BASE}${path}"
}

jget() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }

wait_for() { # wait_for URL DESC
  local url=$1 desc=$2 i
  for i in $(seq 1 50); do curl -fsS "$url" >/dev/null 2>&1 && return 0; sleep 0.2; done
  echo "error: timed out waiting for $desc ($url)" >&2; return 1
}

# --- orchestrator -----------------------------------------------------------
echo "--> starting dry-run orchestrator on :${PORT}"
NP_DRY_RUN=true "$ORCH_BIN" -port "$PORT" -data-dir "$WORKDIR/orch" >"$WORKDIR/orch.log" 2>&1 &
PIDS+=($!)
wait_for "${BASE}/api/v1/health" "orchestrator"

export NP_API_URL="$BASE"
"$ORCH_BIN" auth setup --password "$PASSWORD" >/dev/null 2>&1 || true
API_KEY=$("$ORCH_BIN" apikey create --password "$PASSWORD" 2>&1 | grep -oE 'np_ak_[a-f0-9]+' | head -1)
[[ -n "$API_KEY" ]] || { echo "error: could not create API key" >&2; cat "$WORKDIR/orch.log" >&2; exit 1; }
export API_KEY
echo "    API key: ${API_KEY:0:14}…"

# --- provider + zone (dummy creds; dry-run mocks validation) ----------------
echo "--> seeding provider (dummy token) + zone ${ZONE}"
PROVIDER_ID=$(api POST /api/v1/providers '{"type":"cloudflare","name":"CF-dry","config":{"api_token":"dummy-dry-token"}}' | jget "d['id']")
ZONE_ID=$(api POST /api/v1/zones "{\"provider_id\":\"$PROVIDER_ID\",\"name\":\"$ZONE\"}" | jget "d['id']")
echo "    provider=$PROVIDER_ID zone=$ZONE_ID ($ZONE)"

# --- agents -----------------------------------------------------------------
for n in $(seq 1 "$AGENTS"); do
  fqdn="edge${n}.${ZONE}"
  apiport=$((8780 + n))
  ddir="$WORKDIR/agent${n}"
  mkdir -p "$ddir"
  echo "--> starting dry-run agent ${n}: ${fqdn} (api :${apiport})"
  "$AGENT_BIN" -dry-run -orchestrator "$BASE" -fqdn "$fqdn" -api-port "$apiport" -data-dir "$ddir" \
    >"$WORKDIR/agent${n}.log" 2>&1 &
  PIDS+=($!)

  # wait for the agent to register, then adopt it onto the zone
  agent_id=""
  for i in $(seq 1 50); do
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
  server_id=$(api POST "/api/v1/agents/${agent_id}/servers" '{"name":"app","address":"10.0.0.5:8080"}' | jget "d['id']")
  api POST /api/v1/domains \
    "{\"subdomain\":\"$sub\",\"zone_id\":\"$ZONE_ID\",\"server_id\":\"$server_id\",\"port\":8080,\"ssl_mode\":\"central\"}" >/dev/null
  echo "    domain ${sub}.${ZONE} → server ${server_id} (central TLS)"
done

# --- wait for convergence ---------------------------------------------------
echo "--> waiting for domains to converge..."
for i in $(seq 1 50); do
  active=$(api GET /api/v1/domains | jget "sum(1 for x in d if x['status']=='active')" 2>/dev/null || echo 0)
  [[ "$active" -ge "$AGENTS" ]] && break; sleep 0.4
done

echo
echo "===================================================================="
echo " NurProxy dev sandbox is UP (dry-run — no external DNS/ACME calls)"
echo "   Dashboard / API : ${BASE}"
echo "   Agents          : ${AGENTS} (dry-run, in-memory proxy)"
echo "   Domains active  : ${active:-0}/${AGENTS}"
echo "   Logs            : ${WORKDIR}/{orch,agent*}.log"
echo "===================================================================="
api GET /api/v1/audit-log'?limit=6' | jget "'\n'.join('   audit  %-18s source=%-7s %s' % (e['action'], e['source'], e['details'][:46]) for e in d.get('entries', []))" 2>/dev/null || true
echo

if [[ "$KEEP" == "0" ]]; then
  echo "--> KEEP=0: seeded, tearing down."
  exit 0
fi
echo "--> running. Press Ctrl-C to stop."
wait
