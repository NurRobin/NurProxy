# Reusable Fixtures & Environment Gotchas

> **Scope:** the shared tooling, copy-paste fixtures and environment traps that every other spec in this book references — how to bring up a dry stack, a mini backend, deterministic serve-direct probes, a throwaway dry orchestrator for the security/ops battery, and the homelab-specific gotchas that have actually wasted hours.
> **Code:** `scripts/dev-sandbox.sh`, `Makefile` (`dev-sandbox`, `test-sandbox`), `test/sandbox/sandbox_test.go` (build tag `sandbox`), `cmd/nurproxy/main.go` (orchestrator flags + `NP_DRY_RUN*`), `cmd/nurproxy-agent/main.go` + `internal/agent/config/config.go` (agent flags + dry data-dir relocation), `internal/shared/logging/logging.go` (`NP_LOG_FORMAT` / `NP_LOG_LEVEL`), `cmd/nurproxy/cli_commands.go` (`auth setup`, `apikey create|revoke`).
> **Coverage legend:** D = coverable dry, R = needs a real run. This is a support file (N/A overall) — every fixture below is reused by the feature specs.

## Prerequisites

- A built tree. Most fixtures need the two binaries: `make build-all` produces `./nurproxy` and `./nurproxy-agent`. `make dev-sandbox` and `make test-sandbox` build what they need themselves (`test-sandbox` builds the **headless** orchestrator + agent — see below).
- `python3` on `PATH` (mini backend, the JSON helpers `dev-sandbox.sh` uses, the bcrypt one-liner — bcrypt also needs `pip install bcrypt`).
- `curl` and `openssl` for the serve-direct probes.
- For anything in the **R** column: a real `caddy` on `PATH` (built-in mode) or a real nginx/apache, a real Cloudflare zone + token, and a host that can bind `:80`/`:443`. None of that is needed for the dry fixtures.
- Work from the repo root (`/home/main/nurproxy`); the `./nurproxy*` relative paths below assume it.

## Features covered

- [ ] Mini echo backend (`python3` on `:18099`, `NURPROXY-E2E-PROOF` marker + echoed headers + path).
- [ ] Serve-direct probes: `curl --resolve` (deterministic client IP, `ssl_verify_result`) and `openssl s_client` (cert subject/issuer).
- [ ] Throwaway dry orchestrator for the security/ops battery (`NP_LOG_FORMAT=json NP_DRY_RUN=true ./nurproxy -port 18081 -data-dir /tmp/np-sec`).
- [ ] `make dev-sandbox` launcher and its knobs (`AGENTS=`, `PORT=`, `KEEP=`, plus `WORKDIR`, `PASSWORD`, `ZONE`, `ORCH_BIN`, `AGENT_BIN`).
- [ ] `test/sandbox` end-to-end assertion (`sandbox` build tag, `make test-sandbox`).
- [ ] Running the binaries dry by hand (orchestrator subsystem split, agent dry data-dir relocation).
- [ ] bcrypt one-liner for `basic_auth`.
- [ ] Per-subsystem dry env vars + ACME failure injection (`NP_DNS_DRY_RUN`, `NP_ACME_DRY_RUN`, `NP_DRY_RUN_FAIL`).
- [ ] Structured logging knobs (`NP_LOG_FORMAT`, `NP_LOG_LEVEL`).
- [ ] API key / auth bootstrap CLI (`auth setup`, `apikey create|show|revoke`).
- [ ] Environment gotchas: Tailscale ACL `:8080` (`HTTP 000`), clock skew, sudo, IPv6 hairpin / v4-mapped AAAA, never two live orchestrators on one tailnet/zone, revoke test API keys.

## Tests

### Mini echo backend

- **Must:** a tiny HTTP backend that returns a fixed marker, the request path, and every request header, so proxy / header-rewrite / path-strip / websocket tests can prove the request actually reached the backend and what it looked like on arrival.
- **Access:** plain `python3`, no NurProxy involvement. Binds `0.0.0.0:18099`.
- **Prerequisites:** `python3`.
- **Steps:** save and run:
  ```python
  # /tmp/np-e2e-service.py — python3, binds 0.0.0.0:18099
  import http.server, socketserver, socket
  M = "NURPROXY-E2E-PROOF"
  class H(http.server.BaseHTTPRequestHandler):
      def do_GET(s):
          hdrs = "".join(f"  {k}: {v}\n" for k, v in s.headers.items())
          b = f"{M}\nserved-by={socket.gethostname()}\npath={s.path}\n{hdrs}".encode()
          s.send_response(200); s.send_header("Content-Length", str(len(b))); s.end_headers(); s.wfile.write(b)
      def log_message(s, *a): pass
  socketserver.TCPServer.allow_reuse_address = True
  socketserver.TCPServer(("0.0.0.0", 18099), H).serve_forever()
  ```
  ```bash
  python3 /tmp/np-e2e-service.py &     # then point a NurProxy server/domain at <host>:18099
  curl -s http://127.0.0.1:18099/some/path   # smoke: prints the marker, path=/some/path, headers
  ```
- **Pass:** `curl` returns `NURPROXY-E2E-PROOF`, `path=/some/path`, and the request headers echoed back. Seeing the marker through a NurProxy route proves end-to-end reachability; the echoed path/headers prove rewrite/header directives.
- **Coverage:** R (used by the real proxy-directive matrix; the dry agent does not proxy real traffic, so the backend is only meaningful behind a real agent).
- **Pitfalls:** `allow_reuse_address` lets you restart it immediately without a `TIME_WAIT` bind error. Only handles `GET`. Port `18099` is arbitrary but consistent across this book — keep it so the directive specs line up. `served-by` lets you tell two backends apart in upstream/multi-server tests.

### Serve-direct probes (deterministic client IP + cert inspection)

- **Must:** reach a specific agent's `:443` directly, bypassing DNS and any edge hop, with a deterministic source IP, and read back both the HTTP result and the TLS verification result / cert identity.
- **Access:** `curl` + `openssl`. No NurProxy flags.
- **Prerequisites:** a real agent serving HTTPS for `<host>` (R). For IP allow/block tests, the agent (or the durox edge) must be reachable by LAN IP.
- **Steps:**
  ```bash
  # HTTP result + TLS verify result, pinned to a specific backend IP (no DNS):
  curl --resolve <host>:443:<agent-ip> https://<host>/ \
       -w "http=%{http_code} sslverify=%{ssl_verify_result}\n"

  # Cert identity actually served for <host>:
  echo | openssl s_client -servername <host> -connect <agent-ip>:443 2>/dev/null \
       | openssl x509 -noout -subject -issuer
  ```
- **Pass:** `http=200` and `sslverify=0` (0 = verified OK) for a real LE chain; `subject`/`issuer` match the host and the expected CA (Let's Encrypt for central TLS, self-signed in dry).
- **Coverage:** R.
- **Pitfalls:**
  - `--resolve` is the only reliable way to fix the **observed client IP** for `ip_allowlist`/`ip_blocklist` tests — the public hairpin path mangles the source address. Drive the edge directly via `--resolve host:443:<durox-LAN>`.
  - `ssl_verify_result` is non-zero against a dry / self-signed cert — that is expected, not a failure, in sandbox. Reserve the `sslverify=0` pass bar for the real-run built-in-Caddy / central-TLS specs.
  - `-servername` is mandatory (SNI); without it the agent can't select the right cert.

### Throwaway dry orchestrator (the security / ops battery)

- **Must:** a fully functional orchestrator that touches nothing external, on a non-default port and a temp data dir, so lockout / rate-limit / body-cap / session-revocation tests can run without locking out prod and without external DNS/ACME.
- **Access:** the `nurproxy` binary with env + flags.
- **Prerequisites:** `make build` (or `build-all`).
- **Steps:**
  ```bash
  NP_LOG_FORMAT=json NP_DRY_RUN=true ./nurproxy -port 18081 -data-dir /tmp/np-sec
  # in another shell, bootstrap auth + a key:
  export NP_API_URL=http://localhost:18081
  ./nurproxy auth setup --password 'sandbox-sec-pass'
  ./nurproxy apikey create --password 'sandbox-sec-pass'   # prints: API key (shown once): np_ak_…
  ```
  Flags are verified at `cmd/nurproxy/main.go:69` (`-data-dir`, default `./data`) and `main.go:70` (`-dry-run`); `NP_DRY_RUN` is read at `main.go:87`. JSON logging at `internal/shared/logging/logging.go:33`.
- **Pass:** `GET http://localhost:18081/api/v1/health` returns `dry_run:true` (and `dns_dry_run`/`acme_dry_run` true); logs are one JSON object per line.
- **Coverage:** D.
- **Pitfalls:**
  - **Run the lockout / register-ratelimit tests against THIS instance, never prod** — they lock the real login/register for ~15 min.
  - Use a port that does not collide with `dev-sandbox` (default `8099`) or a real orchestrator (`8080`). `18081` is the book's convention for the security battery.
  - `/tmp/np-sec` survives between runs; `rm -rf /tmp/np-sec` to start from a clean `setup_required:true` state.

### `make dev-sandbox` launcher (whole stack in one command)

- **Must:** build both binaries, start a dry orchestrator + N dry agents, and seed a working topology (provider with a dummy token → zone → adopted agents → server + central-TLS domain per agent) so the dashboard/API look "live" with zero external calls.
- **Access:** `make dev-sandbox` (which runs `scripts/dev-sandbox.sh` with `ORCH_BIN=./nurproxy AGENT_BIN=./nurproxy-agent`, `Makefile:43-44`).
- **Prerequisites:** `python3` (the script's `jget` helper, `dev-sandbox.sh:69`).
- **Steps & knobs** (defaults from `dev-sandbox.sh:29-38`):
  ```bash
  make dev-sandbox                 # orchestrator on :8099, 1 agent, seeded, stays up (Ctrl-C stops)
  make dev-sandbox AGENTS=3        # 3 dry agents on one box (api ports 8781,8782,8783 — see below)
  PORT=9000 make dev-sandbox       # orchestrator on :9000
  KEEP=0 make dev-sandbox          # seed then tear down (smoke check; exits after convergence)
  ```
  Additional env knobs honoured by the script: `WORKDIR` (data/log dir, default `./.dev-sandbox`), `PASSWORD` (admin pw, min 8, default `sandbox123`), `ZONE` (default `sandbox.test`), `ORCH_BIN` (defaults to `./nurproxy`, falls back to `./nurproxy-headless`, `dev-sandbox.sh:51-56`), `AGENT_BIN` (default `./nurproxy-agent`).
- **Pass:** the banner prints `Domains active : N/N`; `GET http://localhost:8099/api/v1/health` reports dry-run; the audit tail shows entries tagged `source=dryrun` (`dev-sandbox.sh:142`).
- **Coverage:** D.
- **Pitfalls:**
  - **Agent API ports are `8780 + n`** (`dev-sandbox.sh:99`), i.e. agent 1 = `:8781`, agent 2 = `:8782`. They do **not** bind `:80`/`:443` (in-memory proxy), so multiple agents on one host don't collide there — but the `api-port` and the per-FQDN temp data dir are what keep them isolated.
  - Each agent gets a **unique subdomain** `app<n>` (`dev-sandbox.sh:120`) so multi-agent runs don't collide on the same FQDN.
  - The seed creates a Cloudflare provider with token `dummy-dry-token` (`dev-sandbox.sh:92`) — that only works because dry-run mocks provider validation. Don't reuse this flow against a non-dry orchestrator.
  - Data is left in `WORKDIR` on exit (`dev-sandbox.sh:46`); `rm -rf ./.dev-sandbox` between runs if you want a clean slate (the script `rm -rf`s it on start anyway, `dev-sandbox.sh:59`).

### `test/sandbox` end-to-end assertion (`make test-sandbox`)

- **Must:** the durable, asserted counterpart of `dev-sandbox.sh` — boots a dry orchestrator + dry agent as subprocesses, drives the public REST API through provider → zone → adopt → server → central-TLS domain, and asserts the control plane converges (domain active, cert issued, DNS records simulated, audit tagged `source=dryrun`) with no external deps.
- **Access:** `make test-sandbox` (`Makefile:28-29`).
- **Prerequisites:** Go toolchain. The target builds the **headless** orchestrator (`build-headless`) + agent first, then runs `go test -count=1 -tags=sandbox -timeout=180s ./test/sandbox/...`.
- **Steps:**
  ```bash
  make test-sandbox
  ```
  The test asserts `health["dry_run"]`, `dns_dry_run`, `acme_dry_run` are all `true` (`test/sandbox/sandbox_test.go:51-54`) before proceeding.
- **Pass:** test passes within 180 s; it is also wired into CI on every push/PR.
- **Coverage:** D.
- **Pitfalls:**
  - It is gated behind the `sandbox` build tag (`//go:build sandbox`, file header) so it never runs in the normal `make test` pass — you must use `make test-sandbox` (or `-tags=sandbox`).
  - It uses the **headless** binary (no embedded dashboard); if you only `make build` the dashboard-embedding orchestrator, `make test-sandbox` still rebuilds the headless one itself.
  - 180 s timeout covers reconcile cycles; a hang past that is a real convergence regression, not slowness.

### Running the binaries dry by hand

- **Must:** developers can run each subsystem dry, in any combination, to isolate DNS vs ACME behaviour and inject ACME failures, and run many dry agents on one box without privileges or port conflicts.
- **Access:** orchestrator + agent flags and env vars.
- **Prerequisites:** `make build-all`.
- **Steps:**
  ```bash
  # Orchestrator — full dry, or per-subsystem (verified cmd/nurproxy/main.go:87-90):
  NP_DRY_RUN=true ./nurproxy                 # mock DNS + ACME   (or: ./nurproxy -dry-run)
  NP_DNS_DRY_RUN=true ./nurproxy             # mock DNS, real ACME
  NP_ACME_DRY_RUN=true ./nurproxy            # real DNS, mock ACME
  NP_ACME_DRY_RUN=true NP_DRY_RUN_FAIL=ratelimit ./nurproxy   # inject ACME failure:
                                             #   ratelimit | challenge | propagation

  # Agent — proxy simulated in-memory (cmd/nurproxy-agent/main.go:48, :53):
  NP_DRY_RUN=true ./nurproxy-agent -orchestrator http://localhost:8080 -fqdn edge1.example.com
  # (or pass -dry-run). proxy-mode defaults to built-in; "existing" is the other value.
  ```
  - Per-subsystem env: `NP_DNS_DRY_RUN` / `NP_ACME_DRY_RUN` each default to the global `NP_DRY_RUN` flag (`main.go:88-89`), so you can flip just one. `NP_DRY_RUN_FAIL` is read at `main.go:90`.
  - Agent flags (`cmd/nurproxy-agent/main.go`): `-data-dir` (default `/var/lib/nurproxy-agent`, `:44`), `-api-port` (default `8780`, `:45`), `-caddy-admin-port` (default `2019`, `:46`), `-dry-run` (`:48`), `-proxy-mode` (`built-in` default | `existing`, `:53`).
- **Pass:** orchestrator `/api/v1/health` reflects exactly the subsystems you turned dry; the agent prints the `DRY-RUN: proxy simulated in-memory` banner (`cmd/nurproxy-agent/main.go:123`) and never binds `:80`/`:443`.
- **Coverage:** D.
- **Pitfalls:**
  - **Dry-agent data-dir auto-relocation:** in dry-run, if you did **not** pin `-data-dir` / `NP_DATA_DIR`, the agent relocates from the privileged default to `${TMPDIR}/nurproxy-agent-dry-<sanitized-fqdn>` (`internal/agent/config/config.go:120-121,270-275`). This is per-FQDN, so several dry agents on one host stay isolated (separate token/identity/cert store) and stable across restarts. An empty FQDN falls back to the shared `nurproxy-agent-dry`. If you **do** pass `-data-dir`, it is used as-is even in dry-run.
  - **`NP_DNS_DRY_RUN` + real ACME always fails DNS-01** — the mock DNS never publishes the challenge TXT. To exercise ACME dry, use full `NP_DRY_RUN` or `NP_ACME_DRY_RUN`, not `NP_DNS_DRY_RUN`.
  - `NP_DRY_RUN_FAIL` only has meaning when ACME is dry (it's an injected ACME failure); accepted values are `ratelimit`, `challenge`, `propagation`.

### Structured logging knobs

- **Must:** the same binary can log human text or machine JSON, at a chosen level, without a rebuild, for both orchestrator and agent.
- **Access:** env vars only (`internal/shared/logging/logging.go`).
- **Steps:**
  ```bash
  NP_LOG_FORMAT=json ./nurproxy ...     # JSON lines (default: text)   logging.go:33-34
  NP_LOG_LEVEL=debug ./nurproxy ...     # debug|info|warn|error (default: info)  logging.go:30,levelFromEnv
  ```
- **Pass:** with `NP_LOG_FORMAT=json` every line is a parseable JSON object carrying a `component` attribute (`orchestrator`/`agent`); `NP_LOG_LEVEL` filters below the chosen level. Note legacy `log.Printf` output is routed through slog too, so it also picks up the format/level.
- **Coverage:** D.
- **Pitfalls:** logs go to **stderr**, not stdout — redirect `2>` when capturing. Unrecognized `NP_LOG_FORMAT` falls back to text (default branch); unrecognized `NP_LOG_LEVEL` falls back to info.

### API key / auth bootstrap CLI

- **Must:** stand up auth and mint/revoke an admin API key with nothing but the binary, so any scripted test can authenticate.
- **Access:** CLI (`cmd/nurproxy/cli_commands.go`) + REST (`internal/orchestrator/api/server.go:225-227`).
- **Steps:**
  ```bash
  export NP_API_URL=http://localhost:18081       # or whatever port the instance is on
  ./nurproxy auth setup --password '<pw>'         # bootstrap admin pw (no creds needed)  cli_commands.go:488
  ./nurproxy auth status                          # setup_required true/false             cli_commands.go:503
  ./nurproxy apikey create --password '<pw>'      # POST /api/v1/api-key → np_ak_… (shown once)  cli_commands.go:463-468
  ./nurproxy apikey show                           # GET  /api/v1/api-key                  cli_commands.go:455
  ./nurproxy apikey revoke                          # DELETE /api/v1/api-key                 cli_commands.go:471-472
  ```
  REST surface: `GET/POST/DELETE /api/v1/api-key` (`server.go:225-227`).
- **Pass:** `apikey create` prints `API key (shown once): np_ak_…`; that key authenticates as `Authorization: Bearer np_ak_…`; `apikey revoke` (DELETE) invalidates it.
- **Coverage:** D.
- **Pitfalls:**
  - `--password` (or `NP_API_PASSWORD`) is **required** for `auth setup` and `apikey create` (`cli_commands.go:494`).
  - The key is shown **once** — capture it. The `dev-sandbox.sh` pattern greps it: `... apikey create --password "$PASSWORD" | grep -oE 'np_ak_[a-f0-9]+'` (`dev-sandbox.sh:85`).
  - **Revoke test keys when done** (`apikey revoke` / `DELETE /api/v1/api-key`) — they end up in transcripts.

### bcrypt one-liner (for `basic_auth`)

- **Must:** the `basic_auth` proxy directive stores a **bcrypt hash**, not a plaintext password — you need a hash to test it.
- **Access:** any bcrypt tool; the book uses Python.
- **Steps:**
  ```bash
  python3 -c 'import bcrypt;print(bcrypt.hashpw(b"pw",bcrypt.gensalt()).decode())'
  # → $2b$12$… — use as the basic_auth password value
  ```
- **Pass:** a `$2a$`/`$2b$` string; configuring it on a domain produces an htpasswd entry and `curl -u user:pw` succeeds while a wrong password gets 401.
- **Coverage:** R (behaviour) — needs `pip install bcrypt`.
- **Pitfalls:** putting a **plaintext** password in the `basic_auth` field will not authenticate — it must be a bcrypt hash. Quote the hash in shells (`$` is special).

### Environment gotchas (homelab specifics — generalise as needed)

- **Must:** known traps that produce confusing-but-benign symptoms; recognise them instead of chasing ghosts.
- **Coverage:** N/A (operational knowledge).
- **The traps:**
  - **Tailscale ACL ports — `HTTP 000`:** the orchestrator API is `:8080`, which must be explicitly allowed in the Tailscale ACL for a node to reach it over the tailnet (the default grant is `22/80/443` only). Same-`/24` LAN bypasses the ACL. Symptom of a blocked port: `curl … :8080` returns `HTTP 000` (connection never established), not a 4xx. (The dry security instance uses `:18081`, also subject to the ACL over Tailscale; reach it via localhost/LAN.)
  - **Clock skew in logs:** the orchestrator (apps-vm) logs **UTC** (`…Z`); agents may log **local** (`+02:00`). Convert before grepping `--since` windows or you'll get empty results that look like "nothing happened".
  - **sudo:** apps-vm is NOPASSWD; durox has passwordless sudo configured. A **password-prompting** host can't be driven non-interactively — run the privileged block over an interactive TTY, e.g. `ssh -t <host> sudo …`.
  - **IPv6 self-tests are flaky from inside:** a host curling its **own** public IPv6 (hairpin) often fails, and `systemd-resolved` may hand back a **v4-mapped** address for an `AAAA` query. Prove external IPv6 from a **different** v6-capable host using `--resolve` to the real `AAAA`, and trust the **authoritative** DNS, not the local resolver.
  - **Never run two live orchestrators on one tailnet/zone:** a restore-verification or a second instance pointed at the same Cloudflare zone + agents will fight over the same DNS records and adoptions. Always restore-verify in **dry** (`NP_DRY_RUN`). The dry fixtures here are safe precisely because they never touch the real zone.
  - **Revoke test API keys when done:** `nurproxy apikey revoke` (or `DELETE /api/v1/api-key`) — keys generated for a test end up in transcripts.

## Acceptance checklist

**Dry (every RC) — these fixtures must work for the rest of the book to be runnable:**
- [ ] `make build-all` produces `./nurproxy` + `./nurproxy-agent`.
- [ ] `make dev-sandbox` comes up: banner shows `Domains active : N/N`, health reports dry-run, audit tail tagged `source=dryrun`.
- [ ] `make dev-sandbox AGENTS=3` brings up 3 isolated dry agents (api ports `8781-8783`, distinct `app1/2/3` subdomains).
- [ ] `KEEP=0 make dev-sandbox` seeds and tears down cleanly.
- [ ] `make test-sandbox` is green.
- [ ] Throwaway dry orchestrator on `:18081` (`/tmp/np-sec`) boots, `auth setup` + `apikey create` yield a working `np_ak_…` key.
- [ ] `NP_LOG_FORMAT=json` emits parseable JSON lines on stderr; `NP_LOG_LEVEL` filters.
- [ ] Dry agent without `-data-dir` relocates to `${TMPDIR}/nurproxy-agent-dry-<fqdn>`.
- [ ] bcrypt one-liner produces a `$2b$…` hash (`pip install bcrypt`).

**Real run (before final):**
- [ ] Mini echo backend reachable through a real agent route (marker + path + headers echoed).
- [ ] `curl --resolve` serve-direct probe returns `http=200 sslverify=0` against a real LE cert.
- [ ] `openssl s_client` shows the expected LE subject/issuer for the host.

**Always:**
- [ ] Test API keys revoked at the end of the session.
- [ ] No second live orchestrator ever pointed at the prod tailnet/zone during testing.
