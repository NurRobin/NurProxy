# Installation & Deployment
> **Scope:** building both binaries, getting them onto a host, configuring them (flags / env / config file), the systemd/OS service install, the data-dir layout, and backup/restore — everything up to "the orchestrator and agent are running".
> **Code:** `Makefile`; `cmd/nurproxy/main.go`, `cmd/nurproxy/install.go`, `cmd/nurproxy/backup.go`, `cmd/nurproxy/cli.go`; `cmd/nurproxy-agent/main.go`, `cmd/nurproxy-agent/install.go`, `cmd/nurproxy-agent/setup.go`, `cmd/nurproxy-agent/apply.go`; `internal/agent/config/config.go`, `internal/agent/config/runtime.go`; `internal/shared/install/{install,systemd,manager}.go`; `internal/shared/logging/logging.go`.
> **Coverage legend:** D = coverable dry, R = needs a real run.

## Prerequisites
- Go 1.23+ and a working `go` toolchain (`go build` is invoked by the Makefile).
- Node + npm in PATH (the `build` target runs `web-build` → `npm ci && npm run build` first; `cmd/nurproxy/main.go:163` switches on `web.HasUI`).
- `make`, `git` (the Makefile derives `VERSION` from `git describe`, `Makefile:3`).
- For the service-install tests: a Linux host **with `systemctl`** and **root** (`install.requireRoot()`, `internal/shared/install/manager.go:60`). Without systemctl the install falls back to OpenRC, then a no-op file-layout-only manager (`manager.go:25`).
- For real built-in-Caddy serving: a real `caddy` binary in PATH (the agent `exec.LookPath("caddy")`s it; it is **not** bundled in the agent binary — `internal/agent/caddy/caddy.go:39`). A bare `make build-agent` dev build has no caddy; the package install ships one.
- For dry/sandbox tests: nothing extra — `make dev-sandbox` or `NP_DRY_RUN=true` on the binaries.

## Features covered
- [ ] Build targets: `build`, `build-agent`, `build-headless`, `build-all`, `test`, `test-integration`, `test-e2e`, `test-sandbox`, `test-cover`, `lint`, `lint-fix`, `dev-sandbox`, `dev`, `web-build`, `web-install`, `clean`, `help`.
- [ ] Orchestrator run mode + flags: `-port`, `-data-dir`, `-dry-run`.
- [ ] Orchestrator subcommands: `install`, `uninstall`, `version`, `backup`, `restore` (and the management CLI dispatch: `provider|zone|agent|server|domain|apikey|auth`).
- [ ] Agent run mode + ALL flags: `-orchestrator`, `-fqdn`, `-data-dir`, `-api-port`, `-caddy-admin-port`, `-version`, `-dry-run`, `-proxy-mode`, `-proxy-type`, `-proxy-binary`, `-proxy-config-dir`, `-proxy-reload-cmd`, `-proxy-test-cmd`, `-proxy-log-paths`, `-proxy-service`.
- [ ] Agent subcommands: `install`, `setup`, `uninstall`, `apply`, `version`.
- [ ] Config precedence (flags > env > config file > defaults) and the complete `NP_*` env var table for both binaries.
- [ ] systemd unit contents (hardening, `ReadWritePaths`, `AmbientCapabilities`, `User`, `EnvironmentFile`).
- [ ] Data-dir layout + file modes — orchestrator (`nurproxy.db`, `encryption.key`, `acme-account.key`) and agent (`agent.yaml`, `token`, `agent-id`, `runtime.json`, `certs/`, `cert.key`).
- [ ] Backup / restore round-trip.
- [ ] Structured logging env vars (`NP_LOG_LEVEL`, `NP_LOG_FORMAT`).
- [ ] Packaging note: package install ships a caddy binary; bare dev build does not.
- [ ] Headless build (`build-headless`): no embedded dashboard, API + MCP + CLI only.

## Tests

### Build targets (`make …`)
- **Must:** every target builds/runs cleanly and produces the expected artifact. From `Makefile`:
  - `build` → rebuilds dashboard assets (`web-build`) then `nurproxy` (`Makefile:7`).
  - `build-agent` → `nurproxy-agent` (`Makefile:10`).
  - `build-headless` → `nurproxy-headless` built with `-tags headless` (no embedded UI) (`Makefile:13`).
  - `build-all` → `build` + `build-agent` (`Makefile:16`).
  - `test` → `go test -race -count=1 ./...` (`Makefile:19`).
  - `test-integration` / `test-e2e` → same with `-tags=integration` / `-tags=e2e` (`Makefile:22,25`).
  - `test-sandbox` → builds `build-headless` + `build-agent`, then `go test -count=1 -tags=sandbox -timeout=180s ./test/sandbox/...` (`Makefile:28`). No `-race`.
  - `test-cover` → coverage profile + `coverage.html` (`Makefile:31`).
  - `lint` → `golangci-lint run ./...` (`Makefile:36`).
  - `dev-sandbox` → builds both, runs `scripts/dev-sandbox.sh` with `ORCH_BIN`/`AGENT_BIN` set (`Makefile:43`).
  - `clean` → removes `nurproxy`, `nurproxy-agent`, coverage files, `web/dist` (`Makefile:57`).
  - Frontend/lint helpers (out of the build/deploy path but present): `dev` (dashboard Vite dev server, `Makefile:47`), `web-build` (`npm ci && npm run build`, `Makefile:50`), `web-install` (`npm install`, `Makefile:53`), `lint-fix` (`golangci-lint run --fix`, `Makefile:39`), `help` (default goal, `Makefile:63`).
- **Access:** CLI only (`make <target>`). `VERSION` overridable: `make build VERSION=v1.2.3` (`Makefile:3`). Default goal is `help` (`Makefile:66`).
- **Steps:**
  ```bash
  cd /home/main/nurproxy
  make build-all          # nurproxy + nurproxy-agent
  make build-headless     # nurproxy-headless
  ./nurproxy version      # prints "nurproxy <VERSION>"
  ./nurproxy-agent -version   # prints "nurproxy-agent <VERSION>"
  make test
  make test-sandbox
  make lint
  ```
- **Pass:** binaries exist; `version` prints the git-derived version; `make test`, `make test-sandbox`, `make lint` exit 0.
- **Coverage:** D.
- **Pitfalls:**
  - `build` fails without Node/npm because `web-build` runs first (`Makefile:7,51`). Use `build-agent`/`build-headless` if you only need the non-UI binaries.
  - `test-sandbox` builds the **headless** orchestrator, not the UI one, and runs **without** `-race` (`Makefile:28`).
  - `version` reads `var version = "dev"` overridden via `-ldflags "-X main.version=…"` (`Makefile:4`, `cmd/nurproxy/main.go:33`). A `go build ./cmd/nurproxy` without ldflags reports `dev`.

### Orchestrator run mode & flags (`-port`, `-data-dir`, `-dry-run`)
- **Must:** with no recognized subcommand, the binary runs the server: creates the data dir, loads/generates `encryption.key`, opens `nurproxy.db`, starts the reconciler + TLS renewer + HTTP server on `:<port>` (`cmd/nurproxy/main.go:68-218`).
- **Access:**
  - CLI flags: `-port` (default `8080`, `main.go:68`), `-data-dir` (default `./data`, `main.go:69`), `-dry-run` (default false, `main.go:70`).
  - Env: `NP_PORT`, `NP_DATA_DIR`, `NP_DRY_RUN`, `NP_DNS_DRY_RUN`, `NP_ACME_DRY_RUN`, `NP_DRY_RUN_FAIL` (see env table).
- **Steps:**
  ```bash
  NP_DRY_RUN=true ./nurproxy -port 18080 -data-dir /tmp/np-orch
  # or equivalently:  ./nurproxy -dry-run -port 18080 -data-dir /tmp/np-orch
  curl -s http://localhost:18080/api/v1/health
  ```
- **Pass:** log line `NurProxy <ver> listening on :18080` (`main.go:214`); in dry mode `DRY-RUN MODE: dns=true acme=true …` (`main.go:92`); `/api/v1/health` reports `dry_run`/`dns_dry_run`/`acme_dry_run` flags (set via `srv.SetDryRun`, `main.go:142`). `/tmp/np-orch/nurproxy.db` and `encryption.key` created.
- **Coverage:** D.
- **Pitfalls:**
  - **Env vs flag for `-port`/`-data-dir`:** unlike most code, the orchestrator parses flags **first**, then *overwrites* them from `NP_PORT`/`NP_DATA_DIR` if those env vars are set (`main.go:74-81`). So **env wins over the flag** for these two. This is the opposite of the agent's precedence — do not assume a uniform rule.
  - `-dry-run`/`NP_DRY_RUN` turns on both DNS and ACME sandboxes; `NP_DNS_DRY_RUN`/`NP_ACME_DRY_RUN` override per-subsystem (`main.go:87-89`). `NP_DNS_DRY_RUN=true` with real ACME **always fails DNS-01** (mock DNS never publishes the TXT) — use full `NP_DRY_RUN` or `NP_ACME_DRY_RUN` (RELEASE-QA §1 pitfall, lines 73-74).
  - Don't run two live (non-dry) orchestrators on the same tailnet/zone — they fight over the same Cloudflare zone + agents (RELEASE-QA line 292).

### Orchestrator subcommands (`install`, `uninstall`, `version`)
- **Must:** `install` writes a hardened systemd unit + env file and starts the service; `uninstall` stops/removes it (optionally purging data); `version` prints and exits.
- **Access:** CLI subcommands dispatched in `cmd/nurproxy/main.go:42-65` before flag parsing.
  - `nurproxy install [--port N] [--data-dir DIR] [--user U] [--bin PATH]` (`cmd/nurproxy/install.go:30-41`). Defaults: port `8080`, data-dir `/var/lib/nurproxy`, user `root`, bin = the running executable (`selfPath()`, `install.go:63`).
  - `nurproxy uninstall [--data-dir DIR] [--purge] [--yes]` (`install.go:44-59`). `--purge` removes data dir + config + env file and prompts for confirmation unless `--yes` (`install.go:51`).
  - `nurproxy version` (`main.go:50-52`).
  - Also dispatched here: the management CLI `provider|zone|agent|server|domain|apikey|auth` (`cmd/nurproxy/cli.go:30-50`); any unrecognized first arg falls through to run the server (`main.go:62`).
- **Prerequisites:** root + a Linux host with systemctl for a full install (`requireRoot()`, `manager.go:60`).
- **Steps (real):**
  ```bash
  sudo ./nurproxy install --port 8080 --data-dir /var/lib/nurproxy --user root
  systemctl status nurproxy
  systemctl cat nurproxy
  sudo ./nurproxy uninstall --purge --yes
  ```
- **Pass:** unit written to `/etc/systemd/system/nurproxy.service` (`install.UnitPath()`, `internal/shared/install/install.go:74`); env file `/etc/nurproxy/nurproxy.env` with `NP_PORT` + `NP_DATA_DIR` (`cmd/nurproxy/install.go:21-25`); service enabled + started (`systemd.go:44`); `journalctl -u nurproxy -f` shows the listening line. `uninstall` disables/removes the unit; `--purge` also removes `/var/lib/nurproxy`.
- **Coverage:** R (the render functions `RenderUnit`/`RenderEnv` are unit-tested → D for the unit text).
- **Pitfalls:**
  - The orchestrator unit gets **no** `ReadWritePaths` beyond its data dir and **no** capabilities — only the agent unit does (compare `cmd/nurproxy/install.go:14-27` vs `cmd/nurproxy-agent/install.go:26-37`).
  - `--bin` defaults to the currently-running binary's path (`os.Executable()`); if you install from `/tmp` the unit's `ExecStart` points at `/tmp`. Pass `--bin /usr/local/bin/nurproxy` for a stable path.
  - On a host without systemctl, install silently degrades to OpenRC or "laid out files only" (`manager.go:25,123`); the service is **not** started. Watch the stdout line (`! no supported service manager found — laid out files only.`).

### Orchestrator backup & restore
- **Must:** `backup` writes a gzip tar containing a **consistent** `nurproxy.db` snapshot plus `encryption.key` and `acme-account.key`; `restore` reconstitutes them losslessly into a data dir; a fresh orchestrator boots on the restored dir and can decrypt its secrets.
- **Access:** CLI subcommands (`cmd/nurproxy/main.go:53-58`, `cmd/nurproxy/backup.go`).
  - `nurproxy backup [--data-dir DIR] [-o OUTFILE]` (`backup.go:45-61`). Default outfile `nurproxy-backup-<UTC timestamp>.tar.gz` (`backup.go:54`).
  - `nurproxy restore [--data-dir DIR] [--force] ARCHIVE` (`backup.go:123-140`). Exactly one positional archive arg required (`backup.go:129`).
  - Data-dir resolution for both: flag → `$NP_DATA_DIR` → `./data` (`resolveDataDir`, `backup.go:30-38`).
- **Steps:**
  ```bash
  # Seed a dry orchestrator first (see dev-sandbox), then:
  ./nurproxy backup --data-dir /tmp/np-orch -o /tmp/np.tgz
  sha256sum /tmp/np-orch/encryption.key /tmp/np-orch/acme-account.key
  ./nurproxy restore --data-dir /tmp/np-restored /tmp/np.tgz
  sha256sum /tmp/np-restored/encryption.key /tmp/np-restored/acme-account.key   # must match
  NP_DRY_RUN=true ./nurproxy -port 18099 -data-dir /tmp/np-restored
  curl -s http://localhost:18099/api/v1/health     # database:ok
  ```
- **Pass:** backup printed `Backup written to …`; restore printed `Restored N file(s) into …`; key checksums match the originals; the dry boot reports `database:ok`, `auth/status` `setup_required:false`, reconciler loads domains/agents and reaches the provider (proves decryption works) (RELEASE-QA §2.9, lines 168-180).
- **Coverage:** D (against a dry DB) / R (against a real production DB).
- **Pitfalls:**
  - Archive captures **only** three flat filenames; any other entry (incl. path-traversal `../`) is rejected on restore (`backup.go:167,181`).
  - A keyless backup is near-useless: a missing key file is skipped with a warning, not an error (`backup.go:101-103`) — every provider config + TLS key in the DB is encrypted with `encryption.key`.
  - `restore` refuses to clobber an existing `nurproxy.db` without `--force` (`backup.go:147`).
  - **Never** boot the restored REAL data with a NON-dry orchestrator on the same tailnet — a second live orchestrator fights prod over the same zone + agents. Always restore-verify in **dry** (RELEASE-QA lines 177-180).
  - Backup is safe while live (VACUUM INTO snapshot, `backup.go:80`); for a guaranteed-consistent snapshot, stop the service.

### Agent run mode & flags
- **Must:** the agent loads config (precedence flags > env > file > defaults, `internal/agent/config/config.go:97`), runs adoption, optionally starts the bundled Caddy, starts the local API, opens the orchestrator stream, and heartbeats (`cmd/nurproxy-agent/main.go:63-447`).
- **Access:** CLI flags only at run time (env + `agent.yaml` feed the same `config.Load`). Full flag list (`cmd/nurproxy-agent/main.go:42-61`):

  | Flag | Default | Meaning |
  |---|---|---|
  | `-orchestrator` | "" (required) | Orchestrator URL |
  | `-fqdn` | "" (required) | Agent anchor FQDN |
  | `-data-dir` | `/var/lib/nurproxy-agent` | Data directory |
  | `-api-port` | `8780` | Agent local API port |
  | `-caddy-admin-port` | `2019` | Bundled Caddy admin API port (localhost) |
  | `-version` | false | Print version and exit |
  | `-dry-run` | false | Sandbox: proxy simulated in-memory, no Caddy, no :80/:443, unprivileged |
  | `-proxy-mode` | "" → `built-in` | `built-in` (bundled Caddy) or `existing` |
  | `-proxy-type` | "" | Existing proxy kind: `caddy` \| `nginx` \| `apache` |
  | `-proxy-binary` | "" | Override detected proxy binary path |
  | `-proxy-config-dir` | "" | Override detected config directory |
  | `-proxy-reload-cmd` | "" | Override reload command |
  | `-proxy-test-cmd` | "" | Override config-test command (e.g. `nginx -t`) |
  | `-proxy-log-paths` | "" | Comma-separated log paths to surface |
  | `-proxy-service` | "" | Service unit (systemd/openrc/launchd) used for reloads |

  `proxy_mode` is validated to be exactly `built-in` or `existing` (`config.go:155`); `-proxy-log-paths` is comma-split (`config.go:360`).
- **Steps (dry):**
  ```bash
  NP_DRY_RUN=true ./nurproxy-agent -orchestrator http://localhost:18080 -fqdn edge1.example.com
  ```
- **Pass:** startup banner prints orchestrator/FQDN/data-dir/API-port/Caddy-admin/proxy-mode (`main.go:115-121`); in dry mode `DRY-RUN: proxy simulated in-memory …` (`main.go:123`) and the data dir auto-relocates to a per-FQDN temp dir (`config.go:120-122`, `dryRunDataDir`); agent registers and (after adoption) heartbeats.
- **Coverage:** D (dry) / R (real built-in Caddy or existing nginx/apache).
- **Pitfalls:**
  - `-orchestrator` and `-fqdn` are **required**; missing either is a fatal config error (`config.go:149-153`). The orchestrator URL must be reachable **from the agent host**, not just your browser (`setup.go:94-104`).
  - In dry mode with the **default** data dir, the agent relocates to `$TMPDIR/nurproxy-agent-dry-<fqdn>` so an unprivileged run never hits `/var/lib` and multiple dry agents don't collide (`config.go:111-122,266-276`). An **explicit** `-data-dir`/`NP_DATA_DIR` is always respected (no relocation).
  - No real caddy in PATH ⇒ the agent runs in **mock mode** (no `:443`) even outside dry-run (`internal/agent/caddy/caddy.go:39-41`; `cmd/nurproxy-agent/main.go:227-235` swaps in the mock client). The package install ships a caddy; a bare dev build does not (RELEASE-QA lines 113-115).
  - `existing` mode does **not** start the bundled Caddy (it would fight the host proxy for :80/:443) and honors the persisted mode at startup via the same hot-switch path (`main.go:206,369-381`).

### Agent subcommands (`install`, `setup`, `uninstall`, `apply`) + `-version`
- **Must:**
  - `install` writes `agent.yaml` into the data dir, lays down a hardened unit with proxy `ReadWritePaths` + capabilities, starts it (`cmd/nurproxy-agent/install.go:41-69`).
  - `setup` is the guided one-shot for the two required values; writes an EnvironmentFile (`NP_ORCHESTRATOR`/`NP_FQDN`) and starts the service (`cmd/nurproxy-agent/setup.go`).
  - `uninstall` stops/removes the unit, `--purge` removes data (`install.go:72-87`).
  - `apply <CODE>` claims a pending admin change, persists it to `agent.yaml`, hot-applies it via the local API, prints remediation, acks (`cmd/nurproxy-agent/apply.go:69-237`).
  - `-version` prints and exits (`main.go:89-92`).
- **Access:** CLI subcommands dispatched in `cmd/nurproxy-agent/main.go:70-85`.
  - `nurproxy-agent install --orchestrator URL --fqdn FQDN [--data-dir DIR] [--api-port N] [--caddy-admin-port N] [--user U] [--bin PATH]` (`install.go:42-50`). `--orchestrator` and `--fqdn` required (`install.go:52`).
  - `nurproxy-agent setup [--orchestrator URL] [--fqdn FQDN] [--data-dir DIR] [--user U] [--bin PATH]` (`setup.go:25-31`). Prompts interactively for any unset of orchestrator/FQDN; must run as root (`setup.go:33`).
  - `nurproxy-agent uninstall [--data-dir DIR] [--purge] [--yes]` (`install.go:73-77`).
  - `nurproxy-agent apply <CODE> [--data-dir DIR] [--orchestrator URL] [--api-port N]` (`apply.go:70-77`). Code is upper-cased/trimmed (`apply.go:96,110`).
  - `nurproxy-agent -version` (`main.go:47`).
- **Prerequisites:** root + systemctl for `install`/`setup`. For `apply`: the host must have been adopted (a `token` + `agent-id` exist) and have started the agent at least once so `runtime.json` resolves orchestrator/api-port zero-arg (`apply.go:117-160`).
- **Steps (real):**
  ```bash
  sudo ./nurproxy-agent install --orchestrator http://orch:8080 --fqdn edge1.example.com
  systemctl cat nurproxy-agent
  sudo ./nurproxy-agent setup --orchestrator http://orch:8080 --fqdn edge1.example.com
  # after the dashboard shows a pending proxy-mode change:
  ./nurproxy-agent apply ABCD-EFGH
  ```
- **Pass:** `install` writes `<data-dir>/agent.yaml` (mode 0640) + unit `/etc/systemd/system/nurproxy-agent.service`; `setup` reaches the orchestrator (`✓ reached … (HTTP …)`) and starts the service; `apply` prints `saved to <data-dir>/agent.yaml` and the hot-apply result, then acks.
- **Coverage:** R (`apply` flag-parsing logic is unit-tested → partial D; `apply_test.go`).
- **Pitfalls:**
  - `install` writes config as **`agent.yaml`**, while `setup` writes an **EnvironmentFile** (`/etc/nurproxy-agent/agent.env`) — two different config surfaces (`install.go:34` vs `setup.go:19,52`). If a package already installed the unit, `setup` only fills the env file and enables the service rather than writing a second unit (`setup.go:54-62,112-123`).
  - `apply`'s positional `<CODE>` may come before *or* after flags; the parser pulls a leading positional then re-checks `fs.Arg(0)` (`apply.go:82-91`). A 404 on claim = wrong/expired/already-used code → exit 1 with a clear message (`apply.go:99-101`).
  - If the running agent isn't reachable on its local API, `apply` still saves to `agent.yaml` and reports "applies on next start" (non-fatal, `apply.go:205-211`).
  - The only `op_type` this build applies is `set_proxy_mode`; anything else is acked as unsupported (`apply.go:172-177`).

### Config precedence & the `NP_*` env table
- **Must:** for the **agent**, precedence is **flags > env > config file > defaults** (`config.go:97`, layered at lines 131-141). For the **orchestrator**, `NP_PORT`/`NP_DATA_DIR` env **override** the parsed flags (`cmd/nurproxy/main.go:74-81`).
- **Access:** env vars, CLI flags, and (agent only) `agent.yaml`.
- **Complete `NP_*` env var table:**

  | Env var | Binary | Flag equivalent | Default | Source |
  |---|---|---|---|---|
  | `NP_PORT` | orchestrator | `-port` | `8080` | `cmd/nurproxy/main.go:74` |
  | `NP_DATA_DIR` | orchestrator + agent | `-data-dir` | orch `./data`, agent `/var/lib/nurproxy-agent` | `main.go:79`, `config.go:103,229` |
  | `NP_DRY_RUN` | orchestrator + agent | `-dry-run` | false | `main.go:87`, `config.go:261` |
  | `NP_DNS_DRY_RUN` | orchestrator | (none) | = `NP_DRY_RUN` | `main.go:88` |
  | `NP_ACME_DRY_RUN` | orchestrator | (none) | = `NP_DRY_RUN` | `main.go:89` |
  | `NP_DRY_RUN_FAIL` | orchestrator | (none) | "" | `main.go:90` (`ratelimit\|challenge\|propagation`) |
  | `NP_API_URL` | orchestrator (management CLI) | `-url` | `http://localhost:8080` | `cmd/nurproxy/cli.go:65` |
  | `NP_API_KEY` | orchestrator (management CLI) | `-key` | "" | `cmd/nurproxy/cli.go:66` |
  | `NP_API_PASSWORD` | orchestrator (management CLI) | `-password` | "" | `cmd/nurproxy/cli.go:67` |
  | `NP_ORCHESTRATOR` | agent | `-orchestrator` | "" (required) | `config.go:223` |
  | `NP_FQDN` | agent | `-fqdn` | "" (required) | `config.go:226` |
  | `NP_API_PORT` | agent | `-api-port` | `8780` | `config.go:232` |
  | `NP_PROXY_MODE` | agent | `-proxy-mode` | `built-in` | `config.go:237` |
  | `NP_PROXY_TYPE` | agent | `-proxy-type` | "" | `config.go:240` |
  | `NP_PROXY_BINARY` | agent | `-proxy-binary` | "" | `config.go:243` |
  | `NP_PROXY_CONFIG_DIR` | agent | `-proxy-config-dir` | "" | `config.go:246` |
  | `NP_PROXY_RELOAD_CMD` | agent | `-proxy-reload-cmd` | "" | `config.go:249` |
  | `NP_PROXY_TEST_CMD` | agent | `-proxy-test-cmd` | "" | `config.go:252` |
  | `NP_PROXY_LOG_PATHS` | agent | `-proxy-log-paths` | "" (comma list) | `config.go:255` |
  | `NP_PROXY_SERVICE` | agent | `-proxy-service` | "" | `config.go:258` |
  | `NP_LOG_LEVEL` | both | (none) | `info` | `internal/shared/logging/logging.go:30,54` |
  | `NP_LOG_FORMAT` | both | (none) | `text` | `logging.go:33` |

  Note: there is **no** `NP_CADDY_ADMIN_PORT` env var — `-caddy-admin-port` is flag-only on the agent (`config.go:222-264` reads no such key; settable in `agent.yaml` as `caddy_admin_port`). `NP_API_URL`/`NP_API_KEY`/`NP_API_PASSWORD` only seed flag defaults for the **management CLI** subcommands (`provider|zone|agent|server|domain|apikey|auth`), not the run-mode server. A grep of `os.Getenv("NP_`/`LookupEnv("NP_` across the two cmd trees + `internal/agent/config` + `internal/shared/logging` yields exactly the rows above.
- **Steps:**
  ```bash
  # Agent: flag beats env. This runs with FQDN=flag.example.com despite the env.
  NP_FQDN=env.example.com NP_DRY_RUN=true \
    ./nurproxy-agent -orchestrator http://localhost:18080 -fqdn flag.example.com
  # Orchestrator: env beats flag for port/data-dir.
  NP_PORT=19000 ./nurproxy -port 18080 -data-dir /tmp/np   # binds :19000
  ```
- **Pass:** agent banner shows `flag.example.com`; orchestrator binds `:19000`.
- **Coverage:** D.
- **Pitfalls:** the orchestrator's env-over-flag for `-port`/`-data-dir` is the **inverse** of the agent's flag-over-env. Truthy env values are `1/true/yes/on` only (`main.go:331-337`, `config.go:304-311`).

### systemd unit contents & hardening
- **Must:** `RenderUnit` emits a `[Unit]` section with `After=network-online.target` + `Wants=network-online.target` (`internal/shared/install/install.go:94-97`) and a hardened `[Service]` (`install.go:99-138`): `Type=simple`, `Restart=on-failure`, `RestartSec=5`, `NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`, `ProtectControlGroups=true`, `ProtectKernelTunables=true`, and `[Install]` `WantedBy=multi-user.target`. `User=` from `--user` (default `root`). `ReadWritePaths=` includes the data dir, and for the agent also the proxy trees (emitted as a **second** `ReadWritePaths=` line, `install.go:122-131`). The agent unit carries `AmbientCapabilities`/`CapabilityBoundingSet`.
- **Access:** produced by `nurproxy install` / `nurproxy-agent install` / `nurproxy-agent setup`.
- **Prerequisites:** root + a Linux host with `systemctl` for an installed unit; the rendered text itself needs nothing (pure function, unit-tested). On macOS/FreeBSD/OpenRC the manager renders a launchd plist / rc.d / OpenRC script instead — `RenderUnit` is systemd-only (`manager.go:25-40`).
- **Steps (real):**
  ```bash
  sudo ./nurproxy-agent install --orchestrator http://orch:8080 --fqdn edge1.example.com
  systemctl cat nurproxy-agent
  ```
- **Pass — agent unit specifics:**
  - `ExecStart=<bin> --data-dir <data-dir>` (`cmd/nurproxy-agent/install.go:30`).
  - `ReadWritePaths` = data dir + `AgentProxyWritePaths`: `-/etc/nginx -/var/log/nginx -/var/lib/nginx -/var/cache/nginx -/etc/apache2 -/etc/httpd -/var/log/apache2 -/var/log/httpd -/etc/caddy -/var/lib/caddy -/var/log/caddy -/run` (`install.go:30-35`, `install.go:33` ref `AgentProxyWritePaths`). The `-` prefix makes systemd ignore a path absent on the host instead of failing to start (`install.go:22-29`).
  - `AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE` and the same `CapabilityBoundingSet` (`install.go:49`, rendered at `install.go:132-136`). `CAP_NET_BIND_SERVICE` lets the bundled Caddy bind :80/:443; `CAP_DAC_OVERRIDE` lets existing-mode `nginx -t` read 0600 TLS keys + write logs.
  - Agent config lives in `agent.yaml` (mode 0640), written by `ensureDataDir` (`manager.go:80`).
- **Pass — orchestrator unit specifics:** `EnvironmentFile=/etc/nurproxy/nurproxy.env` with `NP_PORT` + `NP_DATA_DIR`; `ReadWritePaths=/var/lib/nurproxy`; **no** capabilities or proxy write-paths (`cmd/nurproxy/install.go:14-27`).
- **Coverage:** D for the rendered text (`RenderUnit` is pure + unit-tested, `install_test.go`); R for an installed, running unit.
- **Pitfalls:** without `CAP_DAC_OVERRIDE` an existing-mode agent's reload self-test fails with "permission denied" on the proxy key/log even though `ReadWritePaths` made the mount writable (DAC and the RO mount are independent — `install.go:42-48`). The unit is static and cannot know the file mode at install time.

### Data-directory layout & file modes
- **Must:** each binary creates its data dir and writes its persistent files with the documented modes.
- **Orchestrator data dir (default `/var/lib/nurproxy`, dev `./data`):**
  | File | Created by | Mode | Purpose |
  |---|---|---|---|
  | `nurproxy.db` | `db.Open` (`main.go:107`) | (db default) | SQLite store |
  | `encryption.key` | `crypto.LoadOrGenerateKey` (`main.go:101`) | (crypto default) | AES-256 key for provider configs + TLS keys at rest |
  | `acme-account.key` | `LoadOrGenerateAccountKey` (`main.go:236`) | (tls default) | persistent ACME account key |

  Data dir created `0755` (`main.go:96`). All three are what `backup` archives (`backup.go:22-26`); restore writes each `0600` (`backup.go:224`).
- **Agent data dir (default `/var/lib/nurproxy-agent`):**
  | File | Created by | Mode | Purpose |
  |---|---|---|---|
  | `agent.yaml` | install / `apply` persist | 0640 | resolved config (`manager.go:80`, `apply.go:185-197`) |
  | `token` | `loadOrGenerateToken` | 0600 | agent bearer token (`adoption.go:237`) |
  | `agent-id` | adoption | 0600 | adopted agent id (`adoption.go:256`) |
  | `runtime.json` | `SaveRuntimeInfo` | 0600 | convenience cache of orchestrator URL/FQDN/api-port/agent-id for zero-arg `apply` (`runtime.go:25-41`) |
  | `cert.key` | `crypto.LoadOrGenerateKey` | (crypto default) | AES key encrypting cert private keys at rest (`main.go:269`) |
  | `certs/` | `certstore.New` | dir | orchestrator-issued cert bundles (`main.go:259-277`) |

  `install` creates the data dir `0750` (`manager.go:71`); `SaveRuntimeInfo` creates it `0700` if needed (`runtime.go:29`).
- **Access:** filesystem inspection after a run.
- **Steps (dry):**
  ```bash
  NP_DRY_RUN=true ./nurproxy -data-dir /tmp/np-orch -port 18080 &
  ls -la /tmp/np-orch
  # agent (dry, explicit dir so it isn't relocated to TMPDIR):
  NP_DRY_RUN=true ./nurproxy-agent -orchestrator http://localhost:18080 \
    -fqdn edge1.example.com -data-dir /tmp/np-agent &
  ls -la /tmp/np-agent /tmp/np-agent/certs
  ```
- **Pass:** orchestrator dir has `nurproxy.db`, `encryption.key`, and `acme-account.key` (the account key is generated at boot in `startRenewer` → `LoadOrGenerateAccountKey`, `main.go:236`, before any ACME contact, so it appears even in dry mode); agent dir has `token`, `agent-id`, `runtime.json`, `cert.key` after adoption, `0600` on the secret files.
- **Coverage:** D.
- **Pitfalls:** in dry mode with the **default** agent data dir, files land in `$TMPDIR/nurproxy-agent-dry-<fqdn>`, not `/var/lib` — pass an explicit `-data-dir` if you want a known path (`config.go:120-122`). `certs/` is absolutized so file backends (nginx/apache) embed an absolute `ssl_certificate` path (`main.go:261-268`).

### Structured logging (`NP_LOG_LEVEL`, `NP_LOG_FORMAT`)
- **Must:** both binaries call `logging.Setup` first thing (`cmd/nurproxy/main.go:39`, `cmd/nurproxy-agent/main.go:67`); `NP_LOG_FORMAT=json` yields JSON lines, `NP_LOG_LEVEL` filters, and a stable `component` attribute (`orchestrator`/`agent`) is added (`logging.go:29-50`).
- **Access:** env vars `NP_LOG_LEVEL` (`debug|info|warn|error`, default `info`) and `NP_LOG_FORMAT` (`text|json`, default `text`).
- **Steps:**
  ```bash
  NP_LOG_FORMAT=json NP_LOG_LEVEL=debug NP_DRY_RUN=true \
    ./nurproxy -port 18081 -data-dir /tmp/np-log 2>&1 | head
  ```
- **Pass:** each line is valid JSON with `"component":"orchestrator"`; `debug` shows more than `info`; the legacy `log.Printf` calls also flow through the handler (`logging.go:46-48`).
- **Coverage:** D.
- **Pitfalls:** logs go to **stderr** (`logging.go:36-37`) — redirect `2>&1` when piping. Unrecognized level falls back to `info` (`logging.go:54-64`).

### Headless build
- **Must:** `nurproxy-headless` (built `-tags headless`) serves the API at `/api/v1` and MCP at `/mcp` but has **no** embedded dashboard; `/` returns 404 with a "headless build: no dashboard" message (`cmd/nurproxy/main.go:189-196`).
- **Access:** `make build-headless` (`Makefile:13`); same flags/env as the full orchestrator.
- **Steps:**
  ```bash
  make build-headless
  NP_DRY_RUN=true ./nurproxy-headless -port 18082 -data-dir /tmp/np-hl &
  curl -s -o /dev/null -w '%{http_code}\n' http://localhost:18082/        # 404
  curl -s http://localhost:18082/api/v1/health                             # JSON
  ```
- **Pass:** `/` → 404 with the headless message; `/api/v1/health` works; log line `headless build: dashboard disabled` (`main.go:192`).
- **Coverage:** D.
- **Pitfalls:** `make test-sandbox` uses the headless binary (`Makefile:28`) — do not assume the dashboard is reachable in sandbox e2e.

## Acceptance checklist

### Dry (every RC)
- [ ] `make build-all`, `make build-headless` succeed; `version`/`-version` print the git-derived version.
- [ ] `make test`, `make test-sandbox`, `make lint` pass.
- [ ] Orchestrator runs dry (`NP_DRY_RUN=true ./nurproxy`); `/api/v1/health` shows `dry_run/dns_dry_run/acme_dry_run`.
- [ ] Orchestrator env-over-flag confirmed for `NP_PORT`/`NP_DATA_DIR`.
- [ ] Agent runs dry; flag-over-env precedence confirmed (`-fqdn` beats `NP_FQDN`); dry default data dir relocates to `$TMPDIR/nurproxy-agent-dry-<fqdn>`.
- [ ] Orchestrator data dir has `nurproxy.db` + `encryption.key` (+ `acme-account.key`); agent dir has `token`/`agent-id`/`runtime.json`/`cert.key` (0600) + `certs/`.
- [ ] Backup → restore (into temp dir) → key checksums match → dry boot on restored dir reports `database:ok`, `setup_required:false`, entities load.
- [ ] `NP_LOG_FORMAT=json` → valid JSON lines on stderr; `NP_LOG_LEVEL` filters; `component` attribute present.
- [ ] Headless build: `/` → 404, `/api/v1/health` → JSON.
- [ ] `RenderUnit` text matches expected hardening (unit-tested).

### Real run (before final)
- [ ] `sudo nurproxy install` writes `/etc/systemd/system/nurproxy.service` + `/etc/nurproxy/nurproxy.env` and starts; `uninstall --purge --yes` removes it.
- [ ] `sudo nurproxy-agent install --orchestrator … --fqdn …` writes `agent.yaml` (0640) + a unit with the proxy `ReadWritePaths` + `CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE`; service starts and registers.
- [ ] `sudo nurproxy-agent setup` reaches the orchestrator from the host and starts the service (configures an existing packaged unit if present).
- [ ] `nurproxy-agent apply <CODE>` (after a pending `set_proxy_mode`) persists to `agent.yaml`, hot-applies, and acks; bad code → exit 1.
- [ ] Backup/restore round-trip against the **real** production DB, verified by booting **dry** on the restored copy (never a second live orchestrator on the tailnet).
- [ ] Built-in Caddy serving needs a real `caddy` in PATH (package install ships it; dev build does not) — see the built-in-Caddy QA section.
