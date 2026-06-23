export const meta = {
  name: 'nurproxy-qa-spec',
  description: 'Author an exhaustive docs/qa/ test-spec book covering every NurProxy feature, config & access path',
  phases: [
    { title: 'Write', detail: 'one agent per spec file — reads real code, writes the spec' },
    { title: 'Verify', detail: 'second agent checks each spec against the code and fixes gaps/inaccuracies' },
    { title: 'Synthesize', detail: 'README index + global acceptance checklist; repoint RELEASE-QA.md' },
    { title: 'Audit', detail: 'completeness critic across the whole folder' },
  ],
}

const QA_DIR = '/home/main/nurproxy/docs/qa'
const REPO = '/home/main/nurproxy'

// Shared writing contract every spec author must follow. Kept identical across
// files so the folder reads as one book.
const TEMPLATE = `
You are writing ONE file in NurProxy's QA / acceptance test book under ${QA_DIR}/.
Audience: an engineer running release QA who must be able to test the feature with
zero prior knowledge — they copy-paste your steps and tick boxes.

HARD RULES
- Write in English (the existing docs/RELEASE-QA.md and the codebase are English; no German/English mix).
- GROUND EVERYTHING IN THE REAL CODE. Open and read the referenced files (and grep
  for anything you're unsure about) BEFORE writing. Never invent a flag, endpoint,
  field, enum value, default, or threshold — if the code says X, write X, with a
  file:line reference. If you cannot confirm something, mark it "UNVERIFIED" rather
  than guessing.
- Cover EVERY feature in scope, no matter how small. Exhaustive beats tidy.
- Mine the existing ${REPO}/docs/RELEASE-QA.md for hard-won pitfalls relevant to your
  scope and fold them in (don't lose institutional knowledge).
- Prefer dry/sandbox steps where the capability is coverable dry (cheap, every RC);
  clearly mark anything that needs a real run. See ${REPO}/CLAUDE.md "Dry-run / Sandbox".

REQUIRED FILE SHAPE (Markdown)
# <Title>
> **Scope:** one sentence.
> **Code:** the key source files (with paths).
> **Coverage legend:** D = coverable dry, R = needs a real run.

## Prerequisites
What must already be true/installed/running before any test here (binaries built,
stack up via \`make dev-sandbox\`, a real Caddy/nginx in PATH, a real zone, etc.).

## Features covered
A bullet checklist naming EVERY feature/sub-capability this file tests, so a reader
can see at a glance nothing is missing.

## Tests
One \`###\` subsection per feature/capability. Each subsection MUST contain these
labelled parts (use exactly these bold labels):
- **Must:** what correct behaviour is.
- **Access:** EVERY way a user reaches this feature — Dashboard (page + the exact
  action/field), REST API (method + path + body shape), CLI (\`nurproxy …\` /
  \`nurproxy-agent …\` command + flags), MCP tool, env var / flag. List all that apply.
- **Prerequisites:** anything specific to this test beyond the file-level ones.
- **Steps:** exact, copy-pasteable commands (curl/CLI/make). Use the reusable
  fixtures and the dry instance pattern from the fixtures spec where useful.
- **Pass:** the precise observable pass criteria.
- **Coverage:** D and/or R.
- **Pitfalls:** real gotchas (timing, env, ordering, known bugs / regression-guards).

## Acceptance checklist
A condensed \`- [ ]\` checklist for this subsystem, split into "Dry (every RC)" and
"Real run (before final)" where applicable.

Write the file with the Write tool to the exact path given. Your final text message
should just confirm the path written and list the feature subsections you produced.
`

const SPECS = [
  {
    file: '01-install-and-deployment.md',
    title: 'Installation & Deployment',
    brief: `Scope: getting both binaries onto a host and configured. Cover:
- Building: make build / build-agent / build-all / test / test-cover / lint / test-sandbox (Makefile).
- Orchestrator binary subcommands: install, uninstall, version, backup, restore, and the run mode. Flags: -port, -data-dir, -dry-run. (cmd/nurproxy/main.go)
- Agent binary subcommands: install, uninstall, setup, apply, version, and run mode. ALL flags: -orchestrator, -fqdn, -data-dir, -api-port, -caddy-admin-port, -dry-run, -proxy-mode, -proxy-type, -proxy-binary, -proxy-config-dir, -proxy-reload-cmd, -proxy-test-cmd, -proxy-log-paths, -proxy-service. (cmd/nurproxy-agent/main.go, apply.go)
- EVERY NP_* env var for both binaries and its precedence vs flags (flags > env > file). Make a complete table.
- systemd install/uninstall: what unit it writes, where, ReadWritePaths, user.
- Data directory layout for orchestrator (nurproxy.db, encryption.key, acme-account.key) and agent (token, agent-id, certs, config). Where each lives, file modes.
- Packaging note: package install ships a caddy binary; bare dev build does not (relevant to built-in Caddy serving).
Read cmd/nurproxy/main.go, cmd/nurproxy/install*.go, cmd/nurproxy-agent/main.go, cmd/nurproxy-agent/apply.go, Makefile, internal/shared/logging.`,
  },
  {
    file: '02-onboarding-and-auth.md',
    title: 'Onboarding, Authentication & Sessions',
    brief: `Scope: first-run setup and all auth. Cover:
- Setup wizard flow (provider test → zone → ACME email → agent adopt → done). web SetupWizard.tsx.
- auth/status, auth/setup (min password length), auth/login, auth/logout, auth/change-password — request/response shapes, validation.
- The three auth schemes: session cookie (nurproxy_session: HttpOnly, SameSite=Lax, expiry from session_expiry_hours), admin API key (Bearer np_ak_), agent token (Bearer np_ag_). Which endpoints accept which. (api/middleware.go, api/auth.go, shared/auth/*)
- API key management: GET/POST/DELETE /api/v1/api-key (plaintext shown once, masked otherwise). CLI: nurproxy apikey show/create/revoke. CLI auth flags -url/-key/-password/-json and NP_API_URL/NP_API_KEY/NP_API_PASSWORD.
- Setup via CLI: nurproxy auth setup/status.
Access methods for each: Dashboard (Login/SetupWizard/Settings), REST, CLI. Note source tagging (ui/api) in audit.
Read api/auth.go, api/middleware.go, api/system.go, shared/auth/{session,password,token}.go, cmd/nurproxy/cli_commands.go, web/src/pages/{Login,SetupWizard,Settings}.tsx. Verify the session cookie attributes and the exact min password length in code.`,
  },
  {
    file: '03-providers-and-zones.md',
    title: 'DNS Providers & Zones',
    brief: `Scope: configuring DNS providers and zones. Cover:
- Provider interface methods (Info, ConfigSchema, ValidateConfig, ListZones, Create/Update/Delete/Get/ListRecords). internal/provider/provider.go.
- Cloudflare provider: config (api_token required, zone_id), validation by listing zones, record CRUD, ErrRecordNotFound mapping (CF code 81044), Proxied flag. internal/provider/cloudflare/.
- dryrun provider decorator: in-memory store, synthetic zone/ids, Reset(), how NP_DNS_DRY_RUN / NP_DRY_RUN wraps providers. internal/provider/dryrun/.
- Provider config encryption at rest (AES-256-GCM via encryption.key) — config stripped from API responses.
- Endpoints: GET/POST/PUT/DELETE /providers, POST /providers/test, GET /providers/{id}/zones. Zones: GET/POST /zones, POST /zones/batch, DELETE /zones/{id} (refused if domains exist — verify the guard).
- Access: Dashboard Settings + SetupWizard; CLI nurproxy provider add/list/delete/zones and zone add/list/delete; REST.
Read internal/provider/*, api/providers.go, api/zones.go, cmd/nurproxy/cli_commands.go. Verify zone-delete and provider-delete guards in code.`,
  },
  {
    file: '04-agent-lifecycle.md',
    title: 'Agent Lifecycle (register → adopt → heartbeat → stream → ack)',
    brief: `Scope: the agent control-plane protocol. Cover:
- register (no auth, agent bootstrap): payload (id, fqdn, token, api_url, public_ip, public_ip6, version, proxy_detection, proxy_capabilities). 409 on re-register of adopted agent (expected).
- adopt (requires JSON body — empty body => 400), reject, update, delete. There is NO GET /agents/{id} (405) — list+filter. status endpoint.
- heartbeat payload (every field: public_ip/6, version, caddy_running, last_error, proxy_mode, proxy_detection, proxy_capabilities, proxy_permissions, artifact_checksums) and interval (verify the 30s and the offline timeout default).
- SSE stream (dial-out, keepalive interval, reconnect backoff, 4MiB line cap), routes/ack, artifacts/adopt.
- Proxy detection (Phase-0, read-only) + capabilities reporting + version-skew status (current/outdated/ahead/unknown).
- Multi-agent on one box (dry, per-FQDN temp data dir).
Access: Dashboard Agents page (adopt/reject/edit/delete/auto-reconcile/status, log tail), CLI nurproxy agent list/status/adopt/update/reject/delete, REST, MCP list_agents/get_agent_status.
Read internal/agent/{adoption,stream,ddns}, api/agents.go, api/agents_stream.go, api/version_status.go, cmd/nurproxy-agent/main.go. Verify exact intervals/timeouts and the adopt body requirement.`,
  },
  {
    file: '05-dns-lifecycle-and-ipv6.md',
    title: 'DNS Record Lifecycle, Ownership, DDNS & IPv6',
    brief: `Scope: managed DNS behaviour. Cover:
- CNAME sub->agentFQDN created a reconcile cycle AFTER domain goes active (timing artifact warning).
- Ownership: dns_managed true (created by NurProxy, deleted on teardown) vs false (adopted identical pre-existing, left on teardown). Never overwrite a conflicting record. Audit events dns_created/dns_deleted/dns_adopted/dns_left_adopted.
- Agent A/AAAA records: dns_record_id vs dns_record_id6, separate per family.
- DNS modes per agent: static vs ddns (DNSMode enum) + ddns_interval; public IP detection (ipify/ifconfig/icanhazip), PublicIP6 detection; orchestrator updates records on IP change.
- IPv6/AAAA caveats (hairpin self-test flakiness, authoritative-NS vs public resolver, wildcard *.zone masking).
- Real verification with dig against authoritative NS.
Access: implicit via domain + agent create; observe via audit log + dig.
Read internal/agent/ddns/*, internal/orchestrator/reconciler/*, internal/provider/*, models DNSMode. Verify enum values (static/ddns) and the IP-detection sources. Fold in the §2.2 pitfalls from RELEASE-QA.md.`,
  },
  {
    file: '06-tls-acme.md',
    title: 'TLS — Central DNS-01 Issuance, Renewal, Self-ACME & Failure Modes',
    brief: `Scope: certificate lifecycle. Cover:
- TLS policies per domain: central (orchestrator DNS-01), self-acme (Caddy obtains own), off. Verify the SSLMode enum AND the TLSPolicy enum actual values in code (models + proxymodel/route.go) — the mapping/wizard labels may differ from stored enum; document the real ones.
- Central issuance via lego DNS-01: solver TXT (TTL 120), idempotent present/cleanup, ErrNoTXTSupport fallback.
- Renewal: DefaultRenewWindow (30d), DefaultRenewInterval (12h), retry policy (attempts/backoff), no-retry on rate-limit/ErrACMENotConfigured. Renewer scan + on-demand first issuance.
- Typed errors: RateLimitError (Detail, UnblockURL, RetryAfter), classification.
- Wildcard issuance + shared-key warning.
- ACME account key (P-256, persisted, reused across restarts).
- Dry failure injection: NP_DRY_RUN_FAIL=ratelimit|challenge|propagation; self-signed dry cert (90d). NP_DNS_DRY_RUN + real ACME ALWAYS fails DNS-01 (mock DNS never publishes TXT).
- Real verification: openssl s_client leaf is LE & matches host; sslverify=0.
Access: implicit via domain ssl_mode; settings acme_email + acme_directory.
Read internal/orchestrator/tls/* (manager, issuer, solver, errors, account, lego, dryrun), reconciler/renewal.go. Verify every constant. Fold in §2.3 pitfalls.`,
  },
  {
    file: '07-servers-and-domains.md',
    title: 'Servers & Domains (CRUD + every create/edit field)',
    brief: `Scope: the server and domain objects and all their fields (proxy directives get their own matrix file — here cover the object lifecycle, validation, status). Cover:
- Server CRUD: GET/POST /agents/{id}/servers, PUT/DELETE /servers/{id}. address host:port, notes. Delete refused while domains reference it (verify guard). Subnet suggestions + nginx-inferred upstreams in add dialog.
- Domain CRUD: POST/GET/PUT/DELETE /domains, filters (agent_id/server_id/status). Fields: subdomain (DNS label validation), zone_id, server_id, port (1-65535), websocket, force_https, ssl_mode, proxy_config. Verify the SSLMode enum values in code.
- Domain status machine: pending/applied/error/deleting (verify names). On create: immediate route push + on-demand TLS issuance.
- Domain config preview/override: GET /domains/{id}/config (backend caddy|nginx|apache), PUT (manual override), POST /config/reset.
- Server-move handling (artifact cleanup on old agent, re-push to new).
- force_https + websocket behaviour and capability gating (greyed out if backend lacks it).
Access: Dashboard Servers + Domains pages (General/Headers/Advanced tabs), CLI nurproxy server * and domain *, REST, MCP create/update/delete_domain.
Read api/servers.go, api/domains.go, models (Domain, Server, SSLMode, DomainStatus), web/src/pages/{Servers,Domains}.tsx, cmd/nurproxy/cli_commands.go. Verify enums + the parent-delete guards (cross-link to teardown).`,
  },
  {
    file: '08-proxy-config-matrix.md',
    title: 'Proxy Directive Matrix (every ProxyConfig field × backend)',
    brief: `Scope: THE central matrix. For EVERY field of the ProxyConfig struct, document what it renders to in each backend (built-in Caddy, nginx, apache, external caddy if supported) and how to verify the behaviour. Cover at least: websocket, force_https, max_body_size, custom_request_headers, custom_response_headers, path_strip, path_rewrite, upstream_scheme, timeout_read/write/idle, basic_auth (password is a BCRYPT hash, not plaintext), ip_allowlist, ip_blocklist, rate_limit (nginx => limit_req returns 503 not 429; apache DOES NOT support per-client rate limit), raw_config escape hatch, tls_policy. Find the COMPLETE field list in code — do not rely on this list, enumerate from the struct.
For each field: Must / Access (Dashboard Headers+Advanced tabs, REST proxy_config JSON, CLI --proxy-config-file) / Steps (render-check via GET /domains/{id}/config AND behaviour-check with the mini backend + curl) / Pass / Coverage (render = D unit-tested; behaviour = R) / Pitfalls.
Note which fields are dropped-with-warning per backend (e.g. apache rate_limit).
Read internal/shared/models ProxyConfig, internal/shared/proxymodel/route.go, internal/shared/{caddygen,nginxgen,apachegen}/generate.go and their _test.go files (these tell you the exact rendered directives). Fold in §2.6 pitfalls (durox --resolve for deterministic client IP, 503 for limit_req).`,
  },
  {
    file: '09-backend-builtin-caddy.md',
    title: 'Backend: Built-in (Bundled) Caddy — DEFAULT mode, HIGH RISK',
    brief: `Scope: the default proxy mode serving real HTTPS via bundled Caddy admin API. Cover:
- Selection: -proxy-mode built-in (default). Agent does NOT bundle caddy in its binary — exec.LookPath("caddy"); no caddy => "running in mock mode" (no :443). Package ships caddy; dev build doesn't.
- Apply sequence via admin API (port 2019, -caddy-admin-port): EnsureServer -> ClearRoutes -> AddRoute per route; EnsureServerTLS for central TLS; InstallCerts preflight before apply.
- Real HTTPS end-to-end: route applied, provided LE cert loaded, :443 terminates TLS, proxies to backend; force_https redirects :80.
- Regression guards (#106 history): routes>=1 AND tls_connection_policies>=1 on srv0 AND sslverify=0. caddygen emits raw admin-API JSON tied to the BUNDLED (Alpine) Caddy version — newer Caddy can reject route JSON (RouteList unmarshal). Test with the bundled version, not latest.
- Artifact target kind caddy-route (virtual handle caddy:route:<@id>), checksum is apply-time/in-memory.
Access: agent flags; verify via curl --resolve host:443:agent-ip + openssl + admin API GET on :2019/config.
Read internal/agent/proxy/caddy/*, internal/shared/caddygen/*, internal/agent/proxy/holder.go. Fold in §2.5b pitfalls. Mark all serving steps R.`,
  },
  {
    file: '10-backend-existing-nginx.md',
    title: 'Backend: Existing nginx (apply / reload / adopt / drift / prune)',
    brief: `Scope: managing a host-installed nginx. Cover:
- Selection: -proxy-mode existing -proxy-type nginx. Detection (exec.LookPath nginx, version parse).
- Layout resolution: Debian sites-available + sites-enabled symlinks; RHEL conf.d flat. File naming nurproxy-<host>.conf (only the nurproxy- prefix is managed).
- Atomic apply dance: snapshot -> temp (.nurproxy-tmp) -> stage -> ensure symlink -> nginx -t -> rename + nginx -s reload; rollback on failure. Error attribution (our config vs operator's pre-broken config).
- Overridable commands: -proxy-test-cmd / -proxy-reload-cmd; sudo elevation when unprivileged.
- Adoption (ReadManaged): reads all files, marks nurproxy- as generated, others adopted; operator files never touched. Prune removes stale nurproxy-* files. Remove deletes file + symlink then reload.
- basic_auth htpasswd sidecar files.
- Permission probe (write to sites-available/enabled, reload via sudoers) — cross-link to permissions spec.
- TLS: cert/key paths referenced (ssl_certificate) for central TLS.
Access: agent flags + Dashboard agent detail (detected proxy, permissions). Verify nginx -t ok before/after every apply.
Read internal/agent/proxy/nginx/*, internal/shared/nginxgen/*. Fold in §2.5a + §2.7 pitfalls. Mark serving/reload R.`,
  },
  {
    file: '11-backend-existing-apache.md',
    title: 'Backend: Existing Apache (apply / reload / adopt / drift)',
    brief: `Scope: managing a host-installed Apache (httpd). Cover:
- Selection: -proxy-mode existing -proxy-type apache. Detection (apachectl/apache2ctl/httpd/apache2, version parse).
- Layout: Debian sites-available+sites-enabled; RHEL conf.d. File naming nurproxy-<host>.conf.
- Atomic apply: snapshot -> temp -> stage -> symlink -> apachectl configtest -> rename + apachectl graceful (or systemctl reload override); rollback on failure. Error attribution.
- RATE LIMIT NOT SUPPORTED (apache core has no per-client rate limit; mod_ratelimit only throttles bandwidth) — rate_limit field is dropped with a warning. Document this clearly as the key apache divergence.
- Adoption/prune/remove mirror nginx. basic_auth htpasswd. Permission probe. Central TLS via SSLCertificateFile.
- This backend is NOT YET covered by a real run in the homelab (a known gap) — note it but still provide the full test procedure for when a host is available.
Access: agent flags; verify apachectl configtest before/after, curl behaviour.
Read internal/agent/proxy/apache/*, internal/shared/apachegen/*. Mark serving/reload R and note the coverage gap.`,
  },
  {
    file: '12-backend-existing-caddy.md',
    title: 'Backend: Existing (host-installed) Caddy',
    brief: `Scope: adopting/managing an externally-installed Caddy as a reverse proxy (distinct from the built-in admin-API mode). Cover:
- Selection: -proxy-mode existing -proxy-type caddy. Detection (caddy version).
- VERIFY IN CODE whether a dedicated file-based Caddy backend exists or whether existing+caddy routes through the same admin-API backend / Caddyfile-on-disk path. The mapping was uncertain here — read internal/agent/proxy/caddy/*, internal/agent/proxy/registry.go, holder.go and the proxy.Get("caddy", cfg) construction path and document the ACTUAL behaviour (do not assume). If it is effectively unsupported or routes to admin API, say so explicitly.
- How config is written/reloaded, adoption, TLS handling.
Access: agent flags. Be honest about coverage; if this configuration is not really implemented, mark it as a gap and say what happens if a user selects it.
Read the proxy registry + caddy backend + holder reconfigure path. This file's main job is to resolve the ambiguity truthfully.`,
  },
  {
    file: '13-proxy-mode-and-hotswitch.md',
    title: 'Proxy Modes & Hot-Switch (admin-ops)',
    brief: `Scope: switching an agent between built-in and existing without a restart. Cover:
- proxy_mode field (built-in|existing) per agent; persistence (writes agent config so restart honours it).
- Hot-switch via admin-ops: POST /agents/{id}/admin-ops {op_type:"set_proxy_mode", payload}; mints a ONE-TIME confirmation code (shown once, hash stored, TTL 15min). GET lists pending ops (never code). DELETE revokes. Agent claims: POST /admin-ops/claim {code} (atomic pending->applied), then ack: POST /admin-ops/{opId}/ack {ok,result}. Agent CLI: nurproxy-agent apply <CODE>.
- holder.Reconfigure transitions: existing->existing, built-in->existing (stop bundled caddy, swap, re-probe perms), existing->built-in (rebuild bundled, may need subprocess restart).
- Audit (source=ui prepare, source=agent claim/ack).
Access: Dashboard Agents detail (hot-switch action), REST, agent CLI apply.
Read api/admin_ops.go, internal/agent/proxy/holder.go, cmd/nurproxy-agent/apply.go, models AdminOp*. Verify TTL and the claim atomicity. Coverage: D for the op/code/claim flow; the actual serving change is R.`,
  },
  {
    file: '14-config-artifacts-and-drift.md',
    title: 'Config Artifacts: Versioning, Drift Review, Adoption & Log Tail',
    brief: `Scope: the central config-artifact store and drift workflow. Cover:
- Artifact model: agent_id, backend, target(kind,path), source (generated|manual), domain_id (nullable), live_version, drifted, drift_content, apply_state (pending|applied|apply_failed), content. Verify enums.
- List/filter: GET /artifacts (agent_id, source, apply_state, domain_id, drifted). GET /artifacts/{id}. GET /artifacts/{id}/versions (append-only history).
- Actions: accept, reject, rollback {version}, bulk {action, agent_id}, PUT /content (raw edit -> flips generated to manual), POST /reset-to-model (re-render from domain intent, caddy/model-backed only), GET /mask (structured read-only view).
- Drift healing: heartbeat ships artifact_checksums; file backends re-read+rechecksum each beat; orchestrator detects drift, stores drift_content; accept/reject re-pushes agent. Manual non-nurproxy files left untouched.
- auto_reconcile_config per agent (default off = manual review): PUT /agents/{id}/auto-reconcile.
- On-demand log tail: POST /agents/{id}/logs/tail {path,lines} (path must be in agent log_paths), GET poll {cursor}, DELETE close; agent POSTs chunks via /logs/chunk. Cross-link to backends for log_paths.
Access: Dashboard Config page (search, drifted-only, diff, accept/reject/rollback/bulk, raw edit, reset-to-model), REST.
Read api/artifacts.go, api/artifacts_adopt.go, api/artifact_mask.go, api/logs.go, internal/agent/stream/*, web/src/pages/Config.tsx. Fold in §2.7 drift pitfalls (heartbeat-driven, allow a cycle).`,
  },
  {
    file: '15-permissions-and-remediation.md',
    title: 'Permission Probing & Remediation (existing mode)',
    brief: `Scope: how the agent self-tests and reports whether it can manage the host proxy. Cover:
- ProxyPermissions (checked, ok, can_write, can_reload, remediation, runtime env) — only probed in existing mode; re-probed every heartbeat (grant clears on next beat).
- Write test (temp file in each ProbeDir: sites-available always, sites-enabled Debian only / conf.d on RHEL). Reload test (config-validate via sudo -n).
- RuntimeEnv detection: OS, distro, init system (systemd/openrc/launchd/windows-service), managed, unit, sandboxed, user, is_root.
- Remediation outputs: systemd drop-in ReadWritePaths for sandboxed root; group ownership + scoped sudoers.d line for unprivileged; copy-paste shell steps.
Access: Dashboard Agents detail (permissions panel with remediation). Reported via heartbeat.
Read internal/agent/proxy/permcheck/*, the ProbeDirs in nginx/apache backends, models ProxyPermissions/RuntimeEnv. Coverage: D for the probe logic & reporting; the actual remediation effect is R. Fold in the sudo/passwordless homelab gotcha.`,
  },
  {
    file: '16-security-hardening.md',
    title: 'Security Hardening',
    brief: `Scope: every security control, with exact thresholds from code. Cover:
- Login brute-force lockout: 5 fails / 15min window / 15min lockout per IP => 429 + Retry-After: 900. (api/server.go loginLimiter, api/auth.go)
- Per-IP register rate limit (verify the limiter + threshold on /agents/register). MCP auth rate limit (10/15min).
- Body cap: verify the actual limit and the 400 response (note the >4MiB figure from RELEASE-QA vs the MCP 1MiB io.LimitReader — document BOTH, the real values from code).
- Global session revocation: change password => old cookie 401 (session_secret / signing).
- Agent/admin token separation: agent bearer on admin route => 401; on its own agent route => 200.
- Secure cookie scheme: Secure only when HTTPS (r.TLS or X-Forwarded-Proto: https); plain-HTTP-by-IP keeps working (regression guard — this once locked out plain-HTTP dashboards).
- clientIP from RemoteAddr not X-Forwarded-For (anti-spoof).
- Crypto: bcrypt cost 12, AES-256-GCM provider config + cert key encryption, token prefixes np_ag_/np_ak_, HMAC-SHA256 sessions, constant-time compares.
Access: REST mostly; run on a DRY instance (never prod — locks real login/register 15min).
Read api/server.go, api/auth.go, api/middleware.go, api/mcp/server.go, shared/ratelimit/*, shared/auth/*, shared/crypto/*, api/helpers.go. Verify EVERY threshold. Fold in §2.8 pitfalls. Coverage: D.`,
  },
  {
    file: '17-backup-and-restore.md',
    title: 'Backup & Restore',
    brief: `Scope: data-dir backup/restore round-trip. Cover:
- nurproxy backup -o file.tgz: snapshots nurproxy.db (VACUUM INTO, safe while running), encryption.key, acme-account.key; warns on missing keys / plaintext-key risk. Flat tar.gz, default name nurproxy-backup-YYYYMMDD-HHMMSS.tar.gz.
- nurproxy restore: refuses to overwrite existing DB without --force; rejects path traversal; extracts only known flat filenames.
- Verify round-trip: restore into temp dir -> key checksums match originals -> boot NP_DRY_RUN on restored dir -> /health database:ok, auth/status setup_required:false, reconciler loads entities & decrypts providers (proves encryption.key works).
- HARD WARNING: never boot the restored REAL data with a NON-dry orchestrator on the same tailnet (two live orchestrators fight over the same zone+agents). Always restore-verify in dry.
Access: CLI only (nurproxy backup / restore).
Read cmd/nurproxy/backup.go, db SnapshotTo. Verify flags (-o, --force) and exact backup file set. Fold in §2.9 pitfalls. Coverage: D (dry boot) for the verify; backup of a live real DB is R.`,
  },
  {
    file: '18-ops-health-logging-audit.md',
    title: 'Ops Signals: Health, Logging, Versioning & Audit Log',
    brief: `Scope: operational observability. Cover:
- GET /api/v1/health: status, version, checks.database (ok|error), dry_run/dns_dry_run/acme_dry_run flags; returns 503 when DB wedged (real DB check, #65). Note it's hard to reproduce live (process holds the handle).
- Structured logging: NP_LOG_FORMAT=json (valid JSON lines), NP_LOG_LEVEL filters; component attribute; legacy log.Printf bridged; stderr.
- Version-skew: agent version vs orchestrator -> current/outdated/ahead/unknown; flagged in dashboard. (api/version_status.go)
- Audit log: GET /audit-log (limit default 50 max 1000, offset, source filter). Sources: ui|api|mcp|agent|system|dryrun. Every DNS/cert/route/security/CRUD action recorded. dry events tagged source=dryrun, real system events source=system.
Access: REST health/audit; Dashboard Overview audit tail + version badges; env for logging.
Read api/system.go, internal/shared/logging/*, api/version_status.go, db/audit.go, models AuditSource. Verify health 503 path and the audit source enum. Coverage: D. Fold in clock-skew (UTC vs local) gotcha.`,
  },
  {
    file: '19-interface-dashboard.md',
    title: 'Interface: Dashboard (web UI)',
    brief: `Scope: the React dashboard as a test surface — every page, shell, and global UI behaviour. Cover:
- Routes: / (Overview), /agents, /servers, /domains, /config, /settings, /help/:slug, topology. Verify the actual routes in web/src/shells/appRoutes.tsx.
- Per page: the key actions/fields a tester exercises (cross-reference the feature specs rather than duplicating; here focus on UI-specific behaviour, validation messages, polling intervals).
- Shells/variants: Classic, Workbench, Wallboard (30s poll, no nav), Spreadsheet — selection in Settings. Verify they exist.
- Global: Dry-run banner (when dns_dry_run/acme_dry_run), auth gating/redirect, setup-wizard trigger, i18n/language selector, help/wiki system.
- Topology view (nodes internet->agents->servers->domains, context menu).
Access: browser. Provide how to bring the dashboard up (make dev-sandbox serves it) and a smoke checklist per page.
Read web/src/App.tsx, web/src/shells/*, web/src/pages/*. Coverage: mostly D (against dry stack). Keep it about UI behaviour; defer field semantics to the feature specs with links.`,
  },
  {
    file: '20-interface-cli.md',
    title: 'Interface: Management CLI',
    brief: `Scope: the nurproxy management CLI as a test surface. Cover EVERY subcommand with its flags and the --json output:
- Global auth flags -url/-key/-password/-json + NP_API_URL/NP_API_KEY/NP_API_PASSWORD.
- provider list/add/delete/zones; zone list/add/delete; agent list/status/adopt/update/reject/delete; server list/add/update/delete; domain list/add/update/delete; apikey show/create/revoke; auth setup/status.
- domain add flags incl --proxy-config-file; agent adopt/update flags (--dns-mode etc.).
For each command group: Must / Access (this IS the access) / Steps (run against a dry instance) / Pass (table output + --json shape) / Pitfalls.
Read cmd/nurproxy/cli_commands.go fully and enumerate from code — do not miss a subcommand or flag. Coverage: D (drive a dry orchestrator).`,
  },
  {
    file: '21-interface-rest-api.md',
    title: 'Interface: REST API (full endpoint reference & test surface)',
    brief: `Scope: the complete REST surface as a reference + contract tests. Produce the authoritative endpoint table grouped by area (health, auth, providers, zones, agents, agent-stream, servers, domains, artifacts, system/audit/settings/api-key, mcp), each row: method, path, auth (none/requireAuth/requireAgentAuth), one-line purpose, body shape. Then contract-test guidance: auth enforcement (401/403), method-not-allowed (405, e.g. GET /agents/{id}), 400 on bad bodies (e.g. empty adopt body), CORS behaviour, content-types, pagination.
Access: this IS the access (curl examples against a dry instance with an API key).
Read internal/orchestrator/api/server.go (route registration) and every handler file to confirm method+path+auth. Enumerate from code — this must be exhaustive and exact. Coverage: D.`,
  },
  {
    file: '22-mcp-server.md',
    title: 'MCP Server (AI-driven management)',
    brief: `Scope: the optional MCP endpoint. Cover:
- Off by default; enable via setting mcp_enabled=true (PUT /settings/mcp_enabled). Endpoint POST /mcp (and /mcp/). When disabled: verify the actual behaviour (404 or similar) from code.
- Auth: Bearer admin API key; rate limit (10 fails/15min => 429 Retry-After). Body limit (1MiB io.LimitReader).
- Protocol: JSON-RPC 2.0, version string; methods initialize, ping, tools/list, tools/call.
- Tools: list_agents, get_agent_status, list_servers, list_domains, create_domain, update_domain, delete_domain — inputs/outputs each. Audit source=mcp, actor=mcp.
Access: HTTP JSON-RPC; provide curl examples (initialize, tools/list, tools/call create_domain) against a dry instance.
Read internal/orchestrator/mcp/server.go. Verify the enable mechanism, the exact tool list/schemas, the protocol version, and the disabled-state response. Coverage: D.`,
  },
  {
    file: '23-migrations-and-schema.md',
    title: 'Database Migrations & Schema Integrity',
    brief: `Scope: the SQLite schema and migration safety. Cover:
- Enumerate every migration in internal/orchestrator/db/migrations.go (number + what it creates/alters). Build the table from code, not from the mapping summary — verify count and content.
- Key constraints, esp. FK ON DELETE behaviour: which are CASCADE vs SET NULL vs RESTRICT. Call out the known issue: server/agent/zone delete relies on a 409 application guard, but the FK is still ON DELETE CASCADE so a direct DB delete would leak managed DNS/certs (RESTRICT follow-up open — cross-link teardown). Verify the actual ON DELETE clauses in the CREATE TABLE statements.
- Migration test procedure: fresh DB migrates clean (dry boot); in-place upgrade runs migrations on a populated DB without data loss (cross-link resilience spec). Append-only migrations (never edit a shipped migration).
- Sensitive columns: key_pem_enc, code_hash, admin_password_hash, session_secret, admin_api_key — never returned by API.
Access: inspect via sqlite3 on a dry data-dir; boot logs show migrations applied.
Read internal/orchestrator/db/migrations.go and schema.go. Coverage: D.`,
  },
  {
    file: '24-resilience-and-upgrade.md',
    title: 'Resilience, In-Place Upgrade & Multi-Agent',
    brief: `Scope: operational continuity. Cover:
- Reconciler: what it does each cycle (route reconciliation per agent via stream/instant-push, DNS reconciliation, cert renewal companion), interval setting (reconciler_interval, verify default & min). Instant push on domain change (PushAgentRoutes).
- In-place upgrade: stop -> back up data dir -> swap binary -> start; migrations run clean on the real DB; agents reconnect; NO traffic interruption (agent keeps serving while orchestrator restarts). The one-time ":8780/routes context deadline exceeded" per reconnect is cosmetic (routes delivered by push).
- Reconnect: orchestrator restart -> agent re-adopts artifacts, heartbeats, acks.
- Multi-agent: 2+ agents, overlapping zones, domains on different agents, per-agent artifacts & admin-ops; dry multi-agent on one box.
Access: ops (systemctl/binary swap); observe via /health, agent list, audit.
Read internal/orchestrator/reconciler/*, settings defaults. Coverage: reconcile/multi-agent D; upgrade-with-live-traffic R. Fold in §2.11 pitfalls.`,
  },
  {
    file: '25-fixtures-and-gotchas.md',
    title: 'Reusable Fixtures & Environment Gotchas',
    brief: `Scope: shared tooling every other spec references. Cover (port the content from RELEASE-QA.md §5 and §6, verified and expanded):
- Mini echo backend (python3 on :18099, NURPROXY-E2E-PROOF marker + headers + path) — full snippet.
- Serve-direct curl + openssl s_client snippets (deterministic client IP via --resolve, ssl_verify_result).
- Dry instance for the security/ops battery: NP_LOG_FORMAT=json NP_DRY_RUN=true ./nurproxy -port 18081 -data-dir /tmp/np-sec.
- The make dev-sandbox launcher (AGENTS=, PORT=, KEEP=) and test/sandbox (build tag sandbox, make test-sandbox).
- bcrypt one-liner for basic_auth.
- Environment gotchas: Tailscale ACL :8080 (HTTP 000 symptom), clock skew (orchestrator UTC vs agent local), sudo (apps-vm NOPASSWD, durox passwordless set, password-prompting hosts need ! ssh -t), IPv6 hairpin flakiness + systemd-resolved v4-mapped AAAA, never two live orchestrators on one tailnet/zone, revoke test API keys when done (they end up in transcripts).
This file is referenced by all others, so make the fixtures copy-paste solid.
Read RELEASE-QA.md §5/§6, scripts/dev-sandbox.sh, test/sandbox/*, Makefile. Coverage: N/A (support file).`,
  },
]

log(`Authoring ${SPECS.length} QA spec files (+ README) under ${QA_DIR}`)

const written = await pipeline(
  SPECS,
  // Stage 1: write the spec from real code.
  (spec) => agent(
    `${TEMPLATE}\n\n=== YOUR FILE ===\nPath: ${QA_DIR}/${spec.file}\nTitle: ${spec.title}\n\n=== SCOPE & WHAT TO COVER ===\n${spec.brief}\n\nProject root: ${REPO}. Read the real source before writing. Write the file now.`,
    { label: `write:${spec.file}`, phase: 'Write' }
  ).then(() => spec),
  // Stage 2: verify against code & fix in place.
  (spec) => {
    if (!spec) return null
    return agent(
      `You are the accuracy & completeness reviewer for ONE QA spec file in NurProxy.\n\nFile: ${QA_DIR}/${spec.file} (title: ${spec.title}).\nProject root: ${REPO}.\n\nDo this:\n1. Read the file.\n2. Read the actual source code it covers (scope below) and CHECK every factual claim: endpoints/methods/auth, CLI commands & flags, env vars, enum values, defaults, thresholds, rendered directives, file paths. Fix anything wrong with an Edit. Replace any guess with the verified value or mark UNVERIFIED.\n3. Check COMPLETENESS: is any feature, field, flag, subcommand, or access path (Dashboard/REST/CLI/MCP/env) in scope missing? Add it.\n4. Ensure every '###' subsection has the labelled parts (Must/Access/Prerequisites/Steps/Pass/Coverage/Pitfalls) and that Steps are copy-pasteable. Fix gaps.\n5. Keep it in English, consistent with the rest of the book.\n\nScope reminder:\n${spec.brief}\n\nEdit the file directly. Return a short list of the corrections/additions you made (or 'no changes needed' if truly clean).`,
      { label: `verify:${spec.file}`, phase: 'Verify' }
    ).then((notes) => ({ ...spec, notes }))
  }
)

const ok = written.filter(Boolean)
log(`${ok.length}/${SPECS.length} specs written & verified; synthesizing index`)

phase('Synthesize')
await agent(
  `You are writing the index/README for NurProxy's QA test book at ${QA_DIR}/README.md, plus repointing the old single-file doc.\n\nThe folder now contains these spec files (read each one's title + "Features covered" section to build accurate cross-links):\n${SPECS.map((s) => `- ${s.file} — ${s.title}`).join('\n')}\n\nProject root: ${REPO}.\n\nWrite ${QA_DIR}/README.md with:\n1. A short intro: this is the living release QA / acceptance book; new capabilities must land here with a test before they ship.\n2. "How to use before a release": run the dry battery every RC; the real-run battery on a throwaway domain/agent before the final tag; tick the acceptance checklist; note deviations in release notes.\n3. The "Test environments" table (Dry/sandbox, Single real host, Homelab multi-host — covers vs does NOT cover) ported & updated from ${REPO}/docs/RELEASE-QA.md §1, plus the golden rule (dry proves logic; only a real run proves serving/certs/DNS).\n4. An index table of all spec files with a one-line scope each and a D/R hint.\n5. A consolidated GLOBAL acceptance checklist (condensed - [ ] items) split into "Dry (every RC)", "Real run (before final)", and "Always", aggregating the per-spec checklists. Cover the high-risk items explicitly: built-in Caddy real HTTPS (routes>=1, tls_connection_policies>=1, sslverify=0), teardown no-leak + 409 parent guard, IPv4+IPv6 serving, in-place upgrade no-traffic-drop, security battery, backup/restore dry round-trip.\n6. A "Known gaps" section (port RELEASE-QA.md §4: cert renewal in-window, self-acme serving, existing-apache/external-caddy real run, OpenRC/launchd/rc.d, macOS/FreeBSD, DNS-drift e2e, large-topology perf, provider-failure handling).\n\nThen: rewrite ${REPO}/docs/RELEASE-QA.md to a SHORT stub that says the QA book has moved to docs/qa/ and links to docs/qa/README.md, so the old path doesn't rot. Do NOT delete its unique pitfalls without confirming they were folded into the qa/ specs — if unsure, keep a "Legacy pitfalls" appendix link. Read the current RELEASE-QA.md first.\n\nWrite both files. Confirm the paths.`,
  { label: 'readme+stub', phase: 'Synthesize' }
)

phase('Audit')
const AUDIT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['coverageScore', 'missing', 'inaccurateRisks', 'verdict'],
  properties: {
    coverageScore: { type: 'integer', minimum: 0, maximum: 100, description: 'how completely the folder covers every NurProxy feature & config' },
    missing: { type: 'array', items: { type: 'string' }, description: 'features/configs/access-paths still not covered anywhere in docs/qa/' },
    inaccurateRisks: { type: 'array', items: { type: 'string' }, description: 'claims that look unverified or likely wrong and need a human re-check' },
    weakestFiles: { type: 'array', items: { type: 'string' }, description: 'spec files that are thinnest or least grounded' },
    verdict: { type: 'string', description: 'one-paragraph overall assessment' },
  },
}
const auditResult = await agent(
  `You are the completeness critic for NurProxy's new QA test book at ${QA_DIR}/ (project root ${REPO}).\n\nRead the README and skim every spec file. Then cross-check against the actual codebase surface: is EVERY user-accessible feature, every proxy configuration (built-in caddy, existing nginx, existing apache, existing caddy), every ProxyConfig field, every REST endpoint, CLI subcommand, MCP tool, env var/flag, and migration covered SOMEWHERE with how-to-access + how-to-test? Identify what's missing, what looks unverified or wrong, and which files are weakest. Be specific (name files, features, endpoints). This drives the next round of work.`,
  { label: 'completeness-critic', phase: 'Audit', schema: AUDIT_SCHEMA }
)

return { written: ok.length, total: SPECS.length, audit: auditResult }
