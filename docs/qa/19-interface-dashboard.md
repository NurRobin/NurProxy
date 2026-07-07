# Interface: Dashboard (web UI)
> **Scope:** the React dashboard as a test surface — routes, shell variants, global UI behaviour (auth gating, setup wizard, dry-run banner, i18n, command palette, help/wiki), and the topology view. Field-level semantics of each feature live in their own specs; this file covers UI behaviour only.
> **Code:** `web/src/App.tsx`, `web/src/shells/{appRoutes,nav,Classic,Workbench,Wallboard,Spreadsheet}.tsx`, `web/src/pages/{Overview,Agents,Servers,Domains,Config,Settings,Help,Topology,Wallboard,SpreadsheetOverview,Login,SetupWizard}.tsx`, `web/src/components/{DryRunBanner,CommandPalette,NotificationBell}.tsx`, `web/src/lib/{ui-variant.tsx,ui-variant-context.ts,usePolling.ts,i18n.ts,wiki.ts}`.
> **Coverage legend:** D = coverable dry, R = needs a real run.

## Prerequisites
- Both binaries built with the **embedded** dashboard. `make build` runs `web-build` first (`Makefile:7`), so `./nurproxy` serves the bundled `web/dist`. A `build-headless` orchestrator has **no dashboard** (`Makefile:13`) — do not QA the UI against it.
- A running orchestrator that serves the dashboard. Fastest: `make dev-sandbox` → orchestrator on **`:8099`** by default (`scripts/dev-sandbox.sh:29`), seeded with a provider, zone, adopted agents, servers, and central-TLS domains. Open `http://localhost:8099/` in a browser.
  - `PORT=9000 make dev-sandbox` to move the port; `AGENTS=3 make dev-sandbox` for a multi-agent topology (richer Overview/Topology/Wallboard).
- For live dashboard iteration (HMR) you can also run `make dev` (`Makefile:47`, Vite dev server on its own port) but it expects an orchestrator API to proxy to — prefer the embedded build for QA so you test what ships.
- A browser. Most checks are clickthrough; have the browser devtools Network/Console panel open to spot failed `/api/v1/*` calls.
- Per-feature data semantics (agents adopt, domains issue certs, config drift, etc.) are out of scope here — see the matching feature specs in `docs/qa/`.

## Features covered
- [ ] Routes: `/` (Overview), `/agents`, `/servers`, `/domains`, `/config`, `/settings`, `/help`, `/help/:slug`; `/login` and unknown paths redirect to `/`.
- [ ] Shell variants: Classic, Workbench, Wallboard, Spreadsheet — selection persisted in `localStorage`, switched in Settings or the command palette.
- [ ] Auth gating: loading / orchestrator-unreachable error / setup-required / unauthenticated → Login; logout.
- [ ] Setup wizard trigger (`setup_complete` ≠ `true`).
- [ ] Dry-run banner (shown when `dns_dry_run` or `acme_dry_run`).
- [ ] Per-page UI behaviour & polling intervals (Overview, Agents, Servers, Domains, Config, Settings, plus variant home pages).
- [ ] Topology view: 4-column graph (internet → agents → servers → domains), inspector panel, right-click context menu, filter, collapse.
- [ ] Command palette (⌘K / Ctrl+K): navigation, quick actions, theme + variant switch.
- [ ] i18n / language selector (English, Deutsch).
- [ ] Help / wiki system (sidebar topics, unknown-slug fallback).
- [ ] Theme toggle, notification bell (global chrome).

## Tests

### Routes & navigation
- **Must:** The router (`web/src/shells/appRoutes.tsx`) exposes exactly: `/` (overview, shell-specific), `/agents`, `/servers`, `/domains`, `/config`, `/settings`, `/help`, `/help/:slug`. `/login` redirects to `/` once authenticated, and any unknown path (`*`) redirects to `/`. Nav items (top/side bar) are defined in `web/src/shells/nav.tsx`: Overview, Agents, Servers, Domains, Config, Settings (`/help` is a separate "Docs" link, not in `NAV`).
- **Access:** Browser — click nav links; or type a path directly in the address bar; or ⌘K → a `Go to …` command.
- **Prerequisites:** stack up; logged in.
- **Steps:**
  1. From `/`, click each nav item in turn; confirm the URL and page heading change.
  2. Visit `http://localhost:8099/nonexistent` directly → should land on `/`.
  3. Visit `http://localhost:8099/login` while authenticated → should land on `/`.
  4. Visit `http://localhost:8099/help/cloudflare-token` directly → renders that wiki topic.
- **Pass:** All six nav routes + Docs reachable; bad paths and `/login` redirect to `/`; deep help link renders directly.
- **Coverage:** D.
- **Pitfalls:** Each shell mounts its **own** `<BrowserRouter>` (see each `shells/*.tsx`), and the `/` route renders a **different** component per shell (Overview / Topology / Wallboard / SpreadsheetOverview). When you switch variants the home page changes — that is expected, not a routing bug.

### Shell variants (Classic / Workbench / Wallboard / Spreadsheet)
- **Must:** Four variants exist (`web/src/lib/ui-variant-context.ts` `UI_VARIANTS`; `App.tsx` `SHELLS`): `classic`, `workbench`, `wallboard`, `spreadsheet`. The active variant is stored in `localStorage` under key **`nurproxy-ui`** (`web/src/lib/ui-variant.tsx`), defaults to `classic`, and an invalid stored value falls back to `classic`. Differences:
  - **Classic** (`shells/Classic.tsx`): top nav bar, `/` = Overview (health panel + agent cards + recent activity).
  - **Workbench** (`shells/Workbench.tsx`): left sidebar rail with live count badges on `/agents` and `/domains` (refreshed every **30s**, `useCounts`); `/` = Topology.
  - **Wallboard** (`shells/Wallboard.tsx`): **no nav bar** — only a floating control cluster (Board, Settings, bell, theme, logout) top-right; navigation is via ⌘K only; `/` = Wallboard (big glanceable status grid). Wallboard page polls every **30s** (`pages/Wallboard.tsx:26`).
  - **Spreadsheet** (`shells/Spreadsheet.tsx`): dense top nav; `/` = a sortable, read-only domains table (`pages/SpreadsheetOverview.tsx`).
- **Access:** Settings page → **Appearance** section → click a variant card (`pages/Settings.tsx:206-222`, calls `setVariant`). Or ⌘K → `Switch to <variant>` (`components/CommandPalette.tsx:36`).
- **Prerequisites:** seeded topology (run `AGENTS=3 make dev-sandbox` for a richer Wallboard/Workbench).
- **Steps:**
  1. Go to `/settings`, Appearance section; click each of the four cards; after each, confirm the active card shows the "Active" pill and the shell chrome changes immediately (no reload).
  2. Reload the page; confirm the chosen variant persists (it is in `localStorage` `nurproxy-ui`).
  3. In Wallboard, confirm there is no top/side nav; press ⌘K and navigate to Settings; switch back to Classic.
  4. In Workbench, confirm the sidebar shows numeric badges next to Agents and Domains matching their counts.
- **Pass:** All four variants render; switching is instant and persisted; Wallboard has no nav; Workbench badges match counts.
- **Coverage:** D.
- **Pitfalls:** `localStorage` is per-origin/per-browser-profile — a "wrong" default after testing is usually a leftover `nurproxy-ui` value, not a regression. Clear it to confirm the `classic` default. Wallboard is **read-only** by design — there are no create/delete actions there.

### Auth gating & logout
- **Must:** `App.tsx` resolves one of: `loading` (spinner), `error` ("Can't reach the orchestrator" card with Retry), `setup_required` or `unauthenticated` (Login), `needs_setup_wizard` (SetupWizard), `authenticated` (the shell). It calls `api.authStatus()` (`GET /api/v1/auth/status`) then, if authenticated, `api.getSettings()` to check `setup_complete`. On a `getSettings` failure it shows the **error** card (does **not** fail open into the dashboard — `App.tsx:38-40`). Logout calls `api.logout()` and returns to `unauthenticated`.
- **Access:** Browser. Login form `pages/Login.tsx`; logout button in every shell header/rail.
- **Prerequisites:** dry instance (so you can register/login without touching prod). First boot of a fresh data dir → `setup_required: true`.
- **Steps:**
  1. Fresh dry instance, open `/` → Login renders in **create** mode (welcome copy, password + confirm fields). Password must be ≥ 8 chars and match confirm (`Login.tsx:28-29`); submit creates the admin and proceeds.
  2. Log out (header button) → returns to Login in **sign-in** mode (single password field).
  3. Stop the orchestrator, reload the dashboard → the **error** card with a Retry button appears (not a blank dashboard). Restart, click Retry → recovers.
- **Pass:** Unauthenticated visitors always land on Login; orchestrator outage shows the error card with Retry; logout works.
- **Coverage:** D (use a dry instance).
- **Pitfalls (from `docs/RELEASE-QA.md` §2.8):** Run any lockout/repeat-login tests on a **dry instance** — failed attempts lock the real login/register for 15 min. Secure-cookie regression guard: a plain-HTTP-by-IP dashboard login must still work (the `Secure` flag is only set on HTTPS; this once locked out plain-HTTP dashboards, fixed pre-rc.2). Confirm login over `http://<ip>:8099` succeeds.

### Setup wizard trigger
- **Must:** After auth, `App.tsx` reads settings and shows the SetupWizard when `setup_complete` ≠ `'true'` (`needs_setup_wizard`). The wizard steps are Provider → TLS → Agent → Done (`pages/SetupWizard.tsx` `STEPS`). Completing it calls `onComplete` → state becomes `authenticated`.
- **Access:** Automatic on first authenticated session of a fresh instance.
- **Prerequisites:** a fresh instance where `setup_complete` is not yet `true`. `make dev-sandbox` **pre-seeds** a provider/zone/agents, so on the seeded sandbox the wizard may be skipped — to see the wizard, boot a bare dry orchestrator by hand (`NP_DRY_RUN=true ./nurproxy -data-dir /tmp/wiz`) and create the admin.
- **Steps:**
  1. Bare dry orchestrator, register admin → wizard appears at the Provider step.
  2. Provider validation/token entry is mocked dry (a dummy token works end-to-end). Walk Provider → TLS → Agent → Done.
  3. Reload → you now land on the dashboard (wizard not shown again).
- **Pass:** Wizard appears exactly once on a fresh instance and is skipped thereafter.
- **Coverage:** D. Full wizard feature semantics → the onboarding/setup feature spec.
- **Pitfalls:** Do not expect the wizard on the seeded `make dev-sandbox` — its seed marks setup done. The Agent step polls for the agent to connect; in dry-by-hand you must also start a dry agent pointed at the orchestrator.

### Dry-run banner
- **Must:** `components/DryRunBanner.tsx` fetches `GET /api/v1/health` once on mount. It renders a persistent warning strip **only** when `dns_dry_run` or `acme_dry_run` is truthy; on a normal instance it renders nothing. Text: `Dry-run mode — <scope> calls are simulated. No external requests leave this instance.` where scope is `DNS`, `ACME`, or `DNS + ACME` depending on which flags are set (`DryRunBanner.tsx:20-23`). It mounts above the shell (`App.tsx`).
- **Access:** Always present in the shell; driven by `/api/v1/health` flags, which come from env: `NP_DRY_RUN` sets both; `NP_DNS_DRY_RUN` / `NP_ACME_DRY_RUN` set them individually (see `CLAUDE.md` Dry-run section).
- **Steps:**
  1. `make dev-sandbox` (sets `NP_DRY_RUN=true`) → banner reads `DNS + ACME calls are simulated`.
  2. Boot `NP_ACME_DRY_RUN=true ./nurproxy` (real DNS, mock ACME) → banner reads `ACME calls are simulated`.
  3. Confirm `curl http://localhost:8099/api/v1/health` shows the corresponding `dns_dry_run` / `acme_dry_run` booleans (the banner mirrors them).
- **Pass:** Banner present and scope-correct in dry modes; absent on a fully live instance.
- **Coverage:** D.
- **Pitfalls:** The banner reads health **once on mount** (not polled) — if you toggle the orchestrator's mode you must reload the page. A missing banner on a live instance is correct behaviour, not a bug.

### Overview page (`/`, Classic)
- **Must:** `pages/Overview.tsx` shows a single health panel ("All normal" vs "N need attention"), agent cards, and a recent-activity list (last 15 audit entries). Problem count = errors (agents+domains) + offline agents + **degraded** agents (`isDegraded`, e.g. a connected agent failing its permission self-test — status alone misses these). Polls every **30s** (`Overview.tsx:47`). On a fetch failure it marks data **stale** ("· stale" note) rather than showing stale data as fresh. Audit rows carry a colored source chip: `ui`, `api`, `mcp`, `agent`, `system` (`SOURCE_STYLES`).
- **Access:** Classic shell `/`; "New domain" button → `/domains`; agent card → `/agents?agent=<id>`; problem chips link to `/agents` / `/domains`.
- **Steps:** Open `/` on the seeded sandbox; confirm health panel, agent cards (name, fqdn, ip, "seen", version), and a recent-activity list with source chips. Wait ~30s and confirm a silent refresh (no flicker). Stop the orchestrator briefly → confirm a "stale" note appears.
- **Pass:** Panel/ cards/ activity render; degraded agents counted in "need attention"; stale note on outage.
- **Coverage:** D.
- **Pitfalls:** "All normal" must **not** show while an adopted-but-degraded agent exists — this was a real bug (status-only check); the regression guard is the `isDegraded` count (`Overview.tsx:58`). Audit source chips: dry-simulated DNS/cert events are tagged `system` vs real `system`? Per `CLAUDE.md`, simulated calls are tagged `source=dryrun` in the audit log — the Overview chip styling only enumerates `ui/api/mcp/agent/system`, so a `dryrun` source falls through to the default grey chip. Note this if verifying audit provenance from the UI.

### Agents page (`/agents`)
- **Must:** Lists/manages agents; polls every **5s** (`pages/Agents.tsx:80`) — the fastest-polling page, because adoption/heartbeat state changes quickly. UI-level: an `?agent=<id>` query param (linked from Overview) should focus/scroll the named agent.
- **Access:** Nav → Agents; Overview agent card; Topology context menu "Open in Agents".
- **Steps:** Open `/agents`; confirm the agent list reflects the seeded agents and updates within ~5s when state changes. Follow an Overview agent-card link and confirm the `?agent=` param is honoured.
- **Pass:** Agents render and refresh on the 5s cadence.
- **Coverage:** D. Adoption/approve/reject/install-command semantics → the agents feature spec.

### Servers page (`/servers`)
- **Must:** Manages backend servers per agent (UI for create/list/delete). Standard table/list page within the shell.
- **Access:** Nav → Servers; Topology context menu "Add server" / "Add domain here".
- **Steps:** Open `/servers`; confirm the seeded servers list; confirm create/delete dialogs open.
- **Pass:** Page renders against the dry stack; CRUD dialogs open.
- **Coverage:** D. Server field semantics → the servers feature spec.

### Domains page (`/domains`)
- **Must:** Primary domain CRUD page; create/edit/delete with the cert/DNS lifecycle reflected via status badges. This page is where bulk/multi-select and advanced per-domain config live (the Spreadsheet variant's "bulk actions" description points operators here, not to the read-only SpreadsheetOverview).
- **Access:** Nav → Domains; "New domain" buttons across Overview/Topology/SpreadsheetOverview; Topology context menu "Edit in Domains".
- **Steps:** Open `/domains`; create a domain against a seeded server+zone; watch its status badge progress (dry: simulated DNS-01 → self-signed cert → active). Delete uses an **undoable delete** (toast with Undo, `lib/undo.ts`) on the Topology path; confirm the Domains page delete flow.
- **Pass:** Domain create reaches `active` on the dry stack; delete works.
- **Coverage:** D. Domain field semantics (ssl_mode, force_https, websocket, etc.) → the domains feature spec.

### Config page (`/config`)
- **Must:** Shows the central versioned config store: per-artifact content + status + last error, version history with a diff between any two versions, rollback, and the drift-review flow (diff + Accept/Reject). When **more than 3** artifacts drift at once (`BULK_THRESHOLD = 3`, `pages/Config.tsx`) a bulk-review banner offers accept-all / reject-all. Polls every **15s** (`Config.tsx:68`). Every action routes through audited orchestrator endpoints — the dashboard never touches a host directly.
- **Access:** Nav → Config.
- **Steps:** Open `/config`; confirm artifacts list grouped by agent/server, status badges, the free-text filter and drifted-only toggle, and a diff view when selecting a version. To exercise the bulk banner you need >3 drifted artifacts (drive drift via the config/drift feature flow).
- **Pass:** Artifacts, history/diff, rollback, and drift Accept/Reject render; bulk banner appears past the threshold.
- **Coverage:** D. Drift/config semantics → the config-artifacts feature spec.

### Settings page (`/settings`)
- **Must:** `pages/Settings.tsx` sections: **Appearance** (variant cards + language selector), **DNS providers** (add via 2-step token→zones modal; delete provider/zone with confirm), **Reconciler** (interval seconds, min `5`, `Settings.tsx:272`), **TLS** (ACME email), **Authentication** (change password: new ≥ 8 chars and must match confirm, `Settings.tsx:167-168`), **Admin API key** (generate/regenerate/revoke; plaintext shown once with a "copy now" callout; masked thereafter), **System** (version + status from `/health`). Loads via `api.listProviders/listAllZones/getSettings/health/getAPIKey`. Add-provider is hard-wired to **Cloudflare** (`provType = 'cloudflare'`, `Settings.tsx:51`).
- **Access:** Nav → Settings.
- **Steps:**
  1. Appearance: switch variant + language (see those subsections).
  2. Providers: click "Add provider", paste the dummy dry token, "Connect" → zone-select step → save; confirm zones appear under the provider; delete a zone and a provider (confirm dialog requires typing the provider name).
  3. Reconciler: set interval to `30`, Save → success toast; try `<5` and confirm the input min guards it.
  4. TLS: set ACME email, Save → success toast.
  5. Auth: change password with a too-short / mismatched value → inline error; valid → success toast.
  6. API key: generate → plaintext shown in a success callout once; reload → masked value only, with Regenerate/Revoke.
- **Pass:** Each section saves and surfaces a toast/inline error correctly; dry provider validation succeeds with the dummy token.
- **Coverage:** D. Provider/TLS/auth semantics → their feature specs.
- **Pitfalls:** The admin API key plaintext is shown **once** (`apiKeyPlaintext` state, cleared on regenerate/revoke) — confirm it is not re-displayed after reload. Provider add is Cloudflare-only by design ("more soon" chip).

### Topology view (Workbench `/`, or via context)
- **Must:** `pages/Topology.tsx` renders four columns — Internet → Agents → Upstreams(servers) → Domains — with SVG connectors; connector is "active" when the edge endpoint is healthy (agent `adopted`, domain `active`). Polls every **30s** (`Topology.tsx:61`). Clicking a node opens an **Inspector** side panel (status, key rows, "Manage in …" button). **Right-click** (or context-menu) on a node opens a context menu with: Inspect, navigation ("Open in Agents" / "Add server" / "Add domain here" / "Edit in Domains"), Approve/Reject for `pending` agents, and danger Delete/Remove actions (agent/server/domain). Domain delete from here is **undoable** (optimistic removal + Undo toast, `lib/undo.ts`). A text **filter** narrows agents/servers/domains; per-agent **collapse** (chevron) hides its children. Aggregate health line shows agent/server/domain counts and an error count. Empty state ("Connect an agent") when there are no agents.
- **Access:** Workbench shell `/`; clicking nodes; right-clicking nodes for the menu; the filter input; the "New domain" button.
- **Prerequisites:** seeded topology (`AGENTS=3 make dev-sandbox` for a richer graph; include a `pending` agent to exercise Approve/Reject menu items).
- **Steps:**
  1. Switch to Workbench (Settings → Appearance) or open Topology; confirm four columns and connector lines, with active edges accented.
  2. Click an agent node → Inspector shows FQDN, DNS mode, IP, version, last-seen, server count.
  3. Right-click a domain node → context menu; choose "Delete domain" → confirm the optimistic removal + Undo toast; click Undo → it reappears.
  4. Type in the filter → columns narrow; collapse an agent via its chevron → its servers/domains hide.
- **Pass:** Graph, inspector, context menu, undoable delete, filter, and collapse all behave; counts/error line match the data.
- **Coverage:** D.
- **Pitfalls:** The SVG connectors are decorative (`aria-hidden`); relationships are exposed to screen readers via an `sr-only` summary + per-node aria labels (`Topology.tsx:203-249`) — don't flag missing connector accessibility as a bug. Connector geometry is measured from the DOM (`ResizeObserver` + a 60 ms late `setTimeout` for fonts); on a slow first paint lines may appear a beat after the nodes — that is expected.

### Command palette (⌘K / Ctrl+K)
- **Must:** `components/CommandPalette.tsx` is mounted in **every** shell. ⌘K (mac) / Ctrl+K toggles it (`CommandPalette.tsx:45`); Escape closes. It offers: "Go to …" navigation for each route, "New domain", "Toggle theme", and "Switch to <variant>" for each of the four variants. Type-to-filter by label.
- **Access:** ⌘K / Ctrl+K anywhere in the dashboard (the only navigation in Wallboard).
- **Steps:** Press ⌘K → palette opens with focus in the search box; type "set" → Settings command filters in; Enter navigates. Use it to switch variants and toggle theme. Press Escape to close.
- **Pass:** Palette opens/closes via keyboard, filters, and runs navigation + variant/theme actions.
- **Coverage:** D.
- **Pitfalls:** This is the only way to navigate in Wallboard — verify it there specifically.

### i18n / language selector
- **Must:** `web/src/lib/i18n.ts` ships two languages: English (`en`) and Deutsch (`de`), `LANGUAGES`. Detection order is `localStorage` then `navigator`, cached in `localStorage` key **`nurproxy-lang`**; fallback is `en`. The selector lives in Settings → Appearance (`pages/Settings.tsx:224-228`) and calls `i18n.changeLanguage`.
- **Access:** Settings → Appearance → Language dropdown.
- **Steps:** Switch the language to Deutsch; confirm nav labels and headings change immediately; reload and confirm it persists (key `nurproxy-lang`). Switch back to English.
- **Pass:** Both languages render; selection persists across reloads.
- **Coverage:** D.
- **Pitfalls:** A first-load language can come from the browser's `navigator` language if no `nurproxy-lang` is set — clear it to test the default. Only `en`/`de` are supported; no other languages should appear in the dropdown.

### Help / wiki system
- **Must:** `pages/Help.tsx` + `lib/wiki.ts` render bundled markdown topics from `wiki/*.md` (imported `?raw`). Topics (in order): getting-started, cloudflare-token, agent-reachability, agents, servers, domains, existing-proxies, existing-proxy-permissions, dns-modes, security, cli, troubleshooting, glossary (`wiki.ts` `TOPICS`). `/help` with no slug shows the default (**getting-started**, `DEFAULT_SLUG`). An **unknown** slug redirects to `/help` (`Help.tsx:14-16`). Sidebar links navigate between topics; the active topic is highlighted.
- **Access:** "Docs" link in every shell; deep links `/help/:slug`; in-context HelpTip links (e.g. Settings → "/help/cloudflare-token").
- **Steps:**
  1. Open `/help` → getting-started renders; sidebar lists all 13 topics.
  2. Click through several topics; confirm content + active highlight update.
  3. Visit `/help/does-not-exist` → redirects to `/help`.
- **Pass:** All topics render; default + unknown-slug fallback behave.
- **Coverage:** D.
- **Pitfalls:** Topics are compiled into the bundle from `wiki/*.md` — content changes require a `web-build` (i.e. a rebuilt binary), not just an orchestrator restart.

### Global chrome: theme toggle & notification bell
- **Must:** Every shell header/rail includes a theme toggle (`lib/theme`) and a `NotificationBell` (`components/NotificationBell.tsx`). Theme choice persists (theme context); the bell surfaces notifications.
- **Access:** Header/rail in all shells; theme also via ⌘K "Toggle theme".
- **Steps:** Toggle theme → colors flip and persist across reload; open the notification bell → its panel renders.
- **Pass:** Theme persists; bell opens.
- **Coverage:** D. Notification semantics → the notifications feature spec.

## Acceptance checklist

### Dry (every RC)
- [ ] `make dev-sandbox` serves the dashboard on `:8099`; all six nav routes + Docs load.
- [ ] Unknown path and `/login` (authenticated) redirect to `/`; `/help/:slug` deep link works; unknown slug → `/help`.
- [ ] All four shell variants render, switch instantly, persist via `nurproxy-ui`, default to `classic`; Wallboard has no nav (⌘K only); Workbench badges match counts.
- [ ] Auth: fresh dry instance → create-admin Login; logout → sign-in Login; orchestrator down → error card with working Retry (no fail-open).
- [ ] Setup wizard appears once on a bare dry instance, skipped thereafter (and pre-skipped on the seeded sandbox).
- [ ] Dry-run banner shows correct scope (`DNS + ACME` under `NP_DRY_RUN`; `ACME` under `NP_ACME_DRY_RUN`); absent on a live instance.
- [ ] Overview: health panel counts degraded agents; stale note on outage; audit source chips render. Polls 30s.
- [ ] Page poll cadences observed: Agents 5s, Config 15s, Overview/Wallboard/Spreadsheet/Topology 30s, Workbench nav badges 30s.
- [ ] Settings: variant + language switch; Cloudflare provider add (dummy token) → zone select → save; reconciler interval (min 5); ACME email; password change validation; API key generate-once/regenerate/revoke; System version+status.
- [ ] Topology: 4 columns + connectors, inspector, context menu (incl. Approve/Reject on pending, undoable domain delete), filter, collapse.
- [ ] Command palette opens/closes (⌘K/Ctrl+K, Esc), filters, runs nav + variant + theme actions; usable in Wallboard.
- [ ] i18n: en/de switch + persist (`nurproxy-lang`); Help: 13 topics, default getting-started, unknown-slug fallback.
- [ ] Theme toggle persists; notification bell opens.

### Real run (before final)
- [ ] Dashboard loads from the **embedded** build of the release binary (`make build`, not `build-headless`).
- [ ] Plain-HTTP-by-IP dashboard login works (secure-cookie regression guard, `docs/RELEASE-QA.md` §2.8).
- [ ] Dry-run banner is **absent** on the real (non-dry) instance.
- [ ] Live status badges (agents adopting, domains issuing real certs) progress correctly through the UI end to end.
