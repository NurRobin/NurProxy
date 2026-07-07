# Custom proxy engine

NurProxy ships native renderers for **nginx**, **apache**, and **caddy**. For any
other reverse proxy (HAProxy, Traefik, lighttpd, …) you can run a **custom
engine**: NurProxy keeps managing routes, certs, and DNS exactly as it does for a
native backend, but renders each route through a config **template you provide**.

## Trust model — why it is local-only

A custom engine is defined by a template plus reload/test commands the agent
executes. That is arbitrary code on the host, so it is configured **only from the
agent's local config** (`agent.yaml` / `NP_PROXY_*` / flags) — the host operator,
who already owns the box, opts in. The orchestrator and dashboard never define a
custom engine over the network; a network-pushed switch to `custom` is refused
(no template), and `cmdguard` still restricts network-supplied commands to the
native engines and service managers.

## Configure it (`agent.yaml`)

```yaml
proxy_mode: existing
proxy_type: custom

# Where rendered per-route files are written (NurProxy owns nurproxy-*.<ext>).
proxy_config_dir: /etc/haproxy/conf.d
proxy_file_ext: .cfg

# Reload is required; test (validate) is optional.
proxy_reload_cmd: systemctl reload haproxy
proxy_test_cmd: haproxy -c -f /etc/haproxy/haproxy.cfg

# Native binary commands (e.g. `haproxy -c`) must be allow-listed past cmdguard.
# Service managers (systemctl, service, rc-service, launchctl) are always allowed.
proxy_allowed_commands: [haproxy]

# The route template — inline here, or point proxy_template_file at a file.
proxy_template: |
  # managed by NurProxy — do not edit
  frontend fe_{{ .Host }}
    bind *:80
    {{- if .CertPath }}
    bind *:443 ssl crt {{ .CertPath }}
    {{- end }}
    default_backend be_{{ .Host }}
  backend be_{{ .Host }}
    server s1 {{ .UpstreamAddr }}{{ if eq .Scheme "https" }} ssl{{ end }}

# What your template supports, so the dashboard greys out the rest.
# reverse_proxy is always implied; default is reverse_proxy + central_tls.
proxy_caps: [websocket, force_https, central_tls]
```

`proxy_template_file: /etc/nurproxy/route.tmpl` is an alternative to the inline
`proxy_template`.

## Template data (`generic.RouteContext`)

Each route is rendered with:

| Field | Meaning |
|-------|---------|
| `.Host` | public FQDN |
| `.UpstreamAddr` | backend `host:port` (`.UpstreamHost`, `.UpstreamPort` separately) |
| `.Scheme` | upstream scheme (`http` / `https`) |
| `.TLS` | true unless the TLS policy is `off` |
| `.Policy` | `central` / `self-acme` / `off` |
| `.CertPath`, `.KeyPath` | on-disk cert + key for a central-TLS route (empty until installed — guard with `{{ if .CertPath }}`) |
| `.ForceHTTPS`, `.WebSocket` | route options |
| `.Route` | the full backend-neutral intent (headers, path rules, timeouts, IP rules, rate limit) |

## What NurProxy manages vs. what you own

- NurProxy writes/validates/reloads/prunes only its own `nurproxy-*.<ext>` files
  (atomic apply with rollback). Your hand-written config is read for adoption but
  **never** overwritten.
- Central TLS certs are issued + renewed by the orchestrator and installed to the
  agent cert store; reference them via `.CertPath` / `.KeyPath`.
- The certificate path stays stable, so a hand-written config can point at it too:
  `<data-dir>/certs/<sanitized-host>.crt` and `…/<sanitized-host>.key.plain`.
