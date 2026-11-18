# PAIN-43 Dashboard domain save drops proxy_config fields it doesn't show (tls_policy, raw_config, response headers, ...)

github.com/nurrobin/nurproxy | resolved

web/src/pages/Domains.tsx handleSaveDetail sends a freshly built proxy_config (websocket, force_https, max_body_size, request headers, and since #162 access_log / error_log_level). The API replaces the whole stored ProxyConfig with it, so saving the General or Headers tab silently clears tls_policy, raw_config, custom_response_headers, timeouts, basic_auth, IP lists, rate_limit, path rules and upstream_scheme set via API/CLI. Noticed while adding the logging fields in PR #162; not changed there.

## Motivates

- https://github.com/NurRobin/NurProxy/issues/163

## Evidence

- url: https://github.com/NurRobin/NurProxy/pull/164 in v0.5.1, deployed to production orchestrator apps 2026-10-27 (dashboard sends only changed keys; API merges proxy_config key by key) (resolved)

---
Projection from ghosttree. Edits to this file are lost on the next write.
