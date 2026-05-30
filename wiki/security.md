# Security notes

NurProxy is self-hosted infrastructure that edits your DNS and serves your
traffic. A few things worth knowing.

## The admin account

- There is **one admin password**, set on first launch. There is **no email
  reset** — store it somewhere safe.
- Change it anytime in **Settings → Authentication**.

## DNS provider tokens

- Tokens are encrypted at rest (AES-256-GCM) before storage.
- Use the **least privilege** that works: Zone → Read and DNS → Edit, scoped to
  only the zones you manage. See [Creating a Cloudflare API token](cloudflare-token).
- Revoke the token in your provider if you stop using NurProxy.

## Admin API key

- The API key in **Settings** is a `Bearer` token for programmatic access and the
  MCP server. It's shown **once** at creation — copy it then.
- **Regenerate** to roll it; **Revoke** to disable programmatic access entirely.

## Agent trust

- Only **approve** agents you installed yourself. Approving an agent lets it
  receive proxy and DNS configuration from the orchestrator.
- Reject anything unexpected in the pending list.

## Existing-mode agents (managing an installed nginx/Apache)

- An agent in **Existing** mode edits proxy config files and reloads the service.
  Grant it the **least privilege** that works — group-write on the config dir and
  a sudoers line scoped to exactly the test + reload commands, never blanket
  `sudo`. Full setup and a copy-paste sudoers snippet:
  [Existing-mode permissions](existing-proxy-permissions).
- With **central TLS**, certificate private keys are pushed to the agent and
  stored encrypted at rest. Prefer **per-host certs** (default) over a shared
  **wildcard**, which puts one private key on every agent that serves it. See the
  threat model in [Existing-mode permissions](existing-proxy-permissions).
- The agent only ever **dials out**; the orchestrator never connects to it. An
  agent does not need to be reachable from the internet.
