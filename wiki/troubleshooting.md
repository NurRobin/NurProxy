# Troubleshooting

A short list of the problems people actually hit, and where to look.

## The agent never shows up for approval

The agent dials out to the orchestrator; the orchestrator never reaches in. So the agent needs a URL it can reach from its own network, which is often not the URL in your browser's address bar. This is the most common snag. See [Agent can't connect](agent-reachability).

## Existing nginx/Apache: "missing permissions"

In Existing mode the agent validates and reloads the host proxy, which means it has to write the config directory, reload the service, and read the proxy's TLS keys. The dashboard shows a checklist with the exact, least-privilege commands for whatever is missing. The fix depends on how the agent runs (root under a systemd sandbox vs an unprivileged user), and the dashboard picks the right one. See [Existing-mode permissions](existing-proxy-permissions).

## Reload fails with "exit status 1"

The reload self-test runs the proxy's own config test (`nginx -t`). The dashboard now shows the proxy's real output, so look there first — it usually names the file it could not open. A `permission denied` on a TLS key or log is a capability/ownership issue, not a config error. A genuine config error (a missing `include` or certificate) shows up the same way when you run `sudo nginx -t` on the host.

## Logs won't tail

The agent tails a log only while the viewer is open, and dials out for every line. If a log shows nothing, confirm the path exists on the host and that the agent can read it.

## On-disk config changed and the dashboard flags drift

NurProxy owns only its own `nurproxy-*` artifacts. If one is edited on the host, it surfaces as drift you can **Accept** (keep the on-disk edit) or revert. Hand-written vhosts are never touched without an explicit Accept.

See also: [Agents](agents), [Managing existing proxies](existing-proxies), [Security](security).
