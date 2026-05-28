# Agent can't connect

By far the most common setup snag: you ran the install command, but the agent
never appears in the dashboard. Almost always, the agent can't reach the
**orchestrator URL** you gave it.

## The key idea

The orchestrator URL is the address **the agent uses to reach this dashboard**.
It is *not* necessarily the URL you typed into your browser.

- You might open the dashboard at `http://localhost:8080` or `http://192.168.1.5`.
- The agent runs on a *different* machine. `localhost` there means *its own*
  machine — not your dashboard.

So the URL has to be one the edge server can actually reach over the network.

## Pick the right address

Depends on how the two machines are connected:

- **Same host** — `http://localhost:8080` works for the agent too.
- **Same LAN** — use the dashboard host's LAN IP, e.g. `http://192.168.1.5:8080`.
- **Over a VPN** (WireGuard, Tailscale, etc.) — use the dashboard's VPN address.
- **Across the internet** — use a public hostname with HTTPS,
  e.g. `https://nurproxy.example.com`.

## Test it from the edge server

SSH into the edge server and run:

```
curl -v https://your-dashboard-url/api/v1/health
```

- A JSON health response → the URL is good; re-run the agent installer with it.
- Connection refused / timeout → wrong address or a firewall is blocking it.

## Checklist

- The orchestrator URL resolves and responds **from the edge server**.
- Outbound HTTPS (or your chosen port) isn't blocked by a firewall or security group.
- If you used a hostname, its DNS resolves on the edge server.
- Check the agent's logs for the exact connection error.

Once the agent can reach the orchestrator, it registers within a few seconds and
appears under **Agents** for approval.
