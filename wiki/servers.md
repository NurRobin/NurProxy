# Servers

A **server** is a backend an agent forwards traffic to — an address like `192.168.1.10:8080` or `app.internal:3000`. Servers belong to an agent: each one represents something reachable from that edge host. Domains then point at a server, and the agent proxies the subdomain to it.

## Adding a server

Open **Servers**, pick the agent, and enter a name, the address (`host:port`), and optional notes. The name is just a label for you; the address is what the agent connects to.

## Suggestions from an existing nginx config

When an agent manages a host nginx (Existing mode), NurProxy reads that nginx config and lists the backends it already proxies to, under **"Suggested from this agent's nginx config"**. Each suggestion shows the address and the vhost `server_name`s that reference it.

This is read-only. Nothing is created automatically — you click **Add** on a suggestion, which prefills the form with the address and a name taken from the vhost, and you confirm. It is meant to save you from re-typing backends the box already knows about. A suggestion disappears once a server with that address exists.

The scan resolves both direct `proxy_pass http://host:port` targets and named `upstream { ... }` blocks. Targets that use variables (`proxy_pass $backend`) are skipped, because there is no fixed address to suggest.

## Servers and domains

A domain is the public side (the subdomain and its DNS record); a server is the private side (where the traffic goes). One server can back many domains. Deleting an agent removes its servers; a server in use by a domain is shown with its usage count so you do not pull it out from under a live route by accident.

See also: [Domains](domains), [Managing existing proxies](existing-proxies).
