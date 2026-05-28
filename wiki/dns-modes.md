# DNS modes: Static vs DDNS

When you approve an agent, you choose how its DNS records get their IP address.

## Static

NurProxy points records at a fixed IP — the agent's current public IP at approval
time. Use this when the edge server has a **stable address**: a cloud VM, a
dedicated server, or anything with a static IP.

## DDNS (Dynamic DNS)

The agent reports its current public IP to the orchestrator on an interval, and
NurProxy updates the records whenever it changes. Use this when the address
**moves** — a home connection on a residential ISP, for example.

- **Interval** controls how often the agent checks in (30–600 seconds). Shorter
  means faster recovery after an IP change, at the cost of slightly more traffic.

## Which should I pick?

- Server in a data center or cloud → **Static**.
- Self-hosting at home / dynamic IP → **DDNS**.

You can change the mode later from the **Agents** page.
