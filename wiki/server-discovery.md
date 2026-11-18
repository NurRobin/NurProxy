# Server discovery (Proxmox VE)

Instead of typing every backend by hand, NurProxy can ask a Proxmox VE node or
cluster which VMs and containers exist, and offer them as servers. Discovery
only suggests. You pick which machines become servers, under which agent, and
the imported servers stay ordinary, editable servers.

## What it reads

- **QEMU VMs** and **LXC containers** on every online node of the cluster.
  Templates are skipped.
- **Addresses**, in this order:
  1. For a running VM, the QEMU guest agent (`qemu-guest-agent` must be
     installed in the guest and enabled in the VM options).
  2. Otherwise the static `ip=` / `ip6=` of the VM's cloud-init `ipconfigN`.
  3. For a running container, its live interfaces; otherwise the static
     `ip=` / `ip6=` of its `netN` config.
  4. Nothing found: the machine is still listed, and you type the address when
     you import it. DHCP-only VMs without a guest agent end up here.

Every address the source reports stays visible. NurProxy suggests the most
likely LAN address: private IPv4 (RFC 1918) first, then CGNAT/VPN ranges such
as Tailscale, then public IPv4, then IPv6. Loopback, link-local and container
bridge addresses (`docker0`, `br-*`, `veth*`, ...) are shown struck through and
never suggested. The suggestion is what Proxmox sees; the address must be
reachable **from the agent**, so check it before you import.

## Create an API token

Discovery runs on the orchestrator, so the orchestrator must reach the Proxmox
API (port 8006). Use an API token, not a password, and keep it read-only:

1. In the Proxmox UI open **Datacenter → Permissions → Users** and add a user,
   e.g. `nurproxy@pve` (no password needed).
2. **Datacenter → Permissions → API Tokens → Add**: user `nurproxy@pve`, token
   ID `discovery`. Leave **Privilege Separation** on. Copy the secret; Proxmox
   shows it once.
3. **Datacenter → Permissions → Add → API Token Permission**: path `/`, token
   `nurproxy@pve!discovery`, role **PVEAuditor** (Sys.Audit, VM.Audit, ...).
4. Guest-agent addresses need one more privilege: `VM.Monitor` on PVE 8,
   `VM.GuestAgent.Audit` on PVE 9. Without it, VMs fall back to their
   cloud-init address.

The token ID you enter in NurProxy is the full `nurproxy@pve!discovery`.

## Add the source

**Settings → Server discovery → Add source**:

- **API URL**: any cluster node, e.g. `https://pve1.lan:8006`. Without a port,
  8006 is used.
- **Token ID** and **Token secret**.
- **TLS**: Proxmox nodes ship a self-signed certificate. Either paste the
  node's **SHA-256 fingerprint** (Node → System → Certificates), which then is
  the only certificate accepted, or paste the cluster CA
  (`/etc/pve/pve-root-ca.pem`) and keep verification on. Turning verification
  off without a fingerprint lets anyone on the path read the token.
- **Re-sync**: only on demand, or every 15 minutes to 24 hours.

**Test connection** checks the token and that it can list the nodes. If the
cluster is not reachable yet, tick *Save without testing the connection*.

The token secret is stored encrypted (AES-256-GCM, like DNS provider tokens)
and is never shown again or written to logs or the audit log. To change other
settings later, leave the secret field empty and the stored one is kept.

## Import servers

On **Servers**, each agent has **Discover from Proxmox VE**. The dialog shows
the last result of the source; **Discover now** asks the cluster again. Tick
the machines this agent should proxy to, adjust names and addresses, and
import. Machines that are already imported (under any agent) are greyed out,
so a VM is never imported twice. A selected machine without an address blocks
the import until you enter one or untick it.

Imported servers carry a small badge with the source name. You can edit or
delete them like any other server; a re-sync never overwrites your edits.

## Re-sync and gone machines

Every run (on demand or periodic) stores the result. Machines that are new
since your import show up as selectable rows. An imported server whose machine
the source no longer reports gets a **Gone from source** badge, and the event
lands in the audit log (`discovery_missing`, and `discovery_found` when it comes
back). NurProxy does not delete such a server on its own: its domains keep
working until you decide.

A machine is only marked gone when the run actually covered it. If a node is
offline, its guests are skipped with a warning and nothing on it is marked
gone. A VM that migrates to another node keeps its server: the VMID identifies
it within the cluster.

Deleting a source keeps every server imported from it as a normal server.

## CLI

```bash
nurproxy discovery add --name homelab \
  --config '{"url":"https://pve1.lan:8006","token_id":"nurproxy@pve!discovery","token_secret":"...","fingerprint":"AB:CD:..."}' \
  --sync-interval 3600
nurproxy discovery list
nurproxy discovery run <source-id>          # ask the cluster now, print the machines
nurproxy discovery candidates <source-id>   # last stored result, no API call
nurproxy discovery import <source-id> --agent <agent-id> --id pve/pve1/qemu/101 --id pve/pve1/lxc/200
nurproxy discovery import <source-id> --agent <agent-id> --all \
  --address pve/pve1/qemu/103=192.168.10.23  # --all skips machines without an address unless given
nurproxy discovery update <source-id> --config '{"verify_tls":true}'   # other keys are kept
nurproxy discovery delete <source-id>
```

## Dry-run

In dry-run mode (`NP_DRY_RUN=true`, or `NP_DISCOVERY_DRY_RUN=true` alone) no
Proxmox API is contacted. The connection test always passes and every run
returns the same small cluster: four guests on `pve1` (one with a guest agent
and a docker bridge, one cloud-init VM, one stopped VM without an address, one
container) and an offline `pve2`.

See also: [Servers](servers), [CLI](cli).
