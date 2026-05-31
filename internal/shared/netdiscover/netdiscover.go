// Package netdiscover derives the IP networks attached to a host's interfaces so
// the dashboard can suggest them when adding a Server for an agent (#38), instead
// of making the operator retype a CIDR they already live on. It is read-only and
// best-effort: loopback, down, link-local and obvious container/bridge interfaces
// are dropped; everything else (including VPN tunnels, which are reachable
// networks) is kept. The classification is a pure function over a plain interface
// list so it is table-testable without touching the real host.
package netdiscover

import (
	"net"
	"strings"
)

// Network is one usable network attached to an interface. Address is the host's
// own address on it; Network is the CIDR of the surrounding subnet (the useful
// suggestion). PrefixLength is the mask width.
type Network struct {
	Interface    string `json:"interface"`
	Address      string `json:"address"`
	PrefixLength int    `json:"prefix_length"`
	Network      string `json:"network"`
}

// Iface is the minimal view of a host interface the classifier needs. The agent
// builds this from net.Interfaces(); tests build it by hand.
type Iface struct {
	Name     string
	Up       bool
	Loopback bool
	CIDRs    []string // e.g. "192.168.178.42/24", "fe80::1/64"
}

// virtualPrefixes are interface-name prefixes for container/bridge/virtual nets
// that are noise in a "which subnet is this box on" suggestion. VPN tunnels
// (tun/wg/tailscale) are intentionally NOT here: those are reachable networks.
var virtualPrefixes = []string{"docker", "br-", "veth", "cni", "flannel", "virbr", "kube", "cali", "vnet", "fwbr", "fwln", "tap"}

// FromInterfaces classifies a host's interfaces into suggestable networks. It
// drops down/loopback/virtual interfaces and link-local addresses, computes the
// surrounding subnet CIDR for each remaining address, and de-dupes by
// interface+network. Order follows the input.
func FromInterfaces(ifaces []Iface) []Network {
	var out []Network
	seen := map[string]struct{}{}
	for _, ifc := range ifaces {
		if !ifc.Up || ifc.Loopback || isVirtual(ifc.Name) {
			continue
		}
		for _, cidr := range ifc.CIDRs {
			ip, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				continue
			}
			network := ipnet.String() // network address + prefix, e.g. 192.168.178.0/24
			key := ifc.Name + "|" + network
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			ones, _ := ipnet.Mask.Size()
			out = append(out, Network{
				Interface:    ifc.Name,
				Address:      ip.String(),
				PrefixLength: ones,
				Network:      network,
			})
		}
	}
	return out
}

// isVirtual reports whether an interface name is a container/bridge/virtual one
// we exclude from suggestions.
func isVirtual(name string) bool {
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// Collect reads the live host interfaces and classifies them. It is the only
// part that touches the OS; it returns nil on error (best-effort, never fatal).
func Collect() []Network {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	list := make([]Iface, 0, len(ifaces))
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		cidrs := make([]string, 0, len(addrs))
		for _, a := range addrs {
			cidrs = append(cidrs, a.String())
		}
		list = append(list, Iface{
			Name:     ifc.Name,
			Up:       ifc.Flags&net.FlagUp != 0,
			Loopback: ifc.Flags&net.FlagLoopback != 0,
			CIDRs:    cidrs,
		})
	}
	return FromInterfaces(list)
}
