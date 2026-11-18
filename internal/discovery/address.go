package discovery

import (
	"net/netip"
	"sort"
	"strings"
)

// Address kinds, from most to least useful as a backend address.
const (
	KindPrivate         = "private"          // RFC 1918 IPv4 or IPv6 ULA
	KindShared          = "shared"           // 100.64.0.0/10 (CGNAT, Tailscale)
	KindPublic          = "public"           // globally routable
	KindContainerBridge = "container-bridge" // docker0 and friends, inside the guest only
	KindLinkLocal       = "link-local"
	KindLoopback        = "loopback"
)

// Address is one IP address a source reported for a machine.
type Address struct {
	IP        string `json:"ip"`
	Prefix    int    `json:"prefix,omitempty"`
	Interface string `json:"interface,omitempty"`
	Kind      string `json:"kind"`
}

// bridgeInterfacePrefixes are guest interfaces that belong to a container
// runtime or a nested hypervisor. Their addresses only exist inside the guest.
var bridgeInterfacePrefixes = []string{"docker", "br-", "veth", "cni", "flannel", "cali", "virbr", "lxcbr", "lxdbr", "podman", "kube-"}

// dockerDefault is Docker's default bridge network, used when the interface
// name is not available.
var dockerDefault = netip.MustParsePrefix("172.17.0.0/16")
var sharedSpace = netip.MustParsePrefix("100.64.0.0/10")

// NewAddress classifies ip as reported on iface. It returns false for strings
// that are not an IP address and for addresses no backend can have
// (unspecified, multicast).
func NewAddress(ip string, prefix int, iface string) (Address, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return Address{}, false
	}
	addr = addr.Unmap().WithZone("")
	if addr.IsUnspecified() || addr.IsMulticast() {
		return Address{}, false
	}
	a := Address{IP: addr.String(), Prefix: prefix, Interface: iface}
	switch {
	case addr.IsLoopback():
		a.Kind = KindLoopback
	case addr.IsLinkLocalUnicast():
		a.Kind = KindLinkLocal
	case isBridgeInterface(iface) || (iface == "" && dockerDefault.Contains(addr)):
		a.Kind = KindContainerBridge
	case addr.IsPrivate():
		a.Kind = KindPrivate
	case sharedSpace.Contains(addr):
		a.Kind = KindShared
	default:
		a.Kind = KindPublic
	}
	return a, true
}

// ParseCIDRAddress classifies "192.168.1.10/24" (or a bare address).
func ParseCIDRAddress(cidr, iface string) (Address, bool) {
	cidr = strings.TrimSpace(cidr)
	if p, err := netip.ParsePrefix(cidr); err == nil {
		return NewAddress(p.Addr().String(), p.Bits(), iface)
	}
	return NewAddress(cidr, 0, iface)
}

func isBridgeInterface(iface string) bool {
	iface = strings.ToLower(iface)
	for _, p := range bridgeInterfacePrefixes {
		if strings.HasPrefix(iface, p) {
			return true
		}
	}
	return false
}

// rank orders addresses by how likely the agent reaches the machine on them.
// Negative ranks are never suggested.
func rank(a Address) int {
	v4 := strings.Contains(a.IP, ".")
	switch a.Kind {
	case KindPrivate:
		if v4 {
			return 60
		}
		return 30
	case KindShared:
		return 50
	case KindPublic:
		if v4 {
			return 40
		}
		return 20
	}
	return -1
}

// SortAddresses de-duplicates addrs and orders them best first, keeping the
// ones that are never suggested at the end so they stay visible.
func SortAddresses(addrs []Address) []Address {
	seen := make(map[string]bool, len(addrs))
	out := make([]Address, 0, len(addrs))
	for _, a := range addrs {
		if seen[a.IP] {
			continue
		}
		seen[a.IP] = true
		out = append(out, a)
	}
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i]) > rank(out[j]) })
	return out
}

// Suggest returns the best backend address in addrs, or "" if none is usable.
func Suggest(addrs []Address) string {
	best, bestRank := "", -1
	for _, a := range addrs {
		if r := rank(a); r > bestRank {
			best, bestRank = a.IP, r
		}
	}
	if bestRank < 0 {
		return ""
	}
	return best
}
