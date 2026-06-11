package netdiscover

import (
	"reflect"
	"testing"
)

func TestFromInterfaces_basicIPv4(t *testing.T) {
	got := FromInterfaces([]Iface{
		{Name: "eth0", Up: true, CIDRs: []string{"192.168.178.42/24"}},
	})
	want := []Network{{Interface: "eth0", Address: "192.168.178.42", PrefixLength: 24, Network: "192.168.178.0/24"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestFromInterfaces_filters(t *testing.T) {
	got := FromInterfaces([]Iface{
		{Name: "lo", Up: true, Loopback: true, CIDRs: []string{"127.0.0.1/8"}},
		{Name: "eth1", Up: false, CIDRs: []string{"10.0.0.5/24"}},     // down
		{Name: "docker0", Up: true, CIDRs: []string{"172.17.0.1/16"}}, // virtual
		{Name: "br-abc", Up: true, CIDRs: []string{"172.18.0.1/16"}},  // virtual
		{Name: "veth123", Up: true, CIDRs: []string{"10.1.1.1/24"}},   // virtual
		{Name: "wlan0", Up: true, CIDRs: []string{"169.254.1.2/16"}},  // link-local
		{Name: "eth0", Up: true, CIDRs: []string{"192.168.1.10/24"}},  // keep
	})
	if len(got) != 1 || got[0].Network != "192.168.1.0/24" {
		t.Fatalf("only the real up interface should survive, got %+v", got)
	}
}

func TestFromInterfaces_keepsVPN(t *testing.T) {
	got := FromInterfaces([]Iface{
		{Name: "tailscale0", Up: true, CIDRs: []string{"100.64.0.5/32"}},
		{Name: "wg0", Up: true, CIDRs: []string{"10.8.0.2/24"}},
	})
	if len(got) != 2 {
		t.Fatalf("VPN tunnels are reachable networks and should be kept, got %+v", got)
	}
}

func TestFromInterfaces_multipleAddrsAndDedup(t *testing.T) {
	got := FromInterfaces([]Iface{
		{Name: "eth0", Up: true, CIDRs: []string{"192.168.1.10/24", "192.168.1.11/24", "10.0.0.2/8"}},
	})
	// .10 and .11 share the same /24 network → de-duped to one entry; plus the /8.
	if len(got) != 2 {
		t.Fatalf("same-network addresses should dedup, got %+v", got)
	}
}

func TestFromInterfaces_ipv6GlobalKeptLinkLocalDropped(t *testing.T) {
	got := FromInterfaces([]Iface{
		{Name: "eth0", Up: true, CIDRs: []string{"fe80::1/64", "2001:db8:1::5/64"}},
	})
	if len(got) != 1 || got[0].Network != "2001:db8:1::/64" {
		t.Fatalf("link-local v6 dropped, global v6 kept: got %+v", got)
	}
}

func TestFromInterfaces_garbageCidrIgnored(t *testing.T) {
	got := FromInterfaces([]Iface{{Name: "eth0", Up: true, CIDRs: []string{"not-a-cidr", "192.168.5.5/24"}}})
	if len(got) != 1 || got[0].Network != "192.168.5.0/24" {
		t.Fatalf("garbage CIDR should be skipped, got %+v", got)
	}
}

func TestCollect_neverPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Collect panicked: %v", r)
		}
	}()
	_ = Collect() // whatever this CI host has; just must not blow up
}
