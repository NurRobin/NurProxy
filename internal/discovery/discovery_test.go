package discovery

import (
	"encoding/json"
	"testing"
)

func TestNewAddressKinds(t *testing.T) {
	tests := []struct {
		ip, iface, kind string
		ok              bool
	}{
		{"192.168.1.10", "eth0", KindPrivate, true},
		{"10.0.0.5", "ens18", KindPrivate, true},
		{"fd00::5", "eth0", KindPrivate, true},
		{"100.101.102.103", "tailscale0", KindShared, true},
		{"203.0.113.7", "eth0", KindPublic, true},
		{"2001:db8::1", "eth0", KindPublic, true},
		{"127.0.0.1", "lo", KindLoopback, true},
		{"fe80::1%eth0", "eth0", KindLinkLocal, true},
		{"169.254.10.1", "eth0", KindLinkLocal, true},
		{"172.17.0.1", "docker0", KindContainerBridge, true},
		{"172.18.0.1", "br-1a2b3c", KindContainerBridge, true},
		{"172.17.0.2", "", KindContainerBridge, true},
		{"172.17.0.2", "eth0", KindPrivate, true},
		{"0.0.0.0", "eth0", "", false},
		{"224.0.0.1", "eth0", "", false},
		{"not-an-ip", "eth0", "", false},
	}
	for _, tt := range tests {
		a, ok := NewAddress(tt.ip, 0, tt.iface)
		if ok != tt.ok || a.Kind != tt.kind {
			t.Errorf("NewAddress(%q, %q) = %+v, %v; want kind %q ok %v", tt.ip, tt.iface, a, ok, tt.kind, tt.ok)
		}
	}
}

func TestSuggestPrefersLANIPv4(t *testing.T) {
	mk := func(ip, iface string) Address {
		a, ok := NewAddress(ip, 0, iface)
		if !ok {
			t.Fatalf("bad fixture %s", ip)
		}
		return a
	}
	tests := []struct {
		name  string
		addrs []Address
		want  string
	}{
		{"lan over public and docker", []Address{mk("203.0.113.7", "eth1"), mk("172.17.0.1", "docker0"), mk("192.168.1.10", "eth0")}, "192.168.1.10"},
		{"lan v4 over ula", []Address{mk("fd00::5", "eth0"), mk("10.0.0.5", "eth0")}, "10.0.0.5"},
		{"tailscale over public", []Address{mk("203.0.113.7", "eth0"), mk("100.64.0.9", "tailscale0")}, "100.64.0.9"},
		{"only unusable", []Address{mk("127.0.0.1", "lo"), mk("fe80::1", "eth0"), mk("172.17.0.1", "docker0")}, ""},
		{"none", nil, ""},
	}
	for _, tt := range tests {
		if got := Suggest(tt.addrs); got != tt.want {
			t.Errorf("%s: Suggest = %q, want %q", tt.name, got, tt.want)
		}
		sorted := SortAddresses(tt.addrs)
		if tt.want != "" && sorted[0].IP != tt.want {
			t.Errorf("%s: SortAddresses first = %q, want %q", tt.name, sorted[0].IP, tt.want)
		}
		if len(sorted) != len(tt.addrs) {
			t.Errorf("%s: SortAddresses dropped addresses: %+v", tt.name, sorted)
		}
	}
}

func TestMergeConfigKeepsSecret(t *testing.T) {
	base := json.RawMessage(`{"url":"a","token_secret":"s3cret","verify_tls":true}`)
	got, err := MergeConfig(base, json.RawMessage(`{"verify_tls":false,"token_secret":""}`), []string{"token_secret"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatal(err)
	}
	if m["token_secret"] != "s3cret" || m["verify_tls"] != false || m["url"] != "a" {
		t.Fatalf("merged = %s", got)
	}
	got, _ = MergeConfig(base, json.RawMessage(`{"token_secret":"new"}`), []string{"token_secret"})
	if err := json.Unmarshal(got, &m); err != nil || m["token_secret"] != "new" {
		t.Fatalf("a new secret must replace the stored one: %s", got)
	}
	if _, err := MergeConfig(base, json.RawMessage(`[]`), nil); err == nil {
		t.Fatal("a non-object update must be rejected")
	}
}

func TestResultCovers(t *testing.T) {
	r := &Result{Incomplete: []string{"pve/pve2/", "pve/pve1/lxc/"}}
	for id, want := range map[string]bool{
		"pve/pve1/qemu/101": true,
		"pve/pve1/lxc/200":  false,
		"pve/pve2/qemu/300": false,
	} {
		if r.Covers(id) != want {
			t.Errorf("Covers(%q) = %v, want %v", id, !want, want)
		}
	}
}
