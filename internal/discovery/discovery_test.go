package discovery

import (
	"encoding/json"
	"errors"
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

func TestMergeConfig(t *testing.T) {
	info := Info{
		SecretFields:      []string{"token_secret"},
		SecretBoundFields: []string{"url", "verify_tls", "fingerprint"},
	}
	base := json.RawMessage(`{"url":"https://pve.lan:8006","token_secret":"s3cret","verify_tls":true,"name_hint":"x"}`)
	tests := []struct {
		name       string
		update     string
		wantSecret string // expected token_secret after the merge
		wantErr    bool
		secretErr  bool // error must be ErrSecretRequired
	}{
		{name: "unrelated field keeps secret", update: `{"name_hint":"y"}`, wantSecret: "s3cret"},
		{name: "empty secret keeps secret", update: `{"name_hint":"y","token_secret":""}`, wantSecret: "s3cret"},
		{name: "same bound values keep secret", update: `{"url":"https://pve.lan:8006","verify_tls":true}`, wantSecret: "s3cret"},
		{name: "new secret replaces stored", update: `{"token_secret":"new"}`, wantSecret: "new"},
		{name: "url change with new secret", update: `{"url":"https://other:8006","token_secret":"new"}`, wantSecret: "new"},
		{name: "url change without secret", update: `{"url":"https://evil.example"}`, wantErr: true, secretErr: true},
		{name: "url change with empty secret", update: `{"url":"https://evil.example","token_secret":""}`, wantErr: true, secretErr: true},
		{name: "tls check turned off without secret", update: `{"verify_tls":false}`, wantErr: true, secretErr: true},
		{name: "fingerprint added without secret", update: `{"fingerprint":"AA:BB"}`, wantErr: true, secretErr: true},
		{name: "bound key in other case", update: `{"Fingerprint":"AA:BB"}`, wantErr: true},
		{name: "url key in other case", update: `{"URL":"https://evil.example"}`, wantErr: true},
		{name: "secret key in other case", update: `{"Token_Secret":""}`, wantErr: true},
		{name: "non-object update", update: `[]`, wantErr: true},
		{name: "null update", update: `null`, wantErr: true},
	}
	for _, tt := range tests {
		got, err := MergeConfig(base, json.RawMessage(tt.update), info)
		if tt.wantErr {
			if err == nil {
				t.Errorf("%s: want error, got %s", tt.name, got)
			} else if tt.secretErr && !errors.Is(err, ErrSecretRequired) {
				t.Errorf("%s: want ErrSecretRequired, got %v", tt.name, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error: %v", tt.name, err)
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(got, &m); err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if m["token_secret"] != tt.wantSecret {
			t.Errorf("%s: token_secret = %v, want %q", tt.name, m["token_secret"], tt.wantSecret)
		}
	}
}

func TestMergeConfigNoStoredSecret(t *testing.T) {
	info := Info{SecretFields: []string{"token_secret"}, SecretBoundFields: []string{"url"}}
	// Nothing stored to leak, so changing the endpoint is fine.
	if _, err := MergeConfig(json.RawMessage(`{"url":"a"}`), json.RawMessage(`{"url":"b"}`), info); err != nil {
		t.Fatalf("unexpected error: %v", err)
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
