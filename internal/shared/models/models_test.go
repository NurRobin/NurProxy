package models

import (
	"encoding/json"
	"testing"
)

func TestDomain_FQDN(t *testing.T) {
	tests := []struct {
		name     string
		sub      string
		zone     string
		expected string
	}{
		{"simple", "app", "example.com", "app.example.com"},
		{"nested subdomain", "api.v2", "example.com", "api.v2.example.com"},
		{"wildcard", "*", "example.com", "*.example.com"},
		{"long zone", "svc", "my.long.zone.name", "svc.my.long.zone.name"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := Domain{Subdomain: tt.sub}
			got := d.FQDN(tt.zone)
			if got != tt.expected {
				t.Errorf("FQDN(%q) = %q, want %q", tt.zone, got, tt.expected)
			}
		})
	}
}

func TestAgentStatus_Values(t *testing.T) {
	tests := []struct {
		status AgentStatus
		want   string
	}{
		{AgentStatusPending, "pending"},
		{AgentStatusAdopted, "adopted"},
		{AgentStatusOffline, "offline"},
		{AgentStatusError, "error"},
	}
	for _, tt := range tests {
		if string(tt.status) != tt.want {
			t.Errorf("AgentStatus = %q, want %q", tt.status, tt.want)
		}
	}
}

func TestDomainStatus_Values(t *testing.T) {
	tests := []struct {
		status DomainStatus
		want   string
	}{
		{DomainStatusPending, "pending"},
		{DomainStatusActive, "active"},
		{DomainStatusError, "error"},
		{DomainStatusDeleting, "deleting"},
	}
	for _, tt := range tests {
		if string(tt.status) != tt.want {
			t.Errorf("DomainStatus = %q, want %q", tt.status, tt.want)
		}
	}
}

func TestProvider_ConfigOmittedFromJSON(t *testing.T) {
	p := Provider{
		ID:     "prov-1",
		Type:   "cloudflare",
		Name:   "My CF",
		Config: "secret-encrypted-data",
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["config"]; ok {
		t.Error("Provider.Config should be omitted from JSON (json:\"-\") but was present")
	}
}

func TestNotifier_ConfigOmittedFromJSON(t *testing.T) {
	n := Notifier{
		ID:     "notif-1",
		Type:   "webhook",
		Name:   "alerts",
		Config: "secret-webhook-url",
	}
	data, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["config"]; ok {
		t.Error("Notifier.Config should be omitted from JSON (json:\"-\") but was present")
	}
}

func TestAgent_TokenHashOmittedFromJSON(t *testing.T) {
	a := Agent{
		ID:        "agent-1",
		Name:      "test",
		TokenHash: "supersecret",
	}
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["token_hash"]; ok {
		t.Error("Agent.TokenHash should be omitted from JSON (json:\"-\") but was present")
	}
}

func TestSSLMode_Values(t *testing.T) {
	tests := []struct {
		mode SSLMode
		want string
	}{
		{SSLModeAuto, "auto"},
		{SSLModeManual, "manual"},
		{SSLModeOff, "off"},
	}
	for _, tt := range tests {
		if string(tt.mode) != tt.want {
			t.Errorf("SSLMode = %q, want %q", tt.mode, tt.want)
		}
	}
}

func TestDNSMode_Values(t *testing.T) {
	tests := []struct {
		mode DNSMode
		want string
	}{
		{DNSModeStatic, "static"},
		{DNSModeDDNS, "ddns"},
	}
	for _, tt := range tests {
		if string(tt.mode) != tt.want {
			t.Errorf("DNSMode = %q, want %q", tt.mode, tt.want)
		}
	}
}
