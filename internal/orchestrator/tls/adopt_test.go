package tls

import (
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

func TestNamesCover(t *testing.T) {
	tests := []struct {
		names []string
		host  string
		want  bool
	}{
		{[]string{"app.example.com"}, "app.example.com", true},
		{[]string{"APP.example.com."}, "app.example.com", true},
		{[]string{"*.example.com"}, "app.example.com", true},
		{[]string{"*.example.com"}, "example.com", false},
		{[]string{"*.example.com"}, "a.b.example.com", false},
		{[]string{"other.example.com", "*.example.org"}, "app.example.com", false},
		{nil, "app.example.com", false},
	}
	for _, tc := range tests {
		if got := NamesCover(tc.names, tc.host); got != tc.want {
			t.Errorf("NamesCover(%v, %q) = %v, want %v", tc.names, tc.host, got, tc.want)
		}
	}
}

func TestAdoptableFor(t *testing.T) {
	now := time.Now()
	good := models.DiscoveredCert{
		Fingerprint: strings.Repeat("a", 64), Names: []string{"app.example.com"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour),
	}
	tests := []struct {
		name       string
		edit       func(*models.DiscoveredCert)
		want       bool
		wantReason string
	}{
		{name: "valid", want: true},
		{name: "scan error", edit: func(d *models.DiscoveredCert) { d.Error = "private key does not match the certificate" }, wantReason: "does not match"},
		{name: "no fingerprint", edit: func(d *models.DiscoveredCert) { d.Fingerprint = ""; d.Error = "cannot read" }, wantReason: "cannot read"},
		{name: "other host", edit: func(d *models.DiscoveredCert) { d.Names = []string{"x.example.com"} }, wantReason: "does not cover"},
		{name: "not yet valid", edit: func(d *models.DiscoveredCert) { d.NotBefore = now.Add(time.Hour) }, wantReason: "not valid yet"},
		{name: "expired", edit: func(d *models.DiscoveredCert) { d.NotAfter = now.Add(-time.Minute) }, wantReason: "expired"},
		{name: "renew window", edit: func(d *models.DiscoveredCert) { d.NotAfter = now.Add(DefaultRenewWindow - time.Hour) }, wantReason: "renew window"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dc := good
			if tc.edit != nil {
				tc.edit(&dc)
			}
			ok, reason := AdoptableFor(dc, "app.example.com", now)
			if ok != tc.want || !strings.Contains(reason, tc.wantReason) {
				t.Errorf("AdoptableFor = %v, %q; want %v, %q", ok, reason, tc.want, tc.wantReason)
			}
		})
	}
}

func TestLeafFingerprint(t *testing.T) {
	if _, err := LeafFingerprint("no pem here"); err == nil {
		t.Error("garbage accepted")
	}
	fp, err := LeafFingerprint("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
	if err != nil || len(fp) != 64 {
		t.Errorf("LeafFingerprint = %q, %v; want the certificate block's hash", fp, err)
	}
}
