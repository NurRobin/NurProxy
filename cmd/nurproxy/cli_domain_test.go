package main

import (
	"flag"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

func TestDNSCell(t *testing.T) {
	tests := []struct {
		name string
		dom  models.Domain
		want string
	}{
		{"no record yet", models.Domain{}, "none"},
		{"created or taken over", models.Domain{DNSRecordID: "r1", DNSManaged: true}, "managed"},
		{"adopted", models.Domain{DNSRecordID: "r1"}, "adopted"},
		{"cert-only", models.Domain{CertOnly: true}, "operator"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := dnsCell(tc.dom); got != tc.want {
				t.Errorf("dnsCell = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTakeoverText(t *testing.T) {
	raw := []byte(`{"dry_run":true,"message":"would delete 2 record(s) at app.example.com","plan":{"delete":[
		{"id":"r1","type":"A","name":"app.example.com","content":"203.0.113.9","proxied":true},
		{"id":"r2","type":"MX","name":"app.example.com","content":"mail.example.com"}]}}`)
	got := takeoverText(raw, true, "7")
	for _, want := range []string{
		"dry run, nothing changed: would delete 2 record(s)",
		"delete A app.example.com -> 203.0.113.9 (proxied) [r1]",
		"delete MX app.example.com -> mail.example.com [r2]",
		"dns-takeover --expect-delete r1,r2 7",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output %q does not contain %q", got, want)
		}
	}
}

func TestExpectDeleteIDs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    []string
		wantSet bool
	}{
		{"flag absent", nil, nil, false},
		{"ids", []string{"-expect-delete", "r1, r2"}, []string{"r1", "r2"}, true},
		{"none", []string{"-expect-delete", "none"}, []string{}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("t", flag.ContinueOnError)
			var v string
			fs.StringVar(&v, "expect-delete", "", "")
			if err := fs.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			got, set := expectDeleteIDs(fs, v)
			if set != tc.wantSet || strings.Join(got, ",") != strings.Join(tc.want, ",") || (got == nil) != (tc.want == nil) {
				t.Errorf("expectDeleteIDs = %#v, %v; want %#v, %v", got, set, tc.want, tc.wantSet)
			}
		})
	}
}
