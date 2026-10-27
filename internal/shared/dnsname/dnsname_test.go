package dnsname

import (
	"strings"
	"testing"
)

func TestValidateSubdomain(t *testing.T) {
	valid := []string{
		"jellyfin",
		"api",
		"api.internal",
		"a.b.c",
		"x1-y2",
		"*",          // bare wildcard
		"*.internal", // leading wildcard label
		strings.Repeat("a", 63),
	}
	for _, s := range valid {
		if err := ValidateSubdomain(s); err != nil {
			t.Errorf("ValidateSubdomain(%q) = %v, want nil", s, err)
		}
	}

	invalid := []string{
		"",                      // empty
		"-leading",              // leading hyphen
		"trailing-",             // trailing hyphen
		"has space",             // space
		"under_score",           // underscore not allowed in DNS labels
		"a..b",                  // empty label
		".leading-dot",          // empty first label
		"trailing-dot.",         // empty last label
		"foo.*",                 // wildcard not in first position
		"*bad",                  // '*' mixed into a label
		"@.foo",                 // '@' is only valid as the whole apex sentinel
		"foo.@",                 // '@' not a normal label
		"@",                     // apex sentinel is a domain-row concept, not a hostname
		strings.Repeat("a", 64), // label too long
	}
	for _, s := range invalid {
		if err := ValidateSubdomain(s); err == nil {
			t.Errorf("ValidateSubdomain(%q) = nil, want error", s)
		}
	}
}

// TestValidateSubdomainOrApex pins the split: the "@" sentinel passes here (and
// only here), everything else follows the strict rules.
func TestValidateSubdomainOrApex(t *testing.T) {
	if err := ValidateSubdomainOrApex("@"); err != nil {
		t.Errorf("ValidateSubdomainOrApex(\"@\") = %v, want nil", err)
	}
	if err := ValidateSubdomainOrApex("jellyfin"); err != nil {
		t.Errorf("ValidateSubdomainOrApex(\"jellyfin\") = %v, want nil", err)
	}
	for _, s := range []string{"", "@.foo", "foo.@", "-bad"} {
		if err := ValidateSubdomainOrApex(s); err == nil {
			t.Errorf("ValidateSubdomainOrApex(%q) = nil, want error", s)
		}
	}
}

func TestValidateSubdomain_tooLong(t *testing.T) {
	// 255 chars via 4x63 labels exceeds the 253 cap.
	long := strings.Join([]string{
		strings.Repeat("a", 63),
		strings.Repeat("b", 63),
		strings.Repeat("c", 63),
		strings.Repeat("d", 63),
	}, ".")
	if err := ValidateSubdomain(long); err == nil {
		t.Error("expected error for an over-long name")
	}
}
