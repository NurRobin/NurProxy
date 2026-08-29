package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"os/user"
	"strconv"
	"testing"

	"github.com/NurRobin/NurProxy/internal/agent/recoverycontrol"
)

func TestBuildRootHelperConfigCompilesOnlyPinnedBackendLayouts(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.ParseUint(current.Uid, 10, 32)
	authority := recoverycontrol.AuthorityPin{
		KeyID: "orchestrator-1", PublicKeyText: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
	}
	for _, kind := range []string{"nginx", "apache"} {
		cfg, err := buildRootHelperConfig(helperBootstrapConfigInput{
			AgentID: "agent-1", AgentUser: current.Username, AgentUID: uint32(uid), BuildID: "dev-build",
			HelperInstanceID: "helper-1", AttestationKeyID: "attestation-1", Authority: authority,
			ProxyKind: kind, ProxyBinary: map[string]string{"nginx": "/usr/sbin/nginx", "apache": "/usr/sbin/apachectl"}[kind],
			ProxyVersion: "1.24.0", DebianLayout: true,
		})
		if err != nil || cfg.Validate() != nil || cfg.AgentUID != uint32(uid) || cfg.ManagedApply == nil {
			t.Fatalf("%s config = %+v, err=%v", kind, cfg, err)
		}
		if cfg.ManagedApply.StagingDir != "/var/lib/nurproxy-agent/helper-staging" || cfg.ManagedApply.CertificateDir != "/var/lib/nurproxy-agent/certs" {
			t.Fatalf("%s mutable roots escaped compiled layout: %+v", kind, cfg.ManagedApply)
		}
	}
	for _, unsafe := range []helperBootstrapConfigInput{
		{ProxyKind: "caddy"},
		{ProxyKind: "nginx", ProxyBinary: "/tmp/nginx"},
	} {
		unsafe.AgentID, unsafe.AgentUser, unsafe.AgentUID, unsafe.BuildID = "agent-1", current.Username, uint32(uid), "dev-build"
		unsafe.HelperInstanceID, unsafe.AttestationKeyID, unsafe.Authority = "helper-1", "attestation-1", authority
		if _, err := buildRootHelperConfig(unsafe); err == nil {
			t.Fatalf("unsafe bootstrap mapping accepted: %+v", unsafe)
		}
	}
}

func TestValidateHelperBootstrapInvocation(t *testing.T) {
	if err := validateHelperBootstrapInvocation(0, "dev-build", "https://proxy.example", "nginx"); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		uid              int
		build, url, kind string
	}{{1000, "dev-build", "https://proxy.example", "nginx"}, {0, "", "https://proxy.example", "nginx"}, {0, "dev-build", "", "nginx"}, {0, "dev-build", "https://proxy.example", "caddy"}} {
		if err := validateHelperBootstrapInvocation(test.uid, test.build, test.url, test.kind); err == nil {
			t.Fatalf("unsafe bootstrap invocation accepted: %+v", test)
		}
	}
}
