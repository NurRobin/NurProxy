package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os/user"
	"reflect"
	"strconv"
	"testing"

	"github.com/NurRobin/NurProxy/internal/agent/recoverycontrol"
)

func TestDropHelperBootstrapPrivilegesRejectsRootIdentity(t *testing.T) {
	ops := helperBootstrapPrivilegeOps{}
	for _, identity := range [][2]uint32{{0, 1000}, {1000, 0}} {
		if err := dropHelperBootstrapPrivilegesWith(identity[0], identity[1], ops); err == nil {
			t.Fatalf("dropHelperBootstrapPrivilegesWith(%d, %d) succeeded", identity[0], identity[1])
		}
	}
}

func TestDropHelperBootstrapPrivilegesDropsGroupsBeforeUser(t *testing.T) {
	var calls []string
	ops := helperBootstrapPrivilegeOps{
		setGroups: func(groups []int) error {
			if !reflect.DeepEqual(groups, []int{987}) {
				t.Fatalf("groups = %v", groups)
			}
			calls = append(calls, "groups")
			return nil
		},
		setResGID: func(real, effective, saved int) error {
			if real != 987 || effective != 987 || saved != 987 {
				t.Fatalf("gid tuple = %d/%d/%d", real, effective, saved)
			}
			calls = append(calls, "gid")
			return nil
		},
		setResUID: func(real, effective, saved int) error {
			if real != 1234 || effective != 1234 || saved != 1234 {
				t.Fatalf("uid tuple = %d/%d/%d", real, effective, saved)
			}
			calls = append(calls, "uid")
			return nil
		},
		getUID:  func() int { return 1234 },
		getEUID: func() int { return 1234 },
		getGID:  func() int { return 987 },
		getEGID: func() int { return 987 },
	}
	if err := dropHelperBootstrapPrivilegesWith(1234, 987, ops); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"groups", "gid", "uid"}) {
		t.Fatalf("calls = %v", calls)
	}
}

func TestDropHelperBootstrapPrivilegesFailsClosed(t *testing.T) {
	sentinel := errors.New("setgroups denied")
	ops := helperBootstrapPrivilegeOps{
		setGroups: func([]int) error { return sentinel },
		setResGID: func(int, int, int) error { t.Fatal("setresgid called after failure"); return nil },
		setResUID: func(int, int, int) error { t.Fatal("setresuid called after failure"); return nil },
		getUID:    func() int { return 0 },
		getEUID:   func() int { return 0 },
		getGID:    func() int { return 0 },
		getEGID:   func() int { return 0 },
	}
	if err := dropHelperBootstrapPrivilegesWith(1234, 987, ops); !errors.Is(err, sentinel) {
		t.Fatalf("error = %v", err)
	}
}

func TestDropHelperBootstrapPrivilegesVerifiesIdentity(t *testing.T) {
	ops := helperBootstrapPrivilegeOps{
		setGroups: func([]int) error { return nil },
		setResGID: func(int, int, int) error { return nil },
		setResUID: func(int, int, int) error { return nil },
		getUID:    func() int { return 0 },
		getEUID:   func() int { return 1234 },
		getGID:    func() int { return 987 },
		getEGID:   func() int { return 987 },
	}
	if err := dropHelperBootstrapPrivilegesWith(1234, 987, ops); err == nil {
		t.Fatal("identity verification unexpectedly succeeded")
	}
}

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
