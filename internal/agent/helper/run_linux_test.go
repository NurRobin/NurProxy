//go:build linux

package helper

import (
	"context"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

func TestRunRootHelperRejectsMutableBuildIdentity(t *testing.T) {
	for _, buildID := range []string{"", " build", "build/escape"} {
		if err := RunRootHelper(context.Background(), buildID); err == nil {
			t.Fatalf("RunRootHelper accepted build id %q", buildID)
		}
	}
}

func TestCompiledRootActionsExposeOnlyPinnedProxyServiceMutations(t *testing.T) {
	handler, host, journal := newProxyActionTest(t, helperprotocol.ActionStartProxy, false)
	actions, err := compiledRootActions(RootConfig{ProxyTarget: handler.target}, journal, host)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []helperprotocol.Action{helperprotocol.ActionValidateReloadProxy, helperprotocol.ActionStartProxy, helperprotocol.ActionRestartProxy} {
		if actions[action] == nil {
			t.Fatalf("compiled action %s is missing", action)
		}
	}
	if len(actions) != 3 {
		t.Fatalf("unexpected compiled actions: %v", actions)
	}
	if _, ok := actions[helperprotocol.ActionApplyManagedProxyState]; ok {
		t.Fatal("ordinary apply was exposed through the hard-action engine")
	}
}
