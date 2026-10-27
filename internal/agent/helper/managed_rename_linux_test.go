//go:build linux

package helper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

// A domain renamed on the same agent keeps its resource id, so the old vhost
// can only go through a tombstone with an id of its own (#151). One signed
// apply then writes the renamed route (here also on a new port) and deletes the
// old host's vhost and activation link.
func TestManagedApplyRenameOnSameAgentDeletesOldVhost(t *testing.T) {
	action, intent, _ := newManagedApplyTest(t)
	runManagedApply(t, action, intent)
	oldFile := filepath.Join(action.layout.AvailableDir, "nurproxy-app.example.com.conf")
	oldLink := filepath.Join(action.layout.EnabledDir, "nurproxy-app.example.com.conf")
	if _, err := os.Stat(oldFile); err != nil {
		t.Fatalf("initial vhost not written: %v", err)
	}

	renamed := intent
	renamed.OperationID = "apply-operation-rename"
	renamed.DesiredStateRevision = strings.Repeat("3", 64)
	renamed.Routes = append(renamed.Routes[:0:0], intent.Routes...)
	renamed.Routes[0].Route.Host = "renamed.example.com"
	renamed.Routes[0].Route.Upstream.Port = 9090
	renamed.DeletionSet = []helperprotocol.ManagedDeletion{{ResourceID: "domain-1-was-0123456789abcdef", Host: "app.example.com", Backend: "nginx"}}
	if err := renamed.Validate(); err != nil {
		t.Fatalf("rename intent rejected: %v", err)
	}
	runManagedApply(t, action, renamed)

	for _, path := range []string{oldFile, oldLink} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("old vhost target %s still present (err=%v)", path, err)
		}
	}
	newFile := filepath.Join(action.layout.AvailableDir, "nurproxy-renamed.example.com.conf")
	content, err := os.ReadFile(newFile)
	if err != nil {
		t.Fatalf("renamed vhost not written: %v", err)
	}
	if !strings.Contains(string(content), "renamed.example.com") || !strings.Contains(string(content), "9090") {
		t.Fatalf("renamed vhost does not carry the new host and port:\n%s", content)
	}
	if _, err := os.Lstat(filepath.Join(action.layout.EnabledDir, "nurproxy-renamed.example.com.conf")); err != nil {
		t.Fatalf("renamed vhost not activated: %v", err)
	}
}

// The same resource id cannot be retained and deleted in one signed apply,
// which is why the rename tombstone needs its own identity.
func TestApplyIntentRejectsRetainingAndDeletingOneResource(t *testing.T) {
	_, intent, _ := newManagedApplyTest(t)
	intent.DeletionSet = []helperprotocol.ManagedDeletion{{ResourceID: "domain-1", Host: "old.example.com", Backend: "nginx"}}
	if err := intent.Validate(); err == nil {
		t.Fatal("intent retaining and deleting domain-1 was accepted")
	}
}
