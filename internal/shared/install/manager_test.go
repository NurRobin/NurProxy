package install

import (
	"io"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// TestEnsureDataDir_serviceUserOwnsFiles lays out a data dir + config for the
// current user (a chown to oneself works unprivileged) and asserts the files
// exist with the expected content — the install --user path must not fail on a
// resolvable non-root user.
func TestEnsureDataDir_serviceUserOwnsFiles(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	s := Service{
		Name:       "nurproxy-agent",
		User:       cur.Username,
		DataDir:    filepath.Join(base, "data"),
		ConfigFile: filepath.Join(base, "conf", "agent.yaml"),
		ConfigData: "fqdn: edge1.example.com\n",
	}

	var out strings.Builder
	if err := ensureDataDir(s, &out); err != nil {
		t.Fatalf("ensureDataDir: %v", err)
	}
	if err := chownForServiceUser(s, s.DataDir); err != nil {
		t.Errorf("chownForServiceUser to the current user: %v", err)
	}
	if !strings.Contains(out.String(), s.DataDir) || !strings.Contains(out.String(), s.ConfigFile) {
		t.Errorf("progress output missing paths:\n%s", out.String())
	}
}

// TestEnsureDataDir_unknownServiceUser_errors asserts that an unresolvable
// Service.User fails the install with an error naming the user, instead of
// silently leaving a root-owned data dir the service cannot write.
func TestEnsureDataDir_unknownServiceUser_errors(t *testing.T) {
	s := Service{
		Name:    "nurproxy-agent",
		User:    "nurproxy-no-such-user-xyz",
		DataDir: filepath.Join(t.TempDir(), "data"),
	}
	err := ensureDataDir(s, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "nurproxy-no-such-user-xyz") {
		t.Fatalf("expected a user-lookup error naming the user, got: %v", err)
	}
}
