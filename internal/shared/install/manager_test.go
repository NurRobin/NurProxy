package install

import (
	"io"
	"os"
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
	info, err := os.Stat(s.DataDir)
	if err != nil {
		t.Fatalf("data dir not created: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("data dir %s is not a directory", s.DataDir)
	}
	got, err := os.ReadFile(s.ConfigFile)
	if err != nil {
		t.Fatalf("config file not created: %v", err)
	}
	if string(got) != s.ConfigData {
		t.Errorf("config content = %q, want %q", got, s.ConfigData)
	}
	if fi, err := os.Stat(s.ConfigFile); err == nil && fi.Mode().Perm() != 0o640 {
		t.Errorf("config file mode = %o, want 0640", fi.Mode().Perm())
	}
	if !strings.Contains(out.String(), s.DataDir) || !strings.Contains(out.String(), s.ConfigFile) {
		t.Errorf("progress output missing paths:\n%s", out.String())
	}
}

func TestEnsureDataDirPrivateModeIsRestrictiveAndIdempotent(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "orchestrator")
	if err := os.Mkdir(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	s := Service{DataDir: dataDir, PrivateData: true}
	for i := 0; i < 2; i++ {
		if err := ensureDataDir(s, io.Discard); err != nil {
			t.Fatalf("ensureDataDir pass %d: %v", i+1, err)
		}
	}
	info, err := os.Stat(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("private data dir mode = %04o, want 0700", got)
	}
}

func TestEnsureDataDirPrivateRejectsSymlinkWithoutChangingTarget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(root, "linked")
	if err := os.Symlink(target, linked); err != nil {
		t.Fatal(err)
	}
	if err := ensureDataDir(Service{DataDir: linked, PrivateData: true}, io.Discard); err == nil {
		t.Fatal("private install accepted a linked data dir")
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("target mode = %04o, want unchanged 0755", got)
	}
}

func TestEnsureDataDirAgentDefaultRemainsServiceUserAccessible(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "agent")
	if err := ensureDataDir(Service{DataDir: dataDir}, io.Discard); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o750 {
		t.Fatalf("agent/default data dir mode = %04o, want 0750", got)
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
