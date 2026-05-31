package install

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteEnvFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "agent.env")
	env := map[string]string{"NP_ORCHESTRATOR": "https://np.example.com", "NP_FQDN": "edge1.example.com"}
	if err := WriteEnvFile(path, env, io.Discard); err != nil {
		t.Fatalf("WriteEnvFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	// RenderEnv sorts keys, so FQDN comes before ORCHESTRATOR.
	want := "NP_FQDN=edge1.example.com\nNP_ORCHESTRATOR=https://np.example.com\n"
	if string(got) != want {
		t.Errorf("env file = %q, want %q", got, want)
	}
	if fi, _ := os.Stat(path); fi != nil && fi.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v, want 0640", fi.Mode().Perm())
	}
}
