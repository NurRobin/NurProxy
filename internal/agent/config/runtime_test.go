package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeInfoRoundTrip(t *testing.T) {
	dir := t.TempDir()

	want := RuntimeInfo{
		OrchestratorURL: "https://orch.example",
		APIPort:         8780,
		AgentID:         "abc-123",
	}
	if err := SaveRuntimeInfo(dir, want); err != nil {
		t.Fatalf("SaveRuntimeInfo: %v", err)
	}

	got, err := LoadRuntimeInfo(dir)
	if err != nil {
		t.Fatalf("LoadRuntimeInfo: %v", err)
	}
	if got != want {
		t.Errorf("round-trip mismatch: got %+v want %+v", got, want)
	}
}

func TestLoadRuntimeInfoMissingIsZero(t *testing.T) {
	dir := t.TempDir()
	got, err := LoadRuntimeInfo(dir)
	if err != nil {
		t.Fatalf("LoadRuntimeInfo on missing file should not error: %v", err)
	}
	if got != (RuntimeInfo{}) {
		t.Errorf("expected zero RuntimeInfo, got %+v", got)
	}
}

func TestLoadRuntimeInfoBadJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "runtime.json"), []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRuntimeInfo(dir); err == nil {
		t.Error("expected error on malformed runtime.json")
	}
}
