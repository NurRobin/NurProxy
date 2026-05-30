package provider

import (
	"context"
	"encoding/json"
	"testing"
)

// fakeProvider is a minimal Provider implementation for testing the registry.
type fakeProvider struct {
	id string
}

func (f *fakeProvider) Info() ProviderInfo {
	return ProviderInfo{
		ID:          f.id,
		Name:        "Fake " + f.id,
		Description: "A fake provider for testing",
		Website:     "https://example.com",
		RecordTypes: []string{"A", "AAAA"},
	}
}

func (f *fakeProvider) ConfigSchema() json.RawMessage {
	return json.RawMessage(`{}`)
}

func (f *fakeProvider) ValidateConfig(_ context.Context, _ json.RawMessage) error {
	return nil
}

func (f *fakeProvider) ListZones(_ context.Context, _ json.RawMessage) ([]Zone, error) {
	return nil, nil
}

func (f *fakeProvider) CreateRecord(_ context.Context, _ json.RawMessage, _ Record) (string, error) {
	return "", nil
}

func (f *fakeProvider) UpdateRecord(_ context.Context, _ json.RawMessage, _ string, _ Record) error {
	return nil
}

func (f *fakeProvider) DeleteRecord(_ context.Context, _ json.RawMessage, _ string) error {
	return nil
}

func (f *fakeProvider) GetRecord(_ context.Context, _ json.RawMessage, _ string) (*Record, error) {
	return nil, nil
}

func (f *fakeProvider) ListRecords(_ context.Context, _ json.RawMessage, _, _ string) ([]Record, error) {
	return nil, nil
}

func resetRegistry() {
	mu.Lock()
	defer mu.Unlock()
	providers = make(map[string]Provider)
}

func TestRegisterAndGet(t *testing.T) {
	resetRegistry()

	p := &fakeProvider{id: "test-provider"}
	Register(p)

	got, err := Get("test-provider")
	if err != nil {
		t.Fatalf("Get returned unexpected error: %v", err)
	}
	if got.Info().ID != "test-provider" {
		t.Fatalf("expected provider ID %q, got %q", "test-provider", got.Info().ID)
	}
}

func TestGetUnknownProvider(t *testing.T) {
	resetRegistry()

	_, err := Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown provider, got nil")
	}
}

func TestListProviders(t *testing.T) {
	resetRegistry()

	Register(&fakeProvider{id: "alpha"})
	Register(&fakeProvider{id: "beta"})

	infos := List()
	if len(infos) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(infos))
	}

	ids := make(map[string]bool)
	for _, info := range infos {
		ids[info.ID] = true
	}
	if !ids["alpha"] || !ids["beta"] {
		t.Fatalf("expected providers alpha and beta, got %v", ids)
	}
}
