package api

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestReadJSONLimit_bodySize(t *testing.T) {
	type payload struct {
		Value string `json:"value"`
	}

	tests := []struct {
		name     string
		maxBytes int64
		body     string
		wantErr  bool
		// errContains is checked against the returned error string when wantErr.
		errContains string
		wantValue   string
	}{
		{
			name:      "normal body decodes",
			maxBytes:  maxJSONBody,
			body:      `{"value":"hello"}`,
			wantErr:   false,
			wantValue: "hello",
		},
		{
			name:        "oversized body is rejected as too large",
			maxBytes:    64,
			body:        `{"value":"` + strings.Repeat("x", 4096) + `"}`,
			wantErr:     true,
			errContains: "too large",
		},
		{
			name:        "invalid json is rejected",
			maxBytes:    maxJSONBody,
			body:        `{not json`,
			wantErr:     true,
			errContains: "invalid JSON",
		},
		{
			name:      "body exactly at the limit decodes",
			maxBytes:  int64(len(`{"value":"hi"}`)),
			body:      `{"value":"hi"}`,
			wantErr:   false,
			wantValue: "hi",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "/", io.NopCloser(strings.NewReader(tt.body)))
			if err != nil {
				t.Fatal(err)
			}
			var v payload
			err = readJSONLimit(req, &v, tt.maxBytes)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (decoded %+v)", v)
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Fatalf("error = %q, want it to contain %q", err.Error(), tt.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if v.Value != tt.wantValue {
				t.Fatalf("value = %q, want %q", v.Value, tt.wantValue)
			}
		})
	}
}

// TestReadJSON_rejectsOversizedBody asserts the default readJSON path caps the
// body and that an over-cap payload is rejected rather than fully buffered.
func TestReadJSON_rejectsOversizedBody(t *testing.T) {
	huge := `{"value":"` + strings.Repeat("x", int(maxJSONBody)+1024) + `"}`
	req, err := http.NewRequest(http.MethodPost, "/", io.NopCloser(strings.NewReader(huge)))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Value string `json:"value"`
	}
	if err := readJSON(req, &v); err == nil {
		t.Fatal("expected readJSON to reject an oversized body, got nil error")
	} else if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("error = %q, want 'too large'", err.Error())
	}
}
