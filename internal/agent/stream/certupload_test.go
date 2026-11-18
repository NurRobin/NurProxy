package stream

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/agent/caddy"
	"github.com/NurRobin/NurProxy/internal/agent/certdiscover"
	"github.com/NurRobin/NurProxy/internal/agent/health"
	caddybackend "github.com/NurRobin/NurProxy/internal/agent/proxy/caddy"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

func TestCertUploadRequest(t *testing.T) {
	tests := []struct {
		name    string
		loader  CertLoader
		wantErr string
		wantPEM bool
	}{
		{
			name: "uploads the loaded bundle",
			loader: func(fp string) (*certdiscover.Bundle, error) {
				if fp != "abc" {
					return nil, certdiscover.ErrNotFound
				}
				return &certdiscover.Bundle{Pair: certdiscover.Pair{CertPath: "/etc/letsencrypt/live/a/fullchain.pem"}, CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")}, nil
			},
			wantPEM: true,
		},
		{
			name: "reports a load failure",
			loader: func(string) (*certdiscover.Bundle, error) {
				return nil, errors.New("private key not readable by the agent: permission denied")
			},
			wantErr: "private key not readable by the agent: permission denied",
		},
		{name: "discovery disabled", wantErr: "certificate discovery is not enabled on this agent"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := make(chan proxymodel.CertUpload, 1)
			mux := http.NewServeMux()
			mux.HandleFunc("POST /api/v1/agents/agent-1/certificates/upload", func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer tok" {
					t.Errorf("upload not authenticated")
				}
				var up proxymodel.CertUpload
				_ = json.NewDecoder(r.Body).Decode(&up)
				got <- up
			})
			ts := httptest.NewServer(mux)
			defer ts.Close()

			c := New(ts.URL, "agent-1", "tok", caddybackend.New(caddy.NewMockClient()), health.New())
			if tc.loader != nil {
				c.WithCertLoader(tc.loader)
			}
			c.handleEvent(context.Background(), "cert_upload_request", `{"request_id":"certup-1","fingerprint":"abc"}`)

			select {
			case up := <-got:
				if up.RequestID != "certup-1" || up.Fingerprint != "abc" || up.Error != tc.wantErr {
					t.Errorf("upload = %+v, want error %q", up, tc.wantErr)
				}
				if hasPEM := up.CertPEM == "CERT" && up.KeyPEM == "KEY" && up.SourcePath != ""; hasPEM != tc.wantPEM {
					t.Errorf("upload carries bundle = %v, want %v", hasPEM, tc.wantPEM)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no upload posted")
			}
		})
	}
}
