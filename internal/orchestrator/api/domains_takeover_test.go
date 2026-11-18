package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// fakeTakeover records which takeover entry point the handler used.
type fakeTakeover struct {
	mu        sync.Mutex
	previews  int
	takeovers int
	err       error
	dnsNow    chan int64
	expect    []string
}

func (f *fakeTakeover) plan(id int64) *models.DNSTakeoverPlan {
	return &models.DNSTakeoverPlan{
		DomainID: id, FQDN: "app.example.com", Target: "agent.example.com", Action: models.DNSTakeoverReplace,
		Delete: []models.DNSRecordInfo{
			{ID: "r1", Type: "A", Name: "app.example.com", Content: "203.0.113.9"},
			{ID: "r2", Type: "MX", Name: "app.example.com", Content: "mail.example.com"},
		},
	}
}

func (f *fakeTakeover) TakeoverDomainDNS(_ context.Context, id int64, expect []string) (*models.DNSTakeoverPlan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.takeovers++
	f.expect = expect
	if f.err != nil {
		return nil, f.err
	}
	return f.plan(id), nil
}

func (f *fakeTakeover) PreviewDomainDNSTakeover(_ context.Context, id int64) (*models.DNSTakeoverPlan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.previews++
	return f.plan(id), nil
}

func (f *fakeTakeover) ReconcileDomainDNSNow(id int64) {
	if f.dnsNow != nil {
		f.dnsNow <- id
	}
}

// TestDomainDNSTakeover_expectDelete: the record ids the dashboard or CLI saw
// in the preview reach the takeover; no body means no check.
func TestDomainDNSTakeover_expectDelete(t *testing.T) {
	tests := []struct {
		name string
		body any
		want []string
	}{
		{"no body", nil, nil},
		{"previewed ids", map[string]any{"expect_delete": []string{"r1", "r2"}}, []string{"r1", "r2"}},
		{"nothing to delete", map[string]any{"expect_delete": []string{}}, []string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, database := testServer(t)
			fake := &fakeTakeover{}
			srv.SetDNSTakeover(fake)
			handler := srv.Handler()
			cookie := setupAdmin(t, handler)
			proxiedFixture(t, database)
			dom := &models.Domain{Subdomain: "app", ZoneID: "zone-cf", ServerID: "srv-1", Port: 80,
				SSLMode: models.SSLModeAuto, Status: models.DomainStatusActive}
			if err := database.CreateDomain(dom); err != nil {
				t.Fatal(err)
			}
			w := doRequest(t, handler, "POST", "/api/v1/domains/"+strconv.FormatInt(dom.ID, 10)+"/dns/takeover", tc.body, cookie)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", w.Code, w.Body.String())
			}
			if (fake.expect == nil) != (tc.want == nil) || strings.Join(fake.expect, ",") != strings.Join(tc.want, ",") {
				t.Errorf("expect_delete passed = %#v, want %#v", fake.expect, tc.want)
			}
		})
	}
}

func TestDomainDNSTakeover(t *testing.T) {
	tests := []struct {
		name          string
		certOnly      bool
		query         string
		takeoverErr   error
		wantCode      int
		wantPreviews  int
		wantTakeovers int
		wantInBody    []string
	}{
		{"dry run lists the records and changes nothing", false, "?dry_run=true", nil, http.StatusOK, 1, 0,
			[]string{`"dry_run":true`, "would delete 2 record(s)", "A 203.0.113.9", "MX mail.example.com"}},
		{"takeover returns what it deleted", false, "", nil, http.StatusOK, 0, 1,
			[]string{"deleted 2 record(s)", `"plan"`}},
		{"cert-only is refused before any DNS call", true, "", nil, http.StatusConflict, 0, 0,
			[]string{"cert-only"}},
		{"cert-only preview is refused too", true, "?dry_run=true", nil, http.StatusConflict, 0, 0,
			[]string{"cert-only"}},
		{"provider failure passes the reason through", false, "", errors.New("old records were already deleted; retry"), http.StatusBadGateway, 0, 1,
			[]string{"already deleted", "retry"}},
		{"records changed since the preview is a conflict", false, "", fmt.Errorf("%w: app.example.com now has A", models.ErrDNSTakeoverPlanChanged), http.StatusConflict, 0, 1,
			[]string{"changed since the preview"}},
		{"dry_run=1 is a dry run", false, "?dry_run=1", nil, http.StatusOK, 1, 0, []string{`"dry_run":true`}},
		{"dry_run=false takes over", false, "?dry_run=false", nil, http.StatusOK, 0, 1, []string{"deleted 2 record(s)"}},
		{"unrecognized dry_run is rejected", false, "?dry_run=yes", nil, http.StatusBadRequest, 0, 0, []string{"dry_run"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, database := testServer(t)
			fake := &fakeTakeover{err: tc.takeoverErr}
			srv.SetDNSTakeover(fake)
			handler := srv.Handler()
			cookie := setupAdmin(t, handler)
			proxiedFixture(t, database)
			dom := &models.Domain{Subdomain: "app", ZoneID: "zone-cf", ServerID: "srv-1", Port: 80,
				SSLMode: models.SSLModeAuto, CertOnly: tc.certOnly, Status: models.DomainStatusActive}
			if err := database.CreateDomain(dom); err != nil {
				t.Fatal(err)
			}

			w := doRequest(t, handler, "POST", "/api/v1/domains/"+strconv.FormatInt(dom.ID, 10)+"/dns/takeover"+tc.query, nil, cookie)
			if w.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.wantCode, w.Body.String())
			}
			body := w.Body.String()
			for _, want := range tc.wantInBody {
				if !strings.Contains(body, want) {
					t.Errorf("body %s does not contain %q", body, want)
				}
			}
			if fake.previews != tc.wantPreviews || fake.takeovers != tc.wantTakeovers {
				t.Errorf("previews=%d takeovers=%d, want %d/%d", fake.previews, fake.takeovers, tc.wantPreviews, tc.wantTakeovers)
			}
			if tc.wantCode == http.StatusOK {
				var resp struct {
					Plan models.DNSTakeoverPlan `json:"plan"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatal(err)
				}
				if len(resp.Plan.Delete) != 2 {
					t.Errorf("plan lists %d records, want 2", len(resp.Plan.Delete))
				}
			}
		})
	}
}

// TestCreateDomain_triggersDNSPass: a new domain gets its DNS pass right away
// instead of waiting for the next reconcile cycle, while the agent already
// serves it.
func TestCreateDomain_triggersDNSPass(t *testing.T) {
	tests := []struct {
		name     string
		certOnly bool
		want     bool
	}{
		{"served domain", false, true},
		{"cert-only domain", true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, database := testServer(t)
			fake := &fakeTakeover{dnsNow: make(chan int64, 1)}
			srv.SetDNSTakeover(fake)
			handler := srv.Handler()
			cookie := setupAdmin(t, handler)
			proxiedFixture(t, database)

			w := doRequest(t, handler, "POST", "/api/v1/domains", map[string]any{
				"subdomain": "downloads", "zone_id": "zone-cf", "server_id": "srv-1", "port": 3030, "cert_only": tc.certOnly,
			}, cookie)
			if w.Code != http.StatusCreated {
				t.Fatalf("status = %d: %s", w.Code, w.Body.String())
			}
			var dom models.Domain
			if err := json.Unmarshal(w.Body.Bytes(), &dom); err != nil {
				t.Fatal(err)
			}
			// The pass runs in a goroutine; a cert-only domain needs a short
			// wait to show that none comes.
			wait := 2 * time.Second
			if !tc.want {
				wait = 300 * time.Millisecond
			}
			select {
			case id := <-fake.dnsNow:
				if !tc.want {
					t.Errorf("cert-only domain %d got a DNS pass", id)
				} else if id != dom.ID {
					t.Errorf("DNS pass for domain %d, want %d", id, dom.ID)
				}
			case <-time.After(wait):
				if tc.want {
					t.Error("creating a domain did not trigger a DNS pass")
				}
			}
		})
	}
}
