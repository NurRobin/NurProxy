package tls

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/go-acme/lego/v4/challenge/dns01"

	"github.com/NurRobin/NurProxy/internal/provider"
)

// providerSolver creates and removes the _acme-challenge.<host> TXT records a
// DNS-01 challenge needs, driving the orchestrator's existing DNS provider (the
// same one used for A/AAAA/CNAME records). It satisfies two interfaces:
//
//   - DNSSolver — the seam used by hand-written fakes in tests.
//   - lego's challenge.Provider (Present/CleanUp with token/keyAuth) — so the
//     real lego ACMEClient can use it directly.
//
// It tracks the provider record IDs it created so CleanUp can delete exactly
// what Present added.
type providerSolver struct {
	provider provider.Provider
	config   json.RawMessage
	logger   *slog.Logger

	mu sync.Mutex
	// createdID maps "fqdn\x00value" to the provider record ID created for it,
	// so CleanUp deletes exactly what Present added.
	createdID map[string]string
}

// --- DNSSolver (the test seam) ---

func (s *providerSolver) Present(ctx context.Context, fqdn, value string) error {
	name := strings.TrimSuffix(fqdn, ".")
	id, err := s.provider.CreateRecord(ctx, s.config, provider.Record{
		Type:    "TXT",
		Name:    name,
		Content: value,
		TTL:     120,
	})
	if err != nil {
		return fmt.Errorf("tls: creating challenge TXT %s: %w", name, err)
	}

	s.mu.Lock()
	if s.createdID == nil {
		s.createdID = make(map[string]string)
	}
	s.createdID[challengeKey(fqdn, value)] = id
	s.mu.Unlock()

	if s.logger != nil {
		s.logger.DebugContext(ctx, "presented DNS-01 challenge",
			slog.String("fqdn", name),
			slog.String("record_id", id),
		)
	}
	return nil
}

func (s *providerSolver) CleanUp(ctx context.Context, fqdn, value string) error {
	s.mu.Lock()
	id := s.createdID[challengeKey(fqdn, value)]
	delete(s.createdID, challengeKey(fqdn, value))
	s.mu.Unlock()

	if id == "" {
		return nil
	}
	if err := s.provider.DeleteRecord(ctx, s.config, id); err != nil {
		return fmt.Errorf("tls: deleting challenge TXT %s: %w", strings.TrimSuffix(fqdn, "."), err)
	}
	return nil
}

// --- lego's challenge.Provider (used by the real ACME client) ---

// legoPresent implements lego's challenge.Provider.Present. lego passes the
// challenged domain plus the ACME token/keyAuth; we compute the challenge FQDN
// and TXT value and delegate to the context-aware Present.
func (s *providerSolver) legoPresent(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	return s.Present(context.Background(), info.FQDN, info.Value)
}

func (s *providerSolver) legoCleanUp(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	return s.CleanUp(context.Background(), info.FQDN, info.Value)
}

func challengeKey(fqdn, value string) string {
	return fqdn + "\x00" + value
}
