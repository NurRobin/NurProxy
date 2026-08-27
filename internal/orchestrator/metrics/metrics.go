// Package metrics exposes the orchestrator's state to Prometheus (#71). A
// custom Collector reads the database lazily at scrape time — no background
// sampling loop, no staleness: every scrape reflects the DB at that instant,
// and an idle orchestrator does zero extra work. The HTTP handler is mounted
// at /metrics and gated with the admin API key (Bearer), like MCP, so fleet
// state (hostnames, cert expiry) is never world-readable.
package metrics

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/auth"
)

var (
	agentsDesc = prometheus.NewDesc(
		"nurproxy_agents_total",
		"Number of agents by status (pending/adopted/offline/...).",
		[]string{"status"}, nil,
	)
	domainsDesc = prometheus.NewDesc(
		"nurproxy_domains_total",
		"Number of domains by status (active/pending/error/deleting).",
		[]string{"status"}, nil,
	)
	certExpiryDesc = prometheus.NewDesc(
		"nurproxy_certificate_expiry_seconds",
		"Seconds until the stored certificate for host expires (negative = expired).",
		[]string{"host"}, nil,
	)
	certBackoffDesc = prometheus.NewDesc(
		"nurproxy_certificate_backoff",
		"1 while issuance for host is held after an ACME rate limit (#70).",
		[]string{"host"}, nil,
	)
	scrapeErrDesc = prometheus.NewDesc(
		"nurproxy_metrics_scrape_errors",
		"Database read failures during this scrape (0 on a clean scrape).",
		nil, nil,
	)
)

// collector reads the DB at scrape time. It is stateless; Prometheus's
// registry serializes Collect calls, and each DB read uses the read pool.
type collector struct {
	db *db.DB
}

func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- agentsDesc
	ch <- domainsDesc
	ch <- certExpiryDesc
	ch <- certBackoffDesc
	ch <- scrapeErrDesc
}

func (c *collector) Collect(ch chan<- prometheus.Metric) {
	scrapeErrs := 0

	if agents, err := c.db.ListAgents(); err == nil {
		counts := map[string]int{}
		for i := range agents {
			counts[string(agents[i].Status)]++
		}
		for status, n := range counts {
			ch <- prometheus.MustNewConstMetric(agentsDesc, prometheus.GaugeValue, float64(n), status)
		}
	} else {
		scrapeErrs++
		log.Printf("metrics: listing agents: %v", err)
	}

	if domains, err := c.db.ListDomains(db.DomainFilter{}); err == nil {
		counts := map[string]int{}
		for i := range domains {
			counts[string(domains[i].Status)]++
		}
		for status, n := range counts {
			ch <- prometheus.MustNewConstMetric(domainsDesc, prometheus.GaugeValue, float64(n), status)
		}
	} else {
		scrapeErrs++
		log.Printf("metrics: listing domains: %v", err)
	}

	if certs, err := c.db.ListCertificates(); err == nil {
		now := time.Now()
		for i := range certs {
			cert := &certs[i]
			if cert.ExpiresAt.IsZero() {
				continue // no recorded expiry — nothing meaningful to export
			}
			ch <- prometheus.MustNewConstMetric(certExpiryDesc, prometheus.GaugeValue,
				cert.ExpiresAt.Sub(now).Seconds(), cert.Host)
		}
	} else {
		scrapeErrs++
		log.Printf("metrics: listing certificates: %v", err)
	}

	if holds, err := c.db.ActiveCertBackoffs(time.Now().UTC()); err == nil {
		for host := range holds {
			ch <- prometheus.MustNewConstMetric(certBackoffDesc, prometheus.GaugeValue, 1, host)
		}
	} else {
		scrapeErrs++
		log.Printf("metrics: listing cert backoffs: %v", err)
	}

	ch <- prometheus.MustNewConstMetric(scrapeErrDesc, prometheus.GaugeValue, float64(scrapeErrs))
}

// Handler returns the /metrics HTTP handler: a dedicated Prometheus registry
// (only NurProxy metrics — no Go runtime noise unless wanted later) behind
// admin-API-key Bearer auth. Without a generated key every request is 401 —
// metrics never default to open.
func Handler(database *db.DB) http.Handler {
	reg := prometheus.NewRegistry()
	reg.MustRegister(&collector{db: database})
	promHandler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stored, err := database.GetSetting("admin_api_key")
		if err != nil || stored == "" {
			http.Error(w, "metrics require an admin API key", http.StatusUnauthorized)
			return
		}
		const prefix = "Bearer "
		authz := r.Header.Get("Authorization")
		if !strings.HasPrefix(authz, prefix) {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		ok, _ := auth.MatchesStoredAPIKey(stored, strings.TrimSpace(authz[len(prefix):]))
		if !ok {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		promHandler.ServeHTTP(w, r)
	})
}
