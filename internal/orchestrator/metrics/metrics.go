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
	"github.com/NurRobin/NurProxy/internal/shared/models"
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
	recoveryDiagnosticsActiveDesc = prometheus.NewDesc(
		"nurproxy_recovery_diagnostics_active",
		"Number of unresolved recovery diagnostics by bounded classification.",
		[]string{"code", "severity", "ownership"}, nil,
	)
	recoveryOperationsTotalDesc = prometheus.NewDesc(
		"nurproxy_recovery_operations_total",
		"Number of durably completed recovery operations by bounded outcome.",
		[]string{"action", "outcome", "request_source"}, nil,
	)
	recoveryOperationsInProgressDesc = prometheus.NewDesc(
		"nurproxy_recovery_operations_in_progress",
		"Number of nonterminal recovery operations by action.",
		[]string{"action"}, nil,
	)
	recoveryCircuitBreakersOpenDesc = prometheus.NewDesc(
		"nurproxy_recovery_circuit_breakers_open",
		"Number of open recovery circuit breakers by action.",
		[]string{"action"}, nil,
	)
	failoverSwitchesDesc = prometheus.NewDesc(
		"nurproxy_domain_failover_switches_total",
		"How often the DNS target of a domain with failover backups switched agents (failover and failback, #74).",
		[]string{"domain"}, nil,
	)
	onBackupDesc = prometheus.NewDesc(
		"nurproxy_domain_on_backup",
		"1 while a domain's DNS record points at a backup agent instead of its primary (#74).",
		[]string{"domain"}, nil,
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
	ch <- recoveryDiagnosticsActiveDesc
	ch <- recoveryOperationsTotalDesc
	ch <- recoveryOperationsInProgressDesc
	ch <- recoveryCircuitBreakersOpenDesc
	ch <- failoverSwitchesDesc
	ch <- onBackupDesc
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
		if err := c.collectFailover(ch, domains); err != nil {
			scrapeErrs++
			log.Printf("metrics: reading failover state: %v", err)
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

	if aggregates, err := c.db.RecoveryAggregates(time.Now().UTC()); err == nil {
		for _, aggregate := range aggregates.DiagnosticsActive {
			ch <- prometheus.MustNewConstMetric(recoveryDiagnosticsActiveDesc, prometheus.GaugeValue, float64(aggregate.Count),
				string(aggregate.Code), string(aggregate.Severity), string(aggregate.Ownership))
		}
		for _, aggregate := range aggregates.OperationsTotal {
			ch <- prometheus.MustNewConstMetric(recoveryOperationsTotalDesc, prometheus.CounterValue, float64(aggregate.Count),
				string(aggregate.Action), string(aggregate.Outcome), string(aggregate.RequestSource))
		}
		for _, aggregate := range aggregates.OperationsInProgress {
			ch <- prometheus.MustNewConstMetric(recoveryOperationsInProgressDesc, prometheus.GaugeValue, float64(aggregate.Count), string(aggregate.Action))
		}
		for _, aggregate := range aggregates.CircuitBreakersOpen {
			ch <- prometheus.MustNewConstMetric(recoveryCircuitBreakersOpenDesc, prometheus.GaugeValue, float64(aggregate.Count), string(aggregate.Action))
		}
	} else {
		scrapeErrs++
		log.Printf("metrics: aggregating recovery health: %v", err)
	}

	ch <- prometheus.MustNewConstMetric(scrapeErrDesc, prometheus.GaugeValue, float64(scrapeErrs))
}

// collectFailover exports the failover series for every domain with backup
// servers, labelled by the domain's FQDN.
func (c *collector) collectFailover(ch chan<- prometheus.Metric, domains []models.Domain) error {
	states, err := c.db.ListDomainFailoverStates()
	if err != nil {
		return err
	}
	if err := c.db.FillDomainFailover(domains); err != nil {
		return err
	}
	zoneNames := map[string]string{}
	for i := range domains {
		dom := &domains[i]
		if len(dom.BackupServerIDs) == 0 {
			continue
		}
		name, ok := zoneNames[dom.ZoneID]
		if !ok {
			zone, err := c.db.GetZone(dom.ZoneID)
			if err != nil {
				continue
			}
			name = zone.Name
			zoneNames[dom.ZoneID] = name
		}
		fqdn := dom.FQDN(name)
		onBackup := 0.0
		if dom.ActiveServerID != dom.ServerID {
			onBackup = 1
		}
		ch <- prometheus.MustNewConstMetric(onBackupDesc, prometheus.GaugeValue, onBackup, fqdn)
		ch <- prometheus.MustNewConstMetric(failoverSwitchesDesc, prometheus.CounterValue, float64(states[dom.ID].Switches), fqdn)
	}
	return nil
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
