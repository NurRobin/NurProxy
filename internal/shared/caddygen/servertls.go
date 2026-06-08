package caddygen

import (
	"sort"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// This file holds the pure renderer for the bundled Caddy server's TLS strategy
// (§7). NurProxy provisions certificates centrally (DNS-01 via the orchestrator)
// and feeds the bundle to the agent, so the built-in Caddy must run on PROVIDED
// certs with automatic_https disabled rather than doing its own ACME. Caddy
// self-ACME stays as an explicit, selectable FALLBACK mode for (a) zones not in
// any configured DNS provider (DNS-01 impossible) and (b) orchestrator-down
// resilience.
//
// Like every renderer in this package, GenerateServerTLS is a pure function
// (intent in, structures out) so both paths are table-driven testable without a
// running Caddy.

// TLSHost is the per-host TLS intent the server-level renderer consumes: a host
// FQDN, its provisioning policy, and (for the provided-cert path) the on-disk
// cert + key file paths the agent already installed via InstallCerts (§7).
type TLSHost struct {
	// Host is the public FQDN this entry governs, e.g. "app.example.com".
	Host string
	// Policy selects provisioning: central provided certs (default) vs Caddy
	// self-ACME (the fallback) vs off (plaintext, no TLS for this host).
	Policy proxymodel.TLSPolicy
	// CertPath is the on-disk leaf+chain PEM path. Required (non-empty) for the
	// central provided-cert path; ignored for self-acme/off.
	CertPath string
	// KeyPath is the on-disk private-key path (the agent decrypts it at rest into
	// a readable file the proxy can load). Required for the central path.
	KeyPath string
}

// ServerTLS is the rendered Caddy TLS strategy for the bundled server: the tls
// app's loaded certificate files plus the http server's automatic_https policy.
// It is consumed by the Caddy backend to PUT the tls app and patch srv0's
// automatic_https without re-deriving the strategy on the agent.
type ServerTLS struct {
	// LoadFiles is the tls app's certificates/load_files entries — one per host on
	// the central provided-cert path. Empty when no host provides its own cert
	// (pure self-ACME fleet), in which case Caddy loads nothing and ACMEs all.
	LoadFiles []LoadFile
	// AutomaticHTTPS is the http server's automatic_https block. Disable is true
	// only when EVERY TLS host runs on provided certs (no host needs ACME); when a
	// self-ACME host coexists, Disable stays false and Skip lists the
	// provided-cert hosts so Caddy does not also try to ACME them (§7 fallback
	// coexistence).
	AutomaticHTTPS AutomaticHTTPS
	// ConnectionPolicies is srv0's tls_connection_policies. Caddy only auto-creates
	// these while automatic_https is enabled; with every host on provided certs
	// (Disable=true) it adds none, so srv0 would terminate plaintext on :443. We
	// then add one default (catch-all) policy so Caddy serves the loaded provided
	// certs by SNI. Empty in the mixed/self-ACME case (automatic_https creates the
	// policies) and when no host actually provides a cert.
	ConnectionPolicies []ConnectionPolicy
}

// ConnectionPolicy is one entry in Caddy's http server `tls_connection_policies`.
// The empty policy {} is a catch-all that serves the best-matching loaded (or
// managed) certificate for the connection's SNI.
type ConnectionPolicy struct{}

// LoadFile is one entry in Caddy's tls app `certificates.load_files`: a cert and
// key file pair Caddy loads at startup and serves for the matching SNI host.
type LoadFile struct {
	Certificate string   `json:"certificate"`
	Key         string   `json:"key"`
	Tags        []string `json:"tags,omitempty"`
}

// AutomaticHTTPS mirrors Caddy's http server `automatic_https` block. Disable
// turns Caddy's on-demand/managed ACME off entirely (the all-provided-cert
// case); Skip lists hosts Caddy must NOT manage automatically (the mixed case,
// where some hosts still self-ACME).
type AutomaticHTTPS struct {
	Disable bool     `json:"disable,omitempty"`
	Skip    []string `json:"skip,omitempty"`
}

// GenerateServerTLS renders the bundled Caddy server's TLS strategy from a set of
// per-host TLS intents (§7). It implements both paths:
//
//   - central provided certs: the host's cert+key files are loaded into the tls
//     app via load_files, and the host is excluded from Caddy's automatic_https
//     so Caddy serves the provided cert instead of trying to obtain its own.
//   - self-ACME fallback: the host is left to Caddy's automatic_https (no
//     load_files entry, not skipped), so Caddy obtains and renews the cert itself
//     — used for zones not in a configured DNS provider and orchestrator-down
//     resilience.
//   - off: the host has no TLS material and is not ACMEd; it is skipped from
//     automatic_https so Caddy never provisions a cert for a plaintext-only host.
//
// When every TLS-bearing host runs on provided certs (no self-ACME host),
// automatic_https is disabled wholesale (Disable=true) — the clean built-in
// path. As soon as one host opts into self-ACME, Disable stays false and only
// the provided/off hosts are listed in Skip, so the self-ACME host still gets a
// managed cert while the provided hosts are untouched.
//
// The function is order-stable (hosts sorted) so the rendered config is
// deterministic and diff-stable in the central store.
func GenerateServerTLS(hosts []TLSHost) ServerTLS {
	// Copy + sort so output is deterministic regardless of input order.
	sorted := make([]TLSHost, len(hosts))
	copy(sorted, hosts)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Host < sorted[j].Host })

	var out ServerTLS
	var skip []string
	anyACME := false

	for _, h := range sorted {
		if h.Host == "" {
			continue
		}
		switch h.Policy {
		case proxymodel.TLSPolicySelfACME:
			// Caddy manages this host's cert itself — do not load a file, do not
			// skip it from automatic_https.
			anyACME = true
		case proxymodel.TLSPolicyOff:
			// No TLS for this host: never let Caddy ACME it.
			skip = append(skip, h.Host)
		default:
			// Central provided cert (the default): load the file and skip ACME.
			if h.CertPath != "" && h.KeyPath != "" {
				out.LoadFiles = append(out.LoadFiles, LoadFile{
					Certificate: h.CertPath,
					Key:         h.KeyPath,
				})
			}
			skip = append(skip, h.Host)
		}
	}

	if anyACME {
		// Mixed fleet: keep automatic_https on for the self-ACME host(s), but skip
		// the provided/off hosts so Caddy does not also try to manage them.
		out.AutomaticHTTPS = AutomaticHTTPS{Skip: skip}
	} else {
		// Every host runs on provided certs (or off): disable Caddy ACME entirely.
		out.AutomaticHTTPS = AutomaticHTTPS{Disable: true}
		// With automatic_https disabled Caddy adds no TLS connection policy, so srv0
		// would serve plaintext on :443. Add a default policy when there is actually
		// a provided cert to serve, so Caddy terminates TLS with the loaded certs.
		if len(out.LoadFiles) > 0 {
			out.ConnectionPolicies = []ConnectionPolicy{{}}
		}
	}
	return out
}
