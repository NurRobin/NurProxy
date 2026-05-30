package proxy

import (
	"fmt"
	"sync"
)

// Config carries the per-agent backend settings (§9) a Factory needs to build a
// Proxy: the resolved binary, config dir, reload/test commands, service unit,
// and log paths. It is backend-neutral; each Factory reads the fields it needs
// and ignores the rest. The built-in Caddy admin-API backend, for instance,
// uses only AdminPort.
type Config struct {
	// Type is the requested backend name (caddy / nginx / apache); it matches the
	// registry key used in Get.
	Type string
	// Binary overrides the detected proxy binary path (empty = autodetect).
	Binary string
	// ConfigDir overrides the detected config directory (empty = OS default).
	ConfigDir string
	// ReloadCmd overrides the service reload command (empty = backend default).
	ReloadCmd string
	// TestCmd overrides the config-validate command (empty = backend default).
	TestCmd string
	// Service is the service unit name (systemd/openrc/launchd) for reloads.
	Service string
	// LogPaths are the error/access log paths to surface in the dashboard (§15).
	LogPaths []string
	// AdminPort is the Caddy admin API port for the built-in admin-API backend.
	AdminPort int
	// CertDir is where InstallCerts writes the centrally-issued cert bundles (§7).
	// Keys are encrypted at rest under EncryptKey before being written. Empty means
	// the backend uses its own default location.
	CertDir string
	// EncryptKey is the agent-local AES-256 key used to encrypt cert private keys at
	// rest on the agent (§7). Empty disables at-rest encryption (keys written in
	// plaintext PEM) — backends log a warning in that case.
	EncryptKey []byte
}

// Factory builds a Proxy for a backend from the given Config. It mirrors the DNS
// provider plugin pattern: backends register a Factory in init() and callers
// resolve one by name through Get. A Factory may return an error if the Config
// is insufficient for that backend.
type Factory func(cfg Config) (Proxy, error)

var (
	mu        sync.RWMutex
	factories = make(map[string]Factory)
)

// Register makes a backend Factory available under name. It is called from a
// backend's init(). Registering the same name twice, or with a nil factory,
// panics — these are programmer errors caught at startup, exactly like the DNS
// provider registry.
func Register(name string, factory Factory) {
	mu.Lock()
	defer mu.Unlock()
	if name == "" {
		panic("proxy: Register called with empty name")
	}
	if factory == nil {
		panic("proxy: Register called with nil factory for " + name)
	}
	if _, dup := factories[name]; dup {
		panic("proxy: Register called twice for " + name)
	}
	factories[name] = factory
}

// Get builds the Proxy registered under name using cfg. It returns an error if
// no backend is registered under that name.
func Get(name string, cfg Config) (Proxy, error) {
	mu.RLock()
	factory, ok := factories[name]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("proxy backend %q not registered", name)
	}
	return factory(cfg)
}

// Registered returns the names of all registered backends, for diagnostics.
func Registered() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(factories))
	for name := range factories {
		names = append(names, name)
	}
	return names
}
