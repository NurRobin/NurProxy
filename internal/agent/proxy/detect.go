// Package proxy provides read-only detection of reverse proxies installed on
// the agent host. Phase 0 (§13.0, §2.1, §9) of the external-proxies design: it
// manages nothing, writes no files, and does not change the running Caddy path.
// It only identifies which proxy (caddy / nginx / apache) is installed, parses
// its version, resolves its config dir / binary / log paths using the §9 OS
// defaults, and — when :80/:443 is occupied — reports which process holds the
// port (§2.1).
//
// The parsing helpers (version-string parsing, ss-output parsing, path
// resolution) are pure functions so they can be unit-tested with captured
// sample outputs, no real host required.
package proxy

import (
	"context"
	"os/exec"
	"strings"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// Kind identifies a supported reverse-proxy implementation.
type Kind string

const (
	KindUnknown Kind = ""
	KindCaddy   Kind = "caddy"
	KindNginx   Kind = "nginx"
	KindApache  Kind = "apache"
)

// Detection is the read-only result reported to the orchestrator at adoption /
// heartbeat. It describes what proxy (if any) is installed on the host and what
// is currently holding the HTTP/HTTPS ports.
type Detection struct {
	// Installed reports whether a supported proxy binary was found.
	Installed bool `json:"installed"`
	// Kind is the detected proxy type (caddy / nginx / apache), empty if none.
	Kind Kind `json:"kind"`
	// Version is the parsed version string (e.g. "1.24.0"), empty if unknown.
	Version string `json:"version,omitempty"`
	// BinaryPath is the absolute path to the resolved proxy binary.
	BinaryPath string `json:"binary_path,omitempty"`
	// ConfigDir is the resolved primary config directory (§9 OS defaults).
	ConfigDir string `json:"config_dir,omitempty"`
	// LogPaths are the discovered error/access log paths (§9 OS defaults).
	LogPaths []string `json:"log_paths,omitempty"`
	// PortConflicts lists the holders of :80/:443 when those ports are occupied.
	PortConflicts []PortConflict `json:"port_conflicts,omitempty"`
}

// PortConflict identifies which process holds a listening port (§2.1). It is
// what turns "Caddy can't bind" into the actionable "nginx is holding :443".
type PortConflict struct {
	Port    int    `json:"port"`
	Process string `json:"process,omitempty"` // e.g. "nginx"
	PID     int    `json:"pid,omitempty"`
}

// ToModel converts the agent-side Detection into the shared wire/storage model
// carried in the adoption + heartbeat payloads. The agent dials out only; this
// is the shape the orchestrator persists on the agent row and exposes read-only.
func (d Detection) ToModel() *models.ProxyDetection {
	m := &models.ProxyDetection{
		Installed:  d.Installed,
		Kind:       string(d.Kind),
		Version:    d.Version,
		BinaryPath: d.BinaryPath,
		ConfigDir:  d.ConfigDir,
		LogPaths:   d.LogPaths,
	}
	for _, c := range d.PortConflicts {
		m.PortConflicts = append(m.PortConflicts, models.ProxyPortConflict{
			Port:    c.Port,
			Process: c.Process,
			PID:     c.PID,
		})
	}
	return m
}

// runner runs an external command and returns its combined output. It is a
// field on Detector so tests can inject captured sample outputs without a real
// host (the pure parsing helpers below are tested directly).
type runner func(ctx context.Context, name string, args ...string) (string, error)

// Detector performs read-only proxy detection. The zero value is usable on a
// real host; tests construct one with injected lookers/runners.
type Detector struct {
	// lookPath resolves a binary name to a path; defaults to exec.LookPath.
	lookPath func(string) (string, error)
	// run executes a command and returns combined stdout+stderr.
	run runner
	// listListeners returns the current listening sockets; defaults to ss.
	listListeners func(ctx context.Context) ([]listener, error)
}

// NewDetector returns a Detector wired to the real host.
func NewDetector() *Detector {
	d := &Detector{
		lookPath: exec.LookPath,
		run:      runCombined,
	}
	d.listListeners = d.listListenersSS
	return d
}

// runCombined runs a command and returns its combined stdout+stderr as a string.
// Many version commands (notably `nginx -v`) print to stderr, so we merge both.
func runCombined(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// candidate describes how to detect one proxy kind: the binary names to probe
// (in order) and the version subcommand to run.
type candidate struct {
	kind        Kind
	binaries    []string // binary names to look for, in priority order
	versionArgs []string // args passed to the resolved binary to print version
}

// candidates is the detection order. nginx/apache are the §13.0 focus alongside
// caddy; caddy is probed too so an external Caddy install is recognized.
var candidates = []candidate{
	{kind: KindNginx, binaries: []string{"nginx"}, versionArgs: []string{"-v"}},
	{kind: KindApache, binaries: []string{"apachectl", "apache2ctl", "httpd", "apache2"}, versionArgs: []string{"-v"}},
	{kind: KindCaddy, binaries: []string{"caddy"}, versionArgs: []string{"version"}},
}

// Detect identifies the installed proxy, its version, and its §9 paths, then
// inspects :80/:443 for conflicts. It never mutates host state. A nil error
// with Installed==false means no supported proxy was found.
func (d *Detector) Detect(ctx context.Context) (Detection, error) {
	det := Detection{}

	for _, c := range candidates {
		bin, ok := d.resolveBinary(c.binaries)
		if !ok {
			continue
		}
		det.Installed = true
		det.Kind = c.kind
		det.BinaryPath = bin

		if out, err := d.run(ctx, bin, c.versionArgs...); err == nil {
			det.Version = ParseVersion(c.kind, out)
		}

		paths := ResolvePaths(c.kind)
		det.ConfigDir = paths.ConfigDir
		det.LogPaths = paths.LogPaths
		break
	}

	det.PortConflicts = d.detectPortConflicts(ctx)
	return det, nil
}

// resolveBinary returns the first resolvable binary path from the candidates.
func (d *Detector) resolveBinary(names []string) (string, bool) {
	look := d.lookPath
	if look == nil {
		look = exec.LookPath
	}
	for _, n := range names {
		if p, err := look(n); err == nil && p != "" {
			return p, true
		}
	}
	return "", false
}

// conflictPorts are the ports the built-in Caddy needs to bind (§2.1).
var conflictPorts = []int{80, 443}

// detectPortConflicts lists which processes hold :80/:443, if any.
func (d *Detector) detectPortConflicts(ctx context.Context) []PortConflict {
	lister := d.listListeners
	if lister == nil {
		return nil
	}
	listeners, err := lister(ctx)
	if err != nil {
		return nil
	}
	var conflicts []PortConflict
	seen := make(map[int]bool)
	for _, want := range conflictPorts {
		for _, l := range listeners {
			if l.port != want || seen[want] {
				continue
			}
			seen[want] = true
			conflicts = append(conflicts, PortConflict{Port: want, Process: l.process, PID: l.pid})
		}
	}
	return conflicts
}

// listListenersSS shells out to `ss -ltnp` and parses the result.
func (d *Detector) listListenersSS(ctx context.Context) ([]listener, error) {
	run := d.run
	if run == nil {
		run = runCombined
	}
	out, err := run(ctx, "ss", "-ltnp")
	if err != nil && strings.TrimSpace(out) == "" {
		return nil, err
	}
	return ParseSSOutput(out), nil
}
