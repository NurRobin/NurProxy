// Package runtimeenv is the agent's read-only self-inspection of HOW it is
// running on this host: the OS/distro, the service manager that started it
// (systemd / OpenRC / launchd / Windows service / none), the unit name, whether
// it runs as root, and whether its filesystem view is sandboxed (e.g. systemd
// ProtectSystem= making /etc a read-only mount).
//
// The point is that the right *fix* for a permission problem depends on this.
// An agent running as root under a systemd sandbox cannot write /etc/nginx
// because the mount is read-only (EROFS) — adding the user to a group or
// granting sudo does nothing; the fix is a ReadWritePaths drop-in. An agent
// running as an unprivileged user needs the opposite: group ownership for the
// config dir and a scoped sudoers entry for reload. So the remediation the
// dashboard shows is selected from this environment, not assumed.
//
// Everything here is read-only and never panics. The parsing helpers
// (os-release, cgroup, mountinfo) are pure functions over file content so they
// are unit-testable without a real host; Detect() wires them to the live
// sources.
package runtimeenv

import (
	"os"
	"os/user"
	"runtime"
	"strings"
)

// Init names the service manager an agent runs under, or "" when it was started
// directly (foreground / a wrapper we don't recognize).
const (
	InitSystemd = "systemd"
	InitOpenRC  = "openrc"
	InitLaunchd = "launchd"
	InitWindows = "windows-service"
)

// Env is the detected runtime environment. Its zero value is a safe "unknown"
// that selects the conservative, non-root remediation path.
type Env struct {
	// OS is runtime.GOOS ("linux", "darwin", "windows", "freebsd", …).
	OS string
	// Distro is the Linux distribution ID from /etc/os-release (e.g. "debian",
	// "ubuntu", "rhel", "arch", "alpine"), empty off Linux or when unknown.
	Distro string
	// DistroLike are the os-release ID_LIKE tokens (e.g. ["debian"] for Ubuntu),
	// useful for matching a family when the exact ID isn't recognized.
	DistroLike []string
	// Init is the service manager that started the agent (see Init* constants),
	// or "" when run directly / unrecognized.
	Init string
	// Managed reports whether a service manager started the agent (vs foreground).
	Managed bool
	// Unit is the service unit name when known (e.g. "nurproxy-agent.service"),
	// woven verbatim into a systemd `systemctl edit`/drop-in remediation.
	Unit string
	// Sandboxed reports whether the agent's filesystem view is read-only-protected
	// (systemd ProtectSystem=/ReadOnlyPaths), detected best-effort by checking
	// whether /etc is a read-only mount for this process.
	Sandboxed bool
	// UID is the effective user id, or -1 where unavailable (Windows).
	UID int
	// User is the username the agent runs as, empty if it could not be resolved.
	User string
	// IsRoot reports whether the agent runs as root (UID 0).
	IsRoot bool
}

// Detect inspects the live host and returns its runtime environment. It is
// read-only, best-effort, and never fails: anything it cannot determine is left
// at its zero value.
func Detect() Env {
	e := Env{OS: runtime.GOOS, UID: -1}

	e.UID = osGeteuid()
	e.IsRoot = e.UID == 0
	if u, err := user.Current(); err == nil {
		e.User = u.Username
	}

	if e.OS == "linux" {
		if data, err := os.ReadFile("/etc/os-release"); err == nil {
			e.Distro, e.DistroLike = parseOSRelease(string(data))
		}
	}

	e.Init, e.Managed, e.Unit = detectInitFromEnv(e.OS, os.Getenv)
	if e.Init == InitSystemd && e.Unit == "" {
		if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
			e.Unit = parseUnitFromCgroup(string(data))
		}
	}

	// A read-only /etc is the tell-tale of systemd ProtectSystem=full|strict; we
	// only bother checking under systemd, where the sandbox exists.
	if e.Init == InitSystemd {
		if data, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
			e.Sandboxed = parseMountinfoReadOnly(string(data), "/etc")
		}
	}

	return e
}

// osGeteuid is a thin wrapper so the dependency is obvious; os.Geteuid returns
// -1 on platforms without the concept (Windows), which Detect carries through.
func osGeteuid() int { return os.Geteuid() }

// parseOSRelease extracts ID and ID_LIKE from /etc/os-release content. Values
// may be quoted; ID_LIKE is a space-separated list. Returns "" / nil when absent.
func parseOSRelease(content string) (id string, idLike []string) {
	for _, ln := range strings.Split(content, "\n") {
		ln = strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(ln, "ID="):
			id = unquote(strings.TrimPrefix(ln, "ID="))
		case strings.HasPrefix(ln, "ID_LIKE="):
			idLike = append(idLike, strings.Fields(unquote(strings.TrimPrefix(ln, "ID_LIKE=")))...)
		}
	}
	return id, idLike
}

// detectInitFromEnv classifies the service manager purely from process
// environment variables the managers set on their children: systemd exports
// INVOCATION_ID / JOURNAL_STREAM, OpenRC exports RC_SVCNAME, launchd exports
// XPC_SERVICE_NAME. It returns the init name, whether the agent is manager-
// started, and the unit name when the env carries it.
func detectInitFromEnv(goos string, getenv func(string) string) (init string, managed bool, unit string) {
	if getenv("INVOCATION_ID") != "" || getenv("JOURNAL_STREAM") != "" {
		return InitSystemd, true, ""
	}
	if svc := getenv("RC_SVCNAME"); svc != "" {
		return InitOpenRC, true, svc
	}
	if goos == "darwin" {
		// launchd sets XPC_SERVICE_NAME to "0" for processes it did NOT launch as a
		// service, so only a real, non-"0" value counts.
		if svc := getenv("XPC_SERVICE_NAME"); svc != "" && svc != "0" {
			return InitLaunchd, true, svc
		}
	}
	return "", false, ""
}

// parseUnitFromCgroup pulls the systemd unit name out of /proc/self/cgroup. Lines
// look like "0::/system.slice/nurproxy-agent.service"; we return the first path
// segment ending in ".service" (or ".scope"). Returns "" when none is present.
func parseUnitFromCgroup(content string) string {
	for _, ln := range strings.Split(content, "\n") {
		path := ln
		if i := strings.LastIndex(ln, ":"); i >= 0 {
			path = ln[i+1:]
		}
		for _, seg := range strings.Split(path, "/") {
			if strings.HasSuffix(seg, ".service") || strings.HasSuffix(seg, ".scope") {
				return seg
			}
		}
	}
	return ""
}

// parseMountinfoReadOnly reports whether the mount that covers target is mounted
// read-only, per /proc/self/mountinfo. The covering mount is the one whose mount
// point is the longest path-prefix of target; its per-mount options field holds
// "ro" or "rw". This is how a systemd ProtectSystem= sandbox surfaces from inside
// the process. Robust to the variable optional fields (it reads by position from
// the front, where mount point [4] and options [5] are fixed).
func parseMountinfoReadOnly(content, target string) bool {
	best := -1
	ro := false
	for _, ln := range strings.Split(content, "\n") {
		f := strings.Fields(ln)
		if len(f) < 6 {
			continue
		}
		mp, opts := f[4], f[5]
		if !pathHasPrefix(target, mp) {
			continue
		}
		if len(mp) > best {
			best = len(mp)
			ro = optContains(opts, "ro")
		}
	}
	return ro
}

// pathHasPrefix reports whether mount point mp covers target (mp == target, mp is
// a parent dir of target, or mp is the root "/").
func pathHasPrefix(target, mp string) bool {
	if mp == "/" {
		return true
	}
	mp = strings.TrimRight(mp, "/")
	return target == mp || strings.HasPrefix(target, mp+"/")
}

// optContains reports whether a comma-separated mount-option list contains want.
func optContains(opts, want string) bool {
	for _, o := range strings.Split(opts, ",") {
		if o == want {
			return true
		}
	}
	return false
}

// unquote strips one layer of surrounding double quotes from an os-release value.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
