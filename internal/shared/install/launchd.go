package install

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// launchdLabel is the launchd job label / plist basename for a service.
func launchdLabel(name string) string { return "de.nurrobin." + name }

// launchdPlistPath is where the daemon plist is written.
func launchdPlistPath(name string) string {
	return filepath.Join("/Library/LaunchDaemons", launchdLabel(name)+".plist")
}

// xmlEscape escapes the handful of characters that matter inside plist text.
func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

// RenderPlist renders a launchd daemon plist for s. Deterministic for testing.
func RenderPlist(s Service) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	w("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	w("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
	w("<plist version=\"1.0\">\n")
	w("<dict>\n")
	w("  <key>Label</key>\n  <string>%s</string>\n", launchdLabel(s.Name))

	w("  <key>ProgramArguments</key>\n  <array>\n")
	w("    <string>%s</string>\n", xmlEscape(s.BinaryPath))
	for _, a := range s.Args {
		w("    <string>%s</string>\n", xmlEscape(a))
	}
	w("  </array>\n")

	if len(s.Env) > 0 {
		w("  <key>EnvironmentVariables</key>\n  <dict>\n")
		for _, k := range sortedKeys(s.Env) {
			w("    <key>%s</key>\n    <string>%s</string>\n", xmlEscape(k), xmlEscape(s.Env[k]))
		}
		w("  </dict>\n")
	}
	if s.User != "" {
		w("  <key>UserName</key>\n  <string>%s</string>\n", xmlEscape(s.User))
	}
	w("  <key>RunAtLoad</key>\n  <true/>\n")
	w("  <key>KeepAlive</key>\n  <true/>\n")
	if s.DataDir != "" {
		w("  <key>StandardOutPath</key>\n  <string>%s</string>\n", xmlEscape(filepath.Join(s.DataDir, s.Name+".log")))
		w("  <key>StandardErrorPath</key>\n  <string>%s</string>\n", xmlEscape(filepath.Join(s.DataDir, s.Name+".err.log")))
	}
	w("</dict>\n</plist>\n")
	return b.String()
}

// launchdManager installs services as launchd daemons on macOS.
type launchdManager struct{}

func (launchdManager) Name() string { return "launchd" }

func (launchdManager) Install(s Service, out io.Writer) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if err := ensureDataDir(s, out); err != nil {
		return err
	}

	path := launchdPlistPath(s.Name)
	if err := os.WriteFile(path, []byte(RenderPlist(s)), 0o644); err != nil {
		return fmt.Errorf("writing plist %s: %w", path, err)
	}
	fprintf(out, "• plist %s\n", path)

	// Prefer the modern bootstrap; fall back to legacy load on older macOS.
	if err := launchctl(out, "bootstrap", "system", path); err != nil {
		_ = launchctl(out, "load", "-w", path)
	}
	_ = launchctl(out, "enable", "system/"+launchdLabel(s.Name))
	fprintf(out, "✓ %s installed and started. Logs: %s\n", s.Name, filepath.Join(s.DataDir, s.Name+".log"))
	return nil
}

func (launchdManager) Uninstall(s Service, purge bool, out io.Writer) error {
	if err := requireRoot(); err != nil {
		return err
	}
	path := launchdPlistPath(s.Name)
	if err := launchctl(out, "bootout", "system", path); err != nil {
		_ = launchctl(out, "unload", "-w", path)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing plist: %w", err)
	}
	fprintf(out, "• removed plist %s\n", path)
	return removeData(s, purge, out)
}

func launchctl(out io.Writer, args ...string) error { return runTool(out, "launchctl", args...) }
