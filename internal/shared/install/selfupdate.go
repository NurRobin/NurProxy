package install

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Agent self-update trigger (#73). The agent runs unprivileged and cannot
// replace its own binary; it stages a verified release in its data dir and
// writes self-update/request.json. A root-owned trigger notices the file and
// runs `nurproxy-agent self-update-apply`, which verifies the staged release
// again, swaps the binary, restarts the agent and rolls back on failure.
const (
	SelfUpdatePathUnit    = "nurproxy-agent-update.path"
	SelfUpdateServiceUnit = "nurproxy-agent-update.service"
	SelfUpdateLaunchd     = "nurproxy-agent-update"
)

// SelfUpdateUnitPaths are where the systemd trigger units are written.
func SelfUpdateUnitPaths() (pathUnit, serviceUnit string) {
	return filepath.Join("/etc/systemd/system", SelfUpdatePathUnit), filepath.Join("/etc/systemd/system", SelfUpdateServiceUnit)
}

// SelfUpdateLaunchdPlistPath is where the launchd trigger job is written.
func SelfUpdateLaunchdPlistPath() string { return launchdPlistPath(SelfUpdateLaunchd) }

func checkUnitPath(kind, p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return fmt.Errorf("%s must be a clean absolute path", kind)
	}
	if strings.ContainsAny(p, " \t\n\"'\\%$;") {
		return fmt.Errorf("%s %q contains characters that are unsafe in a unit file", kind, p)
	}
	return nil
}

// RenderSelfUpdateUnits renders the systemd path unit that watches for a
// request and the root oneshot service that applies it. agentUnit is the unit
// the applier restarts.
func RenderSelfUpdateUnits(binaryPath, dataDir, agentUnit string) (pathUnit, serviceUnit string, err error) {
	if err := checkUnitPath("binary path", binaryPath); err != nil {
		return "", "", err
	}
	if err := checkUnitPath("data dir", dataDir); err != nil {
		return "", "", err
	}
	if agentUnit == "" || strings.ContainsAny(agentUnit, " \t\n/\"'\\") {
		return "", "", fmt.Errorf("invalid agent unit name %q", agentUnit)
	}
	pathUnit = fmt.Sprintf(`[Unit]
Description=NurProxy agent self-update trigger

[Path]
PathExists=%s
Unit=%s

[Install]
WantedBy=paths.target
`, filepath.Join(dataDir, "self-update", "request.json"), SelfUpdateServiceUnit)
	serviceUnit = fmt.Sprintf(`[Unit]
Description=NurProxy agent self-update applier

[Service]
Type=oneshot
ExecStart=%s self-update-apply --data-dir %s --service-manager systemd --unit %s
User=root
Group=root
UMask=0022
TimeoutStartSec=15min
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
`, binaryPath, dataDir, agentUnit)
	return pathUnit, serviceUnit, nil
}

// RenderSelfUpdatePlist renders the launchd job that runs the applier as root
// whenever the agent's self-update directory changes. agentLabel is the
// launchd label of the agent job to restart.
func RenderSelfUpdatePlist(binaryPath, dataDir, agentLabel string) (string, error) {
	if err := checkUnitPath("binary path", binaryPath); err != nil {
		return "", err
	}
	if err := checkUnitPath("data dir", dataDir); err != nil {
		return "", err
	}
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	w("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	w("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
	w("<plist version=\"1.0\">\n<dict>\n")
	w("  <key>Label</key>\n  <string>%s</string>\n", launchdLabel(SelfUpdateLaunchd))
	w("  <key>ProgramArguments</key>\n  <array>\n")
	for _, a := range []string{binaryPath, "self-update-apply", "--data-dir", dataDir, "--service-manager", "launchd", "--unit", agentLabel} {
		w("    <string>%s</string>\n", xmlEscape(a))
	}
	w("  </array>\n")
	w("  <key>UserName</key>\n  <string>root</string>\n")
	w("  <key>WatchPaths</key>\n  <array>\n    <string>%s</string>\n  </array>\n", xmlEscape(filepath.Join(dataDir, "self-update")))
	w("  <key>StandardErrorPath</key>\n  <string>/var/log/nurproxy-agent-update.log</string>\n")
	w("</dict>\n</plist>\n")
	return b.String(), nil
}

// AgentLaunchdLabel is the launchd label `nurproxy-agent install` uses.
func AgentLaunchdLabel() string { return launchdLabel("nurproxy-agent") }
