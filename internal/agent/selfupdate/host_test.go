package selfupdate

import (
	"errors"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/agent/runtimeenv"
)

func TestHostStatus(t *testing.T) {
	base := Host{GOOS: "linux", Version: "1.2.0", Executable: "/usr/local/bin/nurproxy-agent", Init: runtimeenv.InitSystemd, TriggerPresent: true}
	cases := []struct {
		name       string
		mutate     func(*Host)
		supported  bool
		kind       string
		reasonPart string
	}{
		{"standalone systemd", func(*Host) {}, true, InstallStandalone, ""},
		{"dry run", func(h *Host) { *h = Host{DryRun: true} }, true, InstallDryRun, ""},
		{"docker", func(h *Host) { h.InContainer = true }, false, InstallContainer, "container"},
		{"deb", func(h *Host) { h.PackageOwner = InstallDeb }, false, InstallDeb, "package manager"},
		{"rpm", func(h *Host) { h.PackageOwner = InstallRPM }, false, InstallRPM, "package manager"},
		{"aur", func(h *Host) { h.PackageOwner = InstallPacman }, false, InstallPacman, "AUR"},
		{"homebrew", func(h *Host) { h.PackageOwner = InstallHomebrew }, false, InstallHomebrew, "brew upgrade"},
		{"usr bin", func(h *Host) { h.PackageOwner = InstallUsrBin }, false, InstallUsrBin, "/usr/bin"},
		{"dev build", func(h *Host) { h.Version = "dev" }, false, InstallStandalone, "development build"},
		{"no trigger", func(h *Host) { h.TriggerPresent = false }, false, InstallStandalone, "self-update-enable"},
		{"launchd", func(h *Host) { h.GOOS, h.Init = "darwin", runtimeenv.InitLaunchd }, true, InstallStandalone, ""},
		{"openrc as root", func(h *Host) { h.Init, h.IsRoot = runtimeenv.InitOpenRC, true }, true, InstallStandalone, ""},
		{"openrc unprivileged", func(h *Host) { h.Init = runtimeenv.InitOpenRC }, false, InstallStandalone, "root"},
		{"foreground", func(h *Host) { h.Init = "" }, false, InstallStandalone, "not running under"},
		{"unsupported os", func(h *Host) { h.GOOS = "windows" }, false, InstallStandalone, "windows"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := base
			tc.mutate(&h)
			st := h.Status()
			if st.Supported != tc.supported || st.InstallKind != tc.kind || !strings.Contains(st.Reason, tc.reasonPart) {
				t.Fatalf("got %+v", st)
			}
			if !st.Supported && st.Reason == "" {
				t.Fatal("refusal without a reason")
			}
		})
	}
}

func TestPackageOwner(t *testing.T) {
	files := map[string]string{
		"/var/lib/dpkg/info/nurproxy-agent.list": "/.\n/usr\n/usr/bin\n/usr/bin/nurproxy-agent\n",
	}
	probes := func(rpmOwns, pacmanOwns string) packageProbes {
		return packageProbes{
			readFile: func(p string) ([]byte, error) {
				if v, ok := files[p]; ok {
					return []byte(v), nil
				}
				return nil, errors.New("missing")
			},
			glob: func(string) ([]string, error) { return []string{"/var/lib/dpkg/info/nurproxy-agent.list"}, nil },
			run: func(name string, args ...string) bool {
				path := args[len(args)-1]
				return (name == "rpm" && path == rpmOwns) || (name == "pacman" && path == pacmanOwns)
			},
		}
	}
	cases := []struct{ exe, rpm, pacman, want string }{
		{"/usr/bin/nurproxy-agent", "", "", InstallDeb},
		{"/usr/local/bin/nurproxy-agent", "", "", ""},
		{"/opt/np/nurproxy-agent", "/opt/np/nurproxy-agent", "", InstallRPM},
		{"/opt/np/nurproxy-agent", "", "/opt/np/nurproxy-agent", InstallPacman},
		{"/opt/homebrew/Caskroom/nurproxy-agent/1.0/nurproxy-agent", "", "", InstallHomebrew},
		{"/usr/local/Cellar/nurproxy-agent/1.0/bin/nurproxy-agent", "", "", InstallHomebrew},
		{"/usr/bin/nurproxy-agent-copy", "", "", InstallUsrBin},
		{"", "", "", ""},
	}
	for _, tc := range cases {
		if got := packageOwner(tc.exe, probes(tc.rpm, tc.pacman)); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.exe, got, tc.want)
		}
	}
}

func TestInContainer(t *testing.T) {
	none := func(string) bool { return false }
	noRead := func(string) ([]byte, error) { return nil, errors.New("missing") }
	env := func(v string) func(string) string { return func(string) string { return v } }
	cases := []struct {
		name   string
		getenv func(string) string
		exists func(string) bool
		read   func(string) ([]byte, error)
		want   bool
	}{
		{"bare host", env(""), none, func(string) ([]byte, error) { return []byte("0::/init.scope\n"), nil }, false},
		{"podman env", env("podman"), none, noRead, true},
		{"dockerenv", env(""), func(p string) bool { return p == "/.dockerenv" }, noRead, true},
		{"kubernetes cgroup", env(""), none, func(string) ([]byte, error) { return []byte("0::/kubepods/besteffort/pod1\n"), nil }, true},
		{"lxc stays a host", env("lxc"), none, func(string) ([]byte, error) { return []byte("0::/\n"), nil }, false},
	}
	for _, tc := range cases {
		if got := inContainer(tc.getenv, tc.exists, tc.read); got != tc.want {
			t.Errorf("%s: got %v", tc.name, got)
		}
	}
}
