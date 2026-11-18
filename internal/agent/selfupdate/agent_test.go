package selfupdate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/agent/runtimeenv"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

type recordingReporter struct {
	mu      sync.Mutex
	reports []models.UpgradeReport
	reject  bool
}

func (r *recordingReporter) Report(_ context.Context, rep models.UpgradeReport) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reports = append(r.reports, rep)
	if r.reject {
		return ErrReportRejected
	}
	return nil
}

func (r *recordingReporter) states() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := make([]string, len(r.reports))
	for i, rep := range r.reports {
		s[i] = string(rep.State)
	}
	return strings.Join(s, ",")
}

func (r *recordingReporter) last() models.UpgradeReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reports[len(r.reports)-1]
}

func waitTerminal(t *testing.T, r *recordingReporter) models.UpgradeReport {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		n := len(r.reports)
		r.mu.Unlock()
		if n > 0 {
			if last := r.last(); last.State.Terminal() || last.State == models.UpgradeRestarting {
				return last
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no final report; got %s", r.states())
	return models.UpgradeReport{}
}

// releaseServer serves a release like GitHub's download endpoint.
func releaseServer(t *testing.T, rel Release) *httptest.Server {
	t.Helper()
	files := map[string][]byte{
		ChecksumsFile: rel.Checksums, SignatureFile: rel.Signature, CertificateFile: rel.Certificate, rel.Asset: rel.Archive,
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := "/releases/download/v" + rel.Version + "/"
		name, ok := strings.CutPrefix(r.URL.Path, prefix)
		data, found := files[name]
		if !ok || !found {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testAgent(t *testing.T, pki *testPKI, srv *httptest.Server, rep *recordingReporter) *Agent {
	t.Helper()
	a := &Agent{
		Version: "1.2.0", DataDir: t.TempDir(), Trust: pki.trust, Reporter: rep, GOOS: "linux", GOARCH: "amd64",
		Fetcher: Fetcher{BaseURL: srv.URL + "/releases/download", Client: srv.Client()},
	}
	a.SetHost(Host{GOOS: "linux", Version: "1.2.0", Executable: "/usr/local/bin/nurproxy-agent", Init: runtimeenv.InitSystemd, TriggerPresent: true})
	return a
}

func TestAgentStagesVerifiedRelease(t *testing.T) {
	pki := newTestPKI(t)
	rel := pki.release(t, "1.3.0", "linux", "amd64", []byte(newBinary))
	rep := &recordingReporter{}
	a := testAgent(t, pki, releaseServer(t, rel), rep)

	a.Handle(context.Background(), models.UpgradeCommand{UpgradeID: "up-1", Version: "v1.3.0"})
	if last := waitTerminal(t, rep); last.State != models.UpgradeRestarting {
		t.Fatalf("reports %s, last %+v", rep.states(), last)
	}
	if rep.states() != "downloading,installed,restarting" {
		t.Fatalf("reports %s", rep.states())
	}
	dir := StateDir(a.DataDir)
	req, err := dir.ReadRequest()
	if err != nil || req == nil || req.UpgradeID != "up-1" || req.Version != "1.3.0" || req.FromVersion != "1.2.0" {
		t.Fatalf("request %+v, %v", req, err)
	}
	staged, err := dir.LoadStaged("1.3.0", rel.Asset)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.trust.Verify(staged); err != nil {
		t.Fatalf("staged release does not verify: %v", err)
	}
}

func TestAgentRefusals(t *testing.T) {
	pki := newTestPKI(t)
	rel := pki.release(t, "1.3.0", "linux", "amd64", []byte(newBinary))
	cases := []struct {
		name    string
		host    func(*Host)
		tamper  bool
		version string
		wantErr string
	}{
		{"deb install", func(h *Host) { h.Executable, h.PackageOwner = "/usr/bin/nurproxy-agent", InstallDeb }, false, "1.3.0", "deb package"},
		{"container", func(h *Host) { h.InContainer = true }, false, "1.3.0", "container"},
		{"no trigger installed", func(h *Host) { h.TriggerPresent = false }, false, "1.3.0", "self-update-enable"},
		{"downgrade", nil, false, "1.1.0", "only moves to newer"},
		{"tampered download", nil, true, "1.3.0", "checksum mismatch"},
		{"missing release", nil, false, "1.4.0", "HTTP 404"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			served := rel
			if tc.tamper {
				served.Archive = append(append([]byte{}, rel.Archive...), 0)
			}
			rep := &recordingReporter{}
			a := testAgent(t, pki, releaseServer(t, served), rep)
			if tc.host != nil {
				h := a.host
				tc.host(&h)
				a.SetHost(h)
			}
			a.Handle(context.Background(), models.UpgradeCommand{UpgradeID: "up-1", Version: tc.version})
			last := waitTerminal(t, rep)
			if last.State != models.UpgradeFailed || !strings.Contains(last.Error, tc.wantErr) {
				t.Fatalf("got %s / %+v", rep.states(), last)
			}
			if req, _ := StateDir(a.DataDir).ReadRequest(); req != nil {
				t.Fatal("request staged despite the refusal")
			}
		})
	}
}

func TestAgentWatchRelaysResultAndHealth(t *testing.T) {
	rep := &recordingReporter{}
	a := &Agent{Version: "1.3.0", DataDir: t.TempDir(), Reporter: rep}
	dir := StateDir(a.DataDir)
	if err := dir.Ensure(); err != nil {
		t.Fatal(err)
	}

	// The restarted agent proves health once per upgrade.
	if err := dir.WritePending(Pending{UpgradeID: "up-1", FromVersion: "1.2.0", Version: "1.3.0"}); err != nil {
		t.Fatal(err)
	}
	a.HeartbeatOK()
	h, err := dir.ReadHealthy()
	if err != nil || h == nil || h.UpgradeID != "up-1" || h.Version != "1.3.0" {
		t.Fatalf("healthy %+v, %v", h, err)
	}

	// A still-old binary (after a rollback race) must not claim health.
	old := &Agent{Version: "1.2.0", DataDir: a.DataDir}
	_ = dir.RemoveHealthy()
	old.HeartbeatOK()
	if h, _ := dir.ReadHealthy(); h != nil {
		t.Fatal("old binary wrote a health proof")
	}

	if err := dir.WriteResult(Result{UpgradeID: "up-1", State: models.UpgradeDone, Version: "1.3.0"}); err != nil {
		t.Fatal(err)
	}
	a.WatchOnce(context.Background(), time.Minute)
	if rep.states() != "done" || rep.last().UpgradeID != "up-1" || rep.last().Version != "1.3.0" {
		t.Fatalf("reports %+v", rep.reports)
	}
	if r, _ := dir.ReadResult(); r != nil {
		t.Fatal("result not removed after reporting")
	}
}

func TestAgentWatchGivesUpOnUnclaimedRequest(t *testing.T) {
	rep := &recordingReporter{}
	a := &Agent{Version: "1.2.0", DataDir: t.TempDir(), Reporter: rep}
	dir := StateDir(a.DataDir)
	if err := dir.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := dir.WriteRequest(Request{UpgradeID: "up-1", Version: "1.3.0", RequestedAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	a.WatchOnce(context.Background(), time.Minute)
	if last := rep.last(); last.State != models.UpgradeFailed || !strings.Contains(last.Error, "never picked up") {
		t.Fatalf("got %+v", last)
	}
	if r, _ := dir.ReadRequest(); r != nil {
		t.Fatal("stale request not removed")
	}
	if _, err := filepath.Glob(filepath.Join(string(dir), stagedDirName, "*")); err != nil {
		t.Fatal(err)
	}
}

func TestDryRunSimulation(t *testing.T) {
	for _, tc := range []struct {
		fail, want, version string
	}{
		{"", "downloading,installed,restarting,done", "1.3.0"},
		{"verify", "downloading,failed", "1.2.0"},
		{"rollback", "downloading,installed,restarting,rolled_back", "1.2.0"},
	} {
		rep := &recordingReporter{}
		a := &Agent{Version: "1.2.0", DryRun: true, DryRunFail: tc.fail, Reporter: rep, host: Host{DryRun: true}}
		if !a.Status().Supported {
			t.Fatal("dry-run agent reports self-update unsupported")
		}
		a.Handle(context.Background(), models.UpgradeCommand{UpgradeID: "up-1", Version: "1.3.0"})
		deadline := time.Now().Add(5 * time.Second)
		for !strings.HasSuffix(rep.states(), "done") && !strings.HasSuffix(rep.states(), "failed") && !strings.HasSuffix(rep.states(), "rolled_back") {
			if time.Now().After(deadline) {
				t.Fatalf("%q: reports %s", tc.fail, rep.states())
			}
			time.Sleep(10 * time.Millisecond)
		}
		if rep.states() != tc.want || a.CurrentVersion() != tc.version {
			t.Fatalf("%q: reports %s, version %s", tc.fail, rep.states(), a.CurrentVersion())
		}
	}
}

func TestFetcherRefusesPlainHTTP(t *testing.T) {
	if err := ValidateBaseURL("http://mirror.example/releases"); err == nil {
		t.Fatal("http mirror accepted")
	}
	if err := ValidateBaseURL("https://mirror.example/releases?x=1"); err == nil {
		t.Fatal("query accepted")
	}
	if err := ValidateBaseURL("https://mirror.example/nurproxy"); err != nil {
		t.Fatal(err)
	}
}
