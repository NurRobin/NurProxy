//go:build unix

package selfupdate

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// TestApplierSettlesStalePending plays an applier that was killed while it
// waited for the health proof: the next applier run must decide and clear the
// pending record instead of leaving it to block every later upgrade.
func TestApplierSettlesStalePending(t *testing.T) {
	cases := []struct {
		name string
		// running is the version of the binary on disk, which the next
		// applier was started from.
		running   string
		healthy   bool
		startedAt time.Duration // relative to now
		breakPrev bool
		want      models.AgentUpgradeState
		wantBin   string
		wantErr   string
	}{
		{"new binary healthy", "1.3.0", true, -time.Hour, false, models.UpgradeDone, newBinary, ""},
		{"new binary never healthy", "1.3.0", false, -time.Hour, false, models.UpgradeRolledBack, oldBinary, "did not report healthy"},
		{"new binary proves health within the window", "1.3.0", true, 0, false, models.UpgradeDone, newBinary, ""},
		{"swap never happened", "1.2.0", false, -time.Hour, false, models.UpgradeFailed, oldBinary, "still runs 1.2.0"},
		{"unknown binary", "1.1.0", false, -time.Hour, false, models.UpgradeFailed, newBinary, "neither"},
		{"restore fails", "1.3.0", false, -time.Hour, true, models.UpgradeFailed, newBinary, "restoring"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newApplierFixture(t)
			mustDo(t, f.dir.RemoveRequest())
			if tc.wantBin == newBinary || tc.running == "1.3.0" {
				mustDo(t, os.WriteFile(PreviousPath(f.binary), []byte(oldBinary), 0o755))
				mustDo(t, os.WriteFile(f.binary, []byte(newBinary), 0o755))
			}
			if tc.breakPrev {
				mustDo(t, os.Remove(PreviousPath(f.binary)))
			}
			f.applier.CurrentVersion = tc.running
			writeRootState(t, f.dataDir, pendingFile, Pending{UpgradeID: "up-0", FromVersion: "1.2.0", Version: "1.3.0", StartedAt: time.Now().Add(tc.startedAt)})
			if tc.healthy {
				mustDo(t, f.dir.WriteHealthy(Healthy{UpgradeID: "up-0", Version: "1.3.0"}))
			}

			res, err := f.applier.Run(context.Background())
			if err != nil || res == nil {
				t.Fatalf("got %+v, %v", res, err)
			}
			if res.UpgradeID != "up-0" || res.State != tc.want || !strings.Contains(res.Error, tc.wantErr) {
				t.Fatalf("want %s with %q, got %+v", tc.want, tc.wantErr, res)
			}
			if p, _ := f.rootDir.ReadPending(); p != nil {
				t.Fatalf("pending record left behind: %+v", p)
			}
			onDisk, _ := f.rootDir.ReadResult()
			if onDisk == nil || onDisk.UpgradeID != "up-0" || onDisk.State != tc.want {
				t.Fatalf("result on disk %+v", onDisk)
			}
			f.binaryIs(t, tc.wantBin)
		})
	}
}

// TestApplierProcessesRequestAfterSettling checks a stale record does not
// stop the request that triggered the applier.
func TestApplierProcessesRequestAfterSettling(t *testing.T) {
	f := newApplierFixture(t)
	f.newAgentComesUp(t)
	writeRootState(t, f.dataDir, pendingFile, Pending{UpgradeID: "up-0", FromVersion: "1.1.0", Version: "1.2.0", StartedAt: time.Now().Add(-time.Hour)})
	mustDo(t, f.dir.WriteHealthy(Healthy{UpgradeID: "up-0", Version: "1.2.0"}))
	if res := f.run(t); res.UpgradeID != "up-1" || res.State != models.UpgradeDone {
		t.Fatalf("result %+v", res)
	}
	f.binaryIs(t, newBinary)
}

func TestAgentHandlesStalePending(t *testing.T) {
	for _, tc := range []struct {
		name, version string
		want          models.AgentUpgradeState
	}{
		{"agent runs the target", "1.3.0", models.UpgradeDone},
		{"agent still on the old version", "1.2.0", models.UpgradeFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := &recordingReporter{}
			a := &Agent{Version: tc.version, DataDir: t.TempDir(), Reporter: rep}
			writeRootState(t, a.DataDir, pendingFile, Pending{UpgradeID: "up-0", FromVersion: "1.2.0", Version: "1.3.0", StartedAt: time.Now()})
			a.WatchOnce(context.Background(), time.Minute)
			if len(rep.reports) != 0 {
				t.Fatalf("a fresh pending record was reported: %+v", rep.reports)
			}

			writeRootState(t, a.DataDir, pendingFile, Pending{UpgradeID: "up-0", FromVersion: "1.2.0", Version: "1.3.0", StartedAt: time.Now().Add(-time.Hour)})
			a.WatchOnce(context.Background(), time.Minute)
			a.WatchOnce(context.Background(), time.Minute)
			if len(rep.reports) != 1 || rep.last().UpgradeID != "up-0" || rep.last().State != tc.want {
				t.Fatalf("reports %+v", rep.reports)
			}
		})
	}
}

func TestAgentRelaysRefusal(t *testing.T) {
	rep := &recordingReporter{}
	a := &Agent{Version: "1.2.0", DataDir: t.TempDir(), Reporter: rep}
	dir := StateDir(a.DataDir)
	mustDo(t, dir.Ensure())
	mustDo(t, dir.WriteRequest(Request{UpgradeID: "up-1", Version: "1.3.0", RequestedAt: time.Now()}))
	writeRootState(t, a.DataDir, resultFile, Result{State: models.UpgradeFailed, Error: "self-update is group- or world-writable", FinishedAt: time.Now()})
	a.WatchOnce(context.Background(), time.Minute)
	if len(rep.reports) != 1 || rep.last().UpgradeID != "up-1" || rep.last().State != models.UpgradeFailed || !strings.Contains(rep.last().Error, "world-writable") {
		t.Fatalf("reports %+v", rep.reports)
	}
	if req, _ := dir.ReadRequest(); req != nil {
		t.Fatal("refused request left in place")
	}
	a.WatchOnce(context.Background(), time.Minute)
	if len(rep.reports) != 1 {
		t.Fatalf("refusal relayed twice: %+v", rep.reports)
	}
}

func TestAgentNotBlockedByStalePending(t *testing.T) {
	now := time.Now()
	if pendingStale(&Pending{StartedAt: now}, now) {
		t.Fatal("fresh pending treated as stale")
	}
	if !pendingStale(&Pending{StartedAt: now.Add(-DefaultHealthTimeout - staleGrace - time.Second)}, now) {
		t.Fatal("pending past its deadline still blocks")
	}
}
