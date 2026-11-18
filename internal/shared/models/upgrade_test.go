package models

import "testing"

func TestCanTransitionUpgrade(t *testing.T) {
	cases := []struct {
		from, to AgentUpgradeState
		want     bool
	}{
		{UpgradeRequested, UpgradeDownloading, true},
		{UpgradeRequested, UpgradeRestarting, true}, // a lost report must not wedge it
		{UpgradeRequested, UpgradeFailed, true},
		{UpgradeDownloading, UpgradeDownloading, true}, // retried report
		{UpgradeInstalled, UpgradeDownloading, false},
		{UpgradeRestarting, UpgradeDone, true},
		{UpgradeRestarting, UpgradeRolledBack, true},
		{UpgradeRestarting, UpgradeInstalled, false},
		{UpgradeDone, UpgradeFailed, false},
		{UpgradeDone, UpgradeRolledBack, true},
		{UpgradeFailed, UpgradeRolledBack, false},
		{UpgradeFailed, UpgradeDone, false},
		{UpgradeRolledBack, UpgradeRolledBack, false},
		{"bogus", UpgradeDone, false},
		{UpgradeRequested, "bogus", false},
	}
	for _, tc := range cases {
		if got := CanTransitionUpgrade(tc.from, tc.to); got != tc.want {
			t.Errorf("%s -> %s: got %v, want %v", tc.from, tc.to, got, tc.want)
		}
	}
}

func TestIsPrereleaseVersion(t *testing.T) {
	cases := map[string]bool{
		"1.0.0": false, "v1.0.0": false, "1.0.0-rc.1": true, "v0.6.0-beta.2": true, "dev": false, "": false,
	}
	for v, want := range cases {
		if got := IsPrereleaseVersion(v); got != want {
			t.Errorf("IsPrereleaseVersion(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestReleaseVersions(t *testing.T) {
	for _, v := range []string{"0.5.1", "1.0.0-rc.1", "10.20.30", "1.0.0-alpha-1.2"} {
		if !ValidReleaseVersion(v) {
			t.Errorf("%q rejected", v)
		}
	}
	for _, v := range []string{"", "dev", "1.0", "v1.0.0", "1.0.0+build", "01.0.0", "1.0.0-", "1.0.0-rc..1", "1.0.0-01", "1.0.0/../x", "1.0.0-rc_1"} {
		if ValidReleaseVersion(v) {
			t.Errorf("%q accepted", v)
		}
	}
	if v, ok := NormalizeReleaseVersion(" v0.5.1 "); !ok || v != "0.5.1" {
		t.Errorf("normalize: %q %v", v, ok)
	}
	order := []string{"0.4.0", "0.5.0-alpha", "0.5.0-alpha.1", "0.5.0-alpha.beta", "0.5.0-beta.2", "0.5.0-beta.11", "0.5.0-rc.3", "0.5.0", "0.5.1", "0.10.0", "1.0.0"}
	for i := range order {
		for j := range order {
			got, ok := CompareReleaseVersions(order[i], order[j])
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if !ok || got != want {
				t.Errorf("compare(%s, %s) = %d, %v; want %d", order[i], order[j], got, ok, want)
			}
		}
	}
	if _, ok := CompareReleaseVersions("dev", "1.0.0"); ok {
		t.Error("dev compared")
	}
}
