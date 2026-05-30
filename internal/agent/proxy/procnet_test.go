package proxy

import (
	"context"
	"testing"
)

func TestParseProcNetListenInodes(t *testing.T) {
	// Real /proc/net/tcp shape: a header row, then space-padded columns. Two LISTEN
	// rows (st=0A) on :80 (0x50) and :443 (0x1BB), one ESTABLISHED (st=01) row that
	// must be ignored, and a :80 row that is not LISTEN.
	data := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 ffff 100\n" +
		"   1: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1 ffff 200\n" +
		"   2: 0100007F:0050 0100007F:ABCD 01 00000000:00000000 00:00000000 00000000     0        0 333 1 ffff 300\n"

	if got := parseProcNetListenInodes(data, 80); len(got) != 1 || got[0] != 111 {
		t.Errorf(":80 LISTEN inode = %v, want [111]", got)
	}
	if got := parseProcNetListenInodes(data, 443); len(got) != 1 || got[0] != 222 {
		t.Errorf(":443 LISTEN inode = %v, want [222]", got)
	}
	if got := parseProcNetListenInodes(data, 8080); len(got) != 0 {
		t.Errorf(":8080 should have no listeners, got %v", got)
	}
}

func TestSocketInodeFromFDTarget(t *testing.T) {
	cases := []struct {
		in    string
		inode uint64
		ok    bool
	}{
		{"socket:[12345]", 12345, true},
		{"socket:[0]", 0, true},
		{"/dev/null", 0, false},
		{"socket:[abc]", 0, false},
		{"pipe:[999]", 0, false},
	}
	for _, c := range cases {
		ino, ok := socketInodeFromFDTarget(c.in)
		if ok != c.ok || (ok && ino != c.inode) {
			t.Errorf("socketInodeFromFDTarget(%q) = (%d,%v), want (%d,%v)", c.in, ino, ok, c.inode, c.ok)
		}
	}
}

// TestDetectPortConflicts_procFallbackNamesHolder proves the §2.1 fallback: when
// `ss -ltnp` reports the port held but with no process (the unprivileged-agent
// case), detectPortConflicts asks resolveHolder (here a stub standing in for the
// /proc walk) and fills in the holder's name + pid.
func TestDetectPortConflicts_procFallbackNamesHolder(t *testing.T) {
	d := &Detector{
		listListeners: func(context.Context) ([]listener, error) {
			// ss saw :80 held but could not attribute the process (empty/zero).
			return []listener{{port: 80}}, nil
		},
		resolveHolder: func(port int) (string, int, bool) {
			if port == 80 {
				return "nginx", 4242, true
			}
			return "", 0, false
		},
	}
	conflicts := d.detectPortConflicts(context.Background())
	if len(conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d", len(conflicts))
	}
	if conflicts[0].Process != "nginx" || conflicts[0].PID != 4242 {
		t.Errorf("fallback did not name the holder: %+v", conflicts[0])
	}
}

// TestDetectPortConflicts_ssProcessWins proves the fallback is only used when ss
// could not attribute: a process ss already named is kept as-is.
func TestDetectPortConflicts_ssProcessWins(t *testing.T) {
	called := false
	d := &Detector{
		listListeners: func(context.Context) ([]listener, error) {
			return []listener{{port: 443, process: "caddy", pid: 7}}, nil
		},
		resolveHolder: func(int) (string, int, bool) { called = true; return "nginx", 1, true },
	}
	conflicts := d.detectPortConflicts(context.Background())
	if len(conflicts) != 1 || conflicts[0].Process != "caddy" || conflicts[0].PID != 7 {
		t.Fatalf("ss-reported holder should win: %+v", conflicts)
	}
	if called {
		t.Error("resolveHolder must not be called when ss already named the process")
	}
}
