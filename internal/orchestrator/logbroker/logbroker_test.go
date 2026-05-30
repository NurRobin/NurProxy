package logbroker

import (
	"testing"
	"time"
)

func TestBroker_startAppendPoll_deliversNewLinesPastCursor(t *testing.T) {
	b := New()
	b.Start("sess-1", "agent-a", "/var/log/nginx/access.log")

	if got := b.AgentFor("sess-1"); got != "agent-a" {
		t.Fatalf("AgentFor = %q, want agent-a", got)
	}
	if !b.Append("sess-1", []string{"l1", "l2"}, "", false) {
		t.Fatal("Append to a known session should report true")
	}

	p := b.Poll("sess-1", 0)
	if len(p.Lines) != 2 || p.Lines[0].Text != "l1" || p.Lines[1].Text != "l2" {
		t.Fatalf("Poll lines = %+v, want [l1 l2]", p.Lines)
	}
	if p.Cursor != 2 {
		t.Errorf("Cursor = %d, want 2", p.Cursor)
	}
	if p.Done {
		t.Error("session should not be done yet")
	}

	// A second append; polling past the prior cursor returns only the new line.
	b.Append("sess-1", []string{"l3"}, "", false)
	p2 := b.Poll("sess-1", p.Cursor)
	if len(p2.Lines) != 1 || p2.Lines[0].Text != "l3" {
		t.Fatalf("incremental Poll = %+v, want [l3]", p2.Lines)
	}
	if p2.Cursor != 3 {
		t.Errorf("Cursor = %d, want 3", p2.Cursor)
	}
}

func TestBroker_eofMarksDone(t *testing.T) {
	b := New()
	b.Start("s", "a", "/p")
	b.Append("s", nil, "", true)
	if p := b.Poll("s", 0); !p.Done {
		t.Error("EOF append should mark the session done")
	}
}

func TestBroker_errorIsTerminalAndSurfaced(t *testing.T) {
	b := New()
	b.Start("s", "a", "/p")
	b.Append("s", nil, "path not allowed", false)
	p := b.Poll("s", 0)
	if !p.Done {
		t.Error("error should mark the session done")
	}
	if p.Error != "path not allowed" {
		t.Errorf("Error = %q, want 'path not allowed'", p.Error)
	}
}

func TestBroker_unknownSession_appendFalse_pollDone(t *testing.T) {
	b := New()
	if b.Append("ghost", []string{"x"}, "", false) {
		t.Error("Append to unknown session should report false (orphaned tail)")
	}
	if p := b.Poll("ghost", 0); !p.Done {
		t.Error("Poll of unknown session should report Done so the view stops")
	}
	if got := b.AgentFor("ghost"); got != "" {
		t.Errorf("AgentFor unknown = %q, want empty", got)
	}
}

func TestBroker_stopReturnsOwningAgent_thenUnknown(t *testing.T) {
	b := New()
	b.Start("s", "agent-x", "/p")
	if got := b.Stop("s"); got != "agent-x" {
		t.Errorf("Stop = %q, want agent-x", got)
	}
	if got := b.Stop("s"); got != "" {
		t.Errorf("second Stop = %q, want empty", got)
	}
}

func TestBroker_ringDropsOldestPastCap(t *testing.T) {
	b := New()
	b.Start("s", "a", "/p")
	total := maxBufferedLines + 10
	lines := make([]string, total)
	for i := range lines {
		lines[i] = "x"
	}
	b.Append("s", lines, "", false)
	p := b.Poll("s", 0)
	if len(p.Lines) != maxBufferedLines {
		t.Fatalf("buffered %d lines, want cap %d", len(p.Lines), maxBufferedLines)
	}
	// The oldest were dropped, so the lowest retained Seq has advanced past 1.
	if p.Lines[0].Seq != int64(total-maxBufferedLines+1) {
		t.Errorf("first retained Seq = %d, want %d", p.Lines[0].Seq, total-maxBufferedLines+1)
	}
}

func TestBroker_reapIdle_removesStaleSessions_keepsActive(t *testing.T) {
	now := time.Now()
	b := New().withClock(func() time.Time { return now })
	b.Start("stale", "agent-stale", "/p")
	b.Start("fresh", "agent-fresh", "/p")

	// Advance past the idle timeout, then poll only the fresh session to refresh it.
	now = now.Add(idleTimeout + time.Minute)
	b.Poll("fresh", 0)

	reaped := b.ReapIdle()
	if _, ok := reaped["stale"]; !ok {
		t.Error("stale session should be reaped")
	}
	if reaped["stale"] != "agent-stale" {
		t.Errorf("reaped owner = %q, want agent-stale", reaped["stale"])
	}
	if _, ok := reaped["fresh"]; ok {
		t.Error("freshly-polled session should not be reaped")
	}
}
