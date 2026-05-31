package logtail

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestPathAllowed_table(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		allowed []string
		want    bool
	}{
		{
			name:    "exact file match",
			target:  "/var/log/nginx/access.log",
			allowed: []string{"/var/log/nginx/access.log"},
			want:    true,
		},
		{
			name:    "file directly under an allowed directory",
			target:  "/var/log/nginx/error.log",
			allowed: []string{"/var/log/nginx"},
			want:    true,
		},
		{
			name:    "trailing slash on dir entry still matches",
			target:  "/var/log/nginx/error.log",
			allowed: []string{"/var/log/nginx/"},
			want:    true,
		},
		{
			name:    "nested deeper than the named dir is refused",
			target:  "/var/log/nginx/vhosts/app.log",
			allowed: []string{"/var/log/nginx"},
			want:    false,
		},
		{
			name:    "path traversal cannot escape the allowlist",
			target:  "/var/log/nginx/../../etc/shadow",
			allowed: []string{"/var/log/nginx"},
			want:    false,
		},
		{
			name:    "unrelated path refused",
			target:  "/etc/passwd",
			allowed: []string{"/var/log/nginx"},
			want:    false,
		},
		{
			name:    "empty allowlist fails closed",
			target:  "/var/log/nginx/access.log",
			allowed: nil,
			want:    false,
		},
		{
			name:    "empty target refused",
			target:  "",
			allowed: []string{"/var/log/nginx"},
			want:    false,
		},
		{
			name:    "relative target refused",
			target:  "var/log/nginx/access.log",
			allowed: []string{"/var/log/nginx"},
			want:    false,
		},
		{
			name:    "blank allowlist entry is skipped, others still apply",
			target:  "/var/log/nginx/access.log",
			allowed: []string{"", "/var/log/nginx/access.log"},
			want:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PathAllowed(tt.target, tt.allowed); got != tt.want {
				t.Errorf("PathAllowed(%q, %v) = %v, want %v", tt.target, tt.allowed, got, tt.want)
			}
		})
	}
}

func TestResolveBacklog_table(t *testing.T) {
	tests := []struct {
		name      string
		requested int
		want      int
	}{
		{name: "zero falls back to default", requested: 0, want: defaultBacklogLines},
		{name: "negative falls back to default", requested: -5, want: defaultBacklogLines},
		{name: "in-range passes through", requested: 50, want: 50},
		{name: "above cap is clamped", requested: maxBacklogLines + 100, want: maxBacklogLines},
		{name: "exactly cap passes", requested: maxBacklogLines, want: maxBacklogLines},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolveBacklog(tt.requested); got != tt.want {
				t.Errorf("ResolveBacklog(%d) = %d, want %d", tt.requested, got, tt.want)
			}
		})
	}
}

func TestNewTailer_refusesDisallowedPath(t *testing.T) {
	_, err := NewTailer("/etc/passwd", 10, []string{"/var/log/nginx"}, func(Chunk) {})
	if !errors.Is(err, ErrPathNotAllowed) {
		t.Fatalf("NewTailer error = %v, want ErrPathNotAllowed", err)
	}
}

func TestSplitLines_holdsPartialTrailingLine(t *testing.T) {
	lines, leftover := splitLines([]byte("a\r\nb\npartial"))
	if len(lines) != 2 || lines[0] != "a" || lines[1] != "b" {
		t.Errorf("lines = %v, want [a b]", lines)
	}
	if string(leftover) != "partial" {
		t.Errorf("leftover = %q, want partial", leftover)
	}
}

// collector accumulates emitted chunks under a mutex so the test goroutine can
// read them while the tailer goroutine writes.
type collector struct {
	mu     sync.Mutex
	lines  []string
	eof    bool
	tailer error
}

func (c *collector) emit(ch Chunk) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, ch.Lines...)
	if ch.EOF {
		c.eof = true
	}
	if ch.Err != nil {
		c.tailer = ch.Err
	}
}

func (c *collector) snapshot() (lines []string, eof bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.lines...), c.eof, c.tailer
}

func TestTailer_emitsBacklogThenFollowsAppends_andStopsOnCancel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	if err := os.WriteFile(path, []byte("line1\nline2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	col := &collector{}
	tl, err := NewTailer(path, 10, []string{dir}, col.emit)
	if err != nil {
		t.Fatalf("NewTailer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { tl.Run(ctx); close(done) }()

	// Backlog should arrive quickly.
	waitFor(t, func() bool {
		l, _, _ := col.snapshot()
		return len(l) == 2
	}, "backlog of 2 lines")

	// Append a new line; the follower should pick it up.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("line3\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	waitFor(t, func() bool {
		l, _, _ := col.snapshot()
		return len(l) == 3 && l[2] == "line3"
	}, "appended line3")

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("tailer did not stop within 2s of cancel")
	}
	_, eof, terr := col.snapshot()
	if terr != nil {
		t.Errorf("unexpected tail error: %v", terr)
	}
	if !eof {
		t.Error("expected a terminal EOF chunk after cancel")
	}
}

func TestTailer_openError_emitsTerminalErrorChunk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing.log")
	col := &collector{}
	tl, err := NewTailer(path, 10, []string{dir}, col.emit)
	if err != nil {
		t.Fatalf("NewTailer: %v", err)
	}
	tl.Run(context.Background())
	_, _, terr := col.snapshot()
	if terr == nil {
		t.Fatal("expected a terminal error chunk for a missing file")
	}
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
