// Package logtail implements the agent side of the dashboard's on-demand log
// tail (§15). When an operator opens the log view, the orchestrator pushes a
// start request down the agent-initiated stream; the agent tails the requested
// file and emits chunks back over the same control plane (the orchestrator never
// reads the agent inbound — invariant #2). Closing the view pushes a stop, which
// cancels the tailer and frees the file. This is deliberately on-demand: a tail
// exists only while a view is open, never a continuous firehose.
//
// The package splits into a pure, unit-testable core and a thin runtime:
//
//   - PathAllowed and ResolveBacklog are pure string/slice logic, so the
//     security-critical allowlist check and the backlog math are tested without a
//     filesystem.
//   - readBacklog and follow are exercised against temp files.
//   - Tailer wires them together behind a context, emitting chunks via a callback
//     the stream client turns into upstream POSTs.
package logtail

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	// defaultBacklogLines is how many trailing lines a tail sends before following
	// new writes when the request does not specify a line count.
	defaultBacklogLines = 200
	// maxBacklogLines caps the initial backlog so a giant file can never flood the
	// control plane on open.
	maxBacklogLines = 2000
	// pollInterval is how often the follower checks the file for appended bytes.
	// A tail is a low-rate, human-facing view, so polling (rather than inotify) is
	// simple, portable, and cheap enough.
	pollInterval = 500 * time.Millisecond
	// chunkMaxLines bounds how many lines ride a single emitted chunk so a burst of
	// log writes is delivered in bounded batches rather than one unbounded message.
	chunkMaxLines = 200
)

// ErrPathNotAllowed is returned when a requested tail path is not within the
// agent's configured log paths. It is a terminal, audited refusal: a compromised
// orchestrator cannot use the tail to read arbitrary files off the host.
var ErrPathNotAllowed = errors.New("log path not in the configured proxy_log_paths allowlist")

// Chunk is one batch of tailed output the Tailer hands to its emit callback. It
// mirrors proxymodel.LogChunk but is decoupled from the wire type so the package
// has no dependency on the stream layer.
type Chunk struct {
	// Lines are freshly read log lines (no trailing newline).
	Lines []string
	// Err is a terminal tail error; when set the session is finished.
	Err error
	// EOF reports that the tail has ended (context canceled / stop requested).
	EOF bool
}

// PathAllowed reports whether target is permitted to be tailed given the agent's
// configured log paths (proxy_log_paths, §9). A configured entry permits either
// the exact file or — when the entry is a directory — any file directly beneath
// it. Both sides are cleaned and compared as absolute paths so "../" tricks and
// trailing slashes cannot escape the allowlist. An empty allowlist permits
// nothing (fail closed). It is pure and the security-critical check, so it is
// table-driven tested.
func PathAllowed(target string, allowed []string) bool {
	if target == "" || len(allowed) == 0 {
		return false
	}
	t := filepath.Clean(target)
	if !filepath.IsAbs(t) {
		return false
	}
	for _, a := range allowed {
		if a == "" {
			continue
		}
		c := filepath.Clean(a)
		if c == t {
			return true
		}
		// Directory entry: permit files directly inside it (not nested deeper, so a
		// log dir does not transitively expose a subtree the operator did not name).
		if filepath.Dir(t) == c {
			return true
		}
	}
	return false
}

// ResolveBacklog clamps a requested initial-backlog line count into the supported
// range: a non-positive request falls back to the default, anything above the cap
// is clamped down. Pure and unit-tested.
func ResolveBacklog(requested int) int {
	if requested <= 0 {
		return defaultBacklogLines
	}
	if requested > maxBacklogLines {
		return maxBacklogLines
	}
	return requested
}

// Tailer follows a single log file for the lifetime of one tail session. It is
// constructed per session; Run blocks until the context is canceled (stop
// requested or the stream dropped) or a terminal error occurs.
type Tailer struct {
	// path is the validated absolute log file path.
	path string
	// backlog is the resolved number of trailing lines sent on open.
	backlog int
	// emit delivers a chunk to the caller (the stream client POSTs it upstream).
	emit func(Chunk)
}

// NewTailer builds a Tailer for path. The caller must have already validated path
// with PathAllowed; NewTailer re-checks against allowed as defense in depth and
// returns ErrPathNotAllowed when the path is not permitted, so a missed check at
// the call site still fails closed.
func NewTailer(path string, requestedLines int, allowed []string, emit func(Chunk)) (*Tailer, error) {
	if !PathAllowed(path, allowed) {
		return nil, ErrPathNotAllowed
	}
	return &Tailer{
		path:    filepath.Clean(path),
		backlog: ResolveBacklog(requestedLines),
		emit:    emit,
	}, nil
}

// Run tails the file until ctx is canceled. It first emits the trailing backlog,
// then follows appended writes, batching new lines into chunks. A terminal error
// (file cannot be opened) is emitted as a single error chunk and ends the tail. On
// context cancellation it emits a final EOF chunk so the caller can mark the
// session closed.
func (t *Tailer) Run(ctx context.Context) {
	f, err := os.Open(t.path)
	if err != nil {
		t.emit(Chunk{Err: fmt.Errorf("opening log %q: %w", t.path, err)})
		return
	}
	defer f.Close()

	offset, backlog, err := readBacklog(f, t.backlog)
	if err != nil {
		t.emit(Chunk{Err: fmt.Errorf("reading log backlog %q: %w", t.path, err)})
		return
	}
	if len(backlog) > 0 {
		t.emitBatched(backlog)
	}

	t.follow(ctx, f, offset)
	t.emit(Chunk{EOF: true})
}

// follow polls the open file from offset for appended bytes until ctx is canceled,
// emitting each batch of complete new lines. A partial trailing line (no newline
// yet) is held back until it completes, so a half-written line is never shown.
func (t *Tailer) follow(ctx context.Context, f *os.File, offset int64) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	var carry []byte
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			lines, newOffset, leftover, err := readAppended(f, offset, carry)
			if err != nil {
				t.emit(Chunk{Err: fmt.Errorf("following log %q: %w", t.path, err)})
				return
			}
			offset = newOffset
			carry = leftover
			if len(lines) > 0 {
				t.emitBatched(lines)
			}
		}
	}
}

// emitBatched splits lines into chunkMaxLines-sized chunks so a large burst is
// delivered in bounded messages.
func (t *Tailer) emitBatched(lines []string) {
	for len(lines) > 0 {
		n := len(lines)
		if n > chunkMaxLines {
			n = chunkMaxLines
		}
		t.emit(Chunk{Lines: lines[:n]})
		lines = lines[n:]
	}
}

// readBacklog reads the whole file, returns its last n lines and the byte offset
// at end-of-file (where following resumes). Reading the whole file keeps the logic
// simple and is fine for the human-facing, on-open backlog; following afterward is
// incremental. A file with no trailing newline still yields its final line.
func readBacklog(f *os.File, n int) (offset int64, lines []string, err error) {
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, nil, err
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	ring := make([]string, 0, n)
	for scanner.Scan() {
		ring = append(ring, scanner.Text())
		if len(ring) > n {
			ring = ring[1:]
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, nil, err
	}
	return size, ring, nil
}

// readAppended reads bytes added to f past offset, prepends any carried partial
// line, and returns the complete lines found plus the new offset and the still
// partial trailing bytes to carry forward. A truncated/rotated file (current size
// smaller than offset) restarts from zero so a logrotate does not wedge the tail.
func readAppended(f *os.File, offset int64, carry []byte) (lines []string, newOffset int64, leftover []byte, err error) {
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, offset, carry, err
	}
	if size < offset {
		// File was truncated/rotated: restart from the beginning, drop the carry.
		offset = 0
		carry = nil
	}
	if size == offset {
		return nil, offset, carry, nil
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, offset, carry, err
	}
	buf := make([]byte, size-offset)
	read, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, offset, carry, err
	}
	data := make([]byte, 0, len(carry)+read)
	data = append(data, carry...)
	data = append(data, buf[:read]...)
	lines, leftover = splitLines(data)
	return lines, offset + int64(read), leftover, nil
}

// splitLines splits data on '\n' into complete lines, returning any trailing
// bytes without a newline as leftover (a partial line held until it completes). A
// trailing '\r' is trimmed so CRLF logs render cleanly.
func splitLines(data []byte) (lines []string, leftover []byte) {
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] != '\n' {
			continue
		}
		line := data[start:i]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		lines = append(lines, string(line))
		start = i + 1
	}
	return lines, data[start:]
}
