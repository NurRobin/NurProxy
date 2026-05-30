package proxy

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// resolveHolderViaProc names the process holding a TCP listener on port by reading
// the kernel's socket tables (/proc/net/tcp{,6}) for the listening socket's inode,
// then walking /proc/<pid>/fd to find which process owns that inode and reading its
// /proc/<pid>/comm. It is the §2.1 fallback used when `ss -ltnp` did not reveal the
// process — typically because the agent runs unprivileged and the socket belongs to
// another user. It stays best-effort: a process whose /proc/<pid>/fd the agent may
// not read (e.g. a root proxy seen by a non-root agent) is simply not attributed,
// so ok=false means "still couldn't tell" rather than an error. It resolves the
// common cases an unprivileged agent CAN see (its own / same-user processes) and a
// root agent's full view.
func resolveHolderViaProc(port int) (process string, pid int, ok bool) {
	inodes := make(map[uint64]bool)
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, ino := range parseProcNetListenInodes(string(data), port) {
			inodes[ino] = true
		}
	}
	if len(inodes) == 0 {
		return "", 0, false
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return "", 0, false
	}
	for _, e := range entries {
		p, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a pid dir
		}
		fdDir := filepath.Join("/proc", e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // not permitted (another user's process) or gone
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			ino, ok := socketInodeFromFDTarget(target)
			if !ok || !inodes[ino] {
				continue
			}
			return procComm(p), p, true
		}
	}
	return "", 0, false
}

// parseProcNetListenInodes parses /proc/net/tcp (or tcp6) content and returns the
// socket inodes of sockets in LISTEN state on the given local port. The columns are
// space-separated: index 1 is the local address "HEXIP:HEXPORT", index 3 is the
// connection state ("0A" == TCP_LISTEN), index 9 is the inode. Pure + unit-testable.
func parseProcNetListenInodes(data string, port int) []uint64 {
	var out []uint64
	for i, line := range strings.Split(data, "\n") {
		if i == 0 { // header row ("sl local_address ...")
			continue
		}
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		colon := strings.LastIndex(f[1], ":")
		if colon < 0 {
			continue
		}
		p, err := strconv.ParseInt(f[1][colon+1:], 16, 32)
		if err != nil || int(p) != port {
			continue
		}
		if f[3] != "0A" { // not TCP_LISTEN
			continue
		}
		if inode, err := strconv.ParseUint(f[9], 10, 64); err == nil {
			out = append(out, inode)
		}
	}
	return out
}

// socketInodeFromFDTarget extracts the socket inode from a /proc/<pid>/fd symlink
// target of the form "socket:[12345]". Pure + unit-testable.
func socketInodeFromFDTarget(target string) (uint64, bool) {
	const prefix = "socket:["
	if !strings.HasPrefix(target, prefix) || !strings.HasSuffix(target, "]") {
		return 0, false
	}
	inode, err := strconv.ParseUint(target[len(prefix):len(target)-1], 10, 64)
	if err != nil {
		return 0, false
	}
	return inode, true
}

// procComm reads /proc/<pid>/comm (the process command name). Empty on failure.
func procComm(pid int) string {
	if data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm")); err == nil {
		return strings.TrimSpace(string(data))
	}
	return ""
}
