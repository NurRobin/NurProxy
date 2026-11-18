//go:build unix

package selfupdate

import (
	"os"
	"os/exec"
	"syscall"
)

func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}

// copyOwner gives dst the owner and group of src so a swapped binary keeps the
// ownership of the one it replaces.
func copyOwner(src os.FileInfo, dst string) error {
	st, ok := src.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	return os.Lchown(dst, int(st.Uid), int(st.Gid))
}

// detach starts cmd in its own session so stopping the agent's service does
// not take the applier down with it.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
