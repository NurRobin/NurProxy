//go:build linux

package recovery

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func openDirNoSymlinks(path string) (*os.File, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if errors.Is(err, unix.ENOSYS) {
		return openDirNoSymlinksByComponents(path)
	}
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
