//go:build darwin || freebsd

package recovery

import "os"

func openDirNoSymlinks(path string) (*os.File, error) {
	return openDirNoSymlinksByComponents(path)
}
