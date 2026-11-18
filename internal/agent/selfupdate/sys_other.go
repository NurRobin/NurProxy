//go:build !unix

package selfupdate

import (
	"os"
	"os/exec"
)

func openNoFollow(path string) (*os.File, error) { return os.Open(path) }

func copyOwner(os.FileInfo, string) error { return nil }

func detach(*exec.Cmd) {}
