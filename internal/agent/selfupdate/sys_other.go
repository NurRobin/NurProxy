//go:build !unix

package selfupdate

import (
	"errors"
	"os"
	"os/exec"
)

var errUnsupported = errors.New("the self-update applier is only supported on Unix systems")

func openNoFollow(path string) (*os.File, error) { return os.Open(path) }

func detach(*exec.Cmd) {}

func fileOwner(os.FileInfo) uint32 { return ^uint32(0) }

func linkCount(os.FileInfo) uint64 { return 0 }

func openDirAt(*os.File, string) (*os.File, error) { return nil, errUnsupported }

func openFileAt(*os.File, string) (*os.File, error) { return nil, errUnsupported }

func createFileAt(*os.File, string, os.FileMode) (*os.File, error) { return nil, errUnsupported }

func mkdirAt(*os.File, string, os.FileMode) error { return errUnsupported }

func unlinkAt(*os.File, string, bool) error { return errUnsupported }

func renameAt(*os.File, string, string) error { return errUnsupported }
