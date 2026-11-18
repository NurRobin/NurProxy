//go:build linux

package helper

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/NurRobin/NurProxy/internal/agent/proxy/nginx"
	"github.com/NurRobin/NurProxy/internal/shared/nginxgen"
)

// errorLogVersionTimeout bounds the `nginx -V` call of the error log check.
const errorLogVersionTimeout = 10 * time.Second

// errorLogTargetCheck decides whether nginx's root master may open
// nginxgen.DefaultErrorLogPath for a per-domain `error_log` directive. The
// file must either be a regular file (not a symlink) in a directory that
// only root can change, or be the error log nginx was compiled with, which
// the master opens anyway. Otherwise a non-root account that can write the
// directory could point the file somewhere else with a symlink.
type errorLogTargetCheck struct {
	lstat func(string) (os.FileInfo, error)
	// nginxVersion returns the output of `nginx -V`.
	nginxVersion func() (string, error)
}

func newErrorLogTargetCheck(binary string) errorLogTargetCheck {
	return errorLogTargetCheck{
		lstat: os.Lstat,
		nginxVersion: func() (string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), errorLogVersionTimeout)
			defer cancel()
			return runBounded(ctx, binary, "-V")
		},
	}
}

// verify returns nil when the error log target is safe, else an error that
// says why for the operator.
func (c errorLogTargetCheck) verify() error {
	path := nginxgen.DefaultErrorLogPath
	fileReason := c.fileReason(path)
	if fileReason == "" {
		return nil
	}
	if c.nginxVersion == nil {
		return fmt.Errorf("%s; nginx -V is unavailable", fileReason)
	}
	output, err := c.nginxVersion()
	if err != nil {
		return fmt.Errorf("%s, and nginx -V failed", fileReason)
	}
	compiled := nginx.CompiledErrorLogPath(output)
	if compiled == path {
		return nil
	}
	if compiled == "" {
		return fmt.Errorf("%s, and nginx -V reports no --error-log-path", fileReason)
	}
	return fmt.Errorf("%s, and nginx -V reports --error-log-path=%s", fileReason, compiled)
}

// fileReason returns "" when path is a regular file in a root-owned
// directory that neither group nor others can write, else why not.
func (c errorLogTargetCheck) fileReason(path string) string {
	if c.lstat == nil {
		return "the error log cannot be inspected"
	}
	info, err := c.lstat(path)
	switch {
	case err != nil:
		return fmt.Sprintf("%s does not exist or cannot be inspected", path)
	case info.Mode()&os.ModeSymlink != 0:
		return fmt.Sprintf("%s is a symlink", path)
	case !info.Mode().IsRegular():
		return fmt.Sprintf("%s is not a regular file", path)
	}
	dir := filepath.Dir(path)
	dirInfo, err := c.lstat(dir)
	if err != nil {
		return fmt.Sprintf("%s cannot be inspected", dir)
	}
	if !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Sprintf("%s is not a plain directory", dir)
	}
	stat, ok := dirInfo.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return fmt.Sprintf("%s is not owned by root", dir)
	}
	if dirInfo.Mode().Perm()&0o022 != 0 {
		return fmt.Sprintf("%s is writable by group or others", dir)
	}
	return ""
}
