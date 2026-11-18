//go:build unix

package selfupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

func mustDo(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// replaceWithSymlink turns path into a symlink to a copy of what it was, in a
// directory outside the data dir.
func replaceWithSymlink(t *testing.T, path string) {
	t.Helper()
	target := filepath.Join(t.TempDir(), filepath.Base(path))
	mustDo(t, os.Rename(path, target))
	mustDo(t, os.Symlink(target, path))
}

// TestApplierRefusesUntrustedHandoff covers layouts where root must not act at
// all: Run returns an error before claiming anything.
func TestApplierRefusesUntrustedHandoff(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, f *applierFixture)
		wantErr string
	}{
		{"self-update dir is a symlink", func(t *testing.T, f *applierFixture) {
			replaceWithSymlink(t, string(f.dir))
		}, "self-update"},
		{"root dir is a symlink", func(t *testing.T, f *applierFixture) {
			elsewhere := t.TempDir()
			mustDo(t, os.Symlink(elsewhere, string(f.rootDir)))
		}, rootStateDirName},
		{"data dir is a symlink", func(t *testing.T, f *applierFixture) {
			replaceWithSymlink(t, f.dataDir)
		}, "data dir"},
		{"root dir owned by the agent", func(t *testing.T, f *applierFixture) {
			mustDo(t, os.Mkdir(string(f.rootDir), 0o755))
			f.owners[rootStateDirName] = 1000
		}, "not root"},
		{"self-update dir owned by someone else", func(t *testing.T, f *applierFixture) {
			f.owners[stateDirName] = 1001
		}, "not the agent user"},
		{"self-update dir group-writable", func(t *testing.T, f *applierFixture) {
			mustDo(t, os.Chmod(string(f.dir), 0o770))
		}, "group- or world-writable"},
		{"data dir world-writable", func(t *testing.T, f *applierFixture) {
			mustDo(t, os.Chmod(f.dataDir, 0o777))
		}, "group- or world-writable"},
		{"data dir parent not root-owned", func(t *testing.T, f *applierFixture) {
			f.owners[filepath.Base(filepath.Dir(f.dataDir))] = 1000
		}, "not in a root-controlled location"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newApplierFixture(t)
			tc.prepare(t, f)
			res, err := f.applier.Run(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error with %q, got %+v, %v", tc.wantErr, res, err)
			}
			f.binaryIs(t, oldBinary)
			if f.service.restarts != 0 {
				t.Fatalf("restarted after a refusal")
			}
		})
	}
}

// TestApplierRefusesUntrustedInput covers agent-written files root must treat
// as hostile: the request is discarded and nothing is installed.
func TestApplierRefusesUntrustedInput(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, f *applierFixture)
		wantErr string
	}{
		{"oversized request", func(t *testing.T, f *applierFixture) {
			big := `{"upgrade_id":"up-1","version":"1.3.0"}` + strings.Repeat(" ", maxRequestBytes)
			mustDo(t, os.WriteFile(f.dir.path(requestFile), []byte(big), 0o600))
		}, "larger than"},
		{"garbled request", func(t *testing.T, f *applierFixture) {
			mustDo(t, os.WriteFile(f.dir.path(requestFile), []byte(`{"upgrade_id":`), 0o600))
		}, "decoding request.json"},
		{"unknown field in request", func(t *testing.T, f *applierFixture) {
			mustDo(t, os.WriteFile(f.dir.path(requestFile), []byte(`{"upgrade_id":"up-1","version":"1.3.0","binary":"/tmp/x"}`), 0o600))
		}, "unknown field"},
		{"trailing data after request", func(t *testing.T, f *applierFixture) {
			mustDo(t, os.WriteFile(f.dir.path(requestFile), []byte(`{"upgrade_id":"up-1","version":"1.3.0"} {}`), 0o600))
		}, "trailing data"},
		{"request is a symlink", func(t *testing.T, f *applierFixture) {
			replaceWithSymlink(t, f.dir.path(requestFile))
		}, "request.json"},
		{"request is a FIFO", func(t *testing.T, f *applierFixture) {
			mustDo(t, os.Remove(f.dir.path(requestFile)))
			mustDo(t, syscall.Mkfifo(f.dir.path(requestFile), 0o600))
		}, "not a regular file"},
		{"request is a hard link", func(t *testing.T, f *applierFixture) {
			mustDo(t, os.Link(f.dir.path(requestFile), filepath.Join(string(f.dir), "other")))
		}, "hard links"},
		{"request owned by someone else", func(t *testing.T, f *applierFixture) {
			f.owners[requestFile] = 1001
		}, "not the agent user"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newApplierFixture(t)
			tc.prepare(t, f)
			res, err := f.applier.Run(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error with %q, got %+v, %v", tc.wantErr, res, err)
			}
			f.binaryIs(t, oldBinary)
			if _, err := os.Lstat(f.dir.path(requestFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("bad request left in place: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(string(f.dir), stagedDirName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("staged files left behind: %v", err)
			}
		})
	}
}

// TestApplierRefusesUnsafeStagingOrBinary covers refusals after the request
// was claimed: the verdict is a failed result and the binary is untouched.
func TestApplierRefusesUnsafeStagingOrBinary(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, f *applierFixture)
		wantErr string
	}{
		{"staged dir is a symlink", func(t *testing.T, f *applierFixture) {
			replaceWithSymlink(t, filepath.Join(string(f.dir), stagedDirName))
		}, "opening staged release"},
		{"staged archive is a hard link", func(t *testing.T, f *applierFixture) {
			mustDo(t, os.Link(f.dir.staged(stagedArchive), filepath.Join(string(f.dir), "copy")))
		}, "hard links"},
		{"staged archive owned by someone else", func(t *testing.T, f *applierFixture) {
			f.owners[stagedArchive] = 1001
		}, "not the agent user"},
		{"staged archive too large", func(t *testing.T, f *applierFixture) {
			fh, err := os.OpenFile(f.dir.staged(stagedArchive), os.O_WRONLY, 0)
			mustDo(t, err)
			mustDo(t, fh.Truncate(maxArchiveBytes+1))
			mustDo(t, fh.Close())
		}, "larger than"},
		{"archive checksum does not match on root's copy", func(t *testing.T, f *applierFixture) {
			archive, err := os.ReadFile(f.dir.staged(stagedArchive))
			mustDo(t, err)
			archive[len(archive)/2] ^= 0xff
			mustDo(t, os.WriteFile(f.dir.staged(stagedArchive), archive, 0o600))
		}, "checksum mismatch"},
		{"binary owned by the agent", func(t *testing.T, f *applierFixture) {
			f.owners[BinaryName] = 1000
		}, "not root"},
		{"binary world-writable", func(t *testing.T, f *applierFixture) {
			mustDo(t, os.Chmod(f.binary, 0o757))
		}, "group- or world-writable"},
		{"binary directory group-writable", func(t *testing.T, f *applierFixture) {
			mustDo(t, os.Chmod(filepath.Dir(f.binary), 0o775))
		}, "group- or world-writable"},
		{"binary directory owned by the agent", func(t *testing.T, f *applierFixture) {
			f.owners["bin"] = 1000
		}, "not root"},
		{"binary is a symlink", func(t *testing.T, f *applierFixture) {
			replaceWithSymlink(t, f.binary)
		}, "symlink"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newApplierFixture(t)
			tc.prepare(t, f)
			res := f.run(t)
			if res.State != models.UpgradeFailed || !strings.Contains(res.Error, tc.wantErr) {
				t.Fatalf("want failed with %q, got %+v", tc.wantErr, res)
			}
			if f.service.restarts != 0 || len(f.refreshs) != 0 {
				t.Fatalf("restarts=%d refresh=%v after a refusal", f.service.restarts, f.refreshs)
			}
			if _, err := os.Lstat(PreviousPath(f.binary)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal(".prev written for a refused upgrade")
			}
		})
	}
}

// TestApplierWritesOnlyRootState checks the success path leaves root's files
// in the root-owned directory and none in the agent's.
func TestApplierWritesOnlyRootState(t *testing.T) {
	f := newApplierFixture(t)
	f.newAgentComesUp(t)
	if res := f.run(t); res.State != models.UpgradeDone {
		t.Fatalf("result %+v", res)
	}
	info, err := os.Stat(string(f.rootDir))
	mustDo(t, err)
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("root dir mode %v", info.Mode())
	}
	for _, name := range []string{pendingFile, resultFile} {
		if _, err := os.Lstat(f.dir.path(name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s written into the agent's directory", name)
		}
	}
	entries, err := os.ReadDir(string(f.dir))
	mustDo(t, err)
	if len(entries) != 0 {
		t.Fatalf("agent directory not cleaned up: %v", entries)
	}
}

func TestCheckTrustedPath(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "bin")
	mustDo(t, os.Mkdir(dir, 0o755))
	bin := filepath.Join(dir, BinaryName)
	mustDo(t, os.WriteFile(bin, nil, 0o755))
	link := filepath.Join(base, "link")
	mustDo(t, os.Symlink(bin, link))

	cases := []struct {
		name    string
		path    string
		owners  map[string]uint32
		chmod   map[string]os.FileMode
		wantErr string
	}{
		{"root-owned binary", bin, nil, nil, ""},
		{"relative path", "bin/" + BinaryName, nil, nil, "clean absolute"},
		{"symlink", link, nil, nil, "symlink"},
		{"binary owned by the agent", bin, map[string]uint32{BinaryName: 1000}, nil, "owned by uid 1000"},
		{"parent owned by the agent", bin, map[string]uint32{"bin": 1000}, nil, "owned by uid 1000"},
		{"binary group-writable", bin, nil, map[string]os.FileMode{bin: 0o775}, "group- or world-writable"},
		{"parent world-writable", bin, nil, map[string]os.FileMode{dir: 0o757}, "group- or world-writable"},
		{"directory instead of a file", dir, nil, nil, "not a regular file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for p, m := range tc.chmod {
				mustDo(t, os.Chmod(p, m))
				t.Cleanup(func() { _ = os.Chmod(p, 0o755) })
			}
			err := testPolicy(base, tc.owners).checkBinary(tc.path)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error with %q, got %v", tc.wantErr, err)
			}
			if !strings.Contains(err.Error(), "sudo chown root:root") {
				t.Fatalf("error does not tell the operator how to fix it: %v", err)
			}
		})
	}
}
