package main

import (
	"archive/tar"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
)

// backupFiles are the data-dir entries a backup captures. nurproxy.db is written
// as a consistent VACUUM INTO snapshot; the key files are copied verbatim. The
// keys are REQUIRED for a restore to be useful: every provider config and TLS
// private key in the DB is encrypted with encryption.key, and acme-account.key
// identifies the ACME account so issued certs can keep renewing. A DB without
// its keys restores to an install that cannot decrypt its own secrets.
const (
	dbFileName         = "nurproxy.db"
	encryptionKeyName  = "encryption.key"
	acmeAccountKeyName = "acme-account.key"
)

// resolveDataDir returns the data dir from the flag, falling back to NP_DATA_DIR
// then the ./data default — matching the server's own resolution order.
func resolveDataDir(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if env := os.Getenv("NP_DATA_DIR"); env != "" {
		return env
	}
	return "./data"
}

// cmdBackup writes a gzipped tar of the orchestrator's data dir (a consistent DB
// snapshot plus the encryption + ACME account keys) to an output file. It is
// safe to run while the orchestrator is live.
//
//	nurproxy backup [--data-dir DIR] [-o OUTFILE]
func cmdBackup(args []string) {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory (default: $NP_DATA_DIR or ./data)")
	out := fs.String("o", "", "Output file (default: nurproxy-backup-<timestamp>.tar.gz)")
	_ = fs.Parse(args)

	dir := resolveDataDir(*dataDir)
	outPath := *out
	if outPath == "" {
		outPath = fmt.Sprintf("nurproxy-backup-%s.tar.gz", time.Now().UTC().Format("20060102-150405"))
	}

	if err := backupDataDir(dir, outPath); err != nil {
		fatalf("backup: %v", err)
	}
	fmt.Printf("Backup written to %s\n", outPath)
	fmt.Fprintf(os.Stderr, "backup: WARNING: %s contains the plaintext %s — store it as a secret (anyone with it can decrypt every provider config and TLS key in the DB)\n", outPath, encryptionKeyName)
}

// backupDataDir writes a gzipped tar of a consistent DB snapshot plus the key
// files from dataDir to outPath. Missing key files are skipped with a warning.
func backupDataDir(dataDir, outPath string) error {
	dbPath := filepath.Join(dataDir, dbFileName)
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("no database at %s (is the data dir correct?): %w", dbPath, err)
	}

	// Snapshot the DB to a temp file so we archive a consistent image even while
	// the orchestrator is writing. VACUUM INTO refuses to overwrite, so use a
	// fresh temp path and remove it afterward.
	snapDir, err := os.MkdirTemp("", "nurproxy-backup-")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(snapDir) }()
	snapPath := filepath.Join(snapDir, dbFileName)
	if err := db.SnapshotTo(dbPath, snapPath); err != nil {
		return err
	}

	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("creating %s: %w", outPath, err)
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	if err := addFileToTar(tw, snapPath, dbFileName); err != nil {
		return fmt.Errorf("archiving database: %w", err)
	}
	// The key files, copied verbatim. Missing keys are skipped (a fresh install
	// that never generated them yet), but we warn since a keyless backup is of
	// limited use.
	for _, name := range []string{encryptionKeyName, acmeAccountKeyName} {
		p := filepath.Join(dataDir, name)
		if _, err := os.Stat(p); err != nil {
			fmt.Fprintf(os.Stderr, "backup: warning: %s not found, omitting from archive\n", name)
			continue
		}
		if err := addFileToTar(tw, p, name); err != nil {
			return fmt.Errorf("archiving %s: %w", name, err)
		}
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("finalizing archive: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("finalizing gzip: %w", err)
	}
	return nil
}

// cmdRestore extracts a backup archive into a data dir. It refuses to clobber an
// existing database unless --force is given.
//
//	nurproxy restore [--data-dir DIR] [--force] ARCHIVE
func cmdRestore(args []string) {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory to restore into (default: $NP_DATA_DIR or ./data)")
	force := fs.Bool("force", false, "Overwrite an existing database in the data dir")
	_ = fs.Parse(args)

	if fs.NArg() != 1 {
		fatalf("restore: exactly one archive argument is required, e.g. `nurproxy restore backup.tar.gz`")
	}
	dir := resolveDataDir(*dataDir)

	restored, err := restoreArchive(fs.Arg(0), dir, *force)
	if err != nil {
		fatalf("restore: %v", err)
	}
	fmt.Printf("Restored %d file(s) into %s\n", restored, dir)
	fmt.Println("Start the orchestrator against this data dir to bring it back up.")
}

// restoreArchive extracts the recognized NurProxy files from a backup archive
// into dataDir, returning the number of files restored. It refuses to clobber an
// existing database unless force is set, and ignores any entry that isn't one of
// the known flat filenames (rejecting path traversal and stray content).
//
// The restore is ATOMIC with respect to the existing data dir: every entry is
// first extracted to a temp file alongside its destination, the whole archive is
// read to completion (so gzip's CRC validates the full stream and a truncated or
// corrupt archive is caught) and only then are the temp files renamed into place.
// On any error before the commit, the temp files are removed and the existing
// data dir is left byte-for-byte untouched.
func restoreArchive(archivePath, dataDir string, force bool) (int, error) {
	if _, err := os.Stat(filepath.Join(dataDir, dbFileName)); err == nil && !force {
		return 0, fmt.Errorf("%s already has a %s — refusing to overwrite (pass --force to replace it)", dataDir, dbFileName)
	}

	f, err := os.Open(archivePath)
	if err != nil {
		return 0, fmt.Errorf("opening %s: %w", archivePath, err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return 0, fmt.Errorf("%s is not a gzip archive: %w", archivePath, err)
	}
	defer gz.Close()

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return 0, fmt.Errorf("creating data dir %s: %w", dataDir, err)
	}

	allowed := map[string]bool{dbFileName: true, encryptionKeyName: true, acmeAccountKeyName: true}

	// staged maps the final filename to the temp file it has been extracted to.
	// Until the whole archive verifies we touch nothing in dataDir but these
	// temps, which are removed on any failure path.
	staged := map[string]string{}
	committed := false
	defer func() {
		if !committed {
			for _, tmp := range staged {
				_ = os.Remove(tmp)
			}
		}
	}()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			// A truncated/corrupt archive surfaces here (incl. gzip CRC). The
			// defer wipes the staged temps; dataDir is untouched.
			return 0, fmt.Errorf("reading archive: %w", err)
		}
		// Only known, flat filenames are honored — this rejects path traversal
		// (../, absolute paths) and any unexpected entries outright.
		name := filepath.Base(hdr.Name)
		if hdr.Typeflag != tar.TypeReg || name != hdr.Name || !allowed[name] {
			fmt.Fprintf(os.Stderr, "restore: skipping unexpected entry %q\n", hdr.Name)
			continue
		}
		tmp, err := extractToTemp(dataDir, name, tr)
		if err != nil {
			return 0, fmt.Errorf("staging %s: %w", name, err)
		}
		staged[name] = tmp
	}

	if len(staged) == 0 {
		return 0, fmt.Errorf("archive contained no recognizable NurProxy files")
	}

	// The archive read cleanly. Before installing the new DB, guard against a key
	// mismatch: if the archive omits encryption.key but the target already has one,
	// the restored DB would be decrypted with a stale key. Refuse rather than
	// silently leave a DB that cannot read its own secrets.
	if _, bringsKey := staged[encryptionKeyName]; !bringsKey {
		if _, bringsDB := staged[dbFileName]; bringsDB {
			existingKey := filepath.Join(dataDir, encryptionKeyName)
			if _, err := os.Stat(existingKey); err == nil {
				return 0, fmt.Errorf("archive has no %s but %s already exists — the existing key may not match the restored %s; restore from a backup that includes the key, or remove the stale key deliberately first", encryptionKeyName, existingKey, dbFileName)
			}
		}
	}

	// Commit: rename each staged temp over its destination. The DB is installed
	// first; once it lands we clear any stale -wal/-shm so SQLite can't replay a
	// journal that belonged to the previous database.
	restored := 0
	commit := func(name string) error {
		dest := filepath.Join(dataDir, name)
		if err := os.Rename(staged[name], dest); err != nil {
			return fmt.Errorf("installing %s: %w", name, err)
		}
		delete(staged, name)
		restored++
		return nil
	}
	if _, ok := staged[dbFileName]; ok {
		if err := commit(dbFileName); err != nil {
			return restored, err
		}
		for _, sidecar := range []string{dbFileName + "-wal", dbFileName + "-shm"} {
			if err := os.Remove(filepath.Join(dataDir, sidecar)); err != nil && !os.IsNotExist(err) {
				return restored, fmt.Errorf("removing stale %s: %w", sidecar, err)
			}
		}
	}
	for name := range staged {
		if err := commit(name); err != nil {
			return restored, err
		}
	}

	committed = true
	return restored, nil
}

// extractToTemp writes the current tar entry to a temp file in dataDir (same
// filesystem as the destination, so the later rename is atomic) and returns its
// path. The temp is named after the target so a crash leaves it obviously stray.
func extractToTemp(dataDir, name string, tr io.Reader) (string, error) {
	tmp, err := os.CreateTemp(dataDir, "."+name+".restore-*")
	if err != nil {
		return "", err
	}
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", err
	}
	if _, err := io.Copy(tmp, tr); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

// addFileToTar writes the file at srcPath into the tar under name with mode 0600.
func addFileToTar(tw *tar.Writer, srcPath, name string) error {
	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{
		Name:    name,
		Mode:    0600,
		Size:    info.Size(),
		ModTime: info.ModTime(),
	}); err != nil {
		return err
	}
	_, err = io.Copy(tw, in)
	return err
}
