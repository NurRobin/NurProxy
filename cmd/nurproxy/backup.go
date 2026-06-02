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
	defer os.RemoveAll(snapDir)
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
	restored := 0
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return restored, fmt.Errorf("reading archive: %w", err)
		}
		// Only known, flat filenames are honored — this rejects path traversal
		// (../, absolute paths) and any unexpected entries outright.
		name := filepath.Base(hdr.Name)
		if hdr.Typeflag != tar.TypeReg || name != hdr.Name || !allowed[name] {
			fmt.Fprintf(os.Stderr, "restore: skipping unexpected entry %q\n", hdr.Name)
			continue
		}
		if err := writeFileFromTar(filepath.Join(dataDir, name), tr); err != nil {
			return restored, fmt.Errorf("writing %s: %w", name, err)
		}
		restored++
	}

	if restored == 0 {
		return 0, fmt.Errorf("archive contained no recognizable NurProxy files")
	}
	return restored, nil
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

// writeFileFromTar writes the current tar entry to dest with mode 0600 (secrets
// and the DB must not be world-readable).
func writeFileFromTar(dest string, tr io.Reader) error {
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, tr)
	return err
}
