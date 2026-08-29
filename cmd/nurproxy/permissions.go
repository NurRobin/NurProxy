package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/NurRobin/NurProxy/internal/orchestrator/dataperms"
	"github.com/NurRobin/NurProxy/internal/shared/install"
)

func cmdPermissions(args []string) {
	fs := flag.NewFlagSet("permissions", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory (default: $NP_DATA_DIR or ./data)")
	dropIn := fs.String("systemd-drop-in", "", "Write an exact ReadWritePaths systemd drop-in")
	envFile := fs.String("environment-file", "", "Read NP_DATA_DIR from a systemd EnvironmentFile when present")
	_ = fs.Parse(args)
	resolved := resolveDataDir(*dataDir)
	if *envFile != "" {
		f, err := os.Open(*envFile)
		if err == nil {
			parsed, found, parseErr := install.ParseEnvironmentDataDir(f)
			_ = f.Close()
			if parseErr != nil {
				fatalf("permissions: environment file: %v", parseErr)
			}
			if found {
				resolved = parsed
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			fatalf("permissions: environment file: %v", err)
		}
	}
	report, err := dataperms.Ensure(resolved)
	if err != nil {
		fatalf("permissions: %v", err)
	}
	for _, skipped := range report.Skipped {
		fmt.Printf("permissions: skipped %s\n", skipped)
	}
	if *dropIn != "" {
		if err := install.WriteDataDirDropIn(*dropIn, resolved); err != nil {
			fatalf("permissions: systemd drop-in: %v", err)
		}
	}
	fmt.Printf("Restricted %d orchestrator data path(s)\n", len(report.Hardened))
}
