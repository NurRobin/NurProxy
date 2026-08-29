package main

import (
	"flag"
	"fmt"

	"github.com/NurRobin/NurProxy/internal/orchestrator/dataperms"
	"github.com/NurRobin/NurProxy/internal/shared/install"
)

func cmdPermissions(args []string) {
	fs := flag.NewFlagSet("permissions", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory (default: $NP_DATA_DIR or ./data)")
	dropIn := fs.String("systemd-drop-in", "", "Write an exact ReadWritePaths systemd drop-in")
	_ = fs.Parse(args)
	report, err := dataperms.Ensure(resolveDataDir(*dataDir))
	if err != nil {
		fatalf("permissions: %v", err)
	}
	for _, skipped := range report.Skipped {
		fmt.Printf("permissions: skipped %s\n", skipped)
	}
	if *dropIn != "" {
		if err := install.WriteDataDirDropIn(*dropIn, resolveDataDir(*dataDir)); err != nil {
			fatalf("permissions: systemd drop-in: %v", err)
		}
	}
	fmt.Printf("Restricted %d orchestrator data path(s)\n", len(report.Hardened))
}
