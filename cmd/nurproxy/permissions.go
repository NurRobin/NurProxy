package main

import (
	"flag"
	"fmt"

	"github.com/NurRobin/NurProxy/internal/orchestrator/dataperms"
)

func cmdPermissions(args []string) {
	fs := flag.NewFlagSet("permissions", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory (default: $NP_DATA_DIR or ./data)")
	_ = fs.Parse(args)
	report, err := dataperms.Ensure(resolveDataDir(*dataDir))
	if err != nil {
		fatalf("permissions: %v", err)
	}
	for _, skipped := range report.Skipped {
		fmt.Printf("permissions: skipped %s\n", skipped)
	}
	fmt.Printf("Restricted %d orchestrator data path(s)\n", len(report.Hardened))
}
