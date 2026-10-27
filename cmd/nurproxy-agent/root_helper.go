package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/NurRobin/NurProxy/internal/agent/helper"
)

func validateRootHelperInvocation(args []string, effectiveUID int) error {
	if len(args) != 0 {
		return fmt.Errorf("root-helper accepts no arguments")
	}
	if effectiveUID != 0 {
		return fmt.Errorf("root-helper requires effective uid 0")
	}
	return nil
}

func cmdRootHelper(args []string) {
	if err := validateRootHelperInvocation(args, os.Geteuid()); err != nil {
		log.Fatalf("Root helper invocation refused: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := helper.RunRootHelper(ctx, version); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("Root helper failed closed: %v", err)
	}
}

func validateHelperRefreshInvocation(args []string, effectiveUID int, buildID string) error {
	if len(args) != 0 {
		return fmt.Errorf("helper-refresh-build accepts no arguments")
	}
	if effectiveUID != 0 {
		return fmt.Errorf("helper-refresh-build requires effective uid 0")
	}
	if buildID == "" {
		return fmt.Errorf("helper-refresh-build requires an immutable build identity")
	}
	return nil
}

func cmdHelperRefreshBuild(args []string) {
	if err := validateHelperRefreshInvocation(args, os.Geteuid(), version); err != nil {
		log.Fatalf("Root helper build refresh refused: %v", err)
	}
	changed, err := helper.RefreshRootConfigBuildID(helper.DefaultRootConfigPath, version)
	if err != nil {
		log.Fatalf("Root helper build refresh failed: %v", err)
	}
	if changed {
		log.Printf("Root helper build identity refreshed")
	}
}
