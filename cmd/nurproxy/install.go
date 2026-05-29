package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/NurRobin/NurProxy/internal/shared/install"
)

// service builds the orchestrator's install.Service from install flags.
func orchestratorService(bin, dataDir string, port int, user string) install.Service {
	return install.Service{
		Name:        "nurproxy",
		Description: "NurProxy orchestrator",
		BinaryPath:  bin,
		User:        user,
		DataDir:     dataDir,
		EnvFile:     "/etc/nurproxy/nurproxy.env",
		Env: map[string]string{
			"NP_PORT":     strconv.Itoa(port),
			"NP_DATA_DIR": dataDir,
		},
	}
}

// cmdInstall handles `nurproxy install`.
func cmdInstall(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	port := fs.Int("port", 8080, "HTTP port")
	dataDir := fs.String("data-dir", "/var/lib/nurproxy", "Data directory")
	user := fs.String("user", "root", "System user to run the service as")
	bin := fs.String("bin", selfPath(), "Path to the nurproxy binary the service runs")
	_ = fs.Parse(args)

	if err := install.Install(orchestratorService(*bin, *dataDir, *port, *user), os.Stdout); err != nil {
		log.Fatalf("install failed: %v", err)
	}
}

// cmdUninstall handles `nurproxy uninstall`.
func cmdUninstall(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	dataDir := fs.String("data-dir", "/var/lib/nurproxy", "Data directory (only removed with --purge)")
	purge := fs.Bool("purge", false, "Also remove data dir, config, and env file")
	yes := fs.Bool("yes", false, "Skip the confirmation prompt")
	_ = fs.Parse(args)

	if *purge && !*yes && !confirm(fmt.Sprintf("Remove the nurproxy service AND its data at %s? [y/N] ", *dataDir)) {
		fmt.Println("aborted")
		return
	}
	svc := orchestratorService(selfPath(), *dataDir, 0, "")
	if err := install.Uninstall(svc, *purge, os.Stdout); err != nil {
		log.Fatalf("uninstall failed: %v", err)
	}
}

// selfPath returns the absolute path of the running executable, falling back to
// the conventional install location.
func selfPath() string {
	if p, err := os.Executable(); err == nil {
		return p
	}
	return "/usr/local/bin/nurproxy"
}

// confirm prompts for a y/N answer on stdin.
func confirm(prompt string) bool {
	fmt.Print(prompt)
	var resp string
	_, _ = fmt.Scanln(&resp)
	return resp == "y" || resp == "Y" || resp == "yes"
}
