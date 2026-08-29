//go:build linux

package helper

import (
	"context"
	"fmt"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

const DefaultRootConfigPath = "/etc/nurproxy-agent/root-helper.json"

// RunRootHelper starts only the local socket-activated privileged service. It
// does not initialize the agent HTTP API, outbound clients, adoption, or DDNS.
func RunRootHelper(ctx context.Context, buildID string) error {
	if !validConfigID(buildID) {
		return fmt.Errorf("invalid helper build identity")
	}
	if err := validateSelfExecutable(0); err != nil {
		return fmt.Errorf("helper executable is not trusted: %w", err)
	}
	config, err := LoadRootConfig(DefaultRootConfigPath)
	if err != nil {
		return err
	}
	key, err := LoadOrCreateAttestationKey(config.AttestationPrivateKeyFile)
	if err != nil {
		return fmt.Errorf("load helper attestation key: %w", err)
	}
	journal, err := NewJournal(config.StoreDir, 0)
	if err != nil {
		return fmt.Errorf("open helper journal: %w", err)
	}
	if err := journal.Recover(); err != nil {
		return fmt.Errorf("recover helper journal: %w", err)
	}
	engine, err := NewEngine(config, buildID, journal, key, map[helperprotocol.Action]ActionHandler{})
	if err != nil {
		return fmt.Errorf("initialize helper engine: %w", err)
	}
	listener, err := SystemdListener()
	if err != nil {
		return err
	}
	defer listener.Close()
	return NewServer(engine).Serve(ctx, listener)
}
