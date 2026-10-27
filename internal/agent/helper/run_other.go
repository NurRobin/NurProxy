//go:build !linux

package helper

import (
	"context"
	"fmt"
)

const DefaultRootConfigPath = "/etc/nurproxy-agent/root-helper.json"

func RunRootHelper(context.Context, string) error {
	return fmt.Errorf("privileged root helper is supported only on Linux")
}
