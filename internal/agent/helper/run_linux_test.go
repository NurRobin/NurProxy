//go:build linux

package helper

import (
	"context"
	"testing"
)

func TestRunRootHelperRejectsMutableBuildIdentity(t *testing.T) {
	for _, buildID := range []string{"", " build", "build/escape"} {
		if err := RunRootHelper(context.Background(), buildID); err == nil {
			t.Fatalf("RunRootHelper accepted build id %q", buildID)
		}
	}
}
