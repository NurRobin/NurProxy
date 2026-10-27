//go:build windows

package helper

import (
	"fmt"
	"os"
)

func readTrustedFile(string, uint32, int64, bool) ([]byte, error) {
	return nil, fmt.Errorf("privileged helper is unsupported on Windows")
}

func validateTrustedDirectory(string, uint32) error {
	return fmt.Errorf("privileged helper is unsupported on Windows")
}

func fileOwnerUID(os.FileInfo) uint32 { return ^uint32(0) }

func syncDirectory(string) error { return fmt.Errorf("privileged helper is unsupported on Windows") }
