//go:build sandbox

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	switch strings.Join(os.Args[1:], " ") {
	case "-v":
		fmt.Fprintln(os.Stderr, "nginx version: nginx/1.24.0")
	case "-t":
		if validationFailureEnabled() {
			fmt.Fprintln(os.Stderr, "nginx: [emerg] sandbox fixture injected unclassified validation failure")
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "nginx: configuration file sandbox syntax is ok")
	case "-s reload":
		return
	default:
		fmt.Fprintln(os.Stderr, "sandbox nginx fixture: unsupported arguments")
		os.Exit(2)
	}
}

func validationFailureEnabled() bool {
	executable, err := os.Executable()
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(filepath.Dir(executable), "fail-validation"))
	return err == nil
}
