//go:build !linux

package main

import "log"

func cmdHelperBootstrap(_ []string) {
	log.Fatal("Root helper bootstrap is supported only on Linux")
}
