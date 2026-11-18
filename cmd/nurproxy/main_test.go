package main

import (
	"os"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/auth"
	"golang.org/x/crypto/bcrypt"
)

// TestMain hashes admin passwords at the minimum bcrypt cost so the CLI
// tests that run the setup flow stay fast.
func TestMain(m *testing.M) {
	auth.SetHashCostForTesting(bcrypt.MinCost)
	os.Exit(m.Run())
}
