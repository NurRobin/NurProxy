package api

import (
	"os"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/auth"
	"golang.org/x/crypto/bcrypt"
)

// TestMain hashes admin passwords at the minimum bcrypt cost: almost every
// test here runs the setup flow, and the production cost made the package
// take most of the CI time limit.
func TestMain(m *testing.M) {
	auth.SetHashCostForTesting(bcrypt.MinCost)
	os.Exit(m.Run())
}
