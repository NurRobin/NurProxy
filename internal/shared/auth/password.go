package auth

import "golang.org/x/crypto/bcrypt"

// DefaultHashCost is the bcrypt cost used for stored passwords.
const DefaultHashCost = 12

// hashCost is DefaultHashCost except in tests that lower it with
// SetHashCostForTesting.
var hashCost = DefaultHashCost

// HashPassword returns a bcrypt hash of the given password.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), hashCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CheckPassword compares a bcrypt hash with a plaintext password.
// Returns nil on success or an error if they do not match.
func CheckPassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// SetHashCostForTesting lowers the bcrypt cost so test suites that create
// many admin passwords stay fast (cost 12 takes seconds per hash under the
// race detector). It must only be called from tests, before any test runs.
func SetHashCostForTesting(cost int) {
	if cost < bcrypt.MinCost {
		cost = bcrypt.MinCost
	}
	hashCost = cost
}
