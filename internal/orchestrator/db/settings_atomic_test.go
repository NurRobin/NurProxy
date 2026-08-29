package db

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/crypto"
)

func TestInitializeAdminPassword_ConcurrentConnectionsChooseOneWinner(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "nurproxy.db")
	db1, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db1.Close() })
	db2, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db2.Close() })

	const contenders = 16
	start := make(chan struct{})
	type result struct {
		won bool
		err error
	}
	results := make(chan result, contenders)
	var ready sync.WaitGroup
	ready.Add(contenders)
	for i := 0; i < contenders; i++ {
		database := db1
		if i%2 != 0 {
			database = db2
		}
		go func(i int, database *DB) {
			ready.Done()
			<-start
			won, err := database.InitializeAdminPassword(fmt.Sprintf("hash-%d", i))
			results <- result{won: won, err: err}
		}(i, database)
	}
	ready.Wait()
	close(start)

	winners := 0
	var firstErr error
	for i := 0; i < contenders; i++ {
		result := <-results
		if result.err != nil && firstErr == nil {
			firstErr = result.err
		}
		if result.won {
			winners++
		}
	}
	if firstErr != nil {
		t.Fatalf("InitializeAdminPassword: %v", firstErr)
	}
	if winners != 1 {
		t.Fatalf("winners = %d, want exactly 1", winners)
	}
}

func TestInitializeAdminPassword_ClaimsLegacyEmptySettingOnce(t *testing.T) {
	database := testDB(t)
	if err := database.SetSetting("admin_password_hash", ""); err != nil {
		t.Fatal(err)
	}

	won, err := database.InitializeAdminPassword("first-hash")
	if err != nil {
		t.Fatal(err)
	}
	if !won {
		t.Fatal("empty legacy setting was not claimable")
	}
	won, err = database.InitializeAdminPassword("second-hash")
	if err != nil {
		t.Fatal(err)
	}
	if won {
		t.Fatal("non-empty setting was claimed a second time")
	}
	got, err := database.GetSetting("admin_password_hash")
	if err != nil {
		t.Fatal(err)
	}
	if got != "first-hash" {
		t.Fatalf("stored hash = %q, want first-hash", got)
	}
}

func TestInitializeAdminPassword_RejectsEmptyHash(t *testing.T) {
	database := testDB(t)
	won, err := database.InitializeAdminPassword("")
	if err == nil {
		t.Fatal("empty hash was accepted")
	}
	if won {
		t.Fatal("empty hash reported setup ownership")
	}
	if value, getErr := database.GetSetting("admin_password_hash"); getErr == nil || value != "" {
		t.Fatalf("empty hash created a setting: value=%q err=%v", value, getErr)
	}
}

func TestCompareAndSwapSetting_ConcurrentConnectionsReturnOneValue(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "nurproxy.db")
	db1, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db1.Close() })
	db2, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db2.Close() })
	if err := db1.SetSetting("shared-secret", "malformed"); err != nil {
		t.Fatal(err)
	}

	type result struct {
		actual  string
		swapped bool
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for i, database := range []*DB{db1, db2} {
		go func(i int, database *DB) {
			ready.Done()
			<-start
			actual, swapped, err := database.CompareAndSwapSetting("shared-secret", "malformed", fmt.Sprintf("secret-%d", i))
			results <- result{actual: actual, swapped: swapped, err: err}
		}(i, database)
	}
	ready.Wait()
	close(start)

	first := <-results
	second := <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("CompareAndSwapSetting errors: first=%v second=%v", first.err, second.err)
	}
	if first.actual != second.actual {
		t.Fatalf("connections observed different values: %q and %q", first.actual, second.actual)
	}
	if first.actual != "secret-0" && first.actual != "secret-1" {
		t.Fatalf("stored value = %q, want one contender value", first.actual)
	}
	if first.swapped == second.swapped {
		t.Fatalf("swapped flags = %v/%v, want exactly one winner", first.swapped, second.swapped)
	}
}
