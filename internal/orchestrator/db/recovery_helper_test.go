package db

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

func helperHello() helperprotocol.HelperHello {
	return helperprotocol.HelperHello{
		RequestID:            "enrollment-1",
		HelperInstanceID:     "helper-1",
		HelperBuildID:        "v0.4.0-dev-0619e04",
		AttestationKeyID:     "attestation-1",
		AttestationPublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
}

func TestEnrollRecoveryHelperPersistsAndIsIdempotent(t *testing.T) {
	d := testDB(t)
	agent := createTestAgent(t, d)
	hello := helperHello()
	at := time.Date(2026, 8, 29, 14, 0, 0, 0, time.UTC)
	digest := strings.Repeat("a", 64)
	if err := d.EnrollRecoveryHelper(agent.ID, hello, digest, at); err != nil {
		t.Fatal(err)
	}
	if err := d.EnrollRecoveryHelper(agent.ID, hello, digest, at); err != nil {
		t.Fatalf("idempotent enrollment: %v", err)
	}
	got, err := d.GetRecoveryHelper(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.AgentID != agent.ID || got.HelperInstanceID != hello.HelperInstanceID ||
		got.HelperBuildID != hello.HelperBuildID || got.AttestationKeyID != hello.AttestationKeyID ||
		got.AttestationPublicKey != hello.AttestationPublicKey || got.HelloDigest != digest || !got.EnrolledAt.Equal(at) {
		t.Fatalf("stored helper = %#v", got)
	}
}

func TestEnrollRecoveryHelperRejectsSilentIdentityReplacement(t *testing.T) {
	d := testDB(t)
	agent := createTestAgent(t, d)
	hello := helperHello()
	if err := d.EnrollRecoveryHelper(agent.ID, hello, strings.Repeat("a", 64), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	replaced := hello
	replaced.HelperInstanceID = "helper-attacker"
	if err := d.EnrollRecoveryHelper(agent.ID, replaced, strings.Repeat("b", 64), time.Now().UTC()); !errors.Is(err, ErrRecoveryHelperEnrollmentConflict) {
		t.Fatalf("replacement error = %v, want enrollment conflict", err)
	}
}

func TestEnrollRecoveryHelperAllowsBuildRefreshForSameAttestation(t *testing.T) {
	d := testDB(t)
	agent := createTestAgent(t, d)
	hello := helperHello()
	if err := d.EnrollRecoveryHelper(agent.ID, hello, strings.Repeat("a", 64), time.Date(2026, 8, 29, 14, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	hello.HelperBuildID = "v0.4.0-dev-next"
	refreshedAt := time.Date(2026, 8, 29, 15, 0, 0, 0, time.UTC)
	if err := d.EnrollRecoveryHelper(agent.ID, hello, strings.Repeat("b", 64), refreshedAt); err != nil {
		t.Fatalf("same-key build refresh: %v", err)
	}
	got, err := d.GetRecoveryHelper(agent.ID)
	if err != nil || got.HelperBuildID != hello.HelperBuildID || got.HelloDigest != strings.Repeat("b", 64) || !got.EnrolledAt.Equal(refreshedAt) {
		t.Fatalf("refreshed helper = %#v, err=%v", got, err)
	}
}

func TestRecoveryHelperInstanceCannotMoveAcrossAgents(t *testing.T) {
	d := testDB(t)
	first := createTestAgent(t, d)
	second := *first
	second.ID = "agent-second"
	second.FQDN = "agent-second.example.test"
	if err := d.CreateAgent(&second); err != nil {
		t.Fatal(err)
	}
	hello := helperHello()
	if err := d.EnrollRecoveryHelper(first.ID, hello, strings.Repeat("a", 64), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := d.EnrollRecoveryHelper(second.ID, hello, strings.Repeat("a", 64), time.Now().UTC()); !errors.Is(err, ErrRecoveryHelperEnrollmentConflict) {
		t.Fatalf("cross-agent enrollment error = %v", err)
	}
}

func TestRecoveryHelperAttestationKeyCannotBeRebound(t *testing.T) {
	d := testDB(t)
	first := createTestAgent(t, d)
	second := *first
	second.ID = "agent-second-key"
	second.FQDN = "agent-second-key.example.test"
	if err := d.CreateAgent(&second); err != nil {
		t.Fatal(err)
	}
	hello := helperHello()
	if err := d.EnrollRecoveryHelper(first.ID, hello, strings.Repeat("a", 64), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	hello.HelperInstanceID = "helper-2"
	if err := d.EnrollRecoveryHelper(second.ID, hello, strings.Repeat("b", 64), time.Now().UTC()); !errors.Is(err, ErrRecoveryHelperEnrollmentConflict) {
		t.Fatalf("cross-agent attestation-key error = %v", err)
	}
}
