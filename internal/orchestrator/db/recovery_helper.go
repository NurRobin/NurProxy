package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

var (
	ErrRecoveryHelperEnrollmentConflict = errors.New("recovery helper enrollment conflicts with existing identity")
	ErrRecoveryHelperNotEnrolled        = errors.New("recovery helper not enrolled")
)

type RecoveryHelperInstance struct {
	AgentID              string    `json:"agent_id"`
	HelperInstanceID     string    `json:"helper_instance_id"`
	HelperBuildID        string    `json:"helper_build_id"`
	AttestationKeyID     string    `json:"attestation_key_id"`
	AttestationPublicKey string    `json:"attestation_public_key"`
	HelloDigest          string    `json:"hello_digest"`
	EnrolledAt           time.Time `json:"enrolled_at"`
}

func (d *DB) EnrollRecoveryHelper(agentID string, hello helperprotocol.HelperHello, helloDigest string, at time.Time) error {
	if strings.TrimSpace(agentID) == "" || hello.Validate() != nil || !validRecoveryDigest(helloDigest) || at.IsZero() {
		return fmt.Errorf("invalid recovery helper enrollment")
	}
	atNanos, err := recoveryUnixNano(at)
	if err != nil {
		return fmt.Errorf("encode helper enrollment time: %w", err)
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return fmt.Errorf("begin recovery helper enrollment: %w", err)
	}
	defer tx.Rollback()
	var agentExists int
	if err := tx.QueryRow(`SELECT 1 FROM agents WHERE id = ?`, agentID).Scan(&agentExists); err == sql.ErrNoRows {
		return fmt.Errorf("agent not found: %s", agentID)
	} else if err != nil {
		return fmt.Errorf("query recovery helper agent: %w", err)
	}
	existing, err := scanRecoveryHelper(tx.QueryRow(recoveryHelperSelect+` WHERE agent_id = ?`, agentID))
	if err == nil {
		if existing.HelperInstanceID == hello.HelperInstanceID && existing.HelperBuildID == hello.HelperBuildID &&
			existing.AttestationKeyID == hello.AttestationKeyID && existing.AttestationPublicKey == hello.AttestationPublicKey &&
			existing.HelloDigest == helloDigest {
			return nil
		}
		if existing.HelperInstanceID == hello.HelperInstanceID && existing.AttestationKeyID == hello.AttestationKeyID &&
			existing.AttestationPublicKey == hello.AttestationPublicKey {
			if _, err := tx.Exec(`UPDATE recovery_helper_instances SET helper_build_id = ?, hello_digest = ?, enrolled_at = ?
				WHERE agent_id = ? AND helper_instance_id = ? AND attestation_key_id = ?`, hello.HelperBuildID,
				helloDigest, atNanos, agentID, hello.HelperInstanceID, hello.AttestationKeyID); err != nil {
				return fmt.Errorf("refresh recovery helper build enrollment: %w", err)
			}
			if err := tx.Commit(); err != nil {
				return fmt.Errorf("commit recovery helper build enrollment: %w", err)
			}
			return nil
		}
		return ErrRecoveryHelperEnrollmentConflict
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("query existing recovery helper: %w", err)
	}
	var boundAgent string
	if err := tx.QueryRow(`SELECT agent_id FROM recovery_helper_instances WHERE helper_instance_id = ?`, hello.HelperInstanceID).Scan(&boundAgent); err == nil {
		return ErrRecoveryHelperEnrollmentConflict
	} else if err != sql.ErrNoRows {
		return fmt.Errorf("query recovery helper instance binding: %w", err)
	}
	if err := tx.QueryRow(`SELECT agent_id FROM recovery_helper_instances WHERE attestation_key_id = ?`, hello.AttestationKeyID).Scan(&boundAgent); err == nil {
		return ErrRecoveryHelperEnrollmentConflict
	} else if err != sql.ErrNoRows {
		return fmt.Errorf("query recovery helper attestation binding: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO recovery_helper_instances (
		agent_id, helper_instance_id, helper_build_id, attestation_key_id,
		attestation_public_key, hello_digest, enrolled_at
	) VALUES (?, ?, ?, ?, ?, ?, ?)`, agentID, hello.HelperInstanceID, hello.HelperBuildID,
		hello.AttestationKeyID, hello.AttestationPublicKey, helloDigest, atNanos); err != nil {
		return fmt.Errorf("insert recovery helper enrollment: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit recovery helper enrollment: %w", err)
	}
	return nil
}

func (d *DB) GetRecoveryHelper(agentID string) (*RecoveryHelperInstance, error) {
	if strings.TrimSpace(agentID) == "" {
		return nil, fmt.Errorf("recovery helper agent ID is required")
	}
	instance, err := scanRecoveryHelper(d.read.QueryRow(recoveryHelperSelect+` WHERE agent_id = ?`, agentID))
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%w for agent: %s", ErrRecoveryHelperNotEnrolled, agentID)
	}
	if err != nil {
		return nil, fmt.Errorf("query recovery helper enrollment: %w", err)
	}
	return &instance, nil
}

const recoveryHelperSelect = `SELECT agent_id, helper_instance_id, helper_build_id,
	attestation_key_id, attestation_public_key, hello_digest, enrolled_at
	FROM recovery_helper_instances`

func scanRecoveryHelper(scanner interface{ Scan(...any) error }) (RecoveryHelperInstance, error) {
	var instance RecoveryHelperInstance
	var enrolledAt int64
	if err := scanner.Scan(&instance.AgentID, &instance.HelperInstanceID, &instance.HelperBuildID,
		&instance.AttestationKeyID, &instance.AttestationPublicKey, &instance.HelloDigest, &enrolledAt); err != nil {
		return instance, err
	}
	hello := helperprotocol.HelperHello{
		RequestID: "stored-enrollment", HelperInstanceID: instance.HelperInstanceID,
		HelperBuildID: instance.HelperBuildID, AttestationKeyID: instance.AttestationKeyID,
		AttestationPublicKey: instance.AttestationPublicKey,
	}
	if strings.TrimSpace(instance.AgentID) == "" || hello.Validate() != nil || !validRecoveryDigest(instance.HelloDigest) {
		return instance, fmt.Errorf("invalid stored recovery helper enrollment")
	}
	var err error
	instance.EnrolledAt, err = recoveryTimeFromUnixNano(enrolledAt)
	if err != nil {
		return instance, fmt.Errorf("decode helper enrollment time: %w", err)
	}
	return instance, nil
}

func validRecoveryDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
