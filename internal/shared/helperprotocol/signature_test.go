package helperprotocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSignedEnvelopeBindsKeyDomainTypeAndPayload(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	grant := validExecutionGrant()
	envelope := NewEnvelope(MessageExecutionGrant, grant)
	signed, err := Sign("orchestrator-2026-01", privateKey, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(publicKey, signed, MessageExecutionGrant); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if err := Verify(publicKey, signed, MessageApplyGrant); err == nil {
		t.Fatal("signature accepted for another message type")
	}

	tampered := signed
	tampered.Envelope.Payload.Action = ActionRestartProxy
	if err := Verify(publicKey, tampered, MessageExecutionGrant); err == nil {
		t.Fatal("tampered payload accepted")
	}
	tampered = signed
	tampered.KeyID = "other-key"
	if err := Verify(publicKey, tampered, MessageExecutionGrant); err == nil {
		t.Fatal("signature accepted under another key ID")
	}
	tampered = signed
	tampered.Envelope.Domain = "other.protocol"
	if err := Verify(publicKey, tampered, MessageExecutionGrant); err == nil {
		t.Fatal("signature accepted in another domain")
	}
}
