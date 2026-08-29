package helperprotocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

type signingInput[T any] struct {
	KeyID    string      `json:"key_id"`
	Envelope Envelope[T] `json:"envelope"`
}

func Sign[T any](keyID string, privateKey ed25519.PrivateKey, envelope Envelope[T]) (Signed[T], error) {
	if !validID(keyID) || len(privateKey) != ed25519.PrivateKeySize {
		return Signed[T]{}, fmt.Errorf("invalid signing identity")
	}
	if err := envelope.Validate(); err != nil {
		return Signed[T]{}, err
	}
	input := signingInput[T]{KeyID: keyID, Envelope: envelope}
	canonical, err := CanonicalBytes(input)
	if err != nil {
		return Signed[T]{}, err
	}
	signature := ed25519.Sign(privateKey, canonical)
	return Signed[T]{KeyID: keyID, Envelope: envelope, Signature: base64.RawURLEncoding.EncodeToString(signature)}, nil
}

func Verify[T any](publicKey ed25519.PublicKey, signed Signed[T], expected MessageType) error {
	if len(publicKey) != ed25519.PublicKeySize || signed.Envelope.MessageType != expected || signed.Validate() != nil {
		return fmt.Errorf("invalid signed protocol envelope")
	}
	input := signingInput[T]{KeyID: signed.KeyID, Envelope: signed.Envelope}
	canonical, err := CanonicalBytes(input)
	if err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(signed.Signature)
	if err != nil || !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("protocol signature verification failed")
	}
	return nil
}
