package helperclient

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

const DefaultSocketPath = "/run/nurproxy-agent-helper/helper.sock"

type RemoteError struct {
	Code      helperprotocol.ErrorCode
	Message   string
	Retryable bool
}

func (e *RemoteError) Error() string {
	if e == nil {
		return "root helper request failed"
	}
	return fmt.Sprintf("root helper request failed (%s): %s", e.Code, e.Message)
}

type Pin struct {
	HelperInstanceID     string `json:"helper_instance_id"`
	AttestationKeyID     string `json:"attestation_key_id"`
	AttestationPublicKey string `json:"attestation_public_key"`
}

func (p Pin) Validate() error {
	if !validID(p.HelperInstanceID) || !validID(p.AttestationKeyID) {
		return fmt.Errorf("invalid helper attestation pin identity")
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(p.AttestationPublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid helper attestation public key")
	}
	return nil
}

func (p Pin) publicKey() ed25519.PublicKey {
	key, _ := base64.RawURLEncoding.Strict().DecodeString(p.AttestationPublicKey)
	return ed25519.PublicKey(append([]byte(nil), key...))
}

func validID(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && !strings.ContainsRune("._:-", r) {
			return false
		}
	}
	return true
}
