package recoveryauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

type Authority struct {
	keyID   string
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func New(seed []byte) (*Authority, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("recovery authority seed has invalid size")
	}
	private := ed25519.NewKeyFromSeed(append([]byte(nil), seed...))
	public := append(ed25519.PublicKey(nil), private.Public().(ed25519.PublicKey)...)
	digest := sha256.Sum256(public)
	return &Authority{
		keyID:   "orchestrator-ed25519-" + hex.EncodeToString(digest[:12]),
		private: private,
		public:  public,
	}, nil
}

func LoadOrGenerate(file *os.File, created bool) (*Authority, error) {
	if file == nil {
		return nil, fmt.Errorf("recovery authority key descriptor is required")
	}
	if err := file.Chmod(0o600); err != nil {
		return nil, fmt.Errorf("restrict recovery authority key: %w", err)
	}
	seed := make([]byte, ed25519.SeedSize)
	if created {
		if _, err := io.ReadFull(rand.Reader, seed); err != nil {
			return nil, fmt.Errorf("generate recovery authority seed: %w", err)
		}
		if _, err := file.WriteAt(seed, 0); err != nil {
			return nil, fmt.Errorf("persist recovery authority seed: %w", err)
		}
		if err := file.Truncate(ed25519.SeedSize); err != nil {
			return nil, fmt.Errorf("truncate recovery authority key: %w", err)
		}
		if err := file.Sync(); err != nil {
			return nil, fmt.Errorf("sync recovery authority key: %w", err)
		}
	} else {
		n, err := file.ReadAt(seed, 0)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("load recovery authority seed: %w", err)
		}
		info, statErr := file.Stat()
		if statErr != nil {
			return nil, fmt.Errorf("stat recovery authority key: %w", statErr)
		}
		if n != ed25519.SeedSize || info.Size() != ed25519.SeedSize {
			return nil, fmt.Errorf("recovery authority key has invalid size")
		}
	}
	return New(seed)
}

func (a *Authority) KeyID() string {
	if a == nil {
		return ""
	}
	return a.keyID
}

func (a *Authority) PublicKey() ed25519.PublicKey {
	if a == nil {
		return nil
	}
	return append(ed25519.PublicKey(nil), a.public...)
}

func (a *Authority) PublicKeyText() string {
	return base64.RawURLEncoding.EncodeToString(a.PublicKey())
}

func (a *Authority) SignExecutionGrant(grant helperprotocol.ExecutionGrant) (helperprotocol.Signed[helperprotocol.ExecutionGrant], error) {
	if a == nil || grant.Validate() != nil {
		return helperprotocol.Signed[helperprotocol.ExecutionGrant]{}, fmt.Errorf("invalid recovery execution grant")
	}
	return helperprotocol.Sign(a.keyID, a.private, helperprotocol.NewEnvelope(helperprotocol.MessageExecutionGrant, grant))
}

func (a *Authority) SignApplyIntent(intent helperprotocol.ApplyIntent) (helperprotocol.Signed[helperprotocol.ApplyIntent], error) {
	if a == nil || intent.Validate() != nil {
		return helperprotocol.Signed[helperprotocol.ApplyIntent]{}, fmt.Errorf("invalid managed apply intent")
	}
	return helperprotocol.Sign(a.keyID, a.private, helperprotocol.NewEnvelope(helperprotocol.MessageApplyIntent, intent))
}

func (a *Authority) SignApplyGrant(grant helperprotocol.ApplyGrant) (helperprotocol.Signed[helperprotocol.ApplyGrant], error) {
	if a == nil || grant.Validate() != nil {
		return helperprotocol.Signed[helperprotocol.ApplyGrant]{}, fmt.Errorf("invalid managed apply grant")
	}
	return helperprotocol.Sign(a.keyID, a.private, helperprotocol.NewEnvelope(helperprotocol.MessageApplyGrant, grant))
}

func (a *Authority) SignCancellationGrant(grant helperprotocol.CancellationGrant) (helperprotocol.Signed[helperprotocol.CancellationGrant], error) {
	if a == nil || grant.Validate() != nil {
		return helperprotocol.Signed[helperprotocol.CancellationGrant]{}, fmt.Errorf("invalid cancellation grant")
	}
	return helperprotocol.Sign(a.keyID, a.private, helperprotocol.NewEnvelope(helperprotocol.MessageCancellationGrant, grant))
}
