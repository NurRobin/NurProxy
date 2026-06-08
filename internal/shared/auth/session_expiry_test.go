package auth

import (
	"errors"
	"testing"
	"time"
)

// A signed token must stop verifying once its embedded expiry has passed. The
// old format carried no expiry at all, so this fails against the pre-fix code.
func TestSessionManager_ExpiryEnforced(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		ttl     time.Duration
		elapsed time.Duration
		wantErr error
		wantOK  bool
	}{
		{name: "fresh within ttl", ttl: time.Hour, elapsed: 30 * time.Minute, wantOK: true},
		{name: "just past expiry", ttl: time.Hour, elapsed: time.Hour + time.Second, wantErr: ErrSessionExpired},
		{name: "exactly at expiry", ttl: time.Hour, elapsed: time.Hour, wantErr: ErrSessionExpired},
		{name: "long-lived still valid", ttl: 168 * time.Hour, elapsed: 24 * time.Hour, wantOK: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := base
			sm := NewSessionManager([]byte("k")).WithTTL(tt.ttl)
			sm.now = func() time.Time { return now }

			signed := sm.Sign("tok")
			now = base.Add(tt.elapsed)

			got, err := sm.Verify(signed)
			if tt.wantOK {
				if err != nil {
					t.Fatalf("expected valid, got error: %v", err)
				}
				if got != "tok" {
					t.Fatalf("token = %q, want %q", got, "tok")
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// Bumping the server-side session version must invalidate tokens minted under an
// older version (logout / password-change revocation). Pre-fix there was no
// version in the payload, so a bump had no effect.
func TestSessionManager_VersionRevocation(t *testing.T) {
	version := 0
	sm := NewSessionManager([]byte("k")).
		WithTTL(time.Hour).
		WithVersion(func() int { return version })

	signed := sm.Sign("tok") // minted under version 0

	// Still valid at the same version.
	if _, err := sm.Verify(signed); err != nil {
		t.Fatalf("token should verify before revocation: %v", err)
	}

	// Bump the server-side version: the old cookie must now be rejected.
	version = 1
	if _, err := sm.Verify(signed); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("after version bump: error = %v, want ErrSessionRevoked", err)
	}

	// A freshly signed token (now at version 1) verifies again.
	fresh := sm.Sign("tok2")
	if got, err := sm.Verify(fresh); err != nil || got != "tok2" {
		t.Fatalf("fresh token: got %q err %v, want tok2 nil", got, err)
	}
}

// Tampering with the embedded metadata (version/expiry) must break the HMAC and
// be rejected — the metadata is inside the signed payload.
func TestSessionManager_TamperedMetadata(t *testing.T) {
	sm := NewSessionManager([]byte("k")).WithTTL(time.Hour)
	signed := sm.Sign("tok")

	// Flip a byte in the metadata segment (between the two dots).
	first := -1
	second := -1
	for i, c := range signed {
		if c == '.' {
			if first < 0 {
				first = i
			} else {
				second = i
				break
			}
		}
	}
	if first < 0 || second < 0 {
		t.Fatalf("unexpected token format: %q", signed)
	}
	b := []byte(signed)
	// Mutate a metadata char without breaking base64 alphabet.
	if b[first+1] == 'A' {
		b[first+1] = 'B'
	} else {
		b[first+1] = 'A'
	}
	if _, err := sm.Verify(string(b)); err == nil {
		t.Fatal("tampered metadata should fail verification")
	}
}
