package auth

import (
	"strings"
	"testing"
)

func TestGenerateAgentToken(t *testing.T) {
	token, err := GenerateAgentToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, "np_ag_") {
		t.Errorf("agent token should have prefix 'np_ag_', got %q", token)
	}
	// prefix (6) + 64 hex chars = 70
	if len(token) != 70 {
		t.Errorf("agent token length = %d, want 70", len(token))
	}
}

func TestGenerateAPIKey(t *testing.T) {
	token, err := GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, "np_ak_") {
		t.Errorf("API key should have prefix 'np_ak_', got %q", token)
	}
	// prefix (6) + 64 hex chars = 70
	if len(token) != 70 {
		t.Errorf("API key length = %d, want 70", len(token))
	}
}

func TestGenerateSessionToken(t *testing.T) {
	token, err := GenerateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	// 32 bytes = 64 hex chars
	if len(token) != 64 {
		t.Errorf("session token length = %d, want 64", len(token))
	}
}

func TestTokensAreUnique(t *testing.T) {
	t1, _ := GenerateAgentToken()
	t2, _ := GenerateAgentToken()
	if t1 == t2 {
		t.Error("two generated agent tokens should not be equal")
	}

	k1, _ := GenerateAPIKey()
	k2, _ := GenerateAPIKey()
	if k1 == k2 {
		t.Error("two generated API keys should not be equal")
	}

	s1, _ := GenerateSessionToken()
	s2, _ := GenerateSessionToken()
	if s1 == s2 {
		t.Error("two generated session tokens should not be equal")
	}
}

func TestHashPassword_Roundtrip(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{"simple", "hunter2"},
		{"empty", ""},
		{"long", strings.Repeat("a", 72)},
		{"unicode", "pässwörd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashPassword(tt.password)
			if err != nil {
				t.Fatal(err)
			}
			if err := CheckPassword(hash, tt.password); err != nil {
				t.Errorf("CheckPassword failed for correct password: %v", err)
			}
		})
	}
}

func TestCheckPassword_WrongPassword(t *testing.T) {
	hash, err := HashPassword("correct")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPassword(hash, "wrong"); err == nil {
		t.Error("CheckPassword should fail for wrong password")
	}
}

func TestHashPassword_ProducesDifferentHashes(t *testing.T) {
	h1, _ := HashPassword("same")
	h2, _ := HashPassword("same")
	if h1 == h2 {
		t.Error("bcrypt should produce different hashes for the same password (different salt)")
	}
}

func TestSessionManager_SignAndVerify(t *testing.T) {
	sm := NewSessionManager([]byte("test-secret-key"))

	tests := []struct {
		name  string
		token string
	}{
		{"simple token", "abc123"},
		{"hex token", "deadbeef0123456789abcdef"},
		{"with special chars", "token/with+special=chars"},
		{"empty token", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signed := sm.Sign(tt.token)

			// Signed token should contain original token
			if !strings.HasPrefix(signed, tt.token+".") {
				t.Errorf("signed token should start with token+'.', got %q", signed)
			}

			// Verify should return original token
			got, err := sm.Verify(signed)
			if err != nil {
				t.Fatalf("Verify failed: %v", err)
			}
			if got != tt.token {
				t.Errorf("Verify returned %q, want %q", got, tt.token)
			}
		})
	}
}

func TestSessionManager_TamperedToken(t *testing.T) {
	sm := NewSessionManager([]byte("test-secret-key"))

	signed := sm.Sign("mytoken")

	tests := []struct {
		name    string
		tamper  func(string) string
	}{
		{"modified token", func(s string) string {
			return "tampered" + s[8:]
		}},
		{"modified signature", func(s string) string {
			return s[:len(s)-2] + "XX"
		}},
		{"missing separator", func(_ string) string {
			return "notokenseparator"
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tampered := tt.tamper(signed)
			if _, err := sm.Verify(tampered); err == nil {
				t.Error("Verify should fail for tampered token")
			}
		})
	}
}

func TestSessionManager_DifferentKeys(t *testing.T) {
	sm1 := NewSessionManager([]byte("key-one"))
	sm2 := NewSessionManager([]byte("key-two"))

	signed := sm1.Sign("mytoken")

	if _, err := sm2.Verify(signed); err == nil {
		t.Error("Verify with different key should fail")
	}
}
