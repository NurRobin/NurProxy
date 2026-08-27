package auth

import "testing"

func TestMatchesStoredAPIKey(t *testing.T) {
	key := "np_ak_deadbeef"
	tests := []struct {
		name       string
		stored     string
		token      string
		ok, legacy bool
	}{
		{name: "hashed match", stored: HashToken(key), token: key, ok: true, legacy: false},
		{name: "legacy plaintext match", stored: key, token: key, ok: true, legacy: true},
		{name: "wrong token", stored: HashToken(key), token: "np_ak_wrong", ok: false},
		{name: "empty stored", stored: "", token: key, ok: false},
		{name: "empty token", stored: HashToken(key), token: "", ok: false},
		// A presented HASH must not authenticate against a hashed row (that
		// would make the stored digest a usable credential again).
		{name: "hash as token rejected", stored: HashToken(key), token: HashToken(key), ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, legacy := MatchesStoredAPIKey(tt.stored, tt.token)
			if ok != tt.ok || legacy != tt.legacy {
				t.Errorf("MatchesStoredAPIKey = (%v, %v), want (%v, %v)", ok, legacy, tt.ok, tt.legacy)
			}
		})
	}
}
