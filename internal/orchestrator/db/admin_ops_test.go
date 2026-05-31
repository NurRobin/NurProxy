package db

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// codeShape matches the rendered confirmation-code form: two dash-separated
// groups of four characters from the no-ambiguous Crockford base32 alphabet.
var codeShape = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$`)

func TestGenerateConfirmationCode_format(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		code, err := GenerateConfirmationCode()
		if err != nil {
			t.Fatalf("GenerateConfirmationCode: %v", err)
		}
		if !codeShape.MatchString(code) {
			t.Fatalf("code %q does not match expected shape", code)
		}
		// No ambiguous characters.
		for _, bad := range []string{"I", "L", "O", "U"} {
			if strings.Contains(code, bad) {
				t.Fatalf("code %q contains ambiguous char %q", code, bad)
			}
		}
		seen[code] = true
	}
	// Randomness sanity: 200 draws from a large space should not all collide.
	if len(seen) < 100 {
		t.Fatalf("expected high uniqueness, got %d distinct of 200", len(seen))
	}
}

func TestHashConfirmationCode(t *testing.T) {
	tests := []struct {
		name   string
		a, b   string
		equal  bool
		nonHex bool
	}{
		{name: "deterministic", a: "K7QF-2M9X", b: "K7QF-2M9X", equal: true},
		{name: "case insensitive", a: "k7qf-2m9x", b: "K7QF-2M9X", equal: true},
		{name: "trims whitespace", a: "  K7QF-2M9X  ", b: "K7QF-2M9X", equal: true},
		{name: "different codes differ", a: "K7QF-2M9X", b: "K7QF-2M9Y", equal: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ha := HashConfirmationCode(tt.a)
			hb := HashConfirmationCode(tt.b)
			if (ha == hb) != tt.equal {
				t.Fatalf("hash equality = %v, want %v (a=%q b=%q)", ha == hb, tt.equal, tt.a, tt.b)
			}
			if len(ha) != 64 {
				t.Fatalf("expected 64-hex-char digest, got %d chars", len(ha))
			}
		})
	}
}

func TestSetProxyModePayload_roundTrip(t *testing.T) {
	want := models.SetProxyModePayload{
		ProxyMode:      "existing",
		ProxyType:      "nginx",
		ProxyConfigDir: "/etc/nginx/sites-available",
		ProxyReloadCmd: "nginx -s reload",
		ProxyTestCmd:   "nginx -t",
		ProxyService:   "nginx.service",
		ProxyLogPaths:  []string{"/var/log/nginx/error.log", "/var/log/nginx/access.log"},
	}
	js, err := models.MarshalSetProxyModePayload(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := models.UnmarshalSetProxyModePayload(js)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ProxyMode != want.ProxyMode || got.ProxyType != want.ProxyType ||
		got.ProxyConfigDir != want.ProxyConfigDir || got.ProxyReloadCmd != want.ProxyReloadCmd ||
		got.ProxyTestCmd != want.ProxyTestCmd || got.ProxyService != want.ProxyService {
		t.Fatalf("scalar mismatch: got %+v want %+v", got, want)
	}
	if len(got.ProxyLogPaths) != len(want.ProxyLogPaths) {
		t.Fatalf("log paths len = %d want %d", len(got.ProxyLogPaths), len(want.ProxyLogPaths))
	}
	for i := range want.ProxyLogPaths {
		if got.ProxyLogPaths[i] != want.ProxyLogPaths[i] {
			t.Fatalf("log path[%d] = %q want %q", i, got.ProxyLogPaths[i], want.ProxyLogPaths[i])
		}
	}
}

func TestCreateAdminOp(t *testing.T) {
	d := testDB(t)
	ctx := context.Background()

	payload, err := models.MarshalSetProxyModePayload(models.SetProxyModePayload{
		ProxyMode: "built-in",
	})
	if err != nil {
		t.Fatal(err)
	}
	hash := HashConfirmationCode("K7QF-2M9X")

	op, err := d.CreateAdminOp(ctx, "agent-1", models.AdminOpSetProxyMode, payload, hash, "alice", 15*time.Minute)
	if err != nil {
		t.Fatalf("CreateAdminOp: %v", err)
	}
	if op.ID == "" {
		t.Fatal("expected generated id")
	}
	if op.Status != models.AdminOpPending {
		t.Fatalf("status = %q want pending", op.Status)
	}
	if op.CreatedBy != "alice" || op.OpType != models.AdminOpSetProxyMode {
		t.Fatalf("unexpected fields: %+v", op)
	}
	if !op.ExpiresAt.After(op.CreatedAt) {
		t.Fatalf("expires_at %v not after created_at %v", op.ExpiresAt, op.CreatedAt)
	}
	if op.AppliedAt != nil {
		t.Fatal("expected nil applied_at on fresh op")
	}

	got, err := d.GetAdminOp(ctx, op.ID)
	if err != nil {
		t.Fatalf("GetAdminOp: %v", err)
	}
	if got.Payload != payload || got.CodeHash != hash {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	// Validation.
	if _, err := d.CreateAdminOp(ctx, "", "x", "{}", hash, "", time.Minute); err == nil {
		t.Fatal("expected error for empty agent id")
	}
	if _, err := d.CreateAdminOp(ctx, "a", "", "{}", hash, "", time.Minute); err == nil {
		t.Fatal("expected error for empty op type")
	}
	if _, err := d.CreateAdminOp(ctx, "a", "x", "{}", "", "", time.Minute); err == nil {
		t.Fatal("expected error for empty code hash")
	}
}

func TestClaimAdminOp(t *testing.T) {
	d := testDB(t)
	ctx := context.Background()
	hash := HashConfirmationCode("K7QF-2M9X")

	op, err := d.CreateAdminOp(ctx, "agent-1", models.AdminOpSetProxyMode, "{}", hash, "alice", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	// Happy path: pending -> applied.
	claimed, err := d.ClaimAdminOp(ctx, "agent-1", hash)
	if err != nil {
		t.Fatalf("ClaimAdminOp: %v", err)
	}
	if claimed.ID != op.ID {
		t.Fatalf("claimed wrong op: %s != %s", claimed.ID, op.ID)
	}
	if claimed.Status != models.AdminOpApplied {
		t.Fatalf("status = %q want applied", claimed.Status)
	}
	if claimed.AppliedAt == nil {
		t.Fatal("expected applied_at set after claim")
	}

	// Single-use: a second claim of the same code fails.
	if _, err := d.ClaimAdminOp(ctx, "agent-1", hash); !errors.Is(err, ErrAdminOpNotFound) {
		t.Fatalf("second claim err = %v, want ErrAdminOpNotFound", err)
	}
}

func TestClaimAdminOp_wrongCode(t *testing.T) {
	d := testDB(t)
	ctx := context.Background()
	hash := HashConfirmationCode("K7QF-2M9X")

	if _, err := d.CreateAdminOp(ctx, "agent-1", models.AdminOpSetProxyMode, "{}", hash, "", 15*time.Minute); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		agentID string
		code    string
	}{
		{name: "wrong code", agentID: "agent-1", code: HashConfirmationCode("WRON-GXXX")},
		{name: "wrong agent", agentID: "agent-2", code: hash},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := d.ClaimAdminOp(ctx, tt.agentID, tt.code); !errors.Is(err, ErrAdminOpNotFound) {
				t.Fatalf("err = %v, want ErrAdminOpNotFound", err)
			}
		})
	}

	// The op must still be pending after failed claims.
	got, err := d.GetAdminOp(ctx, mustFirstPendingID(t, d, "agent-1"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != models.AdminOpPending {
		t.Fatalf("status = %q want pending after failed claims", got.Status)
	}
}

func TestClaimAdminOp_expired(t *testing.T) {
	d := testDB(t)
	ctx := context.Background()
	hash := HashConfirmationCode("K7QF-2M9X")

	// TTL already in the past.
	op, err := d.CreateAdminOp(ctx, "agent-1", models.AdminOpSetProxyMode, "{}", hash, "", -time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	// Not claimable.
	if _, err := d.ClaimAdminOp(ctx, "agent-1", hash); !errors.Is(err, ErrAdminOpNotFound) {
		t.Fatalf("expired claim err = %v, want ErrAdminOpNotFound", err)
	}

	// Not listed as pending (and lazily marked expired).
	pending, err := d.ListPendingAdminOps(ctx, "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected no pending ops, got %d", len(pending))
	}
	got, err := d.GetAdminOp(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != models.AdminOpExpired {
		t.Fatalf("status = %q want expired after lazy expiry", got.Status)
	}
}

func TestListPendingAdminOps(t *testing.T) {
	d := testDB(t)
	ctx := context.Background()

	pendingHash := HashConfirmationCode("AAAA-1111")
	if _, err := d.CreateAdminOp(ctx, "agent-1", models.AdminOpSetProxyMode, "{}", pendingHash, "", 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	// Another agent's op must not leak in.
	if _, err := d.CreateAdminOp(ctx, "agent-2", models.AdminOpSetProxyMode, "{}", HashConfirmationCode("BBBB-2222"), "", 15*time.Minute); err != nil {
		t.Fatal(err)
	}

	pending, err := d.ListPendingAdminOps(ctx, "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending op, got %d", len(pending))
	}
	if pending[0].AgentID != "agent-1" {
		t.Fatalf("leaked op from another agent: %+v", pending[0])
	}
}

func TestCancelAdminOp(t *testing.T) {
	d := testDB(t)
	ctx := context.Background()
	hash := HashConfirmationCode("K7QF-2M9X")

	op, err := d.CreateAdminOp(ctx, "agent-1", models.AdminOpSetProxyMode, "{}", hash, "", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	if err := d.CancelAdminOp(ctx, op.ID); err != nil {
		t.Fatalf("CancelAdminOp: %v", err)
	}
	got, err := d.GetAdminOp(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != models.AdminOpCanceled {
		t.Fatalf("status = %q want canceled", got.Status)
	}

	// A canceled op is no longer claimable nor pending.
	if _, err := d.ClaimAdminOp(ctx, "agent-1", hash); !errors.Is(err, ErrAdminOpNotFound) {
		t.Fatalf("claim of canceled op err = %v, want ErrAdminOpNotFound", err)
	}
	pending, err := d.ListPendingAdminOps(ctx, "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected no pending ops after cancel, got %d", len(pending))
	}

	// Missing op errors.
	if err := d.CancelAdminOp(ctx, "no-such-id"); err == nil {
		t.Fatal("expected error canceling missing op")
	}
}

func TestAckAdminOp(t *testing.T) {
	d := testDB(t)
	ctx := context.Background()

	op, err := d.CreateAdminOp(ctx, "agent-1", models.AdminOpSetProxyMode, "{}", HashConfirmationCode("K7QF-2M9X"), "", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.AckAdminOp(ctx, op.ID, "switched to existing/nginx; reload ok"); err != nil {
		t.Fatalf("AckAdminOp: %v", err)
	}
	got, err := d.GetAdminOp(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Result != "switched to existing/nginx; reload ok" {
		t.Fatalf("result = %q, unexpected", got.Result)
	}
	if err := d.AckAdminOp(ctx, "no-such-id", "x"); err == nil {
		t.Fatal("expected error acking missing op")
	}
}

// mustFirstPendingID returns the id of the agent's single pending op, failing
// the test if there isn't exactly one.
func mustFirstPendingID(t *testing.T, d *DB, agentID string) string {
	t.Helper()
	pending, err := d.ListPendingAdminOps(context.Background(), agentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected exactly 1 pending op, got %d", len(pending))
	}
	return pending[0].ID
}
