package tls

import (
	"errors"
	"testing"
	"time"
)

// rateLimitedErr is a lightweight fake implementing the interface
// classifyACMEError recognizes, so we can drive the rate-limit path without lego.
type rateLimitedErr struct {
	detail  string
	unblock string
}

func (e rateLimitedErr) Error() string           { return e.detail }
func (e rateLimitedErr) IsRateLimited() bool     { return true }
func (e rateLimitedErr) UnblockLink() string     { return e.unblock }
func (e rateLimitedErr) RateLimitDetail() string { return e.detail }

func TestParseRetryAfter(t *testing.T) {
	tests := []struct {
		name   string
		detail string
		want   *time.Time
	}{
		{
			name:   "lets encrypt duplicate-cert detail",
			detail: "too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-06-06 10:08:13 UTC: see https://letsencrypt.org/docs/rate-limits/",
			want:   timePtr(time.Date(2026, 6, 6, 10, 8, 13, 0, time.UTC)),
		},
		{
			name:   "no retry-after instant",
			detail: "too many new orders recently",
			want:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRetryAfter(tt.detail)
			switch {
			case tt.want == nil && got != nil:
				t.Fatalf("want nil, got %v", got)
			case tt.want != nil && got == nil:
				t.Fatalf("want %v, got nil", tt.want)
			case tt.want != nil && !got.Equal(*tt.want):
				t.Fatalf("want %v, got %v", tt.want, got)
			}
		})
	}
}

func TestClassifyACMEError_setsRetryAfter(t *testing.T) {
	err := classifyACMEError(rateLimitedErr{
		detail:  "too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-06-06 10:08:13 UTC",
		unblock: "",
	})
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("expected *RateLimitError, got %T", err)
	}
	if rl.RetryAfter == nil {
		t.Fatal("RetryAfter not parsed")
	}
	want := time.Date(2026, 6, 6, 10, 8, 13, 0, time.UTC)
	if !rl.RetryAfter.Equal(want) {
		t.Errorf("RetryAfter = %v, want %v", rl.RetryAfter, want)
	}
	// The friendly message should mention the retry-after date.
	if got := rl.Error(); got == "" || !contains(got, "retry after 2026-06-06 10:08 UTC") {
		t.Errorf("Error() = %q, want it to mention the parsed retry-after", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func timePtr(t time.Time) *time.Time { return &t }
