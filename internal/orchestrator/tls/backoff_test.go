package tls

import (
	"testing"
	"time"
)

func TestNextRateLimitBackoff(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		attempts   int
		retryAfter *time.Time
		min, max   time.Duration // expected delay bounds (base..base+10% jitter)
	}{
		{name: "first attempt", attempts: 1, min: time.Hour, max: time.Hour + 6*time.Minute},
		{name: "second doubles", attempts: 2, min: 2 * time.Hour, max: 2*time.Hour + 12*time.Minute},
		{name: "fourth", attempts: 4, min: 8 * time.Hour, max: 8*time.Hour + 48*time.Minute},
		{name: "capped at 24h", attempts: 10, min: 24 * time.Hour, max: 24*time.Hour + 144*time.Minute},
		{name: "attempts below 1 treated as 1", attempts: 0, min: time.Hour, max: time.Hour + 6*time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NextRateLimitBackoff(now, tt.attempts, tt.retryAfter)
			d := got.Sub(now)
			if d < tt.min || d > tt.max {
				t.Errorf("delay = %v, want within [%v, %v]", d, tt.min, tt.max)
			}
		})
	}

	// A later CA retry-after wins over the computed backoff.
	ra := now.Add(72 * time.Hour)
	if got := NextRateLimitBackoff(now, 1, &ra); !got.Equal(ra) {
		t.Errorf("retry-after should win: got %v, want %v", got, ra)
	}
	// An earlier retry-after does NOT shrink the computed backoff.
	early := now.Add(time.Minute)
	if got := NextRateLimitBackoff(now, 1, &early); got.Sub(now) < time.Hour {
		t.Errorf("earlier retry-after must not shrink the hold: got %v", got.Sub(now))
	}
}
