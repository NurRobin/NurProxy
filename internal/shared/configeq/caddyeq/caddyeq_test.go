package caddyeq

import (
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/configeq"
)

func TestEqual_caddyJSON_scenarios(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{
			name: "byte identical",
			a:    `{"handle":[{"handler":"reverse_proxy"}]}`,
			b:    `{"handle":[{"handler":"reverse_proxy"}]}`,
			want: true,
		},
		{
			name: "key order differs (re-serialization)",
			a:    `{"match":[{"host":["a.example.com"]}],"handle":[{"handler":"reverse_proxy"}]}`,
			b:    `{"handle":[{"handler":"reverse_proxy"}],"match":[{"host":["a.example.com"]}]}`,
			want: true,
		},
		{
			name: "insignificant whitespace differs",
			a:    `{"handle":[{"handler":"reverse_proxy"}]}`,
			b:    "{\n  \"handle\": [ { \"handler\": \"reverse_proxy\" } ]\n}",
			want: true,
		},
		{
			name: "nested key order differs",
			a:    `{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"localhost:8080"}]}]}`,
			b:    `{"handle":[{"upstreams":[{"dial":"localhost:8080"}],"handler":"reverse_proxy"}]}`,
			want: true,
		},
		{
			name: "different upstream value",
			a:    `{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"localhost:8080"}]}]}`,
			b:    `{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"localhost:9090"}]}]}`,
			want: false,
		},
		{
			name: "different host (real intent change)",
			a:    `{"match":[{"host":["a.example.com"]}]}`,
			b:    `{"match":[{"host":["b.example.com"]}]}`,
			want: false,
		},
		{
			name: "array order is significant",
			a:    `{"handle":[{"handler":"a"},{"handler":"b"}]}`,
			b:    `{"handle":[{"handler":"b"},{"handler":"a"}]}`,
			want: false,
		},
		{
			name: "extra key on one side",
			a:    `{"handle":[{"handler":"reverse_proxy"}]}`,
			b:    `{"handle":[{"handler":"reverse_proxy"}],"terminal":true}`,
			want: false,
		},
		{
			name: "numeric equality across formatting",
			a:    `{"port":443}`,
			b:    `{"port":443.0}`,
			want: true,
		},
		{
			name: "different numbers",
			a:    `{"port":443}`,
			b:    `{"port":80}`,
			want: false,
		},
		{
			name: "both invalid json identical falls back to raw equal",
			a:    "not json",
			b:    "not json",
			want: true,
		},
		{
			name: "one invalid json not equal",
			a:    `{"a":1}`,
			b:    "not json",
			want: false,
		},
		{
			name: "both invalid json differ",
			a:    "not json a",
			b:    "not json b",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Equal(tt.a, tt.b); got != tt.want {
				t.Fatalf("Equal(a, b) = %v, want %v\n a=%s\n b=%s", got, tt.want, tt.a, tt.b)
			}
			// Symmetry: Equal must be order-independent in its arguments.
			if got := Equal(tt.b, tt.a); got != tt.want {
				t.Fatalf("Equal(b, a) = %v, want %v (not symmetric)", got, tt.want)
			}
		})
	}
}

func TestEqual_registeredUnderCaddyBackend(t *testing.T) {
	// The init() registration must make configeq.Equal("caddy", ...) use the
	// semantic comparator (key-order-insensitive), not raw byte equality.
	a := `{"a":1,"b":2}`
	b := `{"b":2,"a":1}`
	if !configeq.Equal(Backend, a, b) {
		t.Fatal("configeq.Equal with caddy backend should treat key-reordered JSON as equal")
	}
}
