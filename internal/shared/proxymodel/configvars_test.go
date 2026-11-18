package proxymodel

import (
	"strings"
	"testing"
)

func TestCheckHeaderConfigVars(t *testing.T) {
	tests := []struct {
		name     string
		request  map[string]string
		response map[string]string
		want     string
	}{
		{name: "none"},
		{name: "dollar and brace apart", request: map[string]string{"X-A": "$5 {x} $ {"}},
		{name: "request variable", request: map[string]string{"X-A": "${HOME}"}, want: "request header X-A"},
		{name: "response variable mid value", response: map[string]string{"X-B": "a ${APACHE_RUN_USER} b"}, want: "response header X-B"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckHeaderConfigVars(tt.request, tt.response)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("CheckHeaderConfigVars() = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("CheckHeaderConfigVars() = %v, want %q", err, tt.want)
			}
		})
	}
}
