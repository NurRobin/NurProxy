package main

import (
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

func TestPickServingCandidate(t *testing.T) {
	cand := func(fp string, serving, adoptable bool) certCandidateRow {
		return certCandidateRow{DiscoveredCert: models.DiscoveredCert{Fingerprint: fp}, Serving: serving, Adoptable: adoptable}
	}
	tests := []struct {
		name    string
		cands   []certCandidateRow
		want    string
		wantErr bool
	}{
		{name: "one on the serving agent", cands: []certCandidateRow{cand("a", true, true), cand("b", true, false)}, want: "a"},
		{name: "only another agent has one", cands: []certCandidateRow{cand("x", false, true)}, wantErr: true},
		{name: "serving one wins over other agents", cands: []certCandidateRow{cand("x", false, true), cand("a", true, true)}, want: "a"},
		{name: "two on the serving agent", cands: []certCandidateRow{cand("a", true, true), cand("b", true, true)}, wantErr: true},
		{name: "none", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := pickServingCandidate(tc.cands, "7")
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Errorf("pickServingCandidate = %q, %v; want %q, err=%v", got, err, tc.want, tc.wantErr)
			}
		})
	}
}
