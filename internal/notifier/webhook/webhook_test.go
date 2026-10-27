package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/NurRobin/NurProxy/internal/notifier"
)

func TestNotify_postsSignedJSON(t *testing.T) {
	var gotBody []byte
	var gotSig, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotSig = r.Header.Get(SignatureHeader)
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := New(func() (string, string) { return srv.URL, "s3cret" })
	ev := notifier.Event{Action: "renewed", EntityType: "certificate", EntityID: "a.example.com"}
	if err := s.Notify(context.Background(), ev); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	var decoded notifier.Event
	if err := json.Unmarshal(gotBody, &decoded); err != nil || decoded.Action != "renewed" {
		t.Fatalf("body = %s (err %v), want the event JSON", gotBody, err)
	}
	if gotCT != "application/json" {
		t.Errorf("content-type = %q", gotCT)
	}
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(gotBody)
	if want := "sha256=" + hex.EncodeToString(mac.Sum(nil)); gotSig != want {
		t.Errorf("signature = %q, want %q", gotSig, want)
	}
}

func TestNotify_noURLIsDisabled(t *testing.T) {
	s := New(func() (string, string) { return "", "" })
	if err := s.Notify(context.Background(), notifier.Event{Action: "renewed"}); err != nil {
		t.Fatalf("no URL must be a silent no-op, got %v", err)
	}
}

func TestNotify_retriesOn5xxThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	s := New(func() (string, string) { return srv.URL, "" })
	if err := s.Notify(context.Background(), notifier.Event{Action: "renewed"}); err != nil {
		t.Fatalf("Notify should succeed on retry: %v", err)
	}
	if calls.Load() != 2 {
		t.Errorf("calls = %d, want 2 (one failure, one success)", calls.Load())
	}
}

func TestNotify_noSecretNoSignature(t *testing.T) {
	var gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get(SignatureHeader)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	s := New(func() (string, string) { return srv.URL, "" })
	if err := s.Notify(context.Background(), notifier.Event{Action: "renewed"}); err != nil {
		t.Fatal(err)
	}
	if gotSig != "" {
		t.Errorf("signature header should be absent without a secret, got %q", gotSig)
	}
}
