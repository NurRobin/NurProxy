package ddns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetectPublicIPTrimsWhitespace(t *testing.T) {
	expectedIP := "203.0.113.42"
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(expectedIP + "\n"))
	}))
	defer mock.Close()

	ip, err := detectPublicIPFromServices(context.Background(), []string{mock.URL}, wantIPv4)
	if err != nil {
		t.Fatalf("detectPublicIPFromServices failed: %v", err)
	}
	if ip != expectedIP {
		t.Errorf("ip = %q, want %q", ip, expectedIP)
	}
}

func TestDetectPublicIPWithTestHelper(t *testing.T) {
	expectedIP := "198.51.100.1"
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(expectedIP))
	}))
	defer mock.Close()

	// Test using detectPublicIPFromServices to test the core logic.
	ip, err := detectPublicIPFromServices(context.Background(), []string{mock.URL}, wantIPv4)
	if err != nil {
		t.Fatalf("detectPublicIPFromServices failed: %v", err)
	}

	if ip != expectedIP {
		t.Errorf("ip = %q, want %q", ip, expectedIP)
	}
}

func TestDetectPublicIPAllFail(t *testing.T) {
	// Create a mock server that always returns an error.
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer mock.Close()

	_, err := detectPublicIPFromServices(context.Background(), []string{mock.URL}, wantIPv4)
	if err == nil {
		t.Fatal("expected error when all services fail, got nil")
	}
}

func TestDetectPublicIPFirstFailsSecondSucceeds(t *testing.T) {
	expectedIP := "192.0.2.1"
	callCount := 0

	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(expectedIP))
	}))
	defer mock.Close()

	ip, err := detectPublicIPFromServices(context.Background(), []string{mock.URL, mock.URL}, wantIPv4)
	if err != nil {
		t.Fatalf("detectPublicIPFromServices failed: %v", err)
	}

	if ip != expectedIP {
		t.Errorf("ip = %q, want %q", ip, expectedIP)
	}
}

func TestDetectPublicIPCancelled(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("1.2.3.4"))
	}))
	defer mock.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	_, err := detectPublicIPFromServices(ctx, []string{mock.URL}, wantIPv4)
	if err == nil {
		t.Fatal("expected error with canceled context, got nil")
	}
}

func TestDetectPublicIP6_acceptsIPv6_rejectsIPv4(t *testing.T) {
	v6 := "2001:db8::1"
	mockV6 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(v6 + "\n"))
	}))
	defer mockV6.Close()

	ip, err := detectPublicIPFromServices(context.Background(), []string{mockV6.URL}, wantIPv6)
	if err != nil {
		t.Fatalf("wantIPv6 on a v6 response: %v", err)
	}
	if ip != v6 {
		t.Errorf("ip = %q, want %q", ip, v6)
	}

	// An IPv4 response must NOT satisfy a wantIPv6 query (a dual-stack endpoint
	// returning v4 would otherwise be published as an AAAA record).
	mockV4 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("203.0.113.7"))
	}))
	defer mockV4.Close()
	if _, err := detectPublicIPFromServices(context.Background(), []string{mockV4.URL}, wantIPv6); err == nil {
		t.Fatal("wantIPv6 must reject an IPv4 response")
	}
}

func TestDetectPublicIP_rejectsGarbage(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>error</html>"))
	}))
	defer mock.Close()

	if _, err := detectPublicIPFromServices(context.Background(), []string{mock.URL}, wantIPv4); err == nil {
		t.Fatal("a non-IP response must be rejected, not published verbatim")
	}
}
