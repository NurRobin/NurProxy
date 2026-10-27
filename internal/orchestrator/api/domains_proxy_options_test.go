package api

import (
	"net/http"
	"strconv"
	"testing"
)

// TestDomainProxyOptionsAreValidatedOnSave checks that proxy settings the
// helper would refuse to render are rejected when a domain is created or
// updated, and that ordinary values still save.
func TestDomainProxyOptionsAreValidatedOnSave(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)
	domainID, _ := seedDomainTopology(t, srv, cookie)
	path := "/api/v1/domains/" + strconv.FormatInt(domainID, 10)

	refused := map[string]map[string]interface{}{
		"header value with backslash": {"custom_response_headers": map[string]string{"X-A": `\";include /etc/x;#`}},
		"header value with newline":   {"custom_request_headers": map[string]string{"X-A": "a\nb"}},
		"header name with space":      {"custom_response_headers": map[string]string{"X-A b": "v"}},
		"body size":                   {"max_body_size": "10m;include /etc/x"},
		"decimal body size":           {"max_body_size": "1.5GB"},
		"header expression":           {"custom_response_headers": map[string]string{"X-A": "expr=%{file:/etc/shadow}"}},
		"path rewrite":                {"path_rewrite": "/x break; include /etc/x"},
		"ip list":                     {"ip_allowlist": []string{"10.0.0.0/8;"}},
		"username":                    {"basic_auth": map[string]string{"username": "a:b", "password": "$2y$10$x"}},
	}
	for name, config := range refused {
		t.Run("update/"+name, func(t *testing.T) {
			w := doRequest(t, handler, http.MethodPut, path, map[string]interface{}{"proxy_config": config}, cookie)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("update with %s: got %d: %s", name, w.Code, w.Body.String())
			}
		})
	}
	t.Run("create", func(t *testing.T) {
		w := doRequest(t, handler, http.MethodPost, "/api/v1/domains", map[string]interface{}{
			"subdomain": "other", "zone_id": "zone-1", "server_id": "srv-1", "port": 8080,
			"proxy_config": refused["header value with backslash"],
		}, cookie)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("create with hostile header: got %d: %s", w.Code, w.Body.String())
		}
	})
	t.Run("merged result", func(t *testing.T) {
		stored, err := srv.db.GetDomain(domainID)
		if err != nil {
			t.Fatal(err)
		}
		stored.ProxyConfig.CustomRequestHeaders = map[string]string{"X-Stored": "a\nb"}
		if err := srv.db.UpdateDomain(stored); err != nil {
			t.Fatal(err)
		}
		w := doRequest(t, handler, http.MethodPut, path, map[string]interface{}{"proxy_config": map[string]interface{}{"max_body_size": "10m"}}, cookie)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("patch over an invalid stored value: got %d: %s", w.Code, w.Body.String())
		}
		w = doRequest(t, handler, http.MethodPut, path, map[string]interface{}{"proxy_config": map[string]interface{}{"custom_request_headers": nil}}, cookie)
		if w.Code != http.StatusOK {
			t.Fatalf("patch clearing the invalid stored value: got %d: %s", w.Code, w.Body.String())
		}
	})
	t.Run("ordinary values", func(t *testing.T) {
		w := doRequest(t, handler, http.MethodPut, path, map[string]interface{}{"proxy_config": map[string]interface{}{
			"custom_response_headers": map[string]string{"Content-Security-Policy": "default-src 'self'; img-src *"},
			"max_body_size":           "10MB",
			"path_strip":              "/api",
			"ip_allowlist":            []string{"10.0.0.0/8", "2001:db8::1"},
		}}, cookie)
		if w.Code != http.StatusOK {
			t.Fatalf("update with ordinary values: got %d: %s", w.Code, w.Body.String())
		}
	})
}
