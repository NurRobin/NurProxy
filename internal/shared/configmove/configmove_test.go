package configmove

import (
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// baseRoute is a minimal clean intent reused across cases.
func baseRoute() proxymodel.Route {
	return proxymodel.Route{
		Host:     "app.example.com",
		Upstream: proxymodel.Upstream{Addr: "10.0.0.4", Port: 8080},
		TLS:      proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
	}
}

func TestMove_generated_crossType_reRendersIntentNatively(t *testing.T) {
	tests := []struct {
		name       string
		from, to   string
		wantSubstr []string // markers proving native rendering for the target
	}{
		{
			name: "caddy_to_nginx",
			from: BackendCaddy,
			to:   BackendNginx,
			wantSubstr: []string{
				"server {",
				"server_name app.example.com;",
				"proxy_pass http://10.0.0.4:8080;",
			},
		},
		{
			name: "nginx_to_caddy",
			from: BackendNginx,
			to:   BackendCaddy,
			wantSubstr: []string{
				"\"handle\"", // Caddy JSON
				"10.0.0.4:8080",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan, err := Move(Request{
				From:   tt.from,
				To:     tt.to,
				Source: SourceGenerated,
				Intent: baseRoute(),
			})
			if err != nil {
				t.Fatalf("Move error: %v", err)
			}
			if plan.Backend != tt.to {
				t.Errorf("Backend = %q, want %q", plan.Backend, tt.to)
			}
			if plan.ResultSource != SourceGenerated {
				t.Errorf("ResultSource = %q, want generated (clean stays re-renderable)", plan.ResultSource)
			}
			if plan.BaseTemplate {
				t.Error("BaseTemplate = true, want false for a clean move")
			}
			for _, sub := range tt.wantSubstr {
				if !strings.Contains(plan.Content, sub) {
					t.Errorf("Content missing %q:\n%s", sub, plan.Content)
				}
			}
		})
	}
}

func TestMove_generated_sameType_stillRenders(t *testing.T) {
	plan, err := Move(Request{
		From:   BackendNginx,
		To:     BackendNginx,
		Source: SourceGenerated,
		Intent: baseRoute(),
	})
	if err != nil {
		t.Fatalf("Move error: %v", err)
	}
	if plan.BaseTemplate {
		t.Error("a generated move is never a base template")
	}
	if !strings.Contains(plan.Content, "proxy_pass http://10.0.0.4:8080;") {
		t.Errorf("expected re-rendered nginx content, got:\n%s", plan.Content)
	}
}

func TestMove_manual_sameType_carriesContentVerbatim(t *testing.T) {
	raw := "server {\n    listen 80;\n    # operator's hand-tuned vhost\n}\n"
	plan, err := Move(Request{
		From:          BackendNginx,
		To:            BackendNginx,
		Source:        SourceManual,
		ManualContent: raw,
		Intent:        baseRoute(),
	})
	if err != nil {
		t.Fatalf("Move error: %v", err)
	}
	if plan.Content != raw {
		t.Errorf("same-type manual move must carry content verbatim.\n got: %q\nwant: %q", plan.Content, raw)
	}
	if plan.ResultSource != SourceManual {
		t.Errorf("ResultSource = %q, want manual", plan.ResultSource)
	}
	if plan.BaseTemplate {
		t.Error("same-type manual move is not a base template (content is already valid)")
	}
}

func TestMove_manual_sameType_emptyContent_errors(t *testing.T) {
	_, err := Move(Request{
		From:          BackendNginx,
		To:            BackendNginx,
		Source:        SourceManual,
		ManualContent: "   \n",
		Intent:        baseRoute(),
	})
	if err == nil {
		t.Fatal("expected error for empty manual content on same-type move")
	}
}

func TestMove_manual_crossType_yieldsBaseTemplateFromBaseFacts(t *testing.T) {
	// A hand-edited caddy config moving to nginx cannot be translated; we render a
	// base template from the known options (host + port + the structured intent)
	// and DO NOT carry the operator's original caddy text.
	manual := `{"handle":[{"handler":"reverse_proxy","custom_operator_thing":true}]}`
	route := baseRoute()
	route.WebSocket = true
	route.MaxBodySize = "25MB"

	plan, err := Move(Request{
		From:          BackendCaddy,
		To:            BackendNginx,
		Source:        SourceManual,
		ManualContent: manual,
		Intent:        route,
	})
	if err != nil {
		t.Fatalf("Move error: %v", err)
	}
	if !plan.BaseTemplate {
		t.Error("cross-type manual move must be flagged BaseTemplate")
	}
	if plan.ResultSource != SourceManual {
		t.Errorf("ResultSource = %q, want manual", plan.ResultSource)
	}
	// The operator's original (untranslatable) content is NOT carried over.
	if strings.Contains(plan.Content, "custom_operator_thing") {
		t.Error("base template must not contain the operator's original cross-type content")
	}
	// The base facts ARE rendered natively for the target backend.
	for _, sub := range []string{
		"server_name app.example.com;",
		"proxy_pass http://10.0.0.4:8080;",
		"client_max_body_size 25m;", // MaxBodySize base fact
		"proxy_set_header Upgrade",  // websocket base fact
	} {
		if !strings.Contains(plan.Content, sub) {
			t.Errorf("base template missing base fact %q:\n%s", sub, plan.Content)
		}
	}
	// A clear advisory header tells the operator to re-apply custom directives.
	if !strings.Contains(plan.Content, "base template") {
		t.Error("base template should carry an advisory comment header")
	}
	// And the move surfaces the cross-type advisory as a warning.
	if len(plan.Warnings) == 0 || !strings.Contains(plan.Warnings[0], "different proxy type") {
		t.Errorf("expected cross-type advisory warning, got %v", plan.Warnings)
	}
}

func TestMove_manual_crossType_propagatesDroppedOptionWarnings(t *testing.T) {
	// self-acme is unsupported by nginx (dropped with a warning); a cross-type
	// manual move's base template must surface that drop alongside the advisory,
	// never failing the move (invariant #4).
	route := baseRoute()
	route.TLS.Policy = proxymodel.TLSPolicySelfACME

	plan, err := Move(Request{
		From:          BackendCaddy,
		To:            BackendNginx,
		Source:        SourceManual,
		ManualContent: "{}",
		Intent:        route,
	})
	if err != nil {
		t.Fatalf("Move should not fail on a dropped option: %v", err)
	}
	var sawDrop bool
	for _, w := range plan.Warnings {
		if strings.Contains(w, "self-acme") {
			sawDrop = true
		}
	}
	if !sawDrop {
		t.Errorf("expected a dropped-option warning for self-acme, got %v", plan.Warnings)
	}
}

func TestMove_errors(t *testing.T) {
	tests := []struct {
		name string
		req  Request
	}{
		{name: "empty_target", req: Request{From: BackendNginx, Source: SourceGenerated, Intent: baseRoute()}},
		{name: "unknown_target", req: Request{To: "lighttpd", Source: SourceGenerated, Intent: baseRoute()}},
		{name: "unknown_source", req: Request{To: BackendNginx, Source: Source("weird"), Intent: baseRoute()}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Move(tt.req); err == nil {
				t.Errorf("expected error for %s", tt.name)
			}
		})
	}
}

func TestMove_deterministic(t *testing.T) {
	req := Request{From: BackendCaddy, To: BackendNginx, Source: SourceGenerated, Intent: baseRoute()}
	first, err := Move(req)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		got, err := Move(req)
		if err != nil {
			t.Fatal(err)
		}
		if got.Content != first.Content {
			t.Fatalf("Move output not deterministic on iteration %d", i)
		}
	}
}
