// Package configmove decides how a managed config artifact moves to a different
// host / proxy backend (§3). It is the testable core of the move flow: pure
// functions (intent + facts in, a move Plan out), no host, no I/O.
//
// Two cases the design draws (§3, §13 phase 5):
//
//   - A "clean" (model-backed / generated) artifact is portable across hosts AND
//     across proxy types: the intent (proxymodel.Route) is re-rendered natively
//     for the target backend. nginx→caddy, debian→rhel — it does not matter,
//     because the rendered text was never the source of truth, the intent was.
//
//   - A "hand-edited" (manual) artifact cannot move blindly. Moving it to the
//     SAME proxy type carries the operator's native content verbatim (it is
//     already valid for that backend). Moving it to a DIFFERENT proxy type yields
//     a BASE TEMPLATE rendered from the base facts (proxy + port + the known
//     structured options) for the operator to adapt with their custom bits — we
//     never silently drop or mistranslate hand-written config.
//
// The renderers (caddygen, nginxgen) are the only backend-specific dependency;
// this package dispatches to them by backend name and stays otherwise neutral.
package configmove

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/NurRobin/NurProxy/internal/shared/apachegen"
	"github.com/NurRobin/NurProxy/internal/shared/caddygen"
	"github.com/NurRobin/NurProxy/internal/shared/nginxgen"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// Backend names the supported move targets. They mirror the proxy registry keys
// and proxymodel.RawConfig.Backend tags.
const (
	BackendCaddy  = "caddy"
	BackendNginx  = "nginx"
	BackendApache = "apache"
)

// Source records whether the artifact being moved was model-backed (generated)
// or hand-edited (manual), mirroring models.ArtifactSource. It drives whether the
// move re-renders intent or produces a base template.
type Source string

const (
	// SourceGenerated is a clean, model-backed artifact: portable by re-rendering.
	SourceGenerated Source = "generated"
	// SourceManual is a hand-edited/adopted artifact: native content is the source
	// of truth, so a cross-type move can only offer a base template.
	SourceManual Source = "manual"
)

// Request is everything the move planner needs to decide an outcome. It carries
// no host handles and no I/O — the caller resolves the facts (the artifact's
// source, its base intent, the operator's manual content) and asks for a Plan.
type Request struct {
	// From is the source backend the artifact currently lives on.
	From string
	// To is the target backend the artifact is moving to.
	To string
	// Source is whether the artifact is generated (model-backed) or manual.
	Source Source
	// Intent is the base proxy intent (host + upstream + known options) the
	// orchestrator stores separately from the rendered text (§3). It is always
	// available for a domain-backed artifact and is what a generated move
	// re-renders and what a cross-type manual move distills into a base template.
	Intent proxymodel.Route
	// ManualContent is the operator's hand-edited native config text. It is only
	// used for a same-type manual move (carried verbatim); a cross-type manual
	// move cannot reuse it and falls back to the base template from Intent.
	ManualContent string
}

// Plan is the result of a move: the native content to place on the target host,
// plus metadata the orchestrator stores and surfaces in the UI.
type Plan struct {
	// Backend is the target backend the Content is native to.
	Backend string
	// Content is the native config to write on the target host: a fully rendered
	// config for a clean move (or a same-type manual move), or a starting-point
	// base template for a cross-type manual move.
	Content string
	// ResultSource is the artifact source after the move. A clean move stays
	// generated (still model-backed, re-renderable); any manual move stays manual.
	ResultSource Source
	// BaseTemplate is true when Content is a starting-point template the operator
	// must adapt (cross-type manual move), false when it is a complete config.
	BaseTemplate bool
	// Warnings lists options the target backend could not express (dropped by its
	// renderer, invariant #4) plus the cross-type-manual advisory. The caller logs
	// + audits these; they never make the move fail.
	Warnings []string
}

// Move plans how to move a config artifact from one backend to another (§3). It
// is pure: it renders via the target backend's pure renderer and never touches a
// host. An unknown target backend or an un-renderable intent is an error; a
// dropped option is a warning, never an error (invariant #4).
func Move(req Request) (Plan, error) {
	if req.To == "" {
		return Plan{}, fmt.Errorf("move: target backend is required")
	}

	sameType := req.From != "" && req.From == req.To

	switch req.Source {
	case SourceGenerated:
		// Clean, model-backed: re-render the intent natively for the target. Fully
		// portable across hosts and proxy types — the intent was always the truth.
		content, warns, err := renderIntent(req.To, req.Intent)
		if err != nil {
			return Plan{}, fmt.Errorf("move: re-rendering intent for %q: %w", req.To, err)
		}
		return Plan{
			Backend:      req.To,
			Content:      content,
			ResultSource: SourceGenerated,
			BaseTemplate: false,
			Warnings:     warns,
		}, nil

	case SourceManual:
		if sameType {
			// Same proxy type: the operator's native content is already valid here,
			// carry it verbatim. No template, no re-render (we must not mistranslate).
			if strings.TrimSpace(req.ManualContent) == "" {
				return Plan{}, fmt.Errorf("move: manual same-type move has empty content")
			}
			return Plan{
				Backend:      req.To,
				Content:      req.ManualContent,
				ResultSource: SourceManual,
				BaseTemplate: false,
			}, nil
		}
		// Different proxy type: we cannot translate hand-written config. Render a
		// BASE TEMPLATE from the base facts (proxy + port + known options) for the
		// operator to adapt with their custom bits (§3).
		content, warns, err := renderIntent(req.To, req.Intent)
		if err != nil {
			return Plan{}, fmt.Errorf("move: building base template for %q: %w", req.To, err)
		}
		warns = append([]string{
			"hand-edited config cannot move to a different proxy type; a base template was generated from the known options — re-apply your custom directives",
		}, warns...)
		return Plan{
			Backend:      req.To,
			Content:      annotateBaseTemplate(req.To, content),
			ResultSource: SourceManual,
			BaseTemplate: true,
			Warnings:     warns,
		}, nil

	default:
		return Plan{}, fmt.Errorf("move: unknown artifact source %q", req.Source)
	}
}

// renderIntent dispatches to the target backend's pure renderer and returns the
// native config text plus any dropped-option warnings (invariant #4). It is the
// single place that knows backend-specific output shapes.
func renderIntent(backend string, route proxymodel.Route) (content string, warnings []string, err error) {
	switch backend {
	case BackendNginx:
		res, rErr := nginxgen.Render(nginxgen.Input{Route: route})
		if rErr != nil {
			return "", nil, rErr
		}
		var sb strings.Builder
		if res.HTTPPreamble != "" {
			sb.WriteString(res.HTTPPreamble)
			if !strings.HasSuffix(res.HTTPPreamble, "\n") {
				sb.WriteString("\n")
			}
			sb.WriteString("\n")
		}
		sb.WriteString(res.Server)
		for _, w := range res.Warnings {
			warnings = append(warnings, w.String())
		}
		return sb.String(), warnings, nil

	case BackendApache:
		res, rErr := apachegen.Render(apachegen.Input{Route: route})
		if rErr != nil {
			return "", nil, rErr
		}
		var sb strings.Builder
		if res.Preamble != "" {
			sb.WriteString(res.Preamble)
			if !strings.HasSuffix(res.Preamble, "\n") {
				sb.WriteString("\n")
			}
			sb.WriteString("\n")
		}
		sb.WriteString(res.VHost)
		for _, w := range res.Warnings {
			warnings = append(warnings, w.String())
		}
		return sb.String(), warnings, nil

	case BackendCaddy:
		raw, rErr := caddygen.GenerateRoute(route)
		if rErr != nil {
			return "", nil, rErr
		}
		// Pretty-print so the moved route JSON is human-readable in the store/UI.
		var buf bytes.Buffer
		if err := json.Indent(&buf, raw, "", "  "); err != nil {
			return string(raw), nil, nil
		}
		return buf.String(), nil, nil

	default:
		return "", nil, fmt.Errorf("unsupported target backend %q", backend)
	}
}

// annotateBaseTemplate prepends a backend-appropriate comment header to a base
// template so the operator immediately sees this is a starting point to adapt,
// not a finished config. The comment syntax differs per backend; Caddy JSON has
// no comments, so it is returned unchanged (the BaseTemplate flag carries the
// advisory in the UI instead).
func annotateBaseTemplate(backend, content string) string {
	switch backend {
	case BackendNginx, BackendApache:
		header := "# NurProxy base template — generated from the known options after a\n" +
			"# cross-proxy move. Re-apply any custom directives from your previous\n" +
			"# config, then accept. NurProxy will not overwrite this without an Accept.\n\n"
		return header + content
	default:
		return content
	}
}
