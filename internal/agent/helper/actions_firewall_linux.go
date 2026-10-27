//go:build linux

package helper

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
	"github.com/NurRobin/NurProxy/internal/shared/recoverypolicy"
)

const firewallRuleComment = "NurProxy-managed"

type firewallFacts struct {
	Backend   string `json:"backend"`
	Active    bool   `json:"active"`
	Ambiguous bool   `json:"ambiguous"`
	Port80    bool   `json:"port_80"`
	Port443   bool   `json:"port_443"`
	Owned80   bool   `json:"owned_80"`
	Owned443  bool   `json:"owned_443"`
}

type firewallHost interface {
	Inspect(context.Context, FirewallTargetConfig) (firewallFacts, error)
	Add(context.Context, FirewallTargetConfig, int) error
	Remove(context.Context, FirewallTargetConfig, int) error
}

type firewallAction struct {
	proxyKind string
	target    FirewallTargetConfig
	journal   *Journal
	host      firewallHost
}

func newFirewallAction(proxyKind string, target FirewallTargetConfig, journal *Journal, host firewallHost) (*firewallAction, error) {
	if (proxyKind != "nginx" && proxyKind != "apache" && proxyKind != "caddy") || target.Validate() != nil || journal == nil || host == nil {
		return nil, fmt.Errorf("firewall action is not safely configured")
	}
	return &firewallAction{proxyKind: proxyKind, target: target, journal: journal, host: host}, nil
}

func (a *firewallAction) Plan(ctx context.Context, request helperprotocol.PlanActionRequest) (PlanMaterial, error) {
	if request.Action != helperprotocol.ActionOpenProxyFirewallPorts || request.LogicalTarget != helperprotocol.LogicalTargetLocalFirewall {
		return PlanMaterial{}, fmt.Errorf("firewall request does not match compiled action")
	}
	facts, err := a.inspectRepairable(ctx)
	if err != nil {
		return PlanMaterial{}, err
	}
	digest, err := helperprotocol.Digest(facts)
	if err != nil {
		return PlanMaterial{}, err
	}
	steps := []helperprotocol.PlanStep{{Kind: "snapshot", Summary: "Snapshot exact UFW TCP 80/443 rule state"}}
	if !facts.Port80 {
		steps = append(steps, helperprotocol.PlanStep{Kind: "firewall", Summary: "Add provenanced UFW allow rule for TCP 80"})
	}
	if !facts.Port443 {
		steps = append(steps, helperprotocol.PlanStep{Kind: "firewall", Summary: "Add provenanced UFW allow rule for TCP 443"})
	}
	steps = append(steps, helperprotocol.PlanStep{Kind: "post_validate", Summary: "Verify UFW remains active and TCP 80/443 are allowed"})
	return PlanMaterial{
		Steps: steps, ExecutionPlanHash: digest,
		ResourceFingerprint: recoverypolicy.HardDiagnosticFingerprint(recoverymodel.CodeUnknownProxyError, a.proxyKind, "local_firewall", nil),
		RollbackCoverage:    helperprotocol.RollbackCoveragePartial,
	}, nil
}

func (a *firewallAction) Rediscover(ctx context.Context, _ helperprotocol.HelperPlan) (string, string, error) {
	facts, err := a.inspectRepairable(ctx)
	if err != nil {
		return "", "", err
	}
	digest, err := helperprotocol.Digest(facts)
	return digest, recoverypolicy.HardDiagnosticFingerprint(recoverymodel.CodeUnknownProxyError, a.proxyKind, "local_firewall", nil), err
}

func (a *firewallAction) Prepare(ctx context.Context, operationID string, plan helperprotocol.HelperPlan) (PreparedAction, error) {
	facts, err := a.inspectRepairable(ctx)
	if err != nil {
		return PreparedAction{}, err
	}
	digest, err := helperprotocol.Digest(facts)
	if err != nil || (plan.ExecutionPlanHash != "" && digest != plan.ExecutionPlanHash) {
		return PreparedAction{}, fmt.Errorf("firewall facts changed before snapshot")
	}
	snapshotDigest, err := a.journal.StoreSnapshot(operationID, facts)
	if err != nil {
		return PreparedAction{}, err
	}
	return PreparedAction{SnapshotDigest: snapshotDigest, RollbackCoverage: helperprotocol.RollbackCoveragePartial}, nil
}

func (a *firewallAction) Execute(ctx context.Context, operationID string, plan helperprotocol.HelperPlan, prepared PreparedAction) (ActionResult, error) {
	snapshot, err := a.loadSnapshot(operationID, prepared)
	if err != nil {
		return ActionResult{}, err
	}
	current, err := a.inspectRepairable(ctx)
	currentDigest, digestErr := helperprotocol.Digest(current)
	snapshotDigest, snapshotErr := helperprotocol.Digest(snapshot)
	if err != nil || digestErr != nil || snapshotErr != nil || currentDigest != snapshotDigest ||
		(plan.ExecutionPlanHash != "" && currentDigest != plan.ExecutionPlanHash) {
		return ActionResult{}, fmt.Errorf("firewall facts changed after snapshot")
	}
	mutated := false
	for _, port := range []int{80, 443} {
		if (port == 80 && snapshot.Port80) || (port == 443 && snapshot.Port443) {
			continue
		}
		if err := a.host.Add(ctx, a.target, port); err != nil {
			return ActionResult{Mutated: mutated}, err
		}
		mutated = true
	}
	post, err := a.host.Inspect(ctx, a.target)
	if err != nil || !post.Active || post.Ambiguous || !post.Port80 || !post.Port443 ||
		(!snapshot.Port80 && !post.Owned80) || (!snapshot.Port443 && !post.Owned443) {
		return ActionResult{Mutated: mutated}, fmt.Errorf("firewall postcondition or rule provenance could not be proven")
	}
	return ActionResult{Mutated: mutated, Validated: true, SanitizedResult: "Local UFW allows TCP 80 and 443"}, nil
}

func (a *firewallAction) Rollback(ctx context.Context, operationID string, _ helperprotocol.HelperPlan, prepared PreparedAction) error {
	snapshot, err := a.loadSnapshot(operationID, prepared)
	if err != nil {
		return err
	}
	current, err := a.host.Inspect(ctx, a.target)
	if err != nil || !current.Active || current.Ambiguous {
		return fmt.Errorf("firewall rollback scope changed")
	}
	for _, port := range []int{443, 80} {
		wasOpen := (port == 80 && snapshot.Port80) || (port == 443 && snapshot.Port443)
		isOwned := (port == 80 && current.Owned80) || (port == 443 && current.Owned443)
		if wasOpen {
			continue
		}
		if !isOwned {
			return fmt.Errorf("firewall rollback rule lost exact NurProxy provenance")
		}
		if err := a.host.Remove(ctx, a.target, port); err != nil {
			return err
		}
	}
	post, err := a.host.Inspect(ctx, a.target)
	if err != nil || post.Port80 != snapshot.Port80 || post.Port443 != snapshot.Port443 {
		return fmt.Errorf("firewall pre-state was not restored")
	}
	return nil
}

func (a *firewallAction) inspectRepairable(ctx context.Context) (firewallFacts, error) {
	facts, err := a.host.Inspect(ctx, a.target)
	if err != nil {
		return firewallFacts{}, err
	}
	if facts.Backend != a.target.Backend || !facts.Active || facts.Ambiguous {
		return firewallFacts{}, fmt.Errorf("local firewall scope is inactive or ambiguous")
	}
	if facts.Port80 && facts.Port443 {
		return firewallFacts{}, fmt.Errorf("local firewall already allows proxy ports")
	}
	return facts, nil
}

func (a *firewallAction) loadSnapshot(operationID string, prepared PreparedAction) (firewallFacts, error) {
	payload, err := a.journal.LoadSnapshot(operationID, prepared.SnapshotDigest)
	if err != nil {
		return firewallFacts{}, err
	}
	snapshot, err := helperprotocol.Decode[firewallFacts](payload)
	if err != nil || snapshot.Backend != a.target.Backend {
		return firewallFacts{}, fmt.Errorf("firewall snapshot is invalid")
	}
	return snapshot, nil
}

type systemFirewallHost struct{}

func (systemFirewallHost) Inspect(ctx context.Context, target FirewallTargetConfig) (firewallFacts, error) {
	facts := firewallFacts{Backend: target.Backend}
	if target.Validate() != nil {
		return facts, fmt.Errorf("firewall target is not compiled")
	}
	if _, err := trustedRegularFileDigest(target.Binary, maxTrustedBinaryBytes); err != nil {
		return facts, err
	}
	output, err := runBounded(ctx, target.Binary, "status")
	if err != nil {
		return facts, err
	}
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Status:") {
			facts.Active = strings.TrimSpace(strings.TrimPrefix(trimmed, "Status:")) == "active"
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 || fields[1] != "ALLOW" {
			continue
		}
		portText := strings.TrimSuffix(fields[0], "/tcp")
		port, parseErr := strconv.Atoi(portText)
		if parseErr != nil || (port != 80 && port != 443) {
			continue
		}
		owned := strings.Contains(trimmed, "# "+firewallRuleComment)
		if port == 80 {
			facts.Port80 = true
			facts.Owned80 = facts.Owned80 || owned
		} else {
			facts.Port443 = true
			facts.Owned443 = facts.Owned443 || owned
		}
	}
	return facts, nil
}

func (systemFirewallHost) Add(ctx context.Context, target FirewallTargetConfig, port int) error {
	if port != 80 && port != 443 {
		return fmt.Errorf("unsupported firewall port")
	}
	_, err := runBounded(ctx, target.Binary, "allow", strconv.Itoa(port)+"/tcp", "comment", firewallRuleComment)
	return err
}

func (h systemFirewallHost) Remove(ctx context.Context, target FirewallTargetConfig, port int) error {
	if port != 80 && port != 443 {
		return fmt.Errorf("unsupported firewall port")
	}
	facts, err := h.Inspect(ctx, target)
	owned := (port == 80 && facts.Owned80) || (port == 443 && facts.Owned443)
	if err != nil || !owned {
		return fmt.Errorf("firewall rule is not exact NurProxy provenance")
	}
	_, err = runBounded(ctx, target.Binary, "--force", "delete", "allow", strconv.Itoa(port)+"/tcp")
	return err
}
