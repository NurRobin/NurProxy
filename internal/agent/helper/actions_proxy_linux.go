//go:build linux

package helper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
	"github.com/NurRobin/NurProxy/internal/shared/recoverypolicy"
	"golang.org/x/sys/unix"
)

const (
	maxProxyCommandOutput = 64 << 10
	maxConfigEntries      = 4096
	maxConfigFileBytes    = 8 << 20
	maxConfigTreeBytes    = 64 << 20
	maxTrustedBinaryBytes = 256 << 20
)

type proxyServiceFacts struct {
	Kind         string `json:"kind"`
	BinaryPath   string `json:"binary_path"`
	BinaryDigest string `json:"binary_digest"`
	Unit         string `json:"unit"`
	LoadState    string `json:"load_state"`
	Active       bool   `json:"active"`
	ConfigDigest string `json:"config_digest"`
}

type proxyServiceSnapshot struct {
	Action helperprotocol.Action `json:"action"`
	Facts  proxyServiceFacts     `json:"facts"`
}

type proxyServiceMutation string

const (
	proxyServiceReload  proxyServiceMutation = "reload"
	proxyServiceStart   proxyServiceMutation = "start"
	proxyServiceRestart proxyServiceMutation = "restart"
	proxyServiceStop    proxyServiceMutation = "stop"
)

type proxyServiceHost interface {
	Inspect(context.Context, ProxyTargetConfig) (proxyServiceFacts, error)
	Validate(context.Context, ProxyTargetConfig) error
	Mutate(context.Context, ProxyTargetConfig, proxyServiceMutation) error
}

type proxyServiceAction struct {
	action  helperprotocol.Action
	target  ProxyTargetConfig
	journal *Journal
	host    proxyServiceHost
}

func newProxyServiceAction(action helperprotocol.Action, target ProxyTargetConfig, journal *Journal, host proxyServiceHost) (*proxyServiceAction, error) {
	if action != helperprotocol.ActionValidateReloadProxy && action != helperprotocol.ActionStartProxy && action != helperprotocol.ActionRestartProxy {
		return nil, fmt.Errorf("unsupported proxy service action")
	}
	if err := target.Validate(); err != nil || journal == nil || host == nil {
		return nil, fmt.Errorf("proxy service action is not safely configured")
	}
	return &proxyServiceAction{action: action, target: target, journal: journal, host: host}, nil
}

func (a *proxyServiceAction) Plan(ctx context.Context, request helperprotocol.PlanActionRequest) (PlanMaterial, error) {
	if request.Action != a.action || request.LogicalTarget != helperprotocol.LogicalTargetDetectedProxy {
		return PlanMaterial{}, fmt.Errorf("proxy action request does not match compiled handler")
	}
	facts, err := a.inspectForAction(ctx)
	if err != nil {
		return PlanMaterial{}, err
	}
	executionHash, err := a.executionHash(facts)
	if err != nil {
		return PlanMaterial{}, err
	}
	code, evidenceClass, coverage, steps := proxyActionProfile(a.action, a.target)
	return PlanMaterial{
		Steps:               steps,
		ExecutionPlanHash:   executionHash,
		ResourceFingerprint: recoverypolicy.HardDiagnosticFingerprint(code, a.target.Kind, evidenceClass, nil),
		RollbackCoverage:    coverage,
	}, nil
}

func (a *proxyServiceAction) Rediscover(ctx context.Context, plan helperprotocol.HelperPlan) (string, string, error) {
	if plan.Action != a.action {
		return "", "", fmt.Errorf("helper plan action does not match handler")
	}
	facts, err := a.inspectForAction(ctx)
	if err != nil {
		return "", "", err
	}
	executionHash, err := a.executionHash(facts)
	if err != nil {
		return "", "", err
	}
	code, evidenceClass, _, _ := proxyActionProfile(a.action, a.target)
	return executionHash, recoverypolicy.HardDiagnosticFingerprint(code, a.target.Kind, evidenceClass, nil), nil
}

func (a *proxyServiceAction) Prepare(ctx context.Context, operationID string, plan helperprotocol.HelperPlan) (PreparedAction, error) {
	facts, err := a.inspectForAction(ctx)
	if err != nil {
		return PreparedAction{}, err
	}
	executionHash, err := a.executionHash(facts)
	if err != nil || (plan.ExecutionPlanHash != "" && executionHash != plan.ExecutionPlanHash) {
		return PreparedAction{}, fmt.Errorf("proxy facts changed before snapshot")
	}
	_, _, coverage, _ := proxyActionProfile(a.action, a.target)
	digest, err := a.journal.StoreSnapshot(operationID, proxyServiceSnapshot{Action: a.action, Facts: facts})
	if err != nil {
		return PreparedAction{}, err
	}
	return PreparedAction{SnapshotDigest: digest, RollbackCoverage: coverage}, nil
}

func (a *proxyServiceAction) Execute(ctx context.Context, operationID string, plan helperprotocol.HelperPlan, prepared PreparedAction) (ActionResult, error) {
	snapshot, err := a.loadSnapshot(operationID, prepared)
	if err != nil {
		return ActionResult{}, err
	}
	current, err := a.inspectForAction(ctx)
	if err != nil || current != snapshot.Facts {
		return ActionResult{}, fmt.Errorf("proxy facts changed after privileged snapshot")
	}
	if err := a.host.Validate(ctx, a.target); err != nil {
		return ActionResult{}, fmt.Errorf("native proxy validation failed before mutation: %w", err)
	}
	validatedFacts, err := a.inspectForAction(ctx)
	if err != nil || validatedFacts != snapshot.Facts {
		return ActionResult{}, fmt.Errorf("proxy facts changed between validation and mutation")
	}
	mutation := mutationForAction(a.action)
	if err := a.host.Mutate(ctx, a.target, mutation); err != nil {
		return ActionResult{Mutated: true}, fmt.Errorf("proxy service mutation failed: %w", err)
	}
	if err := a.host.Validate(ctx, a.target); err != nil {
		return ActionResult{Mutated: true}, fmt.Errorf("native proxy validation failed after mutation: %w", err)
	}
	post, err := a.host.Inspect(ctx, a.target)
	if err != nil || !post.Active || post.Kind != snapshot.Facts.Kind || post.BinaryPath != snapshot.Facts.BinaryPath ||
		post.BinaryDigest != snapshot.Facts.BinaryDigest || post.Unit != snapshot.Facts.Unit || post.LoadState != snapshot.Facts.LoadState ||
		post.ConfigDigest != snapshot.Facts.ConfigDigest {
		return ActionResult{Mutated: true}, fmt.Errorf("proxy postcondition could not be proven")
	}
	return ActionResult{Mutated: true, Validated: true, SanitizedResult: fmt.Sprintf("%s %s and native validation passed", a.target.Unit, mutation)}, nil
}

func (a *proxyServiceAction) Rollback(ctx context.Context, operationID string, _ helperprotocol.HelperPlan, prepared PreparedAction) error {
	snapshot, err := a.loadSnapshot(operationID, prepared)
	if err != nil {
		return err
	}
	if a.action != helperprotocol.ActionStartProxy || snapshot.Facts.Active {
		return fmt.Errorf("proxy service pre-state is not fully restorable")
	}
	if err := a.host.Mutate(ctx, a.target, proxyServiceStop); err != nil {
		return err
	}
	post, err := a.host.Inspect(ctx, a.target)
	if err != nil || post.Active {
		return fmt.Errorf("inactive proxy pre-state was not restored")
	}
	return nil
}

func (a *proxyServiceAction) loadSnapshot(operationID string, prepared PreparedAction) (proxyServiceSnapshot, error) {
	payload, err := a.journal.LoadSnapshot(operationID, prepared.SnapshotDigest)
	if err != nil {
		return proxyServiceSnapshot{}, err
	}
	snapshot, err := helperprotocol.Decode[proxyServiceSnapshot](payload)
	if err != nil || snapshot.Action != a.action {
		return proxyServiceSnapshot{}, fmt.Errorf("privileged proxy snapshot is invalid")
	}
	return snapshot, nil
}

func (a *proxyServiceAction) inspectForAction(ctx context.Context) (proxyServiceFacts, error) {
	facts, err := a.host.Inspect(ctx, a.target)
	if err != nil {
		return proxyServiceFacts{}, err
	}
	if facts.Kind != a.target.Kind || facts.BinaryPath != a.target.Binary || facts.Unit != a.target.Unit || facts.LoadState != "loaded" ||
		!validDigest(facts.BinaryDigest) || !validDigest(facts.ConfigDigest) {
		return proxyServiceFacts{}, fmt.Errorf("local proxy target does not match the root-owned mapping")
	}
	switch a.action {
	case helperprotocol.ActionStartProxy:
		if facts.Active {
			return proxyServiceFacts{}, fmt.Errorf("proxy service is already active")
		}
	case helperprotocol.ActionValidateReloadProxy, helperprotocol.ActionRestartProxy:
		if !facts.Active {
			return proxyServiceFacts{}, fmt.Errorf("proxy service is not active")
		}
	}
	return facts, nil
}

func (a *proxyServiceAction) executionHash(facts proxyServiceFacts) (string, error) {
	return helperprotocol.Digest(struct {
		Action helperprotocol.Action `json:"action"`
		Facts  proxyServiceFacts     `json:"facts"`
	}{Action: a.action, Facts: facts})
}

func proxyActionProfile(action helperprotocol.Action, target ProxyTargetConfig) (recoverymodel.Code, string, helperprotocol.RollbackCoverage, []helperprotocol.PlanStep) {
	validate := helperprotocol.PlanStep{Kind: "validate", Summary: fmt.Sprintf("Validate %s with %s against %s", target.Kind, target.Binary, strings.Join(target.ConfigRoots, ", "))}
	post := helperprotocol.PlanStep{Kind: "post_validate", Summary: fmt.Sprintf("Verify %s is active with the same validated configuration", target.Unit)}
	switch action {
	case helperprotocol.ActionStartProxy:
		return recoverymodel.CodeProxyNotRunning, "proxy_not_running", helperprotocol.RollbackCoverageFull, []helperprotocol.PlanStep{
			validate, {Kind: "start", Summary: fmt.Sprintf("Start %s", target.Unit)}, post,
		}
	case helperprotocol.ActionRestartProxy:
		return recoverymodel.CodeProxyReloadFailed, "reload_failed", helperprotocol.RollbackCoveragePartial, []helperprotocol.PlanStep{
			validate, {Kind: "restart", Summary: fmt.Sprintf("Restart %s", target.Unit)}, post,
		}
	default:
		return recoverymodel.CodeProxyReloadFailed, "reload_failed", helperprotocol.RollbackCoveragePartial, []helperprotocol.PlanStep{
			validate, {Kind: "reload", Summary: fmt.Sprintf("Reload %s", target.Unit)}, post,
		}
	}
}

func mutationForAction(action helperprotocol.Action) proxyServiceMutation {
	switch action {
	case helperprotocol.ActionStartProxy:
		return proxyServiceStart
	case helperprotocol.ActionRestartProxy:
		return proxyServiceRestart
	default:
		return proxyServiceReload
	}
}

type systemProxyServiceHost struct{}

func (systemProxyServiceHost) Inspect(ctx context.Context, target ProxyTargetConfig) (proxyServiceFacts, error) {
	binaryDigest, err := trustedRegularFileDigest(target.Binary, maxTrustedBinaryBytes)
	if err != nil {
		return proxyServiceFacts{}, fmt.Errorf("inspect pinned proxy binary: %w", err)
	}
	if _, err := trustedRegularFileDigest(target.SystemctlBinary, maxTrustedBinaryBytes); err != nil {
		return proxyServiceFacts{}, fmt.Errorf("inspect pinned systemctl binary: %w", err)
	}
	configDigest, err := proxyConfigDigest(target.ConfigRoots)
	if err != nil {
		return proxyServiceFacts{}, fmt.Errorf("fingerprint proxy configuration: %w", err)
	}
	out, err := runBounded(ctx, target.SystemctlBinary, "show", target.Unit, "--property=LoadState", "--property=ActiveState", "--property=SubState")
	if err != nil {
		return proxyServiceFacts{}, fmt.Errorf("inspect proxy unit: %w", err)
	}
	properties := parseSystemdProperties(out)
	return proxyServiceFacts{
		Kind: target.Kind, BinaryPath: target.Binary, BinaryDigest: binaryDigest, Unit: target.Unit,
		LoadState: properties["LoadState"], Active: properties["ActiveState"] == "active", ConfigDigest: configDigest,
	}, nil
}

func (systemProxyServiceHost) Validate(ctx context.Context, target ProxyTargetConfig) error {
	var args []string
	switch target.Kind {
	case "nginx":
		args = []string{"-t"}
	case "apache":
		args = []string{"configtest"}
	case "caddy":
		if len(target.ConfigRoots) != 1 {
			return fmt.Errorf("caddy requires one pinned configuration file")
		}
		args = []string{"validate", "--config", target.ConfigRoots[0]}
	default:
		return fmt.Errorf("unsupported proxy validator")
	}
	_, err := runBounded(ctx, target.Binary, args...)
	return err
}

func (systemProxyServiceHost) Mutate(ctx context.Context, target ProxyTargetConfig, mutation proxyServiceMutation) error {
	switch mutation {
	case proxyServiceReload, proxyServiceStart, proxyServiceRestart, proxyServiceStop:
	default:
		return fmt.Errorf("unsupported proxy service mutation")
	}
	_, err := runBounded(ctx, target.SystemctlBinary, string(mutation), target.Unit)
	return err
}

func trustedRegularFileDigest(path string, maxBytes int64) (string, error) {
	if !trustedExecutableLocation(path) {
		return "", fmt.Errorf("executable path is outside compiled roots")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return "", fmt.Errorf("invalid executable descriptor")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || fileOwnerUID(info) != 0 || info.Mode().Perm()&0o022 != 0 || info.Size() < 0 || info.Size() > maxBytes {
		return "", fmt.Errorf("executable identity or permissions are not trusted")
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(file, maxBytes+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func proxyConfigDigest(roots []string) (string, error) {
	type entry struct {
		path string
		mode fs.FileMode
		size int64
		link string
		data []byte
	}
	var entries []entry
	var total int64
	for _, root := range roots {
		rootInfo, err := os.Lstat(root)
		if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("config root is missing or symlinked")
		}
		err = filepath.WalkDir(root, func(path string, dirEntry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if len(entries) >= maxConfigEntries {
				return fmt.Errorf("config tree exceeds entry limit")
			}
			info, err := dirEntry.Info()
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return fmt.Errorf("config entry escaped root")
			}
			item := entry{path: root + "\x00" + rel, mode: info.Mode(), size: info.Size()}
			owner, ok := info.Sys().(*syscall.Stat_t)
			if !ok || owner.Uid != 0 || (info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o022 != 0) {
				return fmt.Errorf("config entry owner or permissions are not trusted")
			}
			switch {
			case info.Mode()&os.ModeSymlink != 0:
				item.link, err = os.Readlink(path)
			case info.Mode().IsRegular():
				if info.Size() < 0 || info.Size() > maxConfigFileBytes || total+info.Size() > maxConfigTreeBytes {
					return fmt.Errorf("config tree exceeds byte limit")
				}
				item.data, err = readNoFollowFile(path, info.Size())
				total += info.Size()
			case info.IsDir():
			default:
				return fmt.Errorf("unsupported config entry type")
			}
			if err == nil {
				entries = append(entries, item)
			}
			return err
		})
		if err != nil {
			return "", err
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	h := sha256.New()
	for _, item := range entries {
		for _, value := range []string{item.path, item.mode.String(), fmt.Sprint(item.size), item.link} {
			_, _ = h.Write([]byte(fmt.Sprintf("%d:", len(value))))
			_, _ = h.Write([]byte(value))
		}
		_, _ = h.Write(item.data)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readNoFollowFile(path string, expectedSize int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("invalid config descriptor")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != expectedSize {
		return nil, fmt.Errorf("config file changed while fingerprinting")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxConfigFileBytes+1))
	if err != nil || int64(len(payload)) != expectedSize {
		return nil, fmt.Errorf("config file changed while reading")
	}
	return payload, nil
}

func runBounded(ctx context.Context, binary string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 2 * time.Second
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
		if errors.Is(err, unix.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	var output boundedCommandBuffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	if output.exceeded {
		return "", fmt.Errorf("command output exceeded limit")
	}
	if err != nil {
		return "", err
	}
	return output.String(), nil
}

type boundedCommandBuffer struct {
	bytes.Buffer
	exceeded bool
}

func (b *boundedCommandBuffer) Write(payload []byte) (int, error) {
	remaining := maxProxyCommandOutput - b.Len()
	if remaining <= 0 {
		b.exceeded = true
		return len(payload), nil
	}
	if len(payload) > remaining {
		_, _ = b.Buffer.Write(payload[:remaining])
		b.exceeded = true
		return len(payload), nil
	}
	return b.Buffer.Write(payload)
}

func parseSystemdProperties(output string) map[string]string {
	properties := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && (key == "LoadState" || key == "ActiveState" || key == "SubState") {
			properties[key] = value
		}
	}
	return properties
}
