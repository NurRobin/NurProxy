//go:build linux

package helper

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
	"golang.org/x/sys/unix"
)

func TestOpenManagedComponentFallsBackOnlyWhenOpenat2IsUnavailable(t *testing.T) {
	openat2Calls, openatCalls := 0, 0
	fd, err := openManagedComponentAtWith(9, "operation-1", unix.O_PATH|unix.O_DIRECTORY, func(dirFD int, path string, how *unix.OpenHow) (int, error) {
		openat2Calls++
		if dirFD != 9 || path != "operation-1" || how.Resolve != uint64(unix.RESOLVE_BENEATH|unix.RESOLVE_NO_MAGICLINKS|unix.RESOLVE_NO_SYMLINKS) {
			t.Fatalf("openat2 = fd %d path %q how %+v", dirFD, path, how)
		}
		return -1, unix.ENOSYS
	}, func(dirFD int, path string, flags int, mode uint32) (int, error) {
		openatCalls++
		if dirFD != 9 || path != "operation-1" || flags&unix.O_NOFOLLOW == 0 || mode != 0 {
			t.Fatalf("openat = fd %d path %q flags %#x mode %#o", dirFD, path, flags, mode)
		}
		return 17, nil
	})
	if err != nil || fd != 17 || openat2Calls != 1 || openatCalls != 1 {
		t.Fatalf("fd=%d err=%v openat2=%d openat=%d", fd, err, openat2Calls, openatCalls)
	}
}

func TestOpenManagedComponentDoesNotFallbackOnPolicyErrors(t *testing.T) {
	sentinel := unix.EACCES
	_, err := openManagedComponentAtWith(9, "artifact.pem", unix.O_RDONLY, func(int, string, *unix.OpenHow) (int, error) {
		return -1, sentinel
	}, func(int, string, int, uint32) (int, error) {
		t.Fatal("openat fallback called for non-ENOSYS failure")
		return -1, nil
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v", err)
	}
}

func TestOpenManagedComponentRejectsPathSyntaxBeforeSyscalls(t *testing.T) {
	for _, name := range []string{"", ".", "..", "nested/file", "/absolute"} {
		_, err := openManagedComponentAtWith(9, name, unix.O_RDONLY, func(int, string, *unix.OpenHow) (int, error) {
			t.Fatalf("openat2 called for %q", name)
			return -1, nil
		}, func(int, string, int, uint32) (int, error) {
			t.Fatalf("openat called for %q", name)
			return -1, nil
		})
		if err == nil {
			t.Fatalf("invalid component %q accepted", name)
		}
	}
}

func newManagedApplyTest(t *testing.T) (*managedApplyAction, helperprotocol.ApplyIntent, *fakeProxyServiceHost) {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"available", "enabled", "certs", "staging"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	operationID := "apply-operation-1"
	if err := os.Mkdir(filepath.Join(root, "staging", operationID), 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := NewJournal(filepath.Join(root, "journal"), uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	host := &fakeProxyServiceHost{facts: proxyServiceFacts{
		Kind: "nginx", BinaryPath: "/usr/sbin/nginx", BinaryDigest: repeatedDigest("a"), Unit: "nginx.service",
		LoadState: "loaded", Active: true, ConfigDigest: repeatedDigest("b"),
	}}
	action := &managedApplyAction{
		agentUID: uint32(os.Getuid()), ownerUID: uint32(os.Getuid()), stagingRootUID: uint32(os.Getuid()), journal: journal, host: host,
		target: ProxyTargetConfig{Kind: "nginx", Binary: "/usr/sbin/nginx", Unit: "nginx.service", SystemctlBinary: "/usr/bin/systemctl", ConfigRoots: []string{filepath.Join(root, "available")}},
		layout: ManagedApplyTargetConfig{
			StagingDir: filepath.Join(root, "staging"), AvailableDir: filepath.Join(root, "available"), EnabledDir: filepath.Join(root, "enabled"),
			CertificateDir: filepath.Join(root, "certs"), CustomPolicyVersion: "proxy-policy-v1", ProxyVersion: "1.22.1",
		},
	}
	set := helperprotocol.NormalizeManagedIntentSet(proxymodel.IntentSet{Intents: []proxymodel.RouteIntent{{
		ArtifactID: "domain-1", Backend: "nginx", Route: proxymodel.Route{
			Host: "app.example.com", Upstream: proxymodel.Upstream{Addr: "10.0.0.2", Port: 8080}, TLS: proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
		},
	}}})
	now := time.Date(2026, 8, 29, 18, 0, 0, 0, time.UTC)
	intent := helperprotocol.ApplyIntent{
		AgentID: "agent-1", HelperInstanceID: "helper-1", OperationID: operationID, DesiredStateRevision: strings.Repeat("1", 64),
		Resources: []string{"domain-1"}, Artifacts: []helperprotocol.LogicalArtifact{}, DeletionSet: []helperprotocol.ManagedDeletion{}, Routes: set.Intents, CertificateKeep: []string{},
		AuthorizationKind: helperprotocol.AuthorizationStoredConvergence, AuthorizationEventID: "desired-event-1",
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339Nano),
	}
	return action, intent, host
}

func TestManagedApplyCompilesSignedStructuredRouteToLocalPinnedTargets(t *testing.T) {
	action, intent, _ := newManagedApplyTest(t)
	compilation, err := action.compile(intent)
	if err != nil {
		t.Fatal(err)
	}
	if len(compilation.Files) != 1 || len(compilation.Links) != 1 {
		t.Fatalf("unexpected compilation: %+v", compilation)
	}
	if !strings.HasPrefix(string(compilation.Files[0].Content), proxy.ManagedArtifactMarker+"\n") ||
		!strings.HasSuffix(compilation.Files[0].Path, "nurproxy-app.example.com.conf") || compilation.Links[0].Target != compilation.Files[0].Path {
		t.Fatalf("managed route did not compile to exact provenanced targets: %+v", compilation)
	}
}

func TestManagedApplyTransactionSnapshotsCommitsValidatesReloadsAndRestores(t *testing.T) {
	action, intent, host := newManagedApplyTest(t)
	material, err := action.Plan(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	plan := helperprotocol.ManagedApplyPlan{
		OperationID: intent.OperationID, CustomPolicyVersion: material.CustomPolicyVersion,
		ExecutionPlanHash: material.ExecutionPlanHash, ResourceFingerprint: material.ResourceFingerprint,
		RollbackCoverage: material.RollbackCoverage,
	}
	prepared, err := action.Prepare(context.Background(), intent.OperationID, plan, intent)
	if err != nil {
		t.Fatal(err)
	}
	result, err := action.Execute(context.Background(), intent.OperationID, plan, intent, prepared)
	if err != nil || !result.Mutated || !result.Validated {
		t.Fatalf("managed execute = %+v, %v", result, err)
	}
	compilation, err := action.compile(intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(compilation.Files[0].Path); err != nil {
		t.Fatal(err)
	}
	if target, err := os.Readlink(compilation.Links[0].Path); err != nil || target != compilation.Files[0].Path {
		t.Fatalf("activation link = %q, %v", target, err)
	}
	if len(host.mutations) != 1 || host.mutations[0] != proxyServiceReload || host.validations != 3 {
		t.Fatalf("native validation/reload sequence = mutations %v validations %d", host.mutations, host.validations)
	}
	if err := action.Rollback(context.Background(), intent.OperationID, plan, intent, prepared); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(compilation.Files[0].Path); !os.IsNotExist(err) {
		t.Fatalf("new file remained after rollback: %v", err)
	}
	if _, err := os.Lstat(compilation.Links[0].Path); !os.IsNotExist(err) {
		t.Fatalf("new link remained after rollback: %v", err)
	}
}

func TestManagedApplyDeletesOnlyExplicitProvenancedRouteAndCanRestoreIt(t *testing.T) {
	action, intent, _ := newManagedApplyTest(t)
	compilation, err := action.compile(intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(compilation.Files[0].Path, compilation.Files[0].Content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(compilation.Links[0].Target, compilation.Links[0].Path); err != nil {
		t.Fatal(err)
	}
	operatorPath := filepath.Join(action.layout.AvailableDir, "operator.conf")
	if err := os.WriteFile(operatorPath, []byte("server { listen 8081; }"), 0o644); err != nil {
		t.Fatal(err)
	}
	intent.OperationID = "apply-operation-delete"
	intent.DesiredStateRevision = strings.Repeat("2", 64)
	intent.Resources = []string{}
	intent.Routes = []proxymodel.RouteIntent{}
	intent.DeletionSet = []helperprotocol.ManagedDeletion{{ResourceID: "domain-1", Host: "app.example.com", Backend: "nginx"}}
	material, err := action.Plan(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	plan := helperprotocol.ManagedApplyPlan{OperationID: intent.OperationID, CustomPolicyVersion: material.CustomPolicyVersion,
		ExecutionPlanHash: material.ExecutionPlanHash, ResourceFingerprint: material.ResourceFingerprint, RollbackCoverage: material.RollbackCoverage}
	prepared, err := action.Prepare(context.Background(), intent.OperationID, plan, intent)
	if err != nil {
		t.Fatal(err)
	}
	result, err := action.Execute(context.Background(), intent.OperationID, plan, intent, prepared)
	if err != nil || !result.Mutated || !result.Validated {
		t.Fatalf("managed delete = %+v, %v", result, err)
	}
	if _, err := os.Lstat(compilation.Files[0].Path); !os.IsNotExist(err) {
		t.Fatalf("managed vhost remained: %v", err)
	}
	if _, err := os.Lstat(compilation.Links[0].Path); !os.IsNotExist(err) {
		t.Fatalf("managed activation remained: %v", err)
	}
	if _, err := os.Stat(operatorPath); err != nil {
		t.Fatalf("operator sibling was touched: %v", err)
	}
	if err := action.Rollback(context.Background(), intent.OperationID, plan, intent, prepared); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(compilation.Files[0].Path); err != nil {
		t.Fatalf("managed vhost was not restored: %v", err)
	}
	if target, err := os.Readlink(compilation.Links[0].Path); err != nil || target != compilation.Links[0].Target {
		t.Fatalf("managed activation was not restored: %q, %v", target, err)
	}
}

func TestManagedApplyPrunesOnlyRecognizedUnretainedCertificateFiles(t *testing.T) {
	action, intent, _ := newManagedApplyTest(t)
	intent.OperationID = "apply-operation-prune"
	intent.PruneCertificates = true
	intent.CertificateKeep = []string{"kept.example.com"}
	staleCert := filepath.Join(action.layout.CertificateDir, "stale.example.com.crt")
	staleKey := filepath.Join(action.layout.CertificateDir, "stale.example.com.key.plain")
	keptCert := filepath.Join(action.layout.CertificateDir, "kept.example.com.crt")
	unknown := filepath.Join(action.layout.CertificateDir, "operator-note")
	for path, content := range map[string]string{staleCert: "cert", staleKey: "key", keptCert: "kept", unknown: "do not touch"} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	material, err := action.Plan(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	plan := helperprotocol.ManagedApplyPlan{OperationID: intent.OperationID, CustomPolicyVersion: material.CustomPolicyVersion,
		ExecutionPlanHash: material.ExecutionPlanHash, ResourceFingerprint: material.ResourceFingerprint, RollbackCoverage: material.RollbackCoverage}
	prepared, err := action.Prepare(context.Background(), intent.OperationID, plan, intent)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := action.Execute(context.Background(), intent.OperationID, plan, intent, prepared); err != nil || !result.Validated {
		t.Fatalf("certificate prune = %+v, %v", result, err)
	}
	for _, path := range []string{staleCert, staleKey} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("stale managed certificate remained at %s: %v", path, err)
		}
	}
	for _, path := range []string{keptCert, unknown} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("retained or unknown certificate sibling was touched at %s: %v", path, err)
		}
	}
	if err := action.Rollback(context.Background(), intent.OperationID, plan, intent, prepared); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{staleCert, staleKey} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("certificate prune rollback did not restore %s: %v", path, err)
		}
	}
}

func TestManagedApplyRefusesRawConfigurationUntilPolicyParserAdmitsIt(t *testing.T) {
	action, intent, _ := newManagedApplyTest(t)
	intent.Routes[0].Route.Raw = proxymodel.RawConfig{Backend: "nginx", Content: "server { listen 8443; }"}
	if _, err := action.Plan(context.Background(), intent); err == nil {
		t.Fatal("raw configuration bypassed managed custom policy")
	}
}

func TestManagedApplyAdmitsParserBoundedNginxCustomConfiguration(t *testing.T) {
	action, intent, _ := newManagedApplyTest(t)
	intent.Routes[0].Route.Raw = proxymodel.RawConfig{Backend: "nginx", Content: `server {
    listen 80;
    listen [::]:80;
    server_name app.example.com;
    location / {
        proxy_pass http://10.0.0.2:8080;
        proxy_set_header Host $host;
    }
}`}
	compilation, err := action.compile(intent)
	if err != nil {
		t.Fatal(err)
	}
	if len(compilation.Files) != 1 || !strings.Contains(string(compilation.Files[0].Content), "proxy_pass http://10.0.0.2:8080") ||
		!proxy.HasManagedArtifactMarker(string(compilation.Files[0].Content)) {
		t.Fatalf("bounded raw config was not compiled: %+v", compilation)
	}
}

func TestManagedApplyPreservesExactExistingPolicyForeignRawConfiguration(t *testing.T) {
	action, intent, host := newManagedApplyTest(t)
	action.agentUID = uint32(os.Getuid()) + 1
	raw := `map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
}
server {
    listen 80;
    server_name app.example.com;
    location / { proxy_pass http://10.0.0.2:8080; }
}`
	intent.Routes[0].Route.Raw = proxymodel.RawConfig{Backend: "nginx", Content: raw}
	available := filepath.Join(action.layout.AvailableDir, managedFileName("nginx", "app.example.com"))
	enabled := filepath.Join(action.layout.EnabledDir, filepath.Base(available))
	if err := os.WriteFile(available, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(available, enabled); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(available)
	if err != nil {
		t.Fatal(err)
	}
	material, err := action.Plan(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	plan := helperprotocol.ManagedApplyPlan{
		OperationID: intent.OperationID, CustomPolicyVersion: material.CustomPolicyVersion,
		ExecutionPlanHash: material.ExecutionPlanHash, ResourceFingerprint: material.ResourceFingerprint,
		RollbackCoverage: material.RollbackCoverage,
	}
	prepared, err := action.Prepare(context.Background(), intent.OperationID, plan, intent)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := action.loadSnapshot(intent.OperationID, prepared)
	if err != nil || len(snapshot.Files) != 0 {
		t.Fatalf("preserved raw targets entered rollback snapshot: %+v, %v", snapshot, err)
	}
	result, err := action.Execute(context.Background(), intent.OperationID, plan, intent, prepared)
	if err != nil || result.Mutated || !result.Validated || len(host.mutations) != 0 {
		t.Fatalf("preserved raw execute = %+v, %v; mutations=%v", result, err, host.mutations)
	}
	after, err := os.Lstat(available)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("preserved raw file identity changed: %v", err)
	}
	if err := os.Remove(enabled); err != nil {
		t.Fatal(err)
	}
	if _, err := action.Plan(context.Background(), intent); err == nil {
		t.Fatal("policy-foreign raw config was admitted without its exact live activation link")
	}
}

func TestManagedApplyPreservesExactUnmarkedLegacyGeneratedConfiguration(t *testing.T) {
	action, intent, host := newManagedApplyTest(t)
	action.agentUID = uint32(os.Getuid()) + 1
	initial, err := action.compile(intent)
	if err != nil {
		t.Fatal(err)
	}
	legacy := strings.TrimPrefix(string(initial.Files[0].Content), proxy.ManagedArtifactMarker+"\n")
	if legacy == string(initial.Files[0].Content) {
		t.Fatal("generated fixture has no managed marker")
	}
	if err := os.WriteFile(initial.Files[0].Path, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(initial.Links[0].Target, initial.Links[0].Path); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(initial.Files[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	material, err := action.Plan(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	compilation, err := action.compile(intent)
	if err != nil || !compilation.Files[0].Preserve || !compilation.Links[0].Preserve {
		t.Fatalf("legacy generated route was not classified as preserve-only: %+v, %v", compilation, err)
	}
	plan := helperprotocol.ManagedApplyPlan{
		OperationID: intent.OperationID, CustomPolicyVersion: material.CustomPolicyVersion,
		ExecutionPlanHash: material.ExecutionPlanHash, ResourceFingerprint: material.ResourceFingerprint,
		RollbackCoverage: material.RollbackCoverage,
	}
	prepared, err := action.Prepare(context.Background(), intent.OperationID, plan, intent)
	if err != nil {
		t.Fatal(err)
	}
	result, err := action.Execute(context.Background(), intent.OperationID, plan, intent, prepared)
	if err != nil || result.Mutated || !result.Validated || len(host.mutations) != 0 {
		t.Fatalf("legacy generated preserve execute = %+v, %v; mutations=%v", result, err, host.mutations)
	}
	after, err := os.Lstat(initial.Files[0].Path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("legacy generated file identity changed: %v", err)
	}
	if err := os.WriteFile(initial.Files[0].Path, []byte(legacy+"\n# operator drift\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := action.Plan(context.Background(), intent); err == nil {
		t.Fatal("drifted unmarked legacy generated config was admitted")
	}
}

func TestManagedApplyRefusesPolicyForeignRawConfigurationWhenLiveBytesDiffer(t *testing.T) {
	action, intent, _ := newManagedApplyTest(t)
	action.agentUID = uint32(os.Getuid()) + 1
	intent.Routes[0].Route.Raw = proxymodel.RawConfig{Backend: "nginx", Content: "server { listen 8443; }"}
	available := filepath.Join(action.layout.AvailableDir, managedFileName("nginx", "app.example.com"))
	if err := os.WriteFile(available, []byte("server { listen 80; }"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := action.Plan(context.Background(), intent); err == nil {
		t.Fatal("policy-foreign raw config was admitted despite different live bytes")
	}
}

func TestManagedApplyReadsCertificatesBeneathPrivateStageAndBindsTheirHashes(t *testing.T) {
	action, intent, _ := newManagedApplyTest(t)
	intent.Routes[0].Route.TLS.Policy = proxymodel.TLSPolicyCentral
	certPEM, keyPEM := managedTestCertificate(t, "app.example.com")
	artifacts, err := helperprotocol.CertificateArtifacts([]proxymodel.CertBundle{{Host: "app.example.com", CertPEM: string(certPEM), KeyPEM: string(keyPEM)}})
	if err != nil {
		t.Fatal(err)
	}
	intent.Artifacts = artifacts
	intent.Resources = append(intent.Resources, helperprotocol.CertificateResourceID("app.example.com"))
	intent.CertificateKeep = []string{"app.example.com"}
	operationDir := filepath.Join(action.layout.StagingDir, intent.OperationID)
	for _, artifact := range artifacts {
		name, err := helperprotocol.StagedArtifactFileName(artifact)
		if err != nil {
			t.Fatal(err)
		}
		data := certPEM
		if artifact.Kind == "source_key" {
			data = keyPEM
		}
		if err := os.WriteFile(filepath.Join(operationDir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	compilation, err := action.compile(intent)
	if err != nil {
		t.Fatal(err)
	}
	var rendered string
	for _, file := range compilation.Files {
		if file.Class == "vhost" {
			rendered = string(file.Content)
		}
	}
	if len(compilation.Files) != 3 || !strings.Contains(rendered, filepath.Join(action.layout.CertificateDir, "app.example.com.crt")) {
		t.Fatalf("certificate paths were not rendered from the local pinned layout: %+v", compilation)
	}
	certificateName, _ := helperprotocol.StagedArtifactFileName(artifacts[0])
	if err := os.WriteFile(filepath.Join(operationDir, certificateName), bytesOfLength(len(certPEM), 'x'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := action.compile(intent); err == nil {
		t.Fatal("staged certificate mutation passed the signed hash check")
	}
}

func managedTestCertificate(t *testing.T, host string) ([]byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func bytesOfLength(length int, value byte) []byte {
	data := make([]byte, length)
	for index := range data {
		data[index] = value
	}
	return data
}
