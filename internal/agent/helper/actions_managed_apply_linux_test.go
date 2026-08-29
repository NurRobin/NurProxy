//go:build linux

package helper

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

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
		Resources: []string{"domain-1"}, Artifacts: []helperprotocol.LogicalArtifact{}, DeletionSet: []string{}, Routes: set.Intents, CertificateKeep: []string{},
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

func TestManagedApplyRefusesRawConfigurationUntilPolicyParserAdmitsIt(t *testing.T) {
	action, intent, _ := newManagedApplyTest(t)
	intent.Routes[0].Route.Raw = proxymodel.RawConfig{Backend: "nginx", Content: "server { listen 8443; }"}
	if _, err := action.Plan(context.Background(), intent); err == nil {
		t.Fatal("raw configuration bypassed managed custom policy")
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
