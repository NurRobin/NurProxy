//go:build linux

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/agent/helper"
	"github.com/NurRobin/NurProxy/internal/agent/helperclient"
	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/agent/recoverycontrol"
	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/google/uuid"
)

type helperBootstrapConfigInput struct {
	AgentID, AgentUser, BuildID, HelperInstanceID, AttestationKeyID string
	AgentUID                                                        uint32
	Authority                                                       recoverycontrol.AuthorityPin
	ProxyKind, ProxyBinary, ProxyVersion                            string
	DebianLayout                                                    bool
}

func validateHelperBootstrapInvocation(effectiveUID int, buildID, orchestrator, proxyKind string) error {
	if effectiveUID != 0 || strings.TrimSpace(buildID) == "" || strings.TrimSpace(orchestrator) == "" || (proxyKind != "nginx" && proxyKind != "apache") {
		return fmt.Errorf("helper-bootstrap requires root, immutable build identity, explicit orchestrator URL and nginx/apache kind")
	}
	return nil
}

func cmdHelperBootstrap(args []string) {
	fs := flag.NewFlagSet("helper-bootstrap", flag.ExitOnError)
	orchestrator := fs.String("orchestrator", "", "Trusted orchestrator URL")
	proxyKind := fs.String("proxy-kind", "", "Pinned existing proxy kind: nginx or apache")
	dataDir := fs.String("data-dir", "/var/lib/nurproxy-agent/state", "Unprivileged agent state directory")
	agentUser := fs.String("agent-user", "nurproxy", "Dedicated main-agent system user")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		log.Fatalf("Root helper bootstrap refused: positional arguments are unsupported")
	}
	if err := validateHelperBootstrapInvocation(os.Geteuid(), version, *orchestrator, *proxyKind); err != nil {
		log.Fatalf("Root helper bootstrap refused: %v", err)
	}

	agentID, err := readBootstrapIdentity(filepath.Join(*dataDir, "agent-id"), 256)
	if err != nil {
		log.Fatalf("Root helper bootstrap cannot read agent identity: %v", err)
	}
	token, err := readBootstrapIdentity(filepath.Join(*dataDir, "token"), 512)
	if err != nil {
		log.Fatalf("Root helper bootstrap cannot read agent credential: %v", err)
	}
	account, err := user.Lookup(*agentUser)
	if err != nil {
		log.Fatalf("Root helper bootstrap cannot resolve dedicated user: %v", err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		log.Fatalf("Root helper bootstrap dedicated user identity is invalid")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	remote, err := recoverycontrol.NewHTTP(*orchestrator, agentID, token, nil)
	if err != nil {
		log.Fatalf("Root helper bootstrap recovery authority client failed: %v", err)
	}
	authority, err := remote.Authority(ctx)
	if err != nil {
		log.Fatalf("Root helper bootstrap cannot authenticate recovery authority: %v", err)
	}
	binary, proxyVersion, debian, err := discoverBootstrapProxy(ctx, *proxyKind)
	if err != nil {
		log.Fatalf("Root helper bootstrap cannot pin local proxy: %v", err)
	}

	config, loadErr := helper.LoadRootConfig(helper.DefaultRootConfigPath)
	if loadErr == nil {
		if config.AgentID != agentID || config.AgentUser != *agentUser || config.AgentUID != uint32(uid) ||
			config.OrchestratorKeyID != authority.KeyID || config.OrchestratorPublicKeyText != authority.PublicKeyText ||
			config.ProxyTarget.Kind != *proxyKind || config.ProxyTarget.Binary != binary {
			log.Fatalf("Root helper bootstrap refuses implicit trust or target rotation")
		}
		if _, err := helper.RefreshRootConfigBuildID(helper.DefaultRootConfigPath, version); err != nil {
			log.Fatalf("Root helper bootstrap cannot refresh build binding: %v", err)
		}
		config.ExpectedBuildID = version
		if config.FirewallTarget == nil && trustedBootstrapFile("/usr/sbin/ufw") {
			config.FirewallTarget = &helper.FirewallTargetConfig{Backend: "ufw", Binary: "/usr/sbin/ufw"}
			if err := helper.WriteRootConfig(helper.DefaultRootConfigPath, config); err != nil {
				log.Fatalf("Root helper bootstrap cannot add compiled firewall mapping: %v", err)
			}
		}
	} else if !os.IsNotExist(rootHelperCause(loadErr)) {
		log.Fatalf("Root helper bootstrap found an untrusted existing configuration: %v", loadErr)
	} else {
		instanceID := "helper-" + uuid.NewString()
		attestationID := "attestation-" + uuid.NewString()
		config, err = buildRootHelperConfig(helperBootstrapConfigInput{
			AgentID: agentID, AgentUser: *agentUser, AgentUID: uint32(uid), BuildID: version,
			HelperInstanceID: instanceID, AttestationKeyID: attestationID, Authority: authority,
			ProxyKind: *proxyKind, ProxyBinary: binary, ProxyVersion: proxyVersion, DebianLayout: debian,
		})
		if err != nil {
			log.Fatalf("Root helper bootstrap cannot compile root trust: %v", err)
		}
		if trustedBootstrapFile("/usr/sbin/ufw") {
			config.FirewallTarget = &helper.FirewallTargetConfig{Backend: "ufw", Binary: "/usr/sbin/ufw"}
		}
		if _, err := helper.LoadOrCreateAttestationKey(config.AttestationPrivateKeyFile); err != nil {
			log.Fatalf("Root helper bootstrap cannot create attestation identity: %v", err)
		}
		if err := helper.WriteRootConfig(helper.DefaultRootConfigPath, config); err != nil {
			log.Fatalf("Root helper bootstrap cannot install root trust: %v", err)
		}
	}
	privateKey, err := helper.LoadOrCreateAttestationKey(config.AttestationPrivateKeyFile)
	if err != nil {
		log.Fatalf("Root helper bootstrap cannot load attestation identity: %v", err)
	}
	if err := activateHelperSocket(ctx); err != nil {
		log.Fatalf("Root helper bootstrap cannot activate helper socket: %v", err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	pin := helperclient.Pin{HelperInstanceID: config.HelperInstanceID, AttestationKeyID: config.AttestationKeyID, AttestationPublicKey: base64.RawURLEncoding.EncodeToString(publicKey)}
	client, err := helperclient.New(agentID, version, pin)
	if err != nil {
		log.Fatalf("Root helper bootstrap cannot create verified local client: %v", err)
	}
	signed, err := client.SignedHello(ctx)
	if err != nil {
		log.Fatalf("Root helper bootstrap local attestation failed: %v", err)
	}
	payload, err := helperprotocol.CanonicalBytes(signed)
	if err != nil {
		log.Fatalf("Root helper bootstrap cannot encode enrollment: %v", err)
	}
	fmt.Println(string(payload))
}

func buildRootHelperConfig(input helperBootstrapConfigInput) (helper.RootConfig, error) {
	available, enabled, unit, pkg, roots := "", "", "", "", []string{}
	switch input.ProxyKind {
	case "nginx":
		unit, pkg, roots = "nginx.service", "nginx", []string{"/etc/nginx"}
		if input.DebianLayout {
			available, enabled = "/etc/nginx/sites-available", "/etc/nginx/sites-enabled"
		} else {
			available = "/etc/nginx/conf.d"
		}
	case "apache":
		pkg = "apache2"
		if input.DebianLayout {
			unit, roots, available, enabled = "apache2.service", []string{"/etc/apache2"}, "/etc/apache2/sites-available", "/etc/apache2/sites-enabled"
		} else {
			unit, roots, available = "httpd.service", []string{"/etc/httpd"}, "/etc/httpd/conf.d"
		}
	default:
		return helper.RootConfig{}, fmt.Errorf("unsupported managed proxy kind")
	}
	systemctl := "/usr/bin/systemctl"
	if _, err := os.Stat(systemctl); err != nil {
		systemctl = "/bin/systemctl"
	}
	config := helper.RootConfig{
		AgentID: input.AgentID, HelperInstanceID: input.HelperInstanceID, ExpectedBuildID: input.BuildID,
		AgentUser: input.AgentUser, AgentUID: input.AgentUID,
		OrchestratorKeyID: input.Authority.KeyID, OrchestratorPublicKeyText: input.Authority.PublicKeyText,
		AttestationKeyID: input.AttestationKeyID, AttestationPrivateKeyFile: "/var/lib/nurproxy-agent/helper/attestation.key",
		StoreDir:      "/var/lib/nurproxy-agent/helper",
		ProxyTarget:   helper.ProxyTargetConfig{Kind: input.ProxyKind, Binary: input.ProxyBinary, Unit: unit, SystemctlBinary: systemctl, ConfigRoots: roots},
		PackageTarget: helper.PackageTargetConfig{Manager: "/usr/bin/apt-get", Package: pkg},
		ManagedApply: &helper.ManagedApplyTargetConfig{
			StagingDir: "/var/lib/nurproxy-agent/helper-staging", AvailableDir: available, EnabledDir: enabled,
			CertificateDir: "/var/lib/nurproxy-agent/certs", CustomPolicyVersion: input.ProxyKind + "-managed-v1", ProxyVersion: input.ProxyVersion,
		},
	}
	if err := config.Validate(); err != nil {
		return helper.RootConfig{}, err
	}
	return config, nil
}

func discoverBootstrapProxy(ctx context.Context, kind string) (string, string, bool, error) {
	candidates := map[string][]string{"nginx": {"nginx"}, "apache": {"apachectl", "apache2ctl", "httpd", "apache2"}}[kind]
	for _, candidate := range candidates {
		binary, err := exec.LookPath(candidate)
		if err != nil {
			continue
		}
		binary, err = filepath.EvalSymlinks(binary)
		if err != nil {
			continue
		}
		args := []string{"-v"}
		output, _ := exec.CommandContext(ctx, binary, args...).CombinedOutput()
		versionText := proxy.ParseVersion(proxy.Kind(kind), string(output))
		if versionText == "" {
			versionText = "unknown"
		}
		debian := (kind == "nginx" && directoryExists("/etc/nginx/sites-available") && directoryExists("/etc/nginx/sites-enabled")) ||
			(kind == "apache" && directoryExists("/etc/apache2/sites-available") && directoryExists("/etc/apache2/sites-enabled"))
		return binary, versionText, debian, nil
	}
	return "", "", false, fmt.Errorf("no trusted %s binary was found", kind)
}

func readBootstrapIdentity(path string, maxBytes int64) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxBytes || info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("identity file is missing or unbounded")
	}
	payload, err := os.ReadFile(path)
	identity := strings.TrimSpace(string(payload))
	if err != nil || identity == "" || strings.ContainsAny(identity, "/\\\x00\r\n\t ") {
		return "", fmt.Errorf("identity file content is invalid")
	}
	return identity, nil
}

func directoryExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func trustedBootstrapFile(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o022 == 0
}

func activateHelperSocket(ctx context.Context) error {
	for _, args := range [][]string{{"reset-failed", "nurproxy-agent-helper.service"}, {"enable", "--now", "nurproxy-agent-helper.socket"}} {
		command := exec.CommandContext(ctx, "/usr/bin/systemctl", args...)
		command.Stdout, command.Stderr = os.Stderr, os.Stderr
		if err := command.Run(); err != nil {
			return err
		}
	}
	return nil
}

func rootHelperCause(err error) error {
	for {
		unwrapped, ok := err.(interface{ Unwrap() error })
		if !ok || unwrapped.Unwrap() == nil {
			return err
		}
		err = unwrapped.Unwrap()
	}
}
