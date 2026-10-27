package nginxparse

import (
	"fmt"
	"strings"
)

type ManagedPolicy struct {
	Host     string
	CertPath string
	KeyPath  string
	AuthPath string
}

func ValidateManaged(content string, policy ManagedPolicy) error {
	if strings.TrimSpace(policy.Host) == "" || strings.ContainsAny(policy.Host, " \t\r\n;/") {
		return fmt.Errorf("managed nginx policy has no exact host")
	}
	parsed := Parse(content)
	if !parsed.OK || parsed.Route.Host != policy.Host || parsed.Route.Upstream.Addr == "" || parsed.Route.Upstream.Port <= 0 || parsed.Route.Upstream.Port > 65535 {
		return fmt.Errorf("raw nginx configuration is not a clean single-route mask")
	}
	blocks, leftover := splitTopLevel(content)
	if len(leftover) != 0 || len(blocks) == 0 || len(blocks) > 2 {
		return fmt.Errorf("raw nginx configuration has unsupported top-level scope")
	}
	for _, server := range blocks {
		if server.kind != "server" || server.args != "" {
			return fmt.Errorf("raw nginx configuration has an unsupported block")
		}
		for _, directive := range server.directives {
			switch directive.name {
			case "listen":
				if !managedListen(directive.args) {
					return fmt.Errorf("raw nginx listener is outside ports 80 and 443")
				}
			case "server_name":
				if strings.TrimSpace(directive.args) != policy.Host {
					return fmt.Errorf("raw nginx server name changed the managed host")
				}
			case "ssl_certificate":
				if policy.CertPath == "" || strings.TrimSpace(directive.args) != policy.CertPath {
					return fmt.Errorf("raw nginx certificate path is not helper-owned")
				}
			case "ssl_certificate_key":
				if policy.KeyPath == "" || strings.TrimSpace(directive.args) != policy.KeyPath {
					return fmt.Errorf("raw nginx key path is not helper-owned")
				}
			case "auth_basic_user_file":
				if policy.AuthPath == "" || strings.TrimSpace(directive.args) != policy.AuthPath {
					return fmt.Errorf("raw nginx authentication path is not helper-owned")
				}
			}
		}
		for _, nested := range server.blocks {
			if nested.kind != "location" || nested.args != "/" || len(nested.blocks) != 0 {
				return fmt.Errorf("raw nginx configuration has an unsupported nested scope")
			}
		}
	}
	return nil
}

func managedListen(arguments string) bool {
	fields := strings.Fields(arguments)
	if len(fields) == 0 {
		return false
	}
	switch fields[0] {
	case "80", "[::]:80", "443", "[::]:443":
	default:
		return false
	}
	for _, option := range fields[1:] {
		if option != "ssl" && option != "http2" {
			return false
		}
	}
	return true
}
