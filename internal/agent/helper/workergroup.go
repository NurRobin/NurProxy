package helper

import (
	"fmt"
	"os/user"
	"strconv"
	"strings"
)

// Main configuration files the worker group is read from. nginx uses the same
// path on Debian and RHEL; Apache differs by layout.
const (
	nginxMainConfigPath        = "/etc/nginx/nginx.conf"
	apacheDebianConfigPath     = "/etc/apache2/apache2.conf"
	apacheDebianEnvvarsPath    = "/etc/apache2/envvars"
	apacheRedHatMainConfigPath = "/etc/httpd/conf/httpd.conf"
)

// resolveProxyWorkerGroup returns the GID the proxy's worker processes run
// with. Those workers open the basic-auth user file on every request, so the
// helper hands that group read access to the file. It fails closed: when the
// group cannot be determined exactly, no auth file is written at all.
//
// Only the main config file itself is parsed (plus Debian's envvars for
// ${APACHE_RUN_GROUP}). Include/IncludeOptional files, conf-enabled/ snippets
// and nginx `include` lines are not followed, so a user or Group set there
// is not seen.
func resolveProxyWorkerGroup(kind, availableDir string, read func(string) ([]byte, error), lookup func(string) (uint32, error)) (uint32, error) {
	var name string
	switch kind {
	case "nginx":
		content, err := read(nginxMainConfigPath)
		if err != nil {
			return 0, fmt.Errorf("read %s: %w", nginxMainConfigPath, err)
		}
		name, err = parseNginxWorkerGroup(string(content))
		if err != nil {
			return 0, fmt.Errorf("%s: %w", nginxMainConfigPath, err)
		}
	case "apache":
		confPath := apacheRedHatMainConfigPath
		if availableDir == "/etc/apache2" || strings.HasPrefix(availableDir, "/etc/apache2/") {
			confPath = apacheDebianConfigPath
		}
		content, err := read(confPath)
		if err != nil {
			return 0, fmt.Errorf("read %s: %w", confPath, err)
		}
		name, err = parseApacheGroupDirective(string(content))
		if err != nil {
			return 0, fmt.Errorf("%s: %w", confPath, err)
		}
		if variable, ok := apacheVariableReference(name); ok {
			if confPath != apacheDebianConfigPath {
				return 0, fmt.Errorf("%s: Group uses ${%s}, which is only resolved from the Debian envvars file", confPath, variable)
			}
			envvars, err := read(apacheDebianEnvvarsPath)
			if err != nil {
				return 0, fmt.Errorf("read %s: %w", apacheDebianEnvvarsPath, err)
			}
			name, err = parseApacheEnvvar(string(envvars), variable)
			if err != nil {
				return 0, fmt.Errorf("%s: %w", apacheDebianEnvvarsPath, err)
			}
		}
		if strings.HasPrefix(name, "#") {
			gid, err := strconv.ParseUint(name[1:], 10, 32)
			if err != nil || gid == 0 || gid >= 1<<32-1 {
				return 0, fmt.Errorf("apache Group %q is not a valid numeric group", name)
			}
			return uint32(gid), nil
		}
	default:
		return 0, fmt.Errorf("no worker group mapping for proxy kind %q", kind)
	}
	if !validGroupName(name) {
		return 0, fmt.Errorf("%s worker group %q is not a plain group name", kind, name)
	}
	gid, err := lookup(name)
	if err != nil {
		return 0, fmt.Errorf("%s worker group %q: %w", kind, name, err)
	}
	return gid, nil
}

// parseNginxWorkerGroup reads the main-context `user` directive. nginx uses the
// group named like the user when the directive names only a user.
func parseNginxWorkerGroup(content string) (string, error) {
	var (
		statement strings.Builder
		depth     int
		quote     rune
		comment   bool
		found     string
	)
	flush := func() error {
		fields := strings.Fields(statement.String())
		statement.Reset()
		if depth != 0 || len(fields) == 0 || fields[0] != "user" {
			return nil
		}
		if found != "" {
			return fmt.Errorf("more than one user directive")
		}
		switch len(fields) {
		case 2:
			found = unquote(fields[1])
		case 3:
			found = unquote(fields[2])
		default:
			return fmt.Errorf("user directive has %d arguments", len(fields)-1)
		}
		return nil
	}
	for _, r := range content {
		switch {
		case comment:
			if r == '\n' {
				comment = false
			}
		case quote != 0:
			statement.WriteRune(r)
			if r == quote {
				quote = 0
			}
		case r == '#':
			comment = true
		case r == '"' || r == '\'':
			quote = r
			statement.WriteRune(r)
		case r == ';':
			if err := flush(); err != nil {
				return "", err
			}
		case r == '{':
			statement.Reset()
			depth++
		case r == '}':
			statement.Reset()
			if depth > 0 {
				depth--
			}
		default:
			statement.WriteRune(r)
		}
	}
	if found == "" {
		return "", fmt.Errorf("no main-context user directive; add one (for example `user www-data;`) so the worker group is explicit")
	}
	return found, nil
}

// parseApacheGroupDirective returns the argument of the server-wide Group
// directive. Apache directive names are case-insensitive.
func parseApacheGroupDirective(content string) (string, error) {
	found := ""
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") || !strings.EqualFold(fields[0], "Group") {
			continue
		}
		if len(fields) != 2 {
			return "", fmt.Errorf("apache Group directive must have exactly one argument")
		}
		value := unquote(fields[1])
		if found != "" && found != value {
			return "", fmt.Errorf("conflicting Group directives %q and %q", found, value)
		}
		found = value
	}
	if found == "" {
		return "", fmt.Errorf("no Group directive")
	}
	return found, nil
}

func apacheVariableReference(value string) (string, bool) {
	if !strings.HasPrefix(value, "${") || !strings.HasSuffix(value, "}") {
		return "", false
	}
	name := value[2 : len(value)-1]
	for _, r := range name {
		if r != '_' && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return "", false
		}
	}
	return name, name != ""
}

// parseApacheEnvvar reads a literal `[export ]NAME=value` assignment from
// Debian's envvars shell fragment. Values that need shell expansion are
// rejected rather than guessed.
func parseApacheEnvvar(content, variable string) (string, error) {
	found := ""
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		name, value, ok := strings.Cut(line, "=")
		if !ok || name != variable {
			continue
		}
		value = unquote(strings.TrimSpace(value))
		if value == "" || strings.ContainsAny(value, "$`\\ \t") {
			return "", fmt.Errorf("%s is not a literal group name", variable)
		}
		found = value
	}
	if found == "" {
		return "", fmt.Errorf("%s is not set", variable)
	}
	return found, nil
}

func unquote(value string) string {
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
		return value[1 : len(value)-1]
	}
	return value
}

func validGroupName(name string) bool {
	if name == "" || len(name) > 32 || name[0] == '-' {
		return false
	}
	for _, r := range name {
		if r != '_' && r != '-' && r != '.' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// lookupGroupID resolves a group name to its GID. The helper is built without
// cgo, so os/user reads /etc/group only; groups served solely by NSS (LDAP,
// SSSD, systemd-userdb) are not found and the lookup fails closed.
func lookupGroupID(name string) (uint32, error) {
	group, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	gid, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("group %q has a non-numeric gid", name)
	}
	return uint32(gid), nil
}
