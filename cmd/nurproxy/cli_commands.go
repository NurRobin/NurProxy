package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// parseClient builds a FlagSet pre-seeded with the shared auth/output flags,
// lets the caller add command-specific flags via setup, parses args, and
// returns a ready client plus the parsed FlagSet (for fs.Visit). Flags may
// appear before or after positional arguments. positional names the single
// positional argument the command expects (e.g. "domain id"), or is empty
// when it takes none; a missing or unexpected positional is a fatal error, so
// a mistyped invocation never runs with half its flags silently ignored.
func parseClient(name string, args []string, positional string, setup func(*flag.FlagSet)) (*client, *flag.FlagSet, string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	u, k, p, j := registerClientFlags(fs)
	if setup != nil {
		setup(fs)
	}
	arg, err := parseArgs(fs, args, positional)
	if err != nil {
		fatalf("%s: %v", name, err)
	}
	return newClient(*u, *k, *p, *j), fs, arg
}

// parseArgs parses args with interspersed flags and checks that exactly the
// expected positional argument (or none, when positional is empty) remains.
func parseArgs(fs *flag.FlagSet, args []string, positional string) (string, error) {
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return "", err
	}
	if positional == "" {
		if len(pos) > 0 {
			return "", fmt.Errorf("unexpected argument %q", pos[0])
		}
		return "", nil
	}
	if len(pos) == 0 || pos[0] == "" {
		return "", fmt.Errorf("missing %s", positional)
	}
	if len(pos) > 1 {
		return "", fmt.Errorf("unexpected argument %q (only one %s expected)", pos[1], positional)
	}
	return pos[0], nil
}

// parseInterspersed parses flags that may appear anywhere among positional
// arguments. The standard flag package stops at the first non-flag argument,
// so parsing is resumed after each positional. A "--" ends flag parsing and
// everything after it is positional.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		consumed := len(args) - len(rest)
		if consumed > 0 && args[consumed-1] == "--" {
			return append(positionals, rest...), nil
		}
		if len(rest) == 0 {
			return positionals, nil
		}
		positionals = append(positionals, rest[0])
		args = rest[1:]
	}
}

// --- provider ------------------------------------------------------------

func cmdProvider(args []string) {
	action, rest := shift(args)
	switch action {
	case "list":
		c, _, _ := parseClient("provider list", rest, "", nil)
		var provs []models.Provider
		if err := c.getInto("/api/v1/providers", &provs); err != nil {
			fatalf("%v", err)
		}
		if c.asJSON {
			c.emit(mustJSON(provs), "")
			return
		}
		rows := make([][]string, len(provs))
		for i, p := range provs {
			rows[i] = []string{p.ID, p.Type, p.Name, boolStr(p.IsDefault)}
		}
		printTable([]string{"ID", "TYPE", "NAME", "DEFAULT"}, rows)

	case "add":
		var typ, name, config, configFile string
		c, _, _ := parseClient("provider add", rest, "", func(fs *flag.FlagSet) {
			fs.StringVar(&typ, "type", "", "Provider type (e.g. cloudflare)")
			fs.StringVar(&name, "name", "", "Display name")
			fs.StringVar(&config, "config", "", "Provider config as JSON")
			fs.StringVar(&configFile, "config-file", "", "Path to a JSON config file (or - for stdin)")
		})
		if typ == "" || name == "" {
			fatalf("--type and --name are required")
		}
		cfg := readConfigArg(config, configFile)
		raw, err := c.do(http.MethodPost, "/api/v1/providers", map[string]interface{}{
			"type": typ, "name": name, "config": json.RawMessage(cfg),
		})
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "provider created: "+gjson(raw, "id"))

	case "delete":
		c, _, id := parseClient("provider delete", rest, "provider id", nil)
		raw, err := c.del("/api/v1/providers/" + id)
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "provider deleted: "+id)

	case "zones":
		c, _, id := parseClient("provider zones", rest, "provider id", nil)
		var zones []models.Zone
		if err := c.getInto("/api/v1/providers/"+id+"/zones", &zones); err != nil {
			fatalf("%v", err)
		}
		printZones(c, zones)

	default:
		usage("provider", "list", "add", "delete <id>", "zones <id>")
	}
}

// --- zone ----------------------------------------------------------------

func cmdZone(args []string) {
	action, rest := shift(args)
	switch action {
	case "list":
		c, _, _ := parseClient("zone list", rest, "", nil)
		var zones []models.Zone
		if err := c.getInto("/api/v1/zones", &zones); err != nil {
			fatalf("%v", err)
		}
		printZones(c, zones)

	case "add":
		var provider, name, externalID string
		c, _, _ := parseClient("zone add", rest, "", func(fs *flag.FlagSet) {
			fs.StringVar(&provider, "provider", "", "Provider ID")
			fs.StringVar(&name, "name", "", "Zone name (e.g. example.com)")
			fs.StringVar(&externalID, "external-id", "", "Provider-side zone ID (optional)")
		})
		if provider == "" || name == "" {
			fatalf("--provider and --name are required")
		}
		raw, err := c.do(http.MethodPost, "/api/v1/zones", map[string]string{
			"provider_id": provider, "name": name, "external_id": externalID,
		})
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "zone created: "+gjson(raw, "id"))

	case "delete":
		var cascade *bool
		c, _, id := parseClient("zone delete", rest, "zone id", func(fs *flag.FlagSet) {
			cascade = fs.Bool("cascade", false, "also delete dependent domains (torn down through the reconciler; the zone is removed once their teardown finishes)")
		})
		url := "/api/v1/zones/" + id
		if *cascade {
			url += "?cascade=true"
		}
		raw, err := c.del(url)
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "zone deleted: "+id)

	default:
		usage("zone", "list", "add", "delete <id> [--cascade]")
	}
}

// --- agent ---------------------------------------------------------------

func cmdAgent(args []string) {
	action, rest := shift(args)
	switch action {
	case "list":
		c, _, _ := parseClient("agent list", rest, "", nil)
		var agents []models.Agent
		if err := c.getInto("/api/v1/agents", &agents); err != nil {
			fatalf("%v", err)
		}
		if c.asJSON {
			c.emit(mustJSON(agents), "")
			return
		}
		rows := make([][]string, len(agents))
		for i, a := range agents {
			rows[i] = []string{a.ID, a.Name, a.FQDN, string(a.Status), dash(a.Version), boolStr(a.CaddyRunning)}
		}
		printTable([]string{"ID", "NAME", "FQDN", "STATUS", "VERSION", "PROXY"}, rows)

	case "status":
		c, _, id := parseClient("agent status", rest, "agent id", nil)
		raw, err := c.get("/api/v1/agents/" + id + "/status")
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, prettyJSON(raw))

	case "adopt":
		var name, fqdn, zones, dnsMode string
		var ddns int
		c, _, id := parseClient("agent adopt", rest, "agent id", func(fs *flag.FlagSet) {
			fs.StringVar(&name, "name", "", "Friendly name")
			fs.StringVar(&fqdn, "fqdn", "", "Anchor FQDN override")
			fs.StringVar(&zones, "zones", "", "Comma-separated zone IDs")
			fs.StringVar(&dnsMode, "dns-mode", "", "DNS mode")
			fs.IntVar(&ddns, "ddns-interval", 0, "DDNS interval (seconds)")
		})
		body := map[string]interface{}{}
		putStr(body, "name", name)
		putStr(body, "fqdn", fqdn)
		putStr(body, "dns_mode", dnsMode)
		if ddns > 0 {
			body["ddns_interval"] = ddns
		}
		if zones != "" {
			body["zone_ids"] = splitCSV(zones)
		}
		raw, err := c.do(http.MethodPut, "/api/v1/agents/"+id+"/adopt", body)
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "agent adopted: "+id)

	case "update":
		var name, fqdn, zones, dnsMode string
		var ddns int
		c, _, id := parseClient("agent update", rest, "agent id", func(fs *flag.FlagSet) {
			fs.StringVar(&name, "name", "", "Friendly name")
			fs.StringVar(&fqdn, "fqdn", "", "Anchor FQDN")
			fs.StringVar(&zones, "zones", "", "Comma-separated zone IDs")
			fs.StringVar(&dnsMode, "dns-mode", "", "DNS mode")
			fs.IntVar(&ddns, "ddns-interval", 0, "DDNS interval (seconds)")
		})
		body := map[string]interface{}{}
		putStr(body, "name", name)
		putStr(body, "fqdn", fqdn)
		putStr(body, "dns_mode", dnsMode)
		if ddns > 0 {
			body["ddns_interval"] = ddns
		}
		if zones != "" {
			body["zone_ids"] = splitCSV(zones)
		}
		raw, err := c.do(http.MethodPut, "/api/v1/agents/"+id, body)
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "agent updated: "+id)

	case "reject":
		c, _, id := parseClient("agent reject", rest, "agent id", nil)
		raw, err := c.do(http.MethodPut, "/api/v1/agents/"+id+"/reject", nil)
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "agent rejected: "+id)

	case "delete":
		var cascade *bool
		c, _, id := parseClient("agent delete", rest, "agent id", func(fs *flag.FlagSet) {
			cascade = fs.Bool("cascade", false, "also delete dependent domains (torn down through the reconciler; the agent is removed once their teardown finishes)")
		})
		url := "/api/v1/agents/" + id
		if *cascade {
			url += "?cascade=true"
		}
		raw, err := c.del(url)
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "agent deleted: "+id)

	default:
		usage("agent", "list", "status <id>", "adopt <id>", "update <id>", "reject <id>", "delete <id> [--cascade]")
	}
}

// --- server --------------------------------------------------------------

func cmdServer(args []string) {
	action, rest := shift(args)
	switch action {
	case "list":
		c, _, agentID := parseClient("server list", rest, "agent id", nil)
		var servers []models.Server
		if err := c.getInto("/api/v1/agents/"+agentID+"/servers", &servers); err != nil {
			fatalf("%v", err)
		}
		if c.asJSON {
			c.emit(mustJSON(servers), "")
			return
		}
		rows := make([][]string, len(servers))
		for i, s := range servers {
			rows[i] = []string{s.ID, s.Name, s.Address, dash(s.Notes)}
		}
		printTable([]string{"ID", "NAME", "ADDRESS", "NOTES"}, rows)

	case "add":
		var name, address, notes string
		c, _, agentID := parseClient("server add", rest, "agent id", func(fs *flag.FlagSet) {
			fs.StringVar(&name, "name", "", "Server name")
			fs.StringVar(&address, "address", "", "Backend address (host:port from the agent's view)")
			fs.StringVar(&notes, "notes", "", "Notes (optional)")
		})
		if name == "" || address == "" {
			fatalf("--name and --address are required")
		}
		raw, err := c.do(http.MethodPost, "/api/v1/agents/"+agentID+"/servers", map[string]string{
			"name": name, "address": address, "notes": notes,
		})
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "server created: "+gjson(raw, "id"))

	case "update":
		var name, address, notes string
		c, _, id := parseClient("server update", rest, "server id", func(fs *flag.FlagSet) {
			fs.StringVar(&name, "name", "", "Server name")
			fs.StringVar(&address, "address", "", "Backend address")
			fs.StringVar(&notes, "notes", "", "Notes")
		})
		body := map[string]interface{}{}
		putStr(body, "name", name)
		putStr(body, "address", address)
		putStr(body, "notes", notes)
		raw, err := c.do(http.MethodPut, "/api/v1/servers/"+id, body)
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "server updated: "+id)

	case "delete":
		var cascade *bool
		c, _, id := parseClient("server delete", rest, "server id", func(fs *flag.FlagSet) {
			cascade = fs.Bool("cascade", false, "also delete dependent domains (torn down through the reconciler; the server is removed once their teardown finishes)")
		})
		url := "/api/v1/servers/" + id
		if *cascade {
			url += "?cascade=true"
		}
		raw, err := c.del(url)
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "server deleted: "+id)

	default:
		usage("server", "list <agent-id>", "add <agent-id>", "update <id>", "delete <id> [--cascade]")
	}
}

// --- domain --------------------------------------------------------------

func cmdDomain(args []string) {
	action, rest := shift(args)
	switch action {
	case "list":
		var agentID, serverID, status string
		c, _, _ := parseClient("domain list", rest, "", func(fs *flag.FlagSet) {
			fs.StringVar(&agentID, "agent", "", "Filter by agent ID")
			fs.StringVar(&serverID, "server", "", "Filter by server ID")
			fs.StringVar(&status, "status", "", "Filter by status")
		})
		q := url.Values{}
		putQuery(q, "agent_id", agentID)
		putQuery(q, "server_id", serverID)
		putQuery(q, "status", status)
		path := "/api/v1/domains"
		if len(q) > 0 {
			path += "?" + q.Encode()
		}
		var domains []models.Domain
		if err := c.getInto(path, &domains); err != nil {
			fatalf("%v", err)
		}
		if c.asJSON {
			c.emit(mustJSON(domains), "")
			return
		}
		rows := make([][]string, len(domains))
		for i, d := range domains {
			rows[i] = []string{
				strconv.FormatInt(d.ID, 10), d.Subdomain, d.ServerID,
				strconv.Itoa(d.Port), proxiedCell(d.Proxied), string(d.Status),
			}
		}
		printTable([]string{"ID", "SUBDOMAIN", "SERVER", "PORT", "PROXIED", "STATUS"}, rows)

	case "add":
		var subdomain, zone, server, sslMode, proxyFile, proxied string
		var port int
		var ws, forceHTTPS bool
		c, _, _ := parseClient("domain add", rest, "", func(fs *flag.FlagSet) {
			fs.StringVar(&subdomain, "subdomain", "", "Subdomain label")
			fs.StringVar(&zone, "zone", "", "Zone ID")
			fs.StringVar(&server, "server", "", "Server ID")
			fs.IntVar(&port, "port", 0, "Upstream port")
			fs.BoolVar(&ws, "websocket", false, "Enable WebSocket support")
			fs.BoolVar(&forceHTTPS, "force-https", false, "Force HTTPS redirect")
			fs.StringVar(&sslMode, "ssl-mode", "", "SSL mode (auto, ...)")
			fs.StringVar(&proxyFile, "proxy-config-file", "", "Path to a ProxyConfig JSON file (advanced)")
			fs.StringVar(&proxied, "proxied", "", proxiedFlagHelp)
		})
		if subdomain == "" || zone == "" || server == "" || port == 0 {
			fatalf("--subdomain, --zone, --server and --port are required")
		}
		body := map[string]interface{}{
			"subdomain": subdomain, "zone_id": zone, "server_id": server, "port": port,
			"websocket": ws, "force_https": forceHTTPS,
		}
		putStr(body, "ssl_mode", sslMode)
		if proxied != "" {
			body["proxied"] = parseProxiedFlag(proxied)
		}
		if proxyFile != "" {
			body["proxy_config"] = json.RawMessage(readFileArg(proxyFile))
		}
		raw, err := c.do(http.MethodPost, "/api/v1/domains", body)
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "domain created: "+gjson(raw, "id"))

	case "update":
		var subdomain, zone, server, sslMode, proxied string
		var port int
		var ws, forceHTTPS bool
		c, fs, id := parseClient("domain update", rest, "domain id", func(fs *flag.FlagSet) {
			fs.StringVar(&subdomain, "subdomain", "", "Subdomain label")
			fs.StringVar(&zone, "zone", "", "Zone ID")
			fs.StringVar(&server, "server", "", "Server ID")
			fs.IntVar(&port, "port", 0, "Upstream port")
			fs.BoolVar(&ws, "websocket", false, "Enable WebSocket support")
			fs.BoolVar(&forceHTTPS, "force-https", false, "Force HTTPS redirect")
			fs.StringVar(&sslMode, "ssl-mode", "", "SSL mode")
			fs.StringVar(&proxied, "proxied", "", proxiedFlagHelp)
		})
		body := map[string]interface{}{}
		putStr(body, "subdomain", subdomain)
		putStr(body, "zone_id", zone)
		putStr(body, "server_id", server)
		putStr(body, "ssl_mode", sslMode)
		if port > 0 {
			body["port"] = port
		}
		// Bools only sent when the corresponding flag was explicitly set, so we
		// don't silently flip them off on every update.
		fs.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "websocket":
				body["websocket"] = ws
			case "force-https":
				body["force_https"] = forceHTTPS
			case "proxied":
				body["proxied"] = parseProxiedFlag(proxied)
			}
		})
		raw, err := c.do(http.MethodPut, "/api/v1/domains/"+id, body)
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "domain updated: "+id)

	case "delete":
		c, _, id := parseClient("domain delete", rest, "domain id", nil)
		raw, err := c.del("/api/v1/domains/" + id)
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "domain marked for deletion: "+id)

	case "dns-takeover":
		c, _, id := parseClient("domain dns-takeover", rest, "domain id", nil)
		raw, err := c.do(http.MethodPost, "/api/v1/domains/"+id+"/dns/takeover", nil)
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "DNS takeover applied for domain "+id)

	case "set-cert":
		var certFile, keyFile string
		c, _, id := parseClient("domain set-cert", rest, "domain id", func(fs *flag.FlagSet) {
			fs.StringVar(&certFile, "cert", "", "PEM file with the certificate, leaf first, chain optional (e.g. fullchain.pem)")
			fs.StringVar(&keyFile, "key", "", "PEM file with the unencrypted private key (e.g. privkey.pem)")
		})
		if certFile == "" || keyFile == "" {
			fatalf("domain set-cert: --cert and --key are required")
		}
		raw, err := c.do(http.MethodPut, "/api/v1/domains/"+id+"/certificate", map[string]string{
			"cert_pem": string(readFileArg(certFile)),
			"key_pem":  string(readFileArg(keyFile)),
		})
		if err != nil {
			fatalf("%v", err)
		}
		msg := "certificate imported for domain " + id + ", expires " + gjson(raw, "expires_at")
		if warning := gjson(raw, "warning"); warning != "" {
			msg += "\nwarning: " + warning
		}
		c.emit(raw, msg)

	default:
		usage("domain", "list", "add", "update <id>", "delete <id>", "dns-takeover <id>", "set-cert <id> --cert FILE --key FILE")
	}
}

// --- apikey --------------------------------------------------------------

func cmdAPIKey(args []string) {
	action, rest := shift(args)
	switch action {
	case "show":
		c, _, _ := parseClient("apikey show", rest, "", nil)
		raw, err := c.get("/api/v1/api-key")
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, prettyJSON(raw))

	case "create":
		c, _, _ := parseClient("apikey create", rest, "", nil)
		raw, err := c.do(http.MethodPost, "/api/v1/api-key", nil)
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "API key (shown once): "+gjson(raw, "api_key"))

	case "revoke":
		c, _, _ := parseClient("apikey revoke", rest, "", nil)
		raw, err := c.del("/api/v1/api-key")
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "API key revoked")

	default:
		usage("apikey", "show", "create", "revoke")
	}
}

// --- auth ----------------------------------------------------------------

func cmdAuth(args []string) {
	action, rest := shift(args)
	switch action {
	case "setup":
		// Bootstrap: sets the admin password on a fresh install. Needs no
		// credentials, so it bypasses the client's auth flow. The password comes
		// from the shared --password / NP_API_PASSWORD flag.
		c, _, _ := parseClient("auth setup", rest, "", nil)
		if c.password == "" {
			fatalf("--password (or NP_API_PASSWORD) is required")
		}
		raw, err := c.postNoAuth("/api/v1/auth/setup", map[string]string{"password": c.password})
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "admin password configured — now run: nurproxy apikey create --password <pw>")

	case "status":
		c, _, _ := parseClient("auth status", rest, "", nil)
		raw, err := c.postNoAuthGet("/api/v1/auth/status")
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, prettyJSON(raw))

	default:
		usage("auth", "setup", "status")
	}
}

// postNoAuth performs an unauthenticated POST (for the setup bootstrap).
func (c *client) postNoAuth(path string, body interface{}) ([]byte, error) {
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.rawDo(req)
}

// postNoAuthGet performs an unauthenticated GET.
func (c *client) postNoAuthGet(path string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	return c.rawDo(req)
}

func (c *client) rawDo(req *http.Request) ([]byte, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s %s: %s", req.Method, req.URL.Path, apiErrorBytes(resp.StatusCode, data))
	}
	return data, nil
}

// --- shared output helpers ----------------------------------------------

func printZones(c *client, zones []models.Zone) {
	if c.asJSON {
		c.emit(mustJSON(zones), "")
		return
	}
	rows := make([][]string, len(zones))
	for i, z := range zones {
		rows[i] = []string{z.ID, z.Name, z.ProviderID, dash(z.ExternalID)}
	}
	printTable([]string{"ID", "NAME", "PROVIDER", "EXTERNAL_ID"}, rows)
}

// --- tiny utilities ------------------------------------------------------

func shift(args []string) (string, []string) {
	if len(args) == 0 {
		return "", nil
	}
	return args[0], args[1:]
}

func usage(group string, actions ...string) {
	fmt.Fprintf(os.Stderr, "usage: nurproxy %s <action>\n\nactions:\n", group)
	for _, a := range actions {
		fmt.Fprintf(os.Stderr, "  %s %s\n", group, a)
	}
	os.Exit(2)
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func putStr(m map[string]interface{}, key, val string) {
	if val != "" {
		m[key] = val
	}
}

const proxiedFlagHelp = "Cloudflare proxy (orange cloud): on, off, or keep (keep whatever the existing record has; the default)"

// parseProxiedFlag maps --proxied to the API's tri-state value. keep becomes
// JSON null, which the API reads as "not set".
func parseProxiedFlag(v string) interface{} {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "true", "yes":
		return true
	case "off", "false", "no":
		return false
	case "keep", "auto", "unset":
		return nil
	}
	fatalf("--proxied must be on, off or keep (got %q)", v)
	return nil
}

// proxiedCell renders a domain's proxied setting for table output.
func proxiedCell(p *bool) string {
	switch {
	case p == nil:
		return "keep"
	case *p:
		return "on"
	default:
		return "off"
	}
}

func putQuery(q url.Values, key, val string) {
	if val != "" {
		q.Set(key, val)
	}
}

func boolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func mustJSON(v interface{}) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}

func prettyJSON(raw []byte) string {
	var buf bytes.Buffer
	if json.Indent(&buf, raw, "", "  ") == nil {
		return buf.String()
	}
	return string(raw)
}

// gjson pulls a top-level string field out of a JSON object response.
func gjson(raw []byte, key string) string {
	var m map[string]interface{}
	if json.Unmarshal(raw, &m) == nil {
		if v, ok := m[key]; ok {
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}

// readConfigArg returns the inline config or the file contents (- means stdin).
func readConfigArg(inline, file string) []byte {
	if inline != "" {
		return []byte(inline)
	}
	if file != "" {
		return readFileArg(file)
	}
	fatalf("provide --config or --config-file")
	return nil
}

func readFileArg(path string) []byte {
	if path == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fatalf("reading stdin: %v", err)
		}
		return data
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fatalf("reading %s: %v", path, err)
	}
	return data
}
