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
// returns a ready client plus the parsed FlagSet (for positional args).
func parseClient(name string, args []string, setup func(*flag.FlagSet)) (*client, *flag.FlagSet) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	u, k, p, j := registerClientFlags(fs)
	if setup != nil {
		setup(fs)
	}
	_ = fs.Parse(args)
	return newClient(*u, *k, *p, *j), fs
}

// requireArg returns the first positional argument or exits with usage help.
func requireArg(fs *flag.FlagSet, what string) string {
	v := fs.Arg(0)
	if v == "" {
		fatalf("missing %s", what)
	}
	return v
}

// --- provider ------------------------------------------------------------

func cmdProvider(args []string) {
	action, rest := shift(args)
	switch action {
	case "list":
		c, _ := parseClient("provider list", rest, nil)
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
		c, _ := parseClient("provider add", rest, func(fs *flag.FlagSet) {
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
		c, fs := parseClient("provider delete", rest, nil)
		id := requireArg(fs, "provider id")
		raw, err := c.del("/api/v1/providers/" + id)
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "provider deleted: "+id)

	case "zones":
		c, fs := parseClient("provider zones", rest, nil)
		id := requireArg(fs, "provider id")
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
		c, _ := parseClient("zone list", rest, nil)
		var zones []models.Zone
		if err := c.getInto("/api/v1/zones", &zones); err != nil {
			fatalf("%v", err)
		}
		printZones(c, zones)

	case "add":
		var provider, name, externalID string
		c, _ := parseClient("zone add", rest, func(fs *flag.FlagSet) {
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
		c, fs := parseClient("zone delete", rest, nil)
		id := requireArg(fs, "zone id")
		raw, err := c.del("/api/v1/zones/" + id)
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "zone deleted: "+id)

	default:
		usage("zone", "list", "add", "delete <id>")
	}
}

// --- agent ---------------------------------------------------------------

func cmdAgent(args []string) {
	action, rest := shift(args)
	switch action {
	case "list":
		c, _ := parseClient("agent list", rest, nil)
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
		c, fs := parseClient("agent status", rest, nil)
		id := requireArg(fs, "agent id")
		raw, err := c.get("/api/v1/agents/" + id + "/status")
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, prettyJSON(raw))

	case "adopt":
		var name, fqdn, zones, dnsMode string
		var ddns int
		c, fs := parseClient("agent adopt", rest, func(fs *flag.FlagSet) {
			fs.StringVar(&name, "name", "", "Friendly name")
			fs.StringVar(&fqdn, "fqdn", "", "Anchor FQDN override")
			fs.StringVar(&zones, "zones", "", "Comma-separated zone IDs")
			fs.StringVar(&dnsMode, "dns-mode", "", "DNS mode")
			fs.IntVar(&ddns, "ddns-interval", 0, "DDNS interval (seconds)")
		})
		id := requireArg(fs, "agent id")
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
		c, fs := parseClient("agent update", rest, func(fs *flag.FlagSet) {
			fs.StringVar(&name, "name", "", "Friendly name")
			fs.StringVar(&fqdn, "fqdn", "", "Anchor FQDN")
			fs.StringVar(&zones, "zones", "", "Comma-separated zone IDs")
			fs.StringVar(&dnsMode, "dns-mode", "", "DNS mode")
			fs.IntVar(&ddns, "ddns-interval", 0, "DDNS interval (seconds)")
		})
		id := requireArg(fs, "agent id")
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
		c, fs := parseClient("agent reject", rest, nil)
		id := requireArg(fs, "agent id")
		raw, err := c.do(http.MethodPut, "/api/v1/agents/"+id+"/reject", nil)
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "agent rejected: "+id)

	case "delete":
		c, fs := parseClient("agent delete", rest, nil)
		id := requireArg(fs, "agent id")
		raw, err := c.del("/api/v1/agents/" + id)
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "agent deleted: "+id)

	default:
		usage("agent", "list", "status <id>", "adopt <id>", "update <id>", "reject <id>", "delete <id>")
	}
}

// --- server --------------------------------------------------------------

func cmdServer(args []string) {
	action, rest := shift(args)
	switch action {
	case "list":
		c, fs := parseClient("server list", rest, nil)
		agentID := requireArg(fs, "agent id")
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
		c, fs := parseClient("server add", rest, func(fs *flag.FlagSet) {
			fs.StringVar(&name, "name", "", "Server name")
			fs.StringVar(&address, "address", "", "Backend address (host:port from the agent's view)")
			fs.StringVar(&notes, "notes", "", "Notes (optional)")
		})
		agentID := requireArg(fs, "agent id")
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
		c, fs := parseClient("server update", rest, func(fs *flag.FlagSet) {
			fs.StringVar(&name, "name", "", "Server name")
			fs.StringVar(&address, "address", "", "Backend address")
			fs.StringVar(&notes, "notes", "", "Notes")
		})
		id := requireArg(fs, "server id")
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
		c, fs := parseClient("server delete", rest, nil)
		id := requireArg(fs, "server id")
		raw, err := c.del("/api/v1/servers/" + id)
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "server deleted: "+id)

	default:
		usage("server", "list <agent-id>", "add <agent-id>", "update <id>", "delete <id>")
	}
}

// --- domain --------------------------------------------------------------

func cmdDomain(args []string) {
	action, rest := shift(args)
	switch action {
	case "list":
		var agentID, serverID, status string
		c, _ := parseClient("domain list", rest, func(fs *flag.FlagSet) {
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
				strconv.Itoa(d.Port), string(d.Status),
			}
		}
		printTable([]string{"ID", "SUBDOMAIN", "SERVER", "PORT", "STATUS"}, rows)

	case "add":
		var subdomain, zone, server, sslMode, proxyFile string
		var port int
		var ws, forceHTTPS bool
		c, _ := parseClient("domain add", rest, func(fs *flag.FlagSet) {
			fs.StringVar(&subdomain, "subdomain", "", "Subdomain label")
			fs.StringVar(&zone, "zone", "", "Zone ID")
			fs.StringVar(&server, "server", "", "Server ID")
			fs.IntVar(&port, "port", 0, "Upstream port")
			fs.BoolVar(&ws, "websocket", false, "Enable WebSocket support")
			fs.BoolVar(&forceHTTPS, "force-https", false, "Force HTTPS redirect")
			fs.StringVar(&sslMode, "ssl-mode", "", "SSL mode (auto, ...)")
			fs.StringVar(&proxyFile, "proxy-config-file", "", "Path to a ProxyConfig JSON file (advanced)")
		})
		if subdomain == "" || zone == "" || server == "" || port == 0 {
			fatalf("--subdomain, --zone, --server and --port are required")
		}
		body := map[string]interface{}{
			"subdomain": subdomain, "zone_id": zone, "server_id": server, "port": port,
			"websocket": ws, "force_https": forceHTTPS,
		}
		putStr(body, "ssl_mode", sslMode)
		if proxyFile != "" {
			body["proxy_config"] = json.RawMessage(readFileArg(proxyFile))
		}
		raw, err := c.do(http.MethodPost, "/api/v1/domains", body)
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "domain created: "+gjson(raw, "id"))

	case "update":
		var subdomain, zone, server, sslMode string
		var port int
		var ws, forceHTTPS bool
		c, fs := parseClient("domain update", rest, func(fs *flag.FlagSet) {
			fs.StringVar(&subdomain, "subdomain", "", "Subdomain label")
			fs.StringVar(&zone, "zone", "", "Zone ID")
			fs.StringVar(&server, "server", "", "Server ID")
			fs.IntVar(&port, "port", 0, "Upstream port")
			fs.BoolVar(&ws, "websocket", false, "Enable WebSocket support")
			fs.BoolVar(&forceHTTPS, "force-https", false, "Force HTTPS redirect")
			fs.StringVar(&sslMode, "ssl-mode", "", "SSL mode")
		})
		id := requireArg(fs, "domain id")
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
			}
		})
		raw, err := c.do(http.MethodPut, "/api/v1/domains/"+id, body)
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "domain updated: "+id)

	case "delete":
		c, fs := parseClient("domain delete", rest, nil)
		id := requireArg(fs, "domain id")
		raw, err := c.del("/api/v1/domains/" + id)
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "domain marked for deletion: "+id)

	default:
		usage("domain", "list", "add", "update <id>", "delete <id>")
	}
}

// --- apikey --------------------------------------------------------------

func cmdAPIKey(args []string) {
	action, rest := shift(args)
	switch action {
	case "show":
		c, _ := parseClient("apikey show", rest, nil)
		raw, err := c.get("/api/v1/api-key")
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, prettyJSON(raw))

	case "create":
		c, _ := parseClient("apikey create", rest, nil)
		raw, err := c.do(http.MethodPost, "/api/v1/api-key", nil)
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "API key (shown once): "+gjson(raw, "api_key"))

	case "revoke":
		c, _ := parseClient("apikey revoke", rest, nil)
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
		c, _ := parseClient("auth setup", rest, nil)
		if c.password == "" {
			fatalf("--password (or NP_API_PASSWORD) is required")
		}
		raw, err := c.postNoAuth("/api/v1/auth/setup", map[string]string{"password": c.password})
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "admin password configured — now run: nurproxy apikey create --password <pw>")

	case "status":
		c, _ := parseClient("auth status", rest, nil)
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
