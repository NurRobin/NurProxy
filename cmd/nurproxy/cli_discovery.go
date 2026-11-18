package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// --- discovery (#25) -----------------------------------------------------

type cliDiscoverySource struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Name         string `json:"name"`
	Summary      string `json:"summary"`
	SyncInterval int    `json:"sync_interval"`
	LastRunAt    string `json:"last_run_at"`
	LastError    string `json:"last_error"`
	Candidates   int    `json:"candidates"`
	Imported     int    `json:"imported"`
	Missing      int    `json:"missing"`
}

type cliDiscoveryView struct {
	LastRunAt  string `json:"last_run_at"`
	LastError  string `json:"last_error"`
	HasResult  bool   `json:"has_result"`
	Candidates []struct {
		ExternalID       string `json:"external_id"`
		Name             string `json:"name"`
		Kind             string `json:"kind"`
		Status           string `json:"status"`
		SuggestedAddress string `json:"suggested_address"`
		AddressSource    string `json:"address_source"`
		Addresses        []struct {
			IP   string `json:"ip"`
			Kind string `json:"kind"`
		} `json:"addresses"`
		ServerID   string `json:"server_id"`
		ServerName string `json:"server_name"`
	} `json:"candidates"`
	Warnings []string `json:"warnings"`
	Missing  []struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		ExternalID string `json:"external_id"`
	} `json:"missing"`
}

// stringList collects a repeatable flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func cmdDiscovery(args []string) {
	action, rest := shift(args)
	switch action {
	case "types":
		c, _, _ := parseClient("discovery types", rest, "", nil)
		raw, err := c.get("/api/v1/discovery/types")
		if err != nil {
			fatalf("%v", err)
		}
		var types []struct{ ID, Name, Description string }
		_ = json.Unmarshal(raw, &types)
		if c.asJSON {
			c.emit(raw, "")
			return
		}
		rows := make([][]string, len(types))
		for i, t := range types {
			rows[i] = []string{t.ID, t.Name, t.Description}
		}
		printTable([]string{"TYPE", "NAME", "DESCRIPTION"}, rows)

	case "list":
		c, _, _ := parseClient("discovery list", rest, "", nil)
		var sources []cliDiscoverySource
		if err := c.getInto("/api/v1/discovery/sources", &sources); err != nil {
			fatalf("%v", err)
		}
		if c.asJSON {
			c.emit(mustJSON(sources), "")
			return
		}
		rows := make([][]string, len(sources))
		for i, s := range sources {
			sync := "manual"
			if s.SyncInterval > 0 {
				sync = strconv.Itoa(s.SyncInterval) + "s"
			}
			rows[i] = []string{s.ID, s.Type, s.Name, dash(s.Summary), sync, dash(s.LastRunAt),
				fmt.Sprintf("%d/%d", s.Imported, s.Candidates), strconv.Itoa(s.Missing), dash(s.LastError)}
		}
		printTable([]string{"ID", "TYPE", "NAME", "ENDPOINT", "SYNC", "LAST RUN", "IMPORTED", "GONE", "LAST ERROR"}, rows)

	case "add":
		var typ, name, config, configFile string
		var syncInterval int
		var skipTest bool
		c, _, _ := parseClient("discovery add", rest, "", func(fs *flag.FlagSet) {
			fs.StringVar(&typ, "type", "proxmox", "Discovery type")
			fs.StringVar(&name, "name", "", "Display name")
			fs.StringVar(&config, "config", "", `Config as JSON, e.g. {"url":"https://pve:8006","token_id":"user@pve!name","token_secret":"...","verify_tls":true}`)
			fs.StringVar(&configFile, "config-file", "", "Path to a JSON config file (or - for stdin)")
			fs.IntVar(&syncInterval, "sync-interval", 0, "Re-sync every N seconds (0 = only on demand, minimum 300)")
			fs.BoolVar(&skipTest, "skip-test", false, "Save without testing the connection")
		})
		if name == "" {
			fatalf("--name is required")
		}
		cfg := readConfigArg(config, configFile)
		raw, err := c.do(http.MethodPost, "/api/v1/discovery/sources", map[string]any{
			"type": typ, "name": name, "config": json.RawMessage(cfg),
			"sync_interval": syncInterval, "skip_test": skipTest,
		})
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "discovery source created: "+gjson(raw, "id"))

	case "update":
		var name, config, configFile string
		var syncInterval int
		var skipTest bool
		c, fs, id := parseClient("discovery update", rest, "source id", func(fs *flag.FlagSet) {
			fs.StringVar(&name, "name", "", "Display name")
			fs.StringVar(&config, "config", "", "Config keys to change, as JSON (keys not given are kept)")
			fs.StringVar(&configFile, "config-file", "", "Path to a JSON file with config keys to change (or - for stdin)")
			fs.IntVar(&syncInterval, "sync-interval", 0, "Re-sync every N seconds (0 = only on demand)")
			fs.BoolVar(&skipTest, "skip-test", false, "Save without testing the connection")
		})
		body := map[string]any{"skip_test": skipTest}
		putStr(body, "name", name)
		if config != "" || configFile != "" {
			body["config"] = json.RawMessage(readConfigArg(config, configFile))
		}
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "sync-interval" {
				body["sync_interval"] = syncInterval
			}
		})
		raw, err := c.do(http.MethodPut, "/api/v1/discovery/sources/"+id, body)
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "discovery source updated: "+id)

	case "delete":
		c, _, id := parseClient("discovery delete", rest, "source id", nil)
		raw, err := c.del("/api/v1/discovery/sources/" + id)
		if err != nil {
			fatalf("%v", err)
		}
		c.emit(raw, "discovery source deleted: "+id+" (imported servers are kept)")

	case "run", "candidates":
		c, _, id := parseClient("discovery "+action, rest, "source id", nil)
		var raw []byte
		var err error
		if action == "run" {
			raw, err = c.do(http.MethodPost, "/api/v1/discovery/sources/"+id+"/run", nil)
		} else {
			raw, err = c.get("/api/v1/discovery/sources/" + id + "/candidates")
		}
		if err != nil {
			fatalf("%v", err)
		}
		if c.asJSON {
			c.emit(raw, "")
			return
		}
		var v cliDiscoveryView
		if err := json.Unmarshal(raw, &v); err != nil {
			fatalf("decoding response: %v", err)
		}
		printDiscoveryView(v)

	case "import":
		var agentID string
		var ids, addrs stringList
		var all bool
		c, _, sourceID := parseClient("discovery import", rest, "source id", func(fs *flag.FlagSet) {
			fs.StringVar(&agentID, "agent", "", "Agent to import the servers under (required)")
			fs.Var(&ids, "id", "External ID to import (repeatable), e.g. pve/node1/qemu/101")
			fs.Var(&addrs, "address", "Address override as <external-id>=<address> (repeatable)")
			fs.BoolVar(&all, "all", false, "Import every machine not imported yet that has an address")
		})
		if agentID == "" {
			fatalf("--agent is required")
		}
		overrides := map[string]string{}
		for _, a := range addrs {
			k, v, ok := strings.Cut(a, "=")
			if !ok || k == "" || v == "" {
				fatalf("--address must be <external-id>=<address>, got %q", a)
			}
			overrides[k] = v
		}
		if all {
			var v cliDiscoveryView
			if err := c.getInto("/api/v1/discovery/sources/"+sourceID+"/candidates", &v); err != nil {
				fatalf("%v", err)
			}
			for _, cand := range v.Candidates {
				if cand.ServerID == "" && (cand.SuggestedAddress != "" || overrides[cand.ExternalID] != "") {
					ids = append(ids, cand.ExternalID)
				}
			}
		}
		if len(ids) == 0 {
			fatalf("nothing to import: pass --id <external-id> (repeatable) or --all")
		}
		items := make([]map[string]string, 0, len(ids))
		for _, id := range ids {
			it := map[string]string{"external_id": id}
			if a := overrides[id]; a != "" {
				it["address"] = a
			}
			items = append(items, it)
		}
		raw, err := c.do(http.MethodPost, "/api/v1/agents/"+agentID+"/servers/import", map[string]any{
			"source_id": sourceID, "items": items,
		})
		if err != nil {
			fatalf("%v", err)
		}
		if c.asJSON {
			c.emit(raw, "")
			return
		}
		var res struct {
			Created []struct{ ID, Name, Address string }
			Skipped []struct {
				ExternalID string `json:"external_id"`
				Reason     string `json:"reason"`
			}
		}
		_ = json.Unmarshal(raw, &res)
		for _, s := range res.Created {
			fmt.Printf("imported %s (%s) as server %s\n", s.Name, s.Address, s.ID)
		}
		for _, s := range res.Skipped {
			fmt.Printf("skipped %s: %s\n", s.ExternalID, s.Reason)
		}

	default:
		usage("discovery", "types", "list",
			"add --name n [--type proxmox] --config '{...}' [--sync-interval s] [--skip-test]",
			"update <id> [--name n] [--config '{...}'] [--sync-interval s] [--skip-test]",
			"delete <id>", "run <id>", "candidates <id>",
			"import <id> --agent <agent-id> (--id <external-id> ... | --all) [--address <external-id>=<addr> ...]")
	}
}

func printDiscoveryView(v cliDiscoveryView) {
	if v.LastError != "" {
		fmt.Printf("last run failed: %s\n", v.LastError)
	}
	if !v.HasResult {
		fmt.Println("no result yet: run `nurproxy discovery run <id>`")
		return
	}
	rows := make([][]string, len(v.Candidates))
	for i, c := range v.Candidates {
		var others []string
		for _, a := range c.Addresses {
			if a.IP != c.SuggestedAddress {
				others = append(others, a.IP+" ("+a.Kind+")")
			}
		}
		imported := "-"
		if c.ServerID != "" {
			imported = c.ServerName
		}
		rows[i] = []string{c.ExternalID, c.Name, c.Status, dash(c.SuggestedAddress), dash(c.AddressSource), dash(strings.Join(others, ", ")), imported}
	}
	printTable([]string{"EXTERNAL ID", "NAME", "STATUS", "ADDRESS", "FROM", "OTHER ADDRESSES", "IMPORTED AS"}, rows)
	for _, w := range v.Warnings {
		fmt.Printf("warning: %s\n", w)
	}
	for _, m := range v.Missing {
		fmt.Printf("gone: server %s (%s) is no longer reported by the source\n", m.Name, m.ExternalID)
	}
}
