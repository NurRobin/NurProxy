package proxmox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NurRobin/NurProxy/internal/discovery"
)

const (
	// TypeID is the registered discovery type.
	TypeID = "proxmox"

	requestTimeout = 15 * time.Second
	// maxParallel bounds the per-guest requests in flight against one cluster.
	maxParallel = 6
)

// Address sources reported in Candidate.AddressSource.
const (
	SourceGuestAgent    = "guest-agent"
	SourceCloudInit     = "cloud-init"
	SourceLXCInterfaces = "lxc-interfaces"
	SourceLXCConfig     = "lxc-config"
)

func init() {
	discovery.Register(&Discoverer{})
}

// Discoverer implements discovery.Discoverer for Proxmox VE.
type Discoverer struct{}

// Info describes the type.
func (*Discoverer) Info() discovery.Info {
	return discovery.Info{
		ID:           TypeID,
		Name:         "Proxmox VE",
		Description:  "QEMU VMs and LXC containers from a Proxmox VE node or cluster, read with an API token",
		SecretFields: []string{"token_secret"},
		// The token secret goes to url and is protected by the TLS settings,
		// and it only belongs to token_id.
		SecretBoundFields: []string{"url", "token_id", "verify_tls", "ca_pem", "fingerprint"},
	}
}

// ValidateConfig checks the config without contacting the cluster.
func (*Discoverer) ValidateConfig(raw json.RawMessage) error {
	_, err := parseConfig(raw)
	return err
}

// Summary shows the endpoint and token ID, never the secret.
func (*Discoverer) Summary(raw json.RawMessage) string {
	var c Config
	if json.Unmarshal(raw, &c) != nil {
		return ""
	}
	endpoint := c.URL
	if u, err := c.baseURL(); err == nil {
		endpoint = u.String()
	}
	if c.TokenID == "" {
		return endpoint
	}
	return endpoint + " as " + c.TokenID
}

// IdentityKey drops the node from "pve/<node>/<kind>/<vmid>": a VMID is unique
// within a cluster, so a guest migrated to another node is the same guest.
func (*Discoverer) IdentityKey(externalID string) string {
	parts := strings.Split(externalID, "/")
	if len(parts) == 4 && parts[0] == "pve" {
		return "pve/" + parts[2] + "/" + parts[3]
	}
	return externalID
}

// Test reads /version, which any valid token may do.
func (*Discoverer) Test(ctx context.Context, raw json.RawMessage) error {
	cfg, err := parseConfig(raw)
	if err != nil {
		return err
	}
	c, err := newClient(cfg)
	if err != nil {
		return err
	}
	var v struct {
		Version string `json:"version"`
	}
	if err := c.get(ctx, "version", &v); err != nil {
		var ae *apiError
		if errors.As(err, &ae) && ae.Status == 401 {
			return errors.New("proxmox rejected the API token (HTTP 401): check token_id and token_secret")
		}
		return err
	}
	// Listing nodes needs Sys.Audit; without it discovery would find nothing.
	var nodes []node
	if err := c.get(ctx, "nodes", &nodes); err != nil {
		return fmt.Errorf("token works, but listing nodes failed: %w", err)
	}
	if len(nodes) == 0 {
		return errors.New("token works, but it sees no nodes: grant it Sys.Audit and VM.Audit (e.g. the PVEAuditor role on /)")
	}
	return nil
}

type node struct {
	Node   string `json:"node"`
	Status string `json:"status"`
}

type guest struct {
	VMID     flexInt `json:"vmid"`
	Name     string  `json:"name"`
	Status   string  `json:"status"`
	Template flexInt `json:"template"`
}

// Discover walks every node and lists its QEMU VMs and LXC containers.
func (*Discoverer) Discover(ctx context.Context, raw json.RawMessage) (*discovery.Result, error) {
	cfg, err := parseConfig(raw)
	if err != nil {
		return nil, err
	}
	c, err := newClient(cfg)
	if err != nil {
		return nil, err
	}
	var nodes []node
	if err := c.get(ctx, "nodes", &nodes); err != nil {
		return nil, err
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Node < nodes[j].Node })

	res := &discovery.Result{Candidates: []discovery.Candidate{}}
	type job struct {
		node  string
		kind  string
		guest guest
	}
	var jobs []job
	for _, n := range nodes {
		if n.Node == "" {
			continue
		}
		prefix := "pve/" + n.Node + "/"
		if n.Status != "" && n.Status != "online" {
			res.Warnings = append(res.Warnings, fmt.Sprintf("node %s is %s; its guests were skipped", n.Node, n.Status))
			res.Incomplete = append(res.Incomplete, prefix)
			continue
		}
		for _, kind := range []string{"qemu", "lxc"} {
			var guests []guest
			if err := c.get(ctx, "nodes/"+url.PathEscape(n.Node)+"/"+kind, &guests); err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				res.Warnings = append(res.Warnings, fmt.Sprintf("node %s: listing %s guests failed: %v", n.Node, kind, err))
				res.Incomplete = append(res.Incomplete, prefix+kind+"/")
				continue
			}
			for _, g := range guests {
				if g.Template == 1 || g.VMID <= 0 {
					continue
				}
				jobs = append(jobs, job{node: n.Node, kind: kind, guest: g})
			}
		}
	}

	cands := make([]discovery.Candidate, len(jobs))
	warns := make([]string, len(jobs))
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			cands[i], warns[i] = describe(ctx, c, j.node, j.kind, j.guest)
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	res.Candidates = cands
	for _, w := range warns {
		if w != "" {
			res.Warnings = append(res.Warnings, w)
		}
	}
	return res, nil
}

// describe builds the candidate for one guest. Address detection failures
// leave the addresses empty; they never fail the run. The returned warning is
// for failures other than the expected "no guest agent".
func describe(ctx context.Context, c *client, nodeName, kind string, g guest) (discovery.Candidate, string) {
	vmid := strconv.Itoa(int(g.VMID))
	cand := discovery.Candidate{
		ExternalID: "pve/" + nodeName + "/" + kind + "/" + vmid,
		Name:       strings.TrimSpace(g.Name),
		Kind:       kind,
		Location:   nodeName,
		Status:     g.Status,
	}
	label := "VM"
	if kind == "lxc" {
		label = "container"
	}
	if cand.Name == "" {
		cand.Name = kind + "-" + vmid
	}
	cand.Notes = fmt.Sprintf("Proxmox %s %s on %s", label, vmid, nodeName)

	base := "nodes/" + url.PathEscape(nodeName) + "/" + kind + "/" + vmid
	var addrs []discovery.Address
	var warn string
	if kind == "qemu" {
		if g.Status == "running" {
			a, err := guestAgentAddresses(ctx, c, base)
			if err != nil && !isNoGuestAgent(err) {
				warn = fmt.Sprintf("VM %s (%s): guest agent query failed: %v", vmid, cand.Name, err)
			}
			if len(a) > 0 {
				addrs, cand.AddressSource = a, SourceGuestAgent
			}
		}
		if discovery.Suggest(addrs) == "" {
			if a, err := cloudInitAddresses(ctx, c, base); err == nil && len(a) > 0 {
				addrs = append(addrs, a...)
				if cand.AddressSource == "" || discovery.Suggest(a) != "" {
					cand.AddressSource = SourceCloudInit
				}
			} else if err != nil && warn == "" {
				warn = fmt.Sprintf("VM %s (%s): reading config failed: %v", vmid, cand.Name, err)
			}
		}
	} else {
		if g.Status == "running" {
			a, err := lxcInterfaceAddresses(ctx, c, base)
			if err != nil {
				warn = fmt.Sprintf("container %s (%s): reading interfaces failed: %v", vmid, cand.Name, err)
			}
			if len(a) > 0 {
				addrs, cand.AddressSource = a, SourceLXCInterfaces
			}
		}
		if discovery.Suggest(addrs) == "" {
			if a, err := lxcConfigAddresses(ctx, c, base); err == nil && len(a) > 0 {
				addrs = append(addrs, a...)
				if cand.AddressSource == "" || discovery.Suggest(a) != "" {
					cand.AddressSource = SourceLXCConfig
				}
			} else if err != nil && warn == "" {
				warn = fmt.Sprintf("container %s (%s): reading config failed: %v", vmid, cand.Name, err)
			}
		}
	}
	cand.Addresses = discovery.SortAddresses(addrs)
	cand.SuggestedAddress = discovery.Suggest(cand.Addresses)
	return cand, warn
}

// isNoGuestAgent reports the PVE answers for a VM whose guest agent is not
// installed, not enabled, or not running yet. They are expected, not errors.
func isNoGuestAgent(err error) bool {
	var ae *apiError
	if !errors.As(err, &ae) {
		return false
	}
	m := strings.ToLower(ae.Message)
	return strings.Contains(m, "guest agent") || strings.Contains(m, "qga") || (ae.Status == 500 && m == "")
}

// guestAgentAddresses asks qemu-guest-agent for the guest's interfaces. The
// reply nests the agent's answer: {"data":{"result":[...]}}.
func guestAgentAddresses(ctx context.Context, c *client, base string) ([]discovery.Address, error) {
	var reply struct {
		Result []struct {
			Name        string `json:"name"`
			IPAddresses []struct {
				IPAddress string  `json:"ip-address"`
				Type      string  `json:"ip-address-type"`
				Prefix    flexInt `json:"prefix"`
			} `json:"ip-addresses"`
		} `json:"result"`
	}
	if err := c.get(ctx, base+"/agent/network-get-interfaces", &reply); err != nil {
		return nil, err
	}
	var out []discovery.Address
	for _, iface := range reply.Result {
		for _, ip := range iface.IPAddresses {
			if a, ok := discovery.NewAddress(ip.IPAddress, int(ip.Prefix), iface.Name); ok {
				out = append(out, a)
			}
		}
	}
	return out, nil
}

// cloudInitAddresses reads the static addresses from ipconfig0..N.
func cloudInitAddresses(ctx context.Context, c *client, base string) ([]discovery.Address, error) {
	var conf map[string]any
	if err := c.get(ctx, base+"/config", &conf); err != nil {
		return nil, err
	}
	var out []discovery.Address
	for _, key := range sortedKeys(conf, "ipconfig") {
		s, _ := conf[key].(string)
		iface := "net" + strings.TrimPrefix(key, "ipconfig")
		out = append(out, staticAddresses(s, iface)...)
	}
	return out, nil
}

// lxcInterfaceAddresses reads the live interfaces of a running container.
// Older PVE releases report "inet"/"inet6" in CIDR form; newer ones add an
// "ip-addresses" list. Both are read.
func lxcInterfaceAddresses(ctx context.Context, c *client, base string) ([]discovery.Address, error) {
	var ifaces []struct {
		Name        string `json:"name"`
		Inet        string `json:"inet"`
		Inet6       string `json:"inet6"`
		IPAddresses []struct {
			IPAddress string  `json:"ip-address"`
			Prefix    flexInt `json:"prefix"`
		} `json:"ip-addresses"`
	}
	if err := c.get(ctx, base+"/interfaces", &ifaces); err != nil {
		return nil, err
	}
	var out []discovery.Address
	for _, iface := range ifaces {
		for _, cidr := range []string{iface.Inet, iface.Inet6} {
			if a, ok := discovery.ParseCIDRAddress(cidr, iface.Name); ok {
				out = append(out, a)
			}
		}
		for _, ip := range iface.IPAddresses {
			if a, ok := discovery.NewAddress(ip.IPAddress, int(ip.Prefix), iface.Name); ok {
				out = append(out, a)
			}
		}
	}
	return out, nil
}

// lxcConfigAddresses reads static addresses from net0..N
// ("name=eth0,bridge=vmbr0,ip=192.168.1.20/24,gw=...").
func lxcConfigAddresses(ctx context.Context, c *client, base string) ([]discovery.Address, error) {
	var conf map[string]any
	if err := c.get(ctx, base+"/config", &conf); err != nil {
		return nil, err
	}
	var out []discovery.Address
	for _, key := range sortedKeys(conf, "net") {
		s, _ := conf[key].(string)
		iface := key
		if name := optionValue(s, "name"); name != "" {
			iface = name
		}
		out = append(out, staticAddresses(s, iface)...)
	}
	return out, nil
}

// staticAddresses extracts ip= and ip6= from a PVE property string, skipping
// dhcp/auto/manual.
func staticAddresses(prop, iface string) []discovery.Address {
	var out []discovery.Address
	for _, key := range []string{"ip", "ip6"} {
		if a, ok := discovery.ParseCIDRAddress(optionValue(prop, key), iface); ok {
			out = append(out, a)
		}
	}
	return out
}

// optionValue returns key's value in a "k1=v1,k2=v2" property string.
func optionValue(prop, key string) string {
	for _, part := range strings.Split(prop, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && k == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// sortedKeys returns the keys "<prefix><n>" of conf in numeric order.
func sortedKeys(conf map[string]any, prefix string) []string {
	type kv struct {
		key string
		n   int
	}
	var keys []kv
	for k := range conf {
		rest, ok := strings.CutPrefix(k, prefix)
		if !ok {
			continue
		}
		n, err := strconv.Atoi(rest)
		if err != nil {
			continue
		}
		keys = append(keys, kv{k, n})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].n < keys[j].n })
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = k.key
	}
	return out
}
