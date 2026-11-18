// Package dryrun provides the sandbox stand-in for a discovery source: config
// is still validated by the real implementation, but nothing is contacted and
// Discover returns a fixed, Proxmox-shaped set of machines.
package dryrun

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/NurRobin/NurProxy/internal/discovery"
)

// Wrap returns a discoverer that keeps inner's metadata and static config
// validation but never makes a network call.
func Wrap(inner discovery.Discoverer) discovery.Discoverer {
	return &dry{inner: inner}
}

type dry struct {
	inner discovery.Discoverer
}

func (d *dry) Info() discovery.Info { return d.inner.Info() }

func (d *dry) ValidateConfig(config json.RawMessage) error { return d.inner.ValidateConfig(config) }

func (d *dry) Summary(config json.RawMessage) string { return d.inner.Summary(config) }

func (d *dry) IdentityKey(externalID string) string {
	if k, ok := d.inner.(discovery.IdentityKeyer); ok {
		return k.IdentityKey(externalID)
	}
	return externalID
}

func (d *dry) Test(_ context.Context, config json.RawMessage) error {
	if err := d.inner.ValidateConfig(config); err != nil {
		return err
	}
	slog.Info("dry-run: discovery source test simulated", "type", d.inner.Info().ID, "source", "dryrun")
	return nil
}

func (d *dry) Discover(_ context.Context, config json.RawMessage) (*discovery.Result, error) {
	if err := d.inner.ValidateConfig(config); err != nil {
		return nil, err
	}
	res := Fixture()
	slog.Info("dry-run: discovery simulated", "type", d.inner.Info().ID, "candidates", len(res.Candidates), "source", "dryrun")
	return res, nil
}

// Fixture is the fixed result every dry-run discovery returns: a two-node
// cluster with one node offline, guests with and without a detectable
// address, and one guest whose guest agent reports a docker bridge.
func Fixture() *discovery.Result {
	addr := func(ip string, prefix int, iface string) discovery.Address {
		a, _ := discovery.NewAddress(ip, prefix, iface)
		return a
	}
	cands := []discovery.Candidate{
		{
			ExternalID: "pve/pve1/qemu/101", Name: "web-01", Kind: "qemu", Location: "pve1", Status: "running",
			Addresses: []discovery.Address{
				addr("192.168.10.21", 24, "ens18"), addr("172.17.0.1", 16, "docker0"),
				addr("fe80::be24:11ff:feaa:bb01", 64, "ens18"), addr("127.0.0.1", 8, "lo"),
			},
			AddressSource: "guest-agent", Notes: "Proxmox VM 101 on pve1",
		},
		{
			ExternalID: "pve/pve1/qemu/102", Name: "db-01", Kind: "qemu", Location: "pve1", Status: "running",
			Addresses:     []discovery.Address{addr("192.168.10.22", 24, "net0")},
			AddressSource: "cloud-init", Notes: "Proxmox VM 102 on pve1",
		},
		{
			ExternalID: "pve/pve1/qemu/103", Name: "win-desktop", Kind: "qemu", Location: "pve1", Status: "stopped",
			Addresses: []discovery.Address{}, Notes: "Proxmox VM 103 on pve1",
		},
		{
			ExternalID: "pve/pve1/lxc/200", Name: "jellyfin", Kind: "lxc", Location: "pve1", Status: "running",
			Addresses:     []discovery.Address{addr("192.168.10.30", 24, "eth0"), addr("127.0.0.1", 8, "lo")},
			AddressSource: "lxc-interfaces", Notes: "Proxmox container 200 on pve1",
		},
	}
	for i := range cands {
		cands[i].Addresses = discovery.SortAddresses(cands[i].Addresses)
		cands[i].SuggestedAddress = discovery.Suggest(cands[i].Addresses)
	}
	return &discovery.Result{
		Candidates: cands,
		Warnings:   []string{"node pve2 is offline; its guests were skipped"},
		Incomplete: []string{"pve/pve2/"},
	}
}
