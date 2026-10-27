package db

import "testing"

// Queueing a record that is already queued replaces the row's values, so an
// ownership learned later is not lost to the first insert, and a deleted
// marker or old snapshot from the earlier row does not stick.
func TestQueueDomainDNSRecordReplacesQueuedValues(t *testing.T) {
	d := testDB(t)
	first := DomainDNSCleanup{DomainID: 1, FQDN: "app.example.com", RecordID: "rec-1", ZoneID: "zone-1", ProviderID: "prov-1", ZoneExternalID: "ext-1"}
	if err := d.QueueDomainDNSRecord(first); err != nil {
		t.Fatal(err)
	}
	rows, err := d.ListDomainDNSCleanups()
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows = %+v, err=%v", rows, err)
	}
	if err := d.SetDomainDNSCleanupProxied(rows[0].ID, true); err != nil {
		t.Fatal(err)
	}
	if err := d.MarkDomainDNSCleanupDeleted(rows[0].ID); err != nil {
		t.Fatal(err)
	}
	second := first
	second.DomainID, second.FQDN, second.Owned, second.Content = 2, "web.example.com", true, "edge.example.com"
	if err := d.QueueDomainDNSRecord(second); err != nil {
		t.Fatal(err)
	}
	rows, err = d.ListDomainDNSCleanups()
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows = %+v, err=%v", rows, err)
	}
	got := rows[0]
	if got.DomainID != 2 || got.FQDN != "web.example.com" || !got.Owned || got.Content != "edge.example.com" || got.Proxied != nil || got.Deleted {
		t.Fatalf("row not replaced: %+v", got)
	}
	if pending, _, err := d.DomainDNSCleanupCounts(t.Context()); err != nil || pending != 1 {
		t.Fatalf("pending = %d, err=%v", pending, err)
	}
}
