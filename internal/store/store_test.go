package store

import (
	"path/filepath"
	"testing"

	"wakeroute/internal/model"
)

func TestStoreCRUDAndPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	ep := model.Endpoint{ID: "e1", Name: "E1", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "1.1.1.1", Port: 443, Enabled: true}
	if err := s.UpsertEndpoint(ep); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertGroup(model.Group{ID: "g1", Name: "G1", Type: model.GroupURLTest, Members: []string{"e1"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertRule(model.Rule{ID: "r1", Default: true, Outbound: "g1"}); err != nil {
		t.Fatal(err)
	}

	// Upsert replaces by ID rather than duplicating.
	ep.Name = "E1b"
	if err := s.UpsertEndpoint(ep); err != nil {
		t.Fatal(err)
	}
	if n := len(s.Profile().Endpoints); n != 1 {
		t.Fatalf("want 1 endpoint, got %d", n)
	}
	if s.Profile().Endpoints[0].Name != "E1b" {
		t.Fatal("upsert did not replace in place")
	}

	// Give g1 a second member so deleting e1 prunes rather than empties it
	// (deleting the sole member of a group is refused).
	if err := s.UpsertEndpoint(model.Endpoint{ID: "e2", Name: "E2", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "2.2.2.2", Port: 443, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertGroup(model.Group{ID: "g1", Name: "G1", Type: model.GroupURLTest, Members: []string{"e1", "e2"}}); err != nil {
		t.Fatal(err)
	}

	// A rule targeting the endpoint blocks its deletion.
	if err := s.UpsertRule(model.Rule{ID: "r2", Domain: []string{"x.com"}, Outbound: "e1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteEndpoint("e1"); err == nil {
		t.Fatal("expected deletion to be blocked by rule r2")
	}

	// Remove the rule, then deletion succeeds and prunes the group member.
	if err := s.DeleteRule("r2"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteEndpoint("e1"); err != nil {
		t.Fatal(err)
	}
	if got := s.Profile().Groups[0].Members; len(got) != 1 || got[0] != "e2" {
		t.Fatalf("group member e1 not pruned (e2 should remain): %v", got)
	}

	// Reopen from disk: state persisted.
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.Profile().Endpoints) != 1 || len(s2.Profile().Groups) != 1 {
		t.Fatalf("persistence mismatch: %d endpoints, %d groups", len(s2.Profile().Endpoints), len(s2.Profile().Groups))
	}
}
