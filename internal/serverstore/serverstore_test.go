package serverstore

import (
	"path/filepath"
	"testing"
)

func TestCRUDAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "servers.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.List()) != 0 {
		t.Fatal("new store should be empty")
	}
	if err := s.Upsert(Server{ID: "srv-a", Name: "A", Host: "1.2.3.4", Port: 22, User: "root", Installed: []string{"amneziawg"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Upsert(Server{ID: "srv-b", Name: "B", Host: "5.6.7.8"}); err != nil {
		t.Fatal(err)
	}
	// Update existing (no duplicate).
	if err := s.Upsert(Server{ID: "srv-a", Name: "A2", Host: "1.2.3.4", Hardened: true}); err != nil {
		t.Fatal(err)
	}
	if got := len(s.List()); got != 2 {
		t.Fatalf("list size = %d, want 2", got)
	}
	a, ok := s.Get("srv-a")
	if !ok || a.Name != "A2" || !a.Hardened {
		t.Fatalf("get srv-a = %+v ok=%v", a, ok)
	}

	// Patch.
	if err := s.Patch("srv-b", func(sv *Server) { sv.Installed = []string{"vless-reality"} }); err != nil {
		t.Fatal(err)
	}
	if err := s.Patch("missing", func(*Server) {}); err == nil {
		t.Fatal("patch of missing server should error")
	}

	// Reload from disk → persisted.
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	b, ok := s2.Get("srv-b")
	if !ok || len(b.Installed) != 1 || b.Installed[0] != "vless-reality" {
		t.Fatalf("reloaded srv-b = %+v ok=%v", b, ok)
	}

	// Delete.
	if err := s2.Delete("srv-a"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.Get("srv-a"); ok {
		t.Fatal("srv-a should be deleted")
	}
	if err := s2.Delete("srv-a"); err == nil {
		t.Fatal("deleting missing server should error")
	}
}

func TestUpsertRequiresID(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "servers.json"))
	if err := s.Upsert(Server{Host: "1.1.1.1"}); err == nil {
		t.Fatal("upsert without id should error")
	}
}
