package util

import "testing"

func TestAWGIface(t *testing.T) {
	id := "amneziawg-62-212-70-48-8443"
	a := AWGIface(id)
	if a != AWGIface(id) {
		t.Fatal("AWGIface not deterministic")
	}
	if len(a) > 15 {
		t.Fatalf("iface %q too long (%d > 15 kernel limit)", a, len(a))
	}
	if a[:3] != "wr-" {
		t.Fatalf("iface %q missing wr- prefix", a)
	}
	if AWGIface("x") == AWGIface("y") {
		t.Fatal("AWGIface collided for different ids")
	}
}
