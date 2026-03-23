package main

import "testing"

func TestNormalizeConstraint(t *testing.T) {
	if got := normalizeConstraint(" CQ_AbC "); got != "abc" {
		t.Fatalf("normalizeConstraint() = %q, want %q", got, "abc")
	}
}

func TestMatchesConstraint(t *testing.T) {
	address := "cq_deadbeef"
	if !matchesConstraint(address, "dead", "beef") {
		t.Fatal("expected prefix+suffix match")
	}
	if matchesConstraint(address, "bead", "beef") {
		t.Fatal("unexpected prefix match")
	}
}

func TestDeriveAddressPrefix(t *testing.T) {
	addr := deriveAddress([]byte("public-key"))
	if len(addr) != len(addressPrefix)+40 {
		t.Fatalf("unexpected address length: %d", len(addr))
	}
	if addr[:len(addressPrefix)] != addressPrefix {
		t.Fatalf("address missing prefix: %q", addr)
	}
}
