// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package keystore

import "testing"

func TestInMemoryKeyStorageRoundTrip(t *testing.T) {
	var backend KeyStorageBackend = NewInMemoryKeyStorage()

	if rec, err := backend.Retrieve("absent"); err != nil || rec != nil {
		t.Fatalf("Retrieve(absent) = (%v, %v), want (nil, nil)", rec, err)
	}
	if err := backend.Store("agent-1", "aa", "bb"); err != nil {
		t.Fatal(err)
	}
	if err := backend.Store("agent-2", "cc", "dd"); err != nil {
		t.Fatal(err)
	}
	rec, err := backend.Retrieve("agent-1")
	if err != nil || rec == nil || rec.PrivateKey != "aa" || rec.PublicKey != "bb" {
		t.Fatalf("Retrieve(agent-1) = (%+v, %v)", rec, err)
	}
	ids, err := backend.List()
	if err != nil || len(ids) != 2 || ids[0] != "agent-1" || ids[1] != "agent-2" {
		t.Fatalf("List() = (%v, %v)", ids, err)
	}
	deleted, err := backend.Delete("agent-1")
	if err != nil || !deleted {
		t.Fatalf("Delete(agent-1) = (%v, %v)", deleted, err)
	}
	if deleted, _ := backend.Delete("agent-1"); deleted {
		t.Error("second Delete returned true")
	}
	if err := backend.Store("", "x", "y"); err == nil {
		t.Error("Store accepted empty agentID")
	}
}
