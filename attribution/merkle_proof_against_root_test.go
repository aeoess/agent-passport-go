// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// VerifyMerkleProofAgainstRoot hardening — Day-145 audit. Kept separate from
// merkle_domain_separation_test.go because that file must also compile
// against the unfixed code for the fail-before run, and this function does
// not exist there.

package attribution

import (
	"testing"
)

// TestVerifyMerkleProofAgainstRootGenuine: a genuine proof verifies against
// the independently held root and fails against a different root.
func TestVerifyMerkleProofAgainstRootGenuine(t *testing.T) {
	leaves := []string{leafA, leafB, leafC}
	three := BuildMerkleRoot(leaves)
	proof := GenerateMerkleProof(leaves, leafC)
	if proof == nil {
		t.Fatal("proof unexpectedly nil")
	}
	if !VerifyMerkleProofAgainstRoot(*proof, three) {
		t.Fatal("genuine proof rejected against the trusted root")
	}
	other := BuildMerkleRoot([]string{leafA, leafB})
	if VerifyMerkleProofAgainstRoot(*proof, other) {
		t.Fatal("proof accepted against an unrelated root")
	}
}

// TestVerifyMerkleProofAgainstRootRejectsPhantom: the phantom-duplicate proof
// generated over [a,b,c,c] must not verify against the honest [a,b,c] root,
// even though it is internally consistent against its own embedded root.
func TestVerifyMerkleProofAgainstRootRejectsPhantom(t *testing.T) {
	three := BuildMerkleRoot([]string{leafA, leafB, leafC})
	phantom := GenerateMerkleProof([]string{leafA, leafB, leafC, leafC}, leafC)
	if phantom == nil {
		t.Fatal("phantom proof unexpectedly nil")
	}
	if VerifyMerkleProofAgainstRoot(*phantom, three) {
		t.Fatal("phantom-duplicate proof accepted against the honest root")
	}
}

// TestVerifyMerkleProofEmptyPath: an empty proof path recomputes to
// sha256(0x00 || leaf), so it is accepted only for the single-leaf tree. The
// old construction accepted any proof whose leaf equalled the claimed root;
// that self-claim must now be rejected.
func TestVerifyMerkleProofEmptyPath(t *testing.T) {
	solo := "only-leaf"
	soloRoot := BuildMerkleRoot([]string{solo})
	soloProof := GenerateMerkleProof([]string{solo}, solo)
	if soloProof == nil {
		t.Fatal("single-leaf proof unexpectedly nil")
	}
	if len(soloProof.Proof) != 0 {
		t.Fatalf("single-leaf proof should have an empty path, got %d nodes", len(soloProof.Proof))
	}
	if !VerifyMerkleProofAgainstRoot(*soloProof, soloRoot) {
		t.Fatal("single-leaf empty proof rejected against its own root")
	}

	// Self-claim forgery: leaf value equals the multi-leaf root, empty path.
	multiRoot := BuildMerkleRoot([]string{leafA, leafB, leafC})
	forged := MerkleProof{ReceiptHash: multiRoot, Root: multiRoot, Proof: nil, Index: 0}
	if VerifyMerkleProof(forged) {
		t.Fatal("empty-path self-claim accepted by VerifyMerkleProof")
	}
	if VerifyMerkleProofAgainstRoot(forged, multiRoot) {
		t.Fatal("empty-path self-claim accepted against the multi-leaf root")
	}

	// An internal node value replayed as a leaf must not verify (leaf/node
	// domain separation).
	internal := hashInternalNode(hashLeafNode(leafA), hashLeafNode(leafB))
	replay := MerkleProof{ReceiptHash: internal, Root: internal, Proof: nil, Index: 0}
	if VerifyMerkleProof(replay) {
		t.Fatal("internal node replayed as a leaf verified")
	}
}
