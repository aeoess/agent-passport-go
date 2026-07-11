// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Merkle domain separation (CVE-2012-2459 class) — Day-145 audit, receipt
// format v1.1 -> v1.2.
//
// The previous Bitcoin-style construction duplicated the trailing odd node
// and hashed leaves and internal nodes under the same function, so distinct
// receipt multisets collided to one root: BuildMerkleRoot([a,b,c]) equalled
// BuildMerkleRoot([a,b,c,c]), and a phantom-duplicate inclusion proof could
// masquerade as membership in the honest 3-receipt commitment. These tests
// fail on that construction and pass once leaves hash under a 0x00 tag,
// internal nodes under a 0x01 tag, and odd nodes are promoted unchanged.
//
// This file deliberately exercises only BuildMerkleRoot / GenerateMerkleProof
// / VerifyMerkleProof so it also compiles against the unfixed code for the
// fail-before run. The VerifyMerkleProofAgainstRoot hardening lives in
// merkle_proof_against_root_test.go.

package attribution

import (
	"fmt"
	"strings"
	"testing"
)

var (
	leafA = strings.Repeat("a", 64)
	leafB = strings.Repeat("b", 64)
	leafC = strings.Repeat("c", 64)
)

// TestMerkleDuplicateLeafCollision: a 3-leaf set and its odd-duplicate 4-leaf
// sibling must produce different roots.
func TestMerkleDuplicateLeafCollision(t *testing.T) {
	three := BuildMerkleRoot([]string{leafA, leafB, leafC})
	dup := BuildMerkleRoot([]string{leafA, leafB, leafC, leafC})
	if three == dup {
		t.Fatalf("CVE-2012-2459: distinct multisets fold to one root %s", three)
	}
}

// TestMerkleGenuineProofStillVerifies: an honest inclusion proof for the
// promoted odd leaf (the worst case for the fold) still verifies, and its
// root equals the committed root.
func TestMerkleGenuineProofStillVerifies(t *testing.T) {
	leaves := []string{leafA, leafB, leafC}
	three := BuildMerkleRoot(leaves)
	for _, target := range leaves {
		proof := GenerateMerkleProof(leaves, target)
		if proof == nil {
			t.Fatalf("GenerateMerkleProof returned nil for present leaf %s", target[:8])
		}
		if proof.Root != three {
			t.Fatalf("proof root %s != committed root %s", proof.Root, three)
		}
		if !VerifyMerkleProof(*proof) {
			t.Fatalf("genuine proof for %s failed to verify", target[:8])
		}
	}
}

// TestMerklePhantomDuplicateRootDiffers: a proof built over the forged
// 4-leaf duplicate view is internally consistent against ITS OWN root, but
// that root must not equal the honest 3-leaf commitment, so the phantom
// cannot be replayed against a verifier holding the honest root.
func TestMerklePhantomDuplicateRootDiffers(t *testing.T) {
	three := BuildMerkleRoot([]string{leafA, leafB, leafC})
	phantom := GenerateMerkleProof([]string{leafA, leafB, leafC, leafC}, leafC)
	if phantom == nil {
		t.Fatal("phantom proof unexpectedly nil")
	}
	if !VerifyMerkleProof(*phantom) {
		t.Fatal("phantom proof should be internally consistent against its own root")
	}
	if phantom.Root == three {
		t.Fatalf("phantom-duplicate root equals the honest 3-leaf root %s", three)
	}
}

// TestMerklePinnedCrossLanguageRoots pins known-answer roots shared verbatim
// with the TypeScript reference (audit/day145/sdk-merkle-domain-separation),
// the Python SDK test suite, and fixtures/merkle-root-parity in the
// conformance suite. Leaves are sha256Hex("aps-merkle-parity-<i>"), i
// ascending from 0; the derivation already yields sorted leaves as inputs,
// and BuildMerkleRoot re-sorts regardless.
func TestMerklePinnedCrossLanguageRoots(t *testing.T) {
	leaves := make([]string, 8)
	for i := range leaves {
		leaves[i] = sha256Hex(fmt.Sprintf("aps-merkle-parity-%d", i))
	}
	cases := []struct {
		n    int
		want string
	}{
		{1, "44e90912f4e083b9d12a68a327611fae945976dd062a696dbd1b4c159b2e206d"},
		{2, "bb4dae845225140a964afd1ea33eac2f49db0845d829a1deed974c6576210a9c"},
		{3, "53fc826f785d4c225cde4fcec9e44d3523f9989be4d112b7be065378f54ae436"},
		{5, "1837e308723f0acf6a8e9605a721def4dc95a60a4e57cd6a07c4af80df1c80a7"},
		{8, "fb88356945f6f9b347aec2a7a4d14f788dbba44472fd911e201f6399cb843096"},
	}
	for _, c := range cases {
		got := BuildMerkleRoot(leaves[:c.n])
		if got != c.want {
			t.Fatalf("n=%d: BuildMerkleRoot = %s, want %s (TS pinned)", c.n, got, c.want)
		}
	}
}
