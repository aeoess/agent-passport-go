// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Package cpa is the MINIMAL Context Provenance Attestation (CPA) v0.1
// commitment core, byte/hex-identical to the APS reference SDK
// (src/v2/context-provenance/merkle.ts + cpa.ts). It is NOT a full public
// API: no network, no policy, no analytics, no stateful store. It exists to
// prove a second language reproduces the frozen CPA tree shape over the same
// hand-anchored JCS bytes.
//
// The frozen tree shape (see TREE-SHAPE.md in the SDK):
//
//   - Domain tags (UTF-8 incl. trailing newline, 14 bytes each):
//     LEAF_TAG = "CPA:v0.1:leaf\n", NODE_TAG = "CPA:v0.1:node\n",
//     SIGN_TAG = "CPA:v0.1:sign\n".
//   - leaf_preimage = EXACTLY {byte_len, channel, content_ref, ctx_id}
//     (content + trust_tier EXCLUDED).
//   - leaf_hash = sha256( utf8(LEAF_TAG) || utf8(JCS(leaf_preimage)) ).
//   - node_hash = sha256( utf8(NODE_TAG) || left32 || right32 ) over RAW
//     32-byte digests.
//   - within a partition: sort leaves ascending by ctx_id (code-point order).
//   - odd-node promotion: the final unpaired node at each level is promoted
//     UNCHANGED (never duplicated; closes CVE-2012-2459).
//   - top root: over PRESENT partition roots taken in CHANNEL_ORDER, reduced
//     with node_hash + the same odd-promotion. Single present partition =>
//     root = partition_root.
//   - empty tree (zero leaves): root = hex( sha256( utf8(NODE_TAG) ||
//     utf8("EMPTY") ) ).
//   - cpa_ref = hex( sha256( utf8(SIGN_TAG) || utf8(JCS(signed_cpa)) ) ).
//
// JCS canonicalization and Ed25519 are REUSED from the existing jcs and keys
// packages; only the domain-tagged sha256 layout lives here.
package cpa

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"

	"github.com/aeoess/agent-passport-go/jcs"
)

// Domain tags. The trailing newline is part of the byte value; each tag is
// exactly 14 UTF-8 bytes.
const (
	LeafTag = "CPA:v0.1:leaf\n"
	NodeTag = "CPA:v0.1:node\n"
	SignTag = "CPA:v0.1:sign\n"
)

// emptySentinel is the pre-image content for the zero-leaf top root.
const emptySentinel = "EMPTY"

// CHANNEL_ORDER is the frozen v0.1 channel order. The top tree is built over
// present partition roots taken in this order.
var ChannelOrder = []string{
	"system-config",
	"developer",
	"user-socket",
	"retrieval-store",
	"tool-result",
	"external",
	"memory",
	"quarantine",
}

// LeafPreimage is EXACTLY the four committed fields. content and trust_tier
// are excluded so the root is identical whether or not raw content is later
// disclosed. JCS sorts keys, so field order here is irrelevant to the bytes.
type LeafPreimage struct {
	ByteLen    int64
	Channel    string
	ContentRef string
	CtxID      string
}

// preimageMap renders a LeafPreimage as the generic JSON shape jcs.Canonicalize
// consumes. Integers are passed as int64 so JCS emits them without a decimal
// point (byte_len must canonicalize as "15", not "15.0").
func (p LeafPreimage) preimageMap() map[string]interface{} {
	return map[string]interface{}{
		"byte_len":    p.ByteLen,
		"channel":     p.Channel,
		"content_ref": p.ContentRef,
		"ctx_id":      p.CtxID,
	}
}

// leafHash = sha256( utf8(LEAF_TAG) || utf8(JCS(preimage)) ), raw 32 bytes.
func leafHash(p LeafPreimage) ([]byte, error) {
	canon, err := jcs.Canonicalize(p.preimageMap())
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte(LeafTag))
	h.Write([]byte(canon))
	return h.Sum(nil), nil
}

// nodeHash = sha256( utf8(NODE_TAG) || left32 || right32 ), raw 32 bytes.
func nodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte(NodeTag))
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// reduce folds a list of raw 32-byte digests to a single root using NODE_TAG.
// An odd node at any level is PROMOTED UNCHANGED to the next level (RFC 6962;
// closes CVE-2012-2459); it is never duplicated. A single element returns that
// element. An empty list is an error (callers handle the empty case).
func reduce(level [][]byte) ([]byte, error) {
	if len(level) == 0 {
		return nil, errors.New("cpa: cannot reduce an empty level")
	}
	current := level
	for len(current) > 1 {
		next := make([][]byte, 0, (len(current)+1)/2)
		for i := 0; i < len(current); i += 2 {
			if i+1 < len(current) {
				next = append(next, nodeHash(current[i], current[i+1]))
			} else {
				// Odd node: promote unchanged.
				next = append(next, current[i])
			}
		}
		current = next
	}
	return current[0], nil
}

// sortLeaves returns the leaves sorted ascending by ctx_id (code-point order,
// which for the ASCII ctx_ids used here is plain byte order; Go string < uses
// byte order, identical to JS code-point order for BMP scalar values). A
// duplicate ctx_id within a partition is an error.
func sortLeaves(leaves []LeafPreimage) ([]LeafPreimage, error) {
	out := make([]LeafPreimage, len(leaves))
	copy(out, leaves)
	sort.SliceStable(out, func(i, j int) bool { return out[i].CtxID < out[j].CtxID })
	for i := 1; i < len(out); i++ {
		if out[i].CtxID == out[i-1].CtxID {
			return nil, errors.New("cpa: duplicate ctx_id within partition")
		}
	}
	return out, nil
}

// BuildPartitionRootBytes builds the raw 32-byte partition root for one
// partition's leaves. Single leaf => the leaf digest unchanged. Empty leaf
// list is an error (empty partitions are omitted upstream).
func BuildPartitionRootBytes(leaves []LeafPreimage) ([]byte, error) {
	if len(leaves) == 0 {
		return nil, errors.New("cpa: a present partition must have at least one leaf")
	}
	sorted, err := sortLeaves(leaves)
	if err != nil {
		return nil, err
	}
	digests := make([][]byte, 0, len(sorted))
	for _, l := range sorted {
		d, err := leafHash(l)
		if err != nil {
			return nil, err
		}
		digests = append(digests, d)
	}
	return reduce(digests)
}

// BuildPartitionRoot is the lowercase-hex wrapper around
// BuildPartitionRootBytes.
func BuildPartitionRoot(leaves []LeafPreimage) (string, error) {
	b, err := BuildPartitionRootBytes(leaves)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// BuildTopRootBytes builds the raw 32-byte top root over present partition
// roots, taken in CHANNEL_ORDER by the caller. Zero partitions => the EMPTY
// sentinel sha256( utf8(NODE_TAG) || utf8("EMPTY") ). One partition => that
// partition root.
func BuildTopRootBytes(partitionRootsInChannelOrder [][]byte) ([]byte, error) {
	if len(partitionRootsInChannelOrder) == 0 {
		h := sha256.New()
		h.Write([]byte(NodeTag))
		h.Write([]byte(emptySentinel))
		return h.Sum(nil), nil
	}
	return reduce(partitionRootsInChannelOrder)
}

// BuildTopRoot takes hex partition roots (already in CHANNEL_ORDER) and returns
// the lowercase-hex top root.
func BuildTopRoot(partitionRootsHexInChannelOrder []string) (string, error) {
	raws := make([][]byte, 0, len(partitionRootsHexInChannelOrder))
	for _, h := range partitionRootsHexInChannelOrder {
		b, err := hex.DecodeString(h)
		if err != nil {
			return "", err
		}
		raws = append(raws, b)
	}
	b, err := BuildTopRootBytes(raws)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// EmptyTreeRoot returns the frozen zero-leaf top root as 64-hex.
func EmptyTreeRoot() string {
	b, _ := BuildTopRootBytes(nil)
	return hex.EncodeToString(b)
}

// ComputeCpaRef content-addresses a fully signed CPA object under SIGN_TAG:
//
//	cpa_ref = hex( sha256( utf8(SIGN_TAG) || utf8(JCS(signedCpa)) ) )
//
// signedCpa is the generic-decoded signed CPA (map[string]interface{}),
// INCLUDING its signature field.
func ComputeCpaRef(signedCpa interface{}) (string, error) {
	canon, err := jcs.Canonicalize(signedCpa)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(SignTag))
	h.Write([]byte(canon))
	return hex.EncodeToString(h.Sum(nil)), nil
}
