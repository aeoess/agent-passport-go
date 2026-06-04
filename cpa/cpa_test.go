// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package cpa

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/aeoess/agent-passport-go/jcs"
	"github.com/aeoess/agent-passport-go/keys"
)

// decodeJSON decodes a JSON document into Go generic types, keeping numbers as
// json.Number so byte_len/leaf_count canonicalize as integers (e.g. "15", not
// "15.0"). This mirrors the jcs package test convention.
func decodeJSON(t *testing.T, raw []byte) interface{} {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return v
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// fixture mirrors the shared cpa-v0.1-vectors.json shape. Inputs that feed back
// into JCS (jcs_kats[].input, cpa_cases[].signed_cpa) are kept as RawMessage so
// they can be re-decoded with UseNumber for byte-faithful canonicalization.
type fixture struct {
	FixedInputs struct {
		Seed string `json:"seed"`
	} `json:"fixed_inputs"`
	JcsKats []struct {
		Name     string          `json:"name"`
		Input    json.RawMessage `json:"input"`
		Expected string          `json:"expected"`
		SHA256   string          `json:"sha256"`
	} `json:"jcs_kats"`
	Ed25519 struct {
		Seed      string `json:"seed"`
		Pubkey    string `json:"pubkey"`
		Msg       string `json:"msg"`
		Signature string `json:"signature"`
	} `json:"ed25519"`
	CpaCases []struct {
		Name           string `json:"name"`
		Mode           string `json:"mode"`
		ProducerPubkey string `json:"producer_pubkey"`
		Partitions     []struct {
			Channel       string `json:"channel"`
			LeafCount     int    `json:"leaf_count"`
			LeafPreimages []struct {
				ByteLen    json.Number `json:"byte_len"`
				Channel    string      `json:"channel"`
				ContentRef string      `json:"content_ref"`
				CtxID      string      `json:"ctx_id"`
			} `json:"leaf_preimages"`
			PartitionRoot string `json:"partition_root"`
		} `json:"partitions"`
		Root      string          `json:"root"`
		CpaRef    string          `json:"cpa_ref"`
		Signature string          `json:"signature"`
		SignedCpa json.RawMessage `json:"signed_cpa"`
	} `json:"cpa_cases"`
}

func loadFixture(t *testing.T) (*fixture, []byte) {
	t.Helper()
	raw, err := os.ReadFile("testdata/cpa-v0.1-vectors.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return &f, raw
}

// TestJcsKats asserts the Go canonicalizer reproduces every HAND-DERIVED JCS
// known-answer vector (the trust anchor) byte-for-byte, plus its sha256.
func TestJcsKats(t *testing.T) {
	f, _ := loadFixture(t)
	if len(f.JcsKats) != 4 {
		t.Fatalf("expected 4 jcs_kats, got %d", len(f.JcsKats))
	}
	for _, k := range f.JcsKats {
		input := decodeJSON(t, k.Input)
		got, err := jcs.Canonicalize(input)
		if err != nil {
			t.Errorf("%s: canonicalize: %v", k.Name, err)
			continue
		}
		if got != k.Expected {
			t.Errorf("%s: canonical mismatch\n got: %s\nwant: %s", k.Name, got, k.Expected)
			continue
		}
		if h := sha256Hex(k.Expected); h != k.SHA256 {
			t.Errorf("%s: sha256(expected) mismatch got=%s want=%s", k.Name, h, k.SHA256)
		}
		if h := sha256Hex(got); h != k.SHA256 {
			t.Errorf("%s: sha256(live canonical) mismatch got=%s want=%s", k.Name, h, k.SHA256)
		}
	}
}

// TestEd25519 asserts the seed derives the pinned pubkey and the pinned
// signature verifies over the pinned message.
func TestEd25519(t *testing.T) {
	f, _ := loadFixture(t)
	e := f.Ed25519
	pub, err := keys.PublicKeyFromPrivate(e.Seed)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate: %v", err)
	}
	if pub != e.Pubkey {
		t.Errorf("pubkey mismatch got=%s want=%s", pub, e.Pubkey)
	}
	if !keys.Verify(e.Msg, e.Signature, e.Pubkey) {
		t.Errorf("ed25519: pinned signature did not verify over pinned message")
	}
	// Negative control: a one-byte message change must not verify.
	if keys.Verify(e.Msg+" ", e.Signature, e.Pubkey) {
		t.Errorf("ed25519: tampered message must not verify")
	}
}

// TestCpaCases recomputes, for every case, each partition_root, the top root,
// and cpa_ref from the fixture and asserts byte/hex-identity. It also
// reconstructs the signing message (signed CPA with signature emptied) and
// asserts the pinned signature verifies under the producer pubkey.
func TestCpaCases(t *testing.T) {
	f, _ := loadFixture(t)
	if len(f.CpaCases) != 4 {
		t.Fatalf("expected 4 cpa_cases, got %d", len(f.CpaCases))
	}

	for _, c := range f.CpaCases {
		// Map channel -> recomputed partition_root hex, recomputed independently
		// from the committed leaf preimages.
		rootByChannel := map[string]string{}
		for _, p := range c.Partitions {
			leaves := make([]LeafPreimage, 0, len(p.LeafPreimages))
			for _, pre := range p.LeafPreimages {
				bl, err := pre.ByteLen.Int64()
				if err != nil {
					t.Fatalf("%s/%s: byte_len not an integer: %v", c.Name, p.Channel, err)
				}
				leaves = append(leaves, LeafPreimage{
					ByteLen:    bl,
					Channel:    pre.Channel,
					ContentRef: pre.ContentRef,
					CtxID:      pre.CtxID,
				})
			}
			if len(leaves) != p.LeafCount {
				t.Errorf("%s/%s: leaf_count=%d but %d preimages", c.Name, p.Channel, p.LeafCount, len(leaves))
			}
			gotRoot, err := BuildPartitionRoot(leaves)
			if err != nil {
				t.Errorf("%s/%s: BuildPartitionRoot: %v", c.Name, p.Channel, err)
				continue
			}
			if gotRoot != p.PartitionRoot {
				t.Errorf("%s/%s: partition_root mismatch\n got: %s\nwant: %s",
					c.Name, p.Channel, gotRoot, p.PartitionRoot)
			}
			rootByChannel[p.Channel] = p.PartitionRoot
		}

		// Top root over present partition roots taken in CHANNEL_ORDER.
		presentRoots := make([]string, 0, len(c.Partitions))
		for _, ch := range ChannelOrder {
			if r, ok := rootByChannel[ch]; ok {
				presentRoots = append(presentRoots, r)
			}
		}
		var gotTop string
		var err error
		if len(presentRoots) == 0 {
			gotTop = EmptyTreeRoot()
		} else {
			gotTop, err = BuildTopRoot(presentRoots)
			if err != nil {
				t.Errorf("%s: BuildTopRoot: %v", c.Name, err)
			}
		}
		if gotTop != c.Root {
			t.Errorf("%s: top root mismatch\n got: %s\nwant: %s", c.Name, gotTop, c.Root)
		}

		// cpa_ref over the fully signed CPA (decode with UseNumber so byte_len /
		// leaf_count canonicalize as integers).
		signed := decodeJSON(t, c.SignedCpa)
		gotRef, err := ComputeCpaRef(signed)
		if err != nil {
			t.Errorf("%s: ComputeCpaRef: %v", c.Name, err)
		}
		if gotRef != c.CpaRef {
			t.Errorf("%s: cpa_ref mismatch\n got: %s\nwant: %s", c.Name, gotRef, c.CpaRef)
		}

		// Reconstruct the signing message: signed CPA with signature set to "".
		signedMap, ok := signed.(map[string]interface{})
		if !ok {
			t.Fatalf("%s: signed_cpa is not an object", c.Name)
		}
		signingObj := make(map[string]interface{}, len(signedMap))
		for k, v := range signedMap {
			signingObj[k] = v
		}
		signingObj["signature"] = ""
		signingMsg, err := jcs.Canonicalize(signingObj)
		if err != nil {
			t.Errorf("%s: canonicalize signing message: %v", c.Name, err)
		}
		if !keys.Verify(signingMsg, c.Signature, c.ProducerPubkey) {
			t.Errorf("%s: pinned signature did not verify over reconstructed signing bytes", c.Name)
		}
		// Negative control: the signed bytes (signature NOT emptied) must NOT
		// verify with the same signature.
		signedBytes, err := jcs.Canonicalize(signed)
		if err != nil {
			t.Errorf("%s: canonicalize signed: %v", c.Name, err)
		}
		if keys.Verify(signedBytes, c.Signature, c.ProducerPubkey) {
			t.Errorf("%s: signature must not verify over the signature-included bytes", c.Name)
		}
	}
}

// TestDomainTags pins the frozen domain-tag byte values (14 bytes each).
func TestDomainTags(t *testing.T) {
	for _, tag := range []string{LeafTag, NodeTag, SignTag} {
		if len(tag) != 14 {
			t.Errorf("domain tag %q is %d bytes, want 14", tag, len(tag))
		}
		if tag[len(tag)-1] != '\n' {
			t.Errorf("domain tag %q must end in a newline", tag)
		}
	}
	if LeafTag != "CPA:v0.1:leaf\n" || NodeTag != "CPA:v0.1:node\n" || SignTag != "CPA:v0.1:sign\n" {
		t.Errorf("domain tag byte values drifted from the frozen shape")
	}
}
