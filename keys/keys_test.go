// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package keys

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/aeoess/agent-passport-go/jcs"
)

// seedFromSeedInput mirrors the conformance runner's deriveKeypairFromSeed:
// the 32-byte Ed25519 seed is sha256(seed_input).
func seedFromSeedInput(seedInput string) string {
	s := sha256.Sum256([]byte(seedInput))
	return hex.EncodeToString(s[:])
}

// TestDeterministicSignatureVsReference proves the Go signing core is byte and
// hex identical to the reference TypeScript implementation. The bilateral
// fixture is a fixed TS key vector: its 32-byte seed is sha256(seed_input), its
// public key is recorded, and each vector carries the TS Ed25519 signature over
// that vector's canonical bytes. We derive the key in Go and re-sign; the Go
// signatures must equal the recorded TS signatures exactly. None of these
// expected values are authored here; they ship with the fixture.
func TestDeterministicSignatureVsReference(t *testing.T) {
	raw, err := os.ReadFile("testdata/bilateral-canonicalize-fixture-v1.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fx struct {
		SeedInput string `json:"seed_input"`
		Keypair   struct {
			PublicKeyHex string `json:"publicKeyHex"`
		} `json:"keypair"`
		Vectors []struct {
			Name   string          `json:"name"`
			Input  json.RawMessage `json:"input"`
			SigHex string          `json:"ed25519_signature_over_canonical_hex"`
			PubHex string          `json:"ed25519_pubkey_hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse: %v", err)
	}

	seedHex := seedFromSeedInput(fx.SeedInput)

	// Public-key derivation matches the reference.
	gotPub, err := PublicKeyFromPrivate(seedHex)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate: %v", err)
	}
	if gotPub != fx.Keypair.PublicKeyHex {
		t.Fatalf("derived pubkey %s != fixture pubkey %s", gotPub, fx.Keypair.PublicKeyHex)
	}

	// Each recorded TS signature must be reproduced exactly by Go Sign over the
	// vector's canonical bytes.
	signed := 0
	for _, v := range fx.Vectors {
		dec := json.NewDecoder(bytes.NewReader(v.Input))
		dec.UseNumber()
		var input interface{}
		if err := dec.Decode(&input); err != nil {
			t.Fatalf("%s: decode: %v", v.Name, err)
		}
		canon, err := jcs.Canonicalize(input)
		if err != nil {
			t.Errorf("%s: canonicalize: %v", v.Name, err)
			continue
		}
		gotSig, err := Sign(canon, seedHex)
		if err != nil {
			t.Errorf("%s: sign: %v", v.Name, err)
			continue
		}
		if gotSig != v.SigHex {
			t.Errorf("%s: Go signature != TS reference\n go: %s\n ts: %s", v.Name, gotSig, v.SigHex)
			continue
		}
		if !Verify(canon, gotSig, v.PubHex) {
			t.Errorf("%s: self-signed signature failed Verify", v.Name)
			continue
		}
		signed++
	}
	t.Logf("deterministic signature equality vs TS reference: %d/%d vectors byte-identical", signed, len(fx.Vectors))
	if signed != len(fx.Vectors) {
		t.Fatalf("only %d/%d signatures matched the reference", signed, len(fx.Vectors))
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if len(kp.PrivateKey) != 64 || len(kp.PublicKey) != 64 {
		t.Fatalf("unexpected key lengths priv=%d pub=%d", len(kp.PrivateKey), len(kp.PublicKey))
	}
	derivedPub, err := PublicKeyFromPrivate(kp.PrivateKey)
	if err != nil || derivedPub != kp.PublicKey {
		t.Fatalf("derived pub %q != generated pub %q (err=%v)", derivedPub, kp.PublicKey, err)
	}
	msg := `{"action":"test","n":1}`
	sig, err := Sign(msg, kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(msg, sig, kp.PublicKey) {
		t.Error("round-trip verify failed")
	}
	if Verify(msg+"x", sig, kp.PublicKey) {
		t.Error("verify accepted a tampered message")
	}
	// Bad key encodings are rejected without leaking key material.
	if _, err := Sign(msg, "nothex"); err == nil {
		t.Error("Sign accepted non-hex key")
	}
	if _, err := Sign(msg, "abcd"); err == nil {
		t.Error("Sign accepted short key")
	}
}

func TestSignArtifactStripsSignatureField(t *testing.T) {
	kp, _ := GenerateKeyPair()
	artifact := map[string]interface{}{
		"delegationId": "del_1",
		"scope":        []interface{}{"data:read"},
		"signature":    "STALE-SHOULD-BE-IGNORED",
	}
	sig, err := SignArtifact(artifact, "signature", kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	// The signature must verify over the canonical bytes of the artifact MINUS
	// the signature field, regardless of what the signature field held.
	rest := map[string]interface{}{"delegationId": "del_1", "scope": []interface{}{"data:read"}}
	canon, _ := jcs.Canonicalize(rest)
	if !Verify(canon, sig, kp.PublicKey) {
		t.Error("SignArtifact signature does not verify over stripped canonical bytes")
	}
}
