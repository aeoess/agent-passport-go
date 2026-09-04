// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package verify

import (
	"bytes"

	"filippo.io/edwards25519"
)

// Ed25519 admissibility.
//
// crypto/ed25519 implements the RFC 8032 verification equation and nothing
// more. It accepts a public key or an R that decodes to a small-order point.
// With the Edwards identity as the public key and R = the identity with s = 0,
// the equation [s]B = R + [k]A degenerates to identity = identity, so one
// signature verifies under every message. A signature that does not depend on
// the message proves nothing about the artifact carrying it.
//
// The rule enforced here is the behaviour on which the two strict
// implementations in the APS family were OBSERVED to agree: libsodium
// (agent-passport-python) and ed25519-dalek verify_strict
// (agent-passport-system aps-verifier-core). They were run over a corpus of
// 2562 vectors, including the Wycheproof Ed25519 suite, all eight small-order
// points in every encoding, small-order R under honest keys, small-order A
// under an ordinary full-order R, non-canonical encodings, s >= L, and 2048
// ordinary generated keys, and agreed on every one.
//
// That agreement is about observable accept and reject. It is NOT a claim that
// the two run the same internal checks, and they do not. Established by
// execution against ed25519-dalek 2.2.0: VerifyingKey::from_bytes ACCEPTS a
// non-canonically encoded public key, so verify_strict has no canonical
// encoding test on A at all.
//
// So the two conditions the vectors actually force are: a public key or an R
// whose decoded point has small order is refused, and a scalar s that is not
// reduced modulo the group order is refused. The third condition is already
// enforced by crypto/ed25519, which decodes s with
// edwards25519.Scalar.SetCanonicalBytes; testdata/ed25519-admissibility-v1.json
// pins that so it would be caught if it ever stopped holding.
//
// The canonical-encoding test below goes BEYOND what any behavioural vector can
// force, and it is kept as hygiene rather than because a test pins it. The
// reason it cannot be forced: a non-canonical encoding exists only for
// y < 19, and producing a signature that satisfies the equation under such a
// point of large order would require that point's discrete logarithm. It is
// kept because two byte strings naming one key is a key-equivocation surface,
// and because libsodium refuses them.
//
// LIMIT, worth stating plainly. Admissibility does not make a public key an
// identity. For any honest key A and any 8-torsion point T, A' = A + T is
// canonical, is not of small order, and passes every test here, and a holder
// of A's private key can sign for A' with at most eight hashes of grinding.
// The eight torsion aliases of one key are therefore all admissible and all
// distinct. Anything that must bind to a single principal has to compare the
// key, or resolve it through an allowlist, rather than infer identity from a
// signature verifying.
//
// edwards25519 is the Go cryptography maintainer's published extraction of the
// standard library's own crypto/internal/edwards25519, so this adds no new
// curve implementation to the trust base.

// admissiblePoint reports whether b is the canonical encoding of an
// edwards25519 point that is not of small order. A point has small order
// exactly when multiplying it by the cofactor 8 yields the identity.
func admissiblePoint(b []byte) bool {
	if len(b) != 32 {
		return false
	}
	point, err := new(edwards25519.Point).SetBytes(b)
	if err != nil {
		return false
	}
	// SetBytes accepts a y coordinate that is not reduced modulo p, so two
	// different byte strings can name the same key. Re-encoding and comparing
	// refuses every non-canonical encoding.
	if !bytes.Equal(point.Bytes(), b) {
		return false
	}
	var cleared edwards25519.Point
	cleared.MultByCofactor(point)
	return cleared.Equal(edwards25519.NewIdentityPoint()) == 0
}
