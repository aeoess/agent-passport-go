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
// implementations in the APS family agree: libsodium (agent-passport-python)
// and ed25519-dalek verify_strict (agent-passport-system aps-verifier-core).
// They were run over a corpus of 2534 vectors, including the Wycheproof
// Ed25519 suite, all eight small-order points in every encoding, small-order R
// under honest keys, non-canonical encodings, s >= L, and 2048 ordinary
// generated keys, and agreed on every one. A public key or an R is admissible
// only when its 32 bytes are the canonical encoding of a point that is not of
// small order.
//
// The third strict condition, a scalar s reduced modulo the group order, is
// already enforced by crypto/ed25519, which decodes s with
// edwards25519.Scalar.SetCanonicalBytes. testdata/ed25519-admissibility-v1.json
// pins that, so the delegation would be caught if it ever stopped holding.
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
