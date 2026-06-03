// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package delegation

import (
	"errors"

	"github.com/aeoess/agent-passport-go/jcs"
	"github.com/aeoess/agent-passport-go/keys"
)

// RevocationRecord is a signed revocation of a delegation, matching the
// reference SDK RevocationRecord. The signature is over the canonical bytes of
// the record with the signature field removed, signed by revokedBy.
//
// This is the revocation SIGNING primitive only. The stateful revocation store
// (cascade, global revoked-set, callbacks) is out of scope by the §5 boundary.
type RevocationRecord struct {
	RevocationID string `json:"revocationId"`
	DelegationID string `json:"delegationId"`
	RevokedBy    string `json:"revokedBy"` // public key hex of the revoker
	RevokedAt    string `json:"revokedAt"`
	Reason       string `json:"reason,omitempty"`
	Signature    string `json:"signature,omitempty"`
}

func (r RevocationRecord) canonicalMap() map[string]interface{} {
	m := map[string]interface{}{
		"revocationId": r.RevocationID,
		"delegationId": r.DelegationID,
		"revokedBy":    r.RevokedBy,
		"revokedAt":    r.RevokedAt,
	}
	if r.Reason != "" {
		m["reason"] = r.Reason
	}
	return m
}

// CreateRevocationOptions are the inputs to CreateRevocation.
type CreateRevocationOptions struct {
	PrivateKey   string // revoker 32-byte seed hex; its public key must equal RevokedBy
	RevocationID string
	DelegationID string
	RevokedBy    string
	RevokedAt    string
	Reason       string
}

// CreateRevocation builds a signed revocation record.
func CreateRevocation(opts CreateRevocationOptions) (RevocationRecord, error) {
	if opts.DelegationID == "" || opts.RevokedBy == "" {
		return RevocationRecord{}, errors.New("delegation: delegationId and revokedBy are required")
	}
	r := RevocationRecord{
		RevocationID: opts.RevocationID,
		DelegationID: opts.DelegationID,
		RevokedBy:    opts.RevokedBy,
		RevokedAt:    opts.RevokedAt,
		Reason:       opts.Reason,
	}
	sig, err := keys.SignArtifact(r.canonicalMap(), "signature", opts.PrivateKey)
	if err != nil {
		return RevocationRecord{}, err
	}
	r.Signature = sig
	return r, nil
}

// VerifyRevocation checks a revocation's signature against its revokedBy key.
func VerifyRevocation(r RevocationRecord) bool {
	if r.Signature == "" {
		return false
	}
	canon, err := jcs.Canonicalize(r.canonicalMap())
	if err != nil {
		return false
	}
	return keys.Verify(canon, r.Signature, r.RevokedBy)
}
