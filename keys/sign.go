// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package keys

import "github.com/aeoess/agent-passport-go/jcs"

// SignArtifact signs an APS artifact the way the reference SDK does: the bytes
// to sign are jcs.Canonicalize(artifact with its signature field removed). It
// returns the lowercase-hex signature. sigField is the name of the signature
// key to strip before canonicalizing (for example "signature").
func SignArtifact(artifact map[string]interface{}, sigField, privateKeyHex string) (string, error) {
	rest := make(map[string]interface{}, len(artifact))
	for k, v := range artifact {
		if k == sigField {
			continue
		}
		rest[k] = v
	}
	canonical, err := jcs.Canonicalize(rest)
	if err != nil {
		return "", err
	}
	return Sign(canonical, privateKeyHex)
}

// SignCanonical signs the canonical bytes of value directly (no field
// stripping). Use this when value is already the exact object to be signed.
func SignCanonical(value interface{}, privateKeyHex string) (string, error) {
	canonical, err := jcs.Canonicalize(value)
	if err != nil {
		return "", err
	}
	return Sign(canonical, privateKeyHex)
}
