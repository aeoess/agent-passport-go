// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Package keys is the APS signing core. It generates Ed25519 keypairs, signs
// messages, and derives public keys, byte-compatible with the reference SDK
// src/crypto/keys.ts.
//
// Key-custody rules, non-negotiable:
//   - Private keys are passed in by the caller. The package keeps no global
//     mutable key state.
//   - Private key material is never logged and never placed in an error string.
//   - Signing lives here, isolated from the verify-only path (verify, jcs,
//     actionref, types) so a verify-only consumer never compiles in key code.
//
// Encoding matches the reference SDK: a private key is the 32-byte Ed25519 seed
// as lowercase hex (64 chars); a public key is 32 bytes as lowercase hex. Ed25519
// is deterministic, so a Go signature over identical message bytes with an
// identical seed equals the reference TypeScript signature byte for byte.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/aeoess/agent-passport-go/verify"
)

// KeyPair is a generated Ed25519 keypair, hex-encoded. Field names match the
// reference SDK JSON shape.
type KeyPair struct {
	PrivateKey string `json:"privateKey"` // 32-byte seed, hex
	PublicKey  string `json:"publicKey"`  // 32-byte public key, hex
}

var (
	errBadPriv = errors.New("keys: private key must be 32-byte hex (64 chars)")
	errGen     = errors.New("keys: key generation failed")
)

// GenerateKeyPair returns a fresh Ed25519 keypair. The private key is the
// 32-byte seed, matching the reference SDK.
func GenerateKeyPair() (KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, errGen
	}
	seed := priv.Seed()
	return KeyPair{
		PrivateKey: hex.EncodeToString(seed),
		PublicKey:  hex.EncodeToString(pub),
	}, nil
}

// seedFromHex decodes a 32-byte seed. Errors never include key material.
func seedFromHex(privateKeyHex string) ([]byte, error) {
	seed, err := hex.DecodeString(privateKeyHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errBadPriv
	}
	return seed, nil
}

// Sign returns the lowercase-hex Ed25519 signature over the UTF-8 bytes of
// message, using the 32-byte seed in privateKeyHex.
func Sign(message, privateKeyHex string) (string, error) {
	seed, err := seedFromHex(privateKeyHex)
	if err != nil {
		return "", err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	sig := ed25519.Sign(priv, []byte(message))
	return hex.EncodeToString(sig), nil
}

// PublicKeyFromPrivate derives the hex public key from a private seed hex.
func PublicKeyFromPrivate(privateKeyHex string) (string, error) {
	seed, err := seedFromHex(privateKeyHex)
	if err != nil {
		return "", err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return hex.EncodeToString(pub), nil
}

// Verify reports whether signatureHex is a valid Ed25519 signature over the
// UTF-8 bytes of message under publicKeyHex. It delegates to the key-free
// verify package so the verification logic has a single source.
func Verify(message, signatureHex, publicKeyHex string) bool {
	return verify.VerifyEd25519([]byte(message), signatureHex, publicKeyHex)
}
