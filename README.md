# agent-passport-go

Verify-first Go SDK for the Agent Passport System (APS). It verifies APS
protocol artifacts: RFC 8785 JCS canonicalization, content-addressed
`action_ref`, Ed25519 signatures, and delegation-chain monotonic narrowing.

This is a protocol-primitives library, scoped to verification. It does not
issue passports, sign on your behalf, or run a gateway.

**Status:** `v0.1.0-alpha.1`, verify-first. Issuing and signing are deferred.

```
go get github.com/aeoess/agent-passport-go@v0.1.0-alpha.1
```

(The version is explicit because the current tag is a prerelease.)

## Usage

```go
package main

import (
	"fmt"

	"github.com/aeoess/agent-passport-go/actionref"
	"github.com/aeoess/agent-passport-go/jcs"
	"github.com/aeoess/agent-passport-go/verify"
)

func main() {
	// Canonical bytes hash (RFC 8785 JCS), the signed-bytes preimage.
	hash, _ := jcs.CanonicalHash(map[string]any{"b": 2, "a": 1})
	fmt.Println("jcs sha256:", hash)

	// Content-addressed action_ref over the intent fields.
	ref, _ := actionref.ComputeActionRef(
		"did:key:zAgent",       // agentID
		"payment.execute",      // actionType
		"payment:execute",      // scopeRequired
		"2026-06-03T12:00:00Z", // createdAt (normalized to second-precision UTC)
	)
	fmt.Println("action_ref:", ref)

	// Monotonic narrowing: does a granted scope cover a required one?
	fmt.Println("covers:", verify.ScopeCovers("payment:*", "payment:execute"))
}
```

## What it does

- **Canonicalize** JSON to RFC 8785 JCS, byte-identical to the APS reference
  SDK (`src/core/canonical-jcs.ts`). This is the signed-bytes preimage.
- **action_ref**: SHA-256 over the JCS preimage of the §4.1 intent fields
  (`agentId`, `actionType`, `scopeRequired`, second-precision UTC timestamp),
  hex-identical to the TS `computeActionRef`.
- **Verify** Ed25519 signatures over canonical bytes.
- **Verify a delegation chain**: authority can only narrow at each hop. Scope
  subsets only, depth within bounds, no widening, expiry and not-before checks.

## What it does not do

- It does not issue or mint passports or delegations.
- It does not sign artifacts (no private-key custody helpers in the verify core).
- It does not implement gateway enforcement, policy hosting, or any product
  intelligence. Those live elsewhere and are out of scope by design.

## Conformance

Validated against the shared APS conformance fixtures through a Go runner
(`aps-conformance-suite/runners/go`) that consumes the same vectors as the
TypeScript runner and imports this SDK. It passes the same set: 37 of 38
vectors, with one documented skip (a diff-document fixture checked by a
separate test), identical per-category to the TS reference.

## License

Apache-2.0. Copyright 2026 Tymofii Pidlisnyi.
