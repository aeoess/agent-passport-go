# agent-passport-go

Verify-first Go SDK for the Agent Passport System (APS). It verifies APS
protocol artifacts: RFC 8785 JCS canonicalization, content-addressed
`action_ref`, Ed25519 signatures, and delegation-chain monotonic narrowing.

This is a protocol-primitives library. It is scoped to verification. It does
not issue passports, sign on your behalf, or run a gateway.

```
go get github.com/aeoess/agent-passport-go
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

Validated against the shared APS conformance fixtures
(`aps-conformance-suite/fixtures`) through a Go runner that consumes the same
vectors as the TypeScript runner. See the conformance report for pass counts.

## License

Apache-2.0. Copyright 2024-2026 Tymofii Pidlisnyi. The signed-bytes spec is CC0.
