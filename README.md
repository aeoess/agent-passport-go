# agent-passport-go

Go SDK for the Agent Passport System (APS): protocol primitives for verifiable
agent identity, scoped delegation, signed receipts, and content-addressed
request identity. It both verifies APS artifacts and, as of this release, issues
and signs them, on RFC 8785 JCS canonical bytes and Ed25519.

**Status:** `v0.2.0-alpha.1`, alpha. Issuing and signing are present (Waves 2
and 3). The earlier line was verify-only; that is no longer the case.

```
go get github.com/aeoess/agent-passport-go@v0.2.0-alpha.1
```

(The version is explicit because the current tags are prereleases.)

## Capabilities

Verify-side (no private keys needed, the verify path never compiles in key code):

- **jcs** - RFC 8785 JSON canonicalization, the signed-bytes preimage.
- **actionref** - content-addressed `action_ref` over the intent fields.
- **verify** - Ed25519 signature checks, delegation-chain monotonic narrowing,
  the scope matcher.

Issuing and signing (Waves 2+3):

- **keys / keystore** - the Ed25519 signing core: generate keypairs, sign, derive
  public keys, and an in-memory key-storage backend.
- **passport** - create, sign, countersign, and verify agent passports, plus
  challenge/response.
- **delegation** - create a delegation, sub-delegate with monotonic narrowing,
  and create/verify a signed revocation record.
- **completion** - create and verify completion receipts, link a permit to a
  completion.
- **attribution** - the beneficiary-attribution primitives: hash a receipt, build
  a Merkle root, generate and verify Merkle proofs, trace a beneficiary.
- **values** - values-floor: load, attest, verify an attestation, evaluate
  compliance, resolve an enforcement mode.
- **coordination** - signed-message create/verify pairs (task brief, assign,
  accept, evidence, review, handoff, deliverable, completion).
- **commerce** - the commerce gate predicates, commerce-scope check, sign/verify
  a commerce receipt, create a commerce delegation, extract a delegation chain.
- **intoto** - emit and parse in-toto decision-receipt statements, compute a
  delegation-chain root.

## Cross-implementation parity

Every primitive here is cross-checked byte-for-byte against the TypeScript
reference SDK: the JCS canonical bytes and the Ed25519 signatures are identical.
Because Ed25519 is deterministic, a Go signature over the same canonical bytes
with the same key equals the reference signature exactly. The tests assert this directly. Most signing packages (passport, completion,
attribution, delegation, intoto, values) re-run the TypeScript reference live
when `APS_TS_REPO` points at a checkout; commerce and coordination assert against
pinned reference values, which are the same TS-produced bytes by the determinism
above (see Conformance).

## What it does not do

- No gateway. No enforcement boundary, policy hosting, or any product
  intelligence.
- No analytics, scoring, or report generators. The weight-based attribution
  report generators, reputation scoring, and spend analytics are not here.
- No commerce orchestrator. The gate predicates are present; the multi-gate
  preflight orchestrator is not.
- No stateful stores. Cascade-revocation stores, task stores, and similar
  mutable global state are not here.

Those all live in the gateway, not in this protocol-primitives library. The
verify-only path (`verify`, `jcs`, `actionref`, `types`) stays key-free, so a
verify-only consumer never compiles in private-key code.

## Conformance

Validated against the shared APS conformance fixtures through a Go runner
(`aps-conformance-suite/runners/go`) that consumes the same vectors as the
TypeScript runner and imports this SDK. It passes the same set: 37 of 38
vectors, with one documented skip (a diff-document fixture checked by a separate
test), identical per-category to the TS reference. The runner additionally
re-signs all 10 bilateral-delegation vectors with the signing core to the
recorded reference signatures.

Most cross-impl tests re-run the reference SDK when `APS_TS_REPO` is set to an
`agent-passport-system` checkout, and skip cleanly when it is unset. Commerce and
coordination assert against pinned reference values in both states; their parity
follows from the JCS canonicalization and Ed25519 signing the other packages
re-run live.

```
# run the cross-impl oracle against a local TS checkout
APS_TS_REPO=/path/to/agent-passport-system go test ./...
```

## License

Apache-2.0. Copyright 2026 Tymofii Pidlisnyi. The signed-bytes spec is CC0.
