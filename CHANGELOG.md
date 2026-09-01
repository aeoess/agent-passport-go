# Changelog

## v0.6.0

Security release. Cross-language parity reference: TypeScript SDK v5.0.0, Rust SDK v0.2.0. The matching git tag v0.6.0 is created and pushed as a separate step.

### Security
- **`Verify` refuses inadmissible Ed25519 key material.** Small-order points for the public key or for the signature's R, non-canonical encodings, and scalars at or above the group order are rejected before the verification equation runs. `crypto/ed25519` implements the equation and does not reject this material, so a degenerate key and signature pair was accepted for arbitrary messages. All 8 previously released module versions were confirmed by execution to accept it. See the advisory.

### Changed
- **Chain authorization is separated from chain structure.** The effective authority ceiling is carried down the chain rather than evaluated pairwise, so an omitted bound at an intermediate hop no longer loses a bounded ancestor's ceiling. A non-finite spend ceiling is refused rather than silently ignored, an empty typed chain fails closed, and depth bounds chain length with the minter inventing nothing.
- **The authorization token states that revocation was established** rather than leaving the caller to assume it.

### Added
- The Ed25519 admissibility corpus and the cross-language narrowing matrix, both pinned as tests.

## v0.5.0

Cross-language parity reference: TypeScript SDK v4.3.0, Python SDK v2.10.0. The matching git tag v0.5.0 is created and pushed as a separate step.

### Breaking
- **`CanonicalizeScopes` now returns `([]string, error)`.** The exported canonicalizer has to be able to reject, so the signature changed. Code compiled against v0.4.0 will not compile against this release. The alternative was an exported canonicalizer that silently accepts input the specification forbids, which is the defect this release exists to close. Callers that ignore the new error keep the previous behavior for valid input.

### Added
- **receipt-core v1 module.** The Go port lands with the same shapes and the same canonical bytes as the TypeScript SDK.

### Behavior change
- **`scope_required` now rejects duplicate elements after NFC normalization.** Section 4.1 defines `scope_required` as a duplicate-free array. The canonicalizer normalized and sorted but neither deduplicated nor rejected, so `["a","a"]` and `["a"]` produced different action references while the specification admits one form. `CanonicalizeScopes` and `ComputeActionRefScopes` now return `ErrDuplicateScopeRequired`, reason `duplicate_scope_required`, before any identity is computed. Detection runs after NFC, so two spellings that collide only under normalization also reject.

### Fixed
- **`decision_ref` construction now normalizes before hashing.** The decision reference was computed over unnormalized input on one path, so two byte-different encodings of the same decision could produce different references.
- **`valid_until` is now bound in `CoreDecisionOutputV1`.** The field was carried but not covered by the signed material, so a validity window could be altered without invalidating the signature.

### Tests
- The sprint parity vectors path is now read from `APS_SPRINT_VECTORS` instead of a hardcoded local path. The parity test skips with a named reason when the variable is unset.

## v0.4.0

Cross-language parity reference: TypeScript SDK v4.1.0, Python SDK v2.9.0. The matching git tag v0.4.0 is created and pushed as a separate step.

### Fixed / Security
- **JCS canonicalization now rejects lone surrogates (RFC 8785).** The raw-JSON decode path let `encoding/json` substitute U+FFFD for an unpaired surrogate before the scanner ran, so input that is not valid Unicode was silently repaired and signed rather than rejected. All raw-JSON decode sites now detect the unpaired surrogate on the original bytes and reject it before hashing. Typed-value strings on the commerce and attribution signing paths are validated before `json.Marshal`, closing a marshal-before-validate gap (WYSIWYS).

### Behavior change
- Input that was previously accepted is now rejected. A value carrying a lone surrogate on a canonicalization or signing path returns an error instead of producing a signature. Callers that never emit unpaired surrogates see no change.

## v0.2.0-alpha.3

This entry is prepared locally. The matching git tag is not created here; tagging and publishing are a
separate step. Cross-language parity reference: TypeScript SDK v2.9.0.

### Added
- **`RecordSpend(commerceDelegation, amount)`** (`commerce/commerce.go`): the stateless write primitive
  for commerce spend. It returns a new CommerceDelegation with `SpentAmount` incremented, refusing a
  non-finite or negative amount and refusing a spend that would exceed `SpendLimit`. Parity with the
  TypeScript `recordSpend` and the Python `record_spend`.

### Fixed / Security
- **Spend-accumulation no-op closed.** `SpentAmount` was read by the spend check but never written;
  `RecordSpend` is the write half. The signed core delegation's `SpentAmount` is the immutable
  spend-at-issue value (always 0), not a running total.
- **`SubDelegate` now verifies the parent before minting a child** (`delegation/delegation.go`). It
  previously sub-delegated without checking that the parent's own signature verified, so a child could be
  derived from a parent with an invalid signature. It now rejects that case.
- **`CheckSpendGate` now denies a currency mismatch** (`commerce/commerce.go`). The gate compared amounts
  without checking currency, so a purchase in one currency passed a budget denominated in another (the
  SDK does no conversion). A declared currency mismatch is now denied (case-insensitive); an absent
  currency on either side stays unconstrained.
- **`ValidateChain` fails closed on a missing `not_after`** (`verify/verify.go`). An empty `not_after`
  was treated as never-expiring (parse returned the current time), which is fail-open. An empty
  `not_after` is now rejected.
- **`VerifyDelegationChain` narrowing checks** (`verify/verify.go`): the chain check now enforces a
  monotonic depth increment, spend-unit narrowing, and a present child expiry.
- **`TraceBeneficiary` verified now does real crypto** (`attribution/attribution.go`). `Verified` was
  set from lookup success alone (a known beneficiary plus a known delegationId on every hop) and checked
  NO signature, so a creator-supplied or forged chain that happened to match known records reported
  `verified=true`. It now matches the TypeScript reference honest split: `Verified` requires at least one
  hop, an authentic receipt signature against the executor key at the chain tail, and every hop backed by
  some delegation that passes `delegation.VerifyDelegation` (ed25519). A forged, empty, or missing
  signature makes `verified=false`. The reused canonical verifiers (`delegation`, `verify`, `jcs`,
  `keys`) mean this package is no longer standalone on the trace path.

### Public API changes
- **`BeneficiaryTrace` gained a `Resolved bool` (`json:"resolved"`) field** (`attribution/attribution.go`),
  matching the TypeScript reference. `Resolved` is the previous lookup-only semantics, honestly renamed:
  it makes no cryptographic claim. `Verified` is now the field to trust.
- **`TraceDelegation` was enriched** (`attribution/attribution.go`) from the lookup-only shape
  (`delegationId`, `delegatedBy`, `delegatedTo`, `scope`) to carry the full canonical delegation preimage
  (`signature`, `spendLimit`, `spendLimitUnit`, `maxDepth`, `currentDepth`, `expiresAt`, `notBefore`,
  `createdAt`) so a hop can be cryptographically verified, not just resolved. Callers that need
  `Verified=true` must populate at least `Signature` plus the signed preimage fields.

### Behavior changes (operations previously permitted now fail closed)
- A beneficiary trace over a forged, unsigned, or otherwise unauthentic receipt/delegation chain now
  reports `verified=false` instead of `verified=true`; `resolved` still reflects lookup success only.
- A cross-currency commerce spend (purchase currency differs from the budget currency) is now denied
  instead of passing.
- A sub-delegation from a parent whose signature does not verify is now rejected instead of produced.
- A delegation chain with a missing or empty `not_after` is now rejected instead of treated as
  never-expiring.
