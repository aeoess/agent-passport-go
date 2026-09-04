# Changelog

## v0.7.0 (2026-09-04)

Security release. The full cross-SDK account, including the affected version
ranges and the severity assessment, is in the security advisory for this
release. [The verification boundary](https://github.com/aeoess/agent-passport-go/blob/main/docs/verification-boundary.md)
draws the authority-against-integrity line, names the surface this release
classified, and records that the other exported verification surfaces here were
not individually classified.

Several exported verification functions returned a successful verification
result (`valid: true` or an equivalent) without establishing all of the trust
and temporal conditions the result implied. In the paths affected here, a
passport verified with no caller-supplied trusted issuer, so the only key
behind the result was the one the artifact carried, or an unreadable timestamp
compared as neither expired nor stale. A relying party that treated those
results as authorization could accept an artifact an attacker produced with
keys the attacker controls.

This release changes what the affected functions establish. Passport
verification establishes issuer authority only from a caller-supplied
trusted-issuer list, and a self-signed passport is accepted only under an
explicit opt-in that marks the result integrity-only. A timestamp the verifier
cannot read fails closed and is reported separately from a timestamp that was
read and found to have passed, and an unreadable caller-supplied clock is
reported separately from an unreadable artifact timestamp.

### Affected surfaces

One row per exported surface and defect class; a surface with two defect classes
appears twice. Copied from the security advisory for this release.

| package | exported name | module path | defect class | consumer change |
|---|---|---|---|---|
| go | `VerifyPassport` | github.com/aeoess/agent-passport-go/passport (passport/passport.go) | invalid time fails open | Valid flips from true to false for artifacts previously accepted. The signature change is described under authority false accept. Go errors are plain strings appended to the existing VerificationResult.Errors slice, so no public type gained a member, nothing is non_exhaustive-shaped, and no downstream code fails to compile. The break is that Valid flips from true to false for artifacts that were accepted, and any consumer that matches on error text must learn three new prefixes: 'Unreadable verifier clock', 'Unreadable expiresAt', 'Unreadable notBefore'. A conforming producer is unaffected; an explicit-offset past timestamp is still 'Passport expired at', |
| go | `VerifyChallenge` | github.com/aeoess/agent-passport-go/passport (passport/challenge.go) | invalid time fails open | behavioural only: returns false when the challenge expiresAt or a non-empty clock cannot be read; there is no error list to inspect |
| go | `VerifyAttestation` | github.com/aeoess/agent-passport-go/values (values/values.go) | invalid time fails open | Valid flips from true to false for artifacts previously accepted. The signature change is described under authority false accept. The signature (bool, []string) is unchanged and the new report is one more plain string in the existing error slice, so there is no exhaustive-match break in Go and nothing fails to compile. Attestations with an unreadable expiresAt now return false; consumers matching on error text gain 'Unreadable attestation expiresAt or verifier clock' |
| go | `NegotiateCommonGround` | github.com/aeoess/agent-passport-go/values (values/values.go) | invalid time fails open | Valid flips from true to false for artifacts previously accepted. The signature change is described under authority false accept. The SharedGround struct is untouched; new entries simply appear in the existing IncompatibilityReasons []string and Compatible flips from true to false for pairs that previously negotiated. Because Go errors are plain strings rather than typed variants, there is no compile-time break for consumers, . Consumers matching on reason text gain the 'has an unreadable expiresAt' phrasing |
| go | `VerifyPassport` | passport/passport.go | authority false accept | a new required input: the two trailing positional parameters become VerifyPassportOptions, so every call site must be updated; VerificationResult gains IssuerTrustChecked and SelfSignedAccepted, which is additive on the wire |

### Migration

| package | old call shape | new call shape | unmigrated call | artifacts reissued |
|---|---|---|---|---|
| go | `VerifyPassport(signed, trustedIssuers, now) returned Valid true for a passport with an absent or unreadable expiresAt` | `VerifyPassport(signed, VerifyPassportOptions{...}); the passport must carry a readable RFC 3339 expiresAt, which the reference type declares as required` | valid false: a new 'Unreadable expiresAt' string is appended to Errors, kept distinct from 'Passport expired at' | yes: passports with an absent or unreadable expiresAt must be reissued |
| go | `VerifyPassport(signed, trustedIssuers, now) silently skipped a present-but-unreadable notBefore` | `VerifyPassport(signed, VerifyPassportOptions{...}); a present notBefore must parse, while an absent one still leaves the lower edge of the window open` | valid false: a new 'Unreadable notBefore' string is appended to Errors | yes: passports carrying an unreadable notBefore must be reissued |
| go | `VerifyChallenge(challenge, signatureHex, publicKeyHex, now) returned true when the challenge ExpiresAt could not be read` | `same signature; the challenge must carry a readable RFC 3339 expiresAt when a non-empty clock is supplied` | valid false: returns false with no error list to inspect; freshness is the only replay protection on this surface | yes: challenges whose expiresAt is unreadable must be reissued |
| go | `VerifyAttestation(att, now) returned true when the attestation ExpiresAt could not be read` | `same signature; a non-empty ExpiresAt with a non-empty clock must parse, while an empty ExpiresAt or empty clock stays a deliberate skip` | valid false: 'Unreadable attestation expiresAt or verifier clock' is appended to the returned error list | yes: attestations with a present but unreadable expiresAt must be reissued |
| go | `VerifyPassport or VerifyAttestation called with an unreadable non-empty now string silently disabled expiry and notBefore for every artifact that verifier checked` | `for VerifyPassport set VerifyPassportOptions.Now to a readable RFC 3339 instant, or leave it empty to skip the time boundaries deliberately; VerifyAttestation, VerifyChallenge and NegotiateCommonGround keep their existing clock argument` | valid false: 'Unreadable verifier clock' is reported separately from an unreadable artifact timestamp, so an operator can tell which one is broken | no: the clock is a caller-supplied string, not an artifact |
| go | `NegotiateCommonGround(pubKeyA, attestationA, pubKeyB, attestationB, now) reported Compatible true across unreadable timestamps` | `same signature; both attestations and the clock must carry readable RFC 3339 timestamps` | valid false: Compatible is false and new entries appear in IncompatibilityReasons; no public type changed | yes: attestations carrying unreadable timestamps must be reissued |
| go | `VerifyPassport(signed, trustedIssuers, now)` returned Valid true on an empty or nil trustedIssuers list | `VerifyPassport(signed, VerifyPassportOptions{TrustedIssuers: ..., Now: ..., AllowSelfSigned: ...})` | compile error: the two trailing positional parameters become one options struct, so every call site fails to build until it is updated | no: no serialized bytes move and the countersignature preimage is untouched |

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
