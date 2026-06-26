# Changelog

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

### Behavior changes (operations previously permitted now fail closed)
- A cross-currency commerce spend (purchase currency differs from the budget currency) is now denied
  instead of passing.
- A sub-delegation from a parent whose signature does not verify is now rejected instead of produced.
- A delegation chain with a missing or empty `not_after` is now rejected instead of treated as
  never-expiring.
