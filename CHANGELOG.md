# Changelog

All notable changes to `@hivecivilization/prov-absence` will be documented here.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

_In development._

---

## [0.0.1] — 2026-01-01

### Added

- Initial prototype implementation of `SortedMerkleTree` with sorted-leaf non-membership proofs.
- `LOW_SENTINEL` and `HIGH_SENTINEL` boundary leaves for uniform non-membership handling at tree edges.
- Domain-separated leaf/internal node hashing (`0x00 || h` for leaves, `0x01 || L || R` for internal nodes) to prevent second-preimage attacks.
- `proveInclusionByHash(leafHash)` — O(log n) Merkle inclusion proof.
- `proveNonMembershipByHash(queryHash)` — O(log n) non-membership proof for a query hash.
- `proveNonMembership(eventId, data)` — convenience wrapper that canonicalizes before proving.
- `serialize() / static deserialize(buf)` — binary round-trip (PMT\0 format, version 1).
- `verifyInclusion(proof, root)` — stateless inclusion proof verifier.
- `verifyNonMembership(proof, eventId, data, root)` — stateless non-membership verifier with all seven validity conditions.
- `verifyNonMembershipByHash(proof, root)` — hash-only non-membership verifier.
- `canonicalize(value)` — RFC 8785 JCS canonical JSON (inlined, no extra dependencies).
- `hashLeafData(eventId, data)` — canonical leaf hash construction.
- CLI: `build`, `prove-inclusion`, `prove-absence`, `verify-inclusion`, `verify-absence`.
- Test suite: 60+ test cases covering construction, inclusion, non-membership, tampering, cross-tree forgery, and serialisation round-trips.
- `examples/audit-window.ts` — 10,000-event LLM audit window demonstration.
- `SPEC.md` — formal specification with security analysis.
- `README.md` — quick-start guide and performance numbers.
- Apache 2.0 license with bidirectional patent grant.

[0.0.1]: https://github.com/hivecivilization/prov-absence/releases/tag/v0.0.1
