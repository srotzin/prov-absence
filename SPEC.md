# `prov.absence` — Formal Specification

**Version:** 0.0.1  
**Status:** Internal Research / Patent Reduction-to-Practice  
**Cross-reference:** Provisional Patent §17 C10 — "Negative-Fact Receipts"  
**License:** Apache 2.0 — Copyright 2026 Hive Civilization

---

## 1. Overview

`prov.absence` is a cryptographic primitive for producing **non-membership proofs** — compact, verifiable attestations that a specific event did **not** appear in a closed observation window.

The dual of a Merkle inclusion proof ("I saw X"), a non-membership proof states: "X was not observed in the set of events committed to this Merkle root."

The primitive is implemented as a **sorted Merkle tree** whose leaves are lexicographically ordered SHA-256 hashes of canonicalized event records.

---

## 2. Leaf Hash Construction

### 2.1 Canonical Form

Given an event with:
- `eventId: string` — a stable, unique identifier (e.g., `"llm-call:uuid:..."`).
- `data: object` — arbitrary JSON-serializable metadata.

The canonical leaf JSON is:

```
{ "data": <data>, "eventId": <eventId> }
```

Keys are in **lexicographic order** per RFC 8785 (JSON Canonicalization Scheme). Nested objects also have their keys sorted recursively.

### 2.2 Leaf Hash

```
leafHash = SHA-256( UTF-8( canonicalize({ data, eventId }) ) )
```

The canonical form is derived deterministically regardless of the programming language or runtime that produces it.

---

## 3. Tree Structure

### 3.1 Sentinel Leaves

Two sentinel leaf hashes bound the sorted range:

```
LOW_SENTINEL  = 0x00 0x00 ... 0x00   (32 bytes, all zero)
HIGH_SENTINEL = 0xff 0xff ... 0xff   (32 bytes, all 0xff)
```

The sentinels are unconditionally inserted:
- `LOW_SENTINEL` is prepended at index 0.
- `HIGH_SENTINEL` is appended as the last real leaf.

This ensures every possible 32-byte hash is bracketed, eliminating special cases for "smaller than all leaves" and "larger than all leaves."

### 3.2 Sorting

User leaf hashes are sorted in **lexicographic byte order** (unsigned byte comparison). The full leaf array is:

```
[LOW_SENTINEL, userLeaf₀, userLeaf₁, ..., userLeafₙ, HIGH_SENTINEL]
```

where `userLeaf₀ ≤ userLeaf₁ ≤ ... ≤ userLeafₙ` (ties are not allowed).

### 3.3 Power-of-2 Padding

The sorted leaf array is padded to the next power-of-2 length by appending copies of `HIGH_SENTINEL`. Padding leaves are present only to make the tree a perfect binary tree; they do not appear in non-membership proofs as bracketing candidates.

### 3.4 Node Hashing (Domain Separation)

To prevent second-preimage attacks where an attacker could present an internal node as a leaf:

```
leafNode(h)        = SHA-256( 0x00 || h )          // 33 bytes
internalNode(L, R) = SHA-256( 0x01 || L || R )     // 65 bytes
```

The domain prefix (`0x00` for leaves, `0x01` for internal nodes) ensures that no valid leaf hash can collide with a valid internal node hash.

### 3.5 Root Computation

The root is computed bottom-up: leaf nodes are hashed first, then paired and hashed level by level until one node remains.

---

## 4. Proof Semantics

### 4.1 Inclusion Proof

An inclusion proof for leaf `h` consists of:
- `leaf: Hash` — the leaf hash being proven.
- `siblings: Hash[]` — one sibling per level, from leaf to root.
- `pathBits: number[]` — `0` if the current node is the left child, `1` if right.
- `leafIndex: number` — the 0-based index in the padded leaf array.
- `root: Hash` — the root at proof generation time.

**Verification:** Recompute the root by hashing `leaf` with `domainSep(0x00)`, then iterating through siblings, using `pathBits` to determine left/right order at each level. The result must equal `expectedRoot`.

### 4.2 Non-Membership Proof

A non-membership proof for queried event `(eventId, data)` consists of:
- `queryHash: Hash` — `SHA-256(canonical({ data, eventId }))`.
- `lowerLeaf: Hash` — the largest real leaf hash in the tree strictly less than `queryHash`.
- `upperLeaf: Hash` — the smallest real leaf hash in the tree strictly greater than `queryHash`.
- `lowerIndex: number`, `upperIndex: number` — their padded indices.
- `lowerProof: InclusionProof`, `upperProof: InclusionProof`.
- `root: Hash`.

**Verification requirements (all must hold):**

1. Both inclusion proofs verify against `expectedRoot`.
2. `lowerLeaf < queryHash < upperLeaf` (strict byte-level ordering).
3. `lowerIndex + 1 === upperIndex` (leaves are **adjacent** in the sorted tree — no gap between them).
4. `lowerProof.leafIndex === lowerIndex`.
5. `upperProof.leafIndex === upperIndex`.
6. `lowerProof.leaf === lowerLeaf` and `upperProof.leaf === upperLeaf`.
7. `lowerLeaf >= LOW_SENTINEL` and `upperLeaf <= HIGH_SENTINEL`.
8. `queryHash ≠ LOW_SENTINEL` and `queryHash ≠ HIGH_SENTINEL`.
9. `queryHash` matches `SHA-256(canonical({ data, eventId }))` for the presented `eventId` and `data`.

**Soundness argument:** The inclusion proofs establish that `lowerLeaf` and `upperLeaf` are both real leaves in the tree with the given root. The adjacency condition (`lowerIndex + 1 === upperIndex`) establishes that there is no slot between them in the sorted order. Because the tree is sorted by construction, no leaf with a hash in the range `(lowerLeaf, upperLeaf)` can exist anywhere in the tree. Therefore, `queryHash` — which lies strictly within that range — cannot be present.

---

## 5. Serialisation Format

Binary format for `tree.serialize()`:

| Offset | Length | Field |
|--------|--------|-------|
| 0 | 4 | Magic: `0x50 0x4D 0x54 0x00` ("PMT\0") |
| 4 | 4 | Version: `1` (big-endian uint32) |
| 8 | 4 | `realCount` — number of real leaves incl. sentinels (big-endian uint32) |
| 12 | 4 | `paddedCount` — padded leaf count (big-endian uint32) |
| 16 | `paddedCount × 32` | Leaf hashes in sorted, padded order |

---

## 6. Security Analysis

### 6.1 Collision Resistance

The primitive relies entirely on the collision resistance of SHA-256. If an adversary can find two distinct events `e₁ ≠ e₂` such that `SHA-256(canonical(e₁)) = SHA-256(canonical(e₂))`, they could produce a non-membership proof for an event that is, in fact, present. Under standard SHA-256 collision resistance assumptions (no known attack with fewer than ~2⁶⁵ operations as of 2026), this attack is computationally infeasible.

### 6.2 Second-Preimage Protection via Domain Separation

Without domain separation, an attacker observing an internal node hash `H_int = SHA-256(left || right)` could attempt to find a leaf value `v` such that `SHA-256(v) = H_int`, and then submit an inclusion proof that walks up through the leaf level instead of the internal level.

The domain prefix prevents this: `SHA-256(0x00 || v)` and `SHA-256(0x01 || L || R)` occupy different input spaces. An adversary would need to find a SHA-256 second preimage across the domain boundary, which is as hard as breaking SHA-256 itself.

### 6.3 What an Attacker Can and Cannot Do

**Cannot:**
- Produce a valid non-membership proof for an event that IS in the tree (soundness).
- Forge a valid inclusion proof for an event not in the tree (inclusion soundness).
- Substitute one proof's authentication path for another tree's root (cross-tree binding via the root field and recomputed path hash).
- Extend the tree after committing the root without invalidating existing proofs.

**Can (limitations / assumptions):**
- Produce any proof they like for a root they chose themselves (the security model requires the root to be externally anchored — e.g., published on-chain or in a tamper-evident log before any disputes arise).
- Observe the tree structure and leaf hashes if they have access to the binary. Leaf hashes reveal nothing about event data beyond what SHA-256 collision resistance guarantees, but the canonical event IDs themselves are not hidden by this scheme. If confidentiality is required, an additional layer (e.g., HMAC-SHA-256 with a secret key as the leaf hash function) should be considered.

### 6.4 Quantum Considerations

SHA-256 provides approximately 128-bit security against Grover's algorithm on a quantum computer. For long-term provenance records (>20 years), migrating to SHA-3 or a post-quantum hash function should be evaluated when this primitive is productionised.

---

## 7. Connection to Provisional Patent §17 C10

This implementation reduces **Claim C10 ("Negative-Fact Receipts")** to practice. The key inventive elements realised here are:

1. **The sorted leaf ordering** enabling gap-based non-membership proofs.
2. **Sentinel boundary leaves** enabling uniform treatment of all non-membership queries.
3. **Dual-inclusion proof verification** with the adjacency constraint.
4. **Domain-separated internal hashing** protecting against second-preimage attacks.
5. **Application to LLM audit windows** — proving that a specific call to a model, tool, or endpoint did NOT occur in a bounded observation period.

The proof size is `O(log n)` bytes (two authentication paths), and verification is `O(log n)` hash operations, making this practical for real-time API-level attestation.
