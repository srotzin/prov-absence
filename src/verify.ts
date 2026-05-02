// Copyright 2026 Hive Civilization
// SPDX-License-Identifier: Apache-2.0

/**
 * Stateless verification of inclusion and non-membership proofs.
 *
 * These functions accept a proof object and an expected root, and return
 * `true` only if ALL validity conditions are satisfied.  They do not mutate
 * any state and have no side effects.
 */

import { sha256 } from "@noble/hashes/sha256";
import { hashLeafData } from "./canonical.js";
import {
  HIGH_SENTINEL,
  LOW_SENTINEL,
  bytesEqual,
  toHex,
} from "./sorted-merkle.js";
import type { Hash, InclusionProof, NonMembershipProof } from "./types.js";

// ---------------------------------------------------------------------------
// Internal helpers (mirroring sorted-merkle.ts — kept local to avoid
// coupling the verifier to the tree's internal implementation details)
// ---------------------------------------------------------------------------

const LEAF_PREFIX = new Uint8Array([0x00]);
const NODE_PREFIX = new Uint8Array([0x01]);

function hashLeafNode(leafHash: Hash): Hash {
  const input = new Uint8Array(1 + 32);
  input.set(LEAF_PREFIX, 0);
  input.set(leafHash, 1);
  return sha256(input);
}

function hashInternalNode(left: Hash, right: Hash): Hash {
  const input = new Uint8Array(1 + 32 + 32);
  input.set(NODE_PREFIX, 0);
  input.set(left, 1);
  input.set(right, 33);
  return sha256(input);
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const diff = (a[i] as number) - (b[i] as number);
    if (diff !== 0) return diff;
  }
  return a.length - b.length;
}

// ---------------------------------------------------------------------------
// Inclusion proof verification
// ---------------------------------------------------------------------------

/**
 * Verify a Merkle inclusion proof.
 *
 * @param proof          The inclusion proof to verify.
 * @param expectedRoot   The trusted Merkle root to check against.
 * @returns `true` if the proof is valid, `false` otherwise.
 */
export function verifyInclusion(
  proof: InclusionProof,
  expectedRoot: Hash
): boolean {
  try {
    const { leaf, siblings, pathBits, leafIndex, root: proofRoot } = proof;

    // 1. The root embedded in the proof must match the trusted root.
    if (!bytesEqual(proofRoot, expectedRoot)) return false;

    // 2. Validate structural consistency.
    if (siblings.length !== pathBits.length) return false;
    if (leaf.length !== 32) return false;

    // 3. Recompute the root from the leaf upward.
    let current = hashLeafNode(leaf);
    let idx = leafIndex;

    for (let i = 0; i < siblings.length; i++) {
      const sibling = siblings[i] as Hash;
      const bit = pathBits[i] as number;

      if (sibling.length !== 32) return false;
      if (bit !== 0 && bit !== 1) return false;

      if (bit === 0) {
        // current is the LEFT child
        current = hashInternalNode(current, sibling);
      } else {
        // current is the RIGHT child
        current = hashInternalNode(sibling, current);
      }
      idx = Math.floor(idx / 2);
    }

    // 4. The recomputed root must equal the expected root.
    return bytesEqual(current, expectedRoot);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Non-membership proof verification
// ---------------------------------------------------------------------------

/**
 * Verify a non-membership proof for a queried event.
 *
 * All of the following conditions must hold for the proof to be valid:
 *
 * 1. Both inclusion proofs verify against `expectedRoot`.
 * 2. `lowerLeaf < hash(queryEventId) < upperLeaf` (strict ordering).
 * 3. `lowerIndex + 1 === upperIndex` (leaves are adjacent in the sorted tree).
 * 4. `lowerProof.leafIndex === lowerIndex`.
 * 5. `upperProof.leafIndex === upperIndex`.
 * 6. `lowerProof.leaf` and `upperProof.leaf` match `lowerLeaf` and `upperLeaf`.
 * 7. `lowerLeaf >= LOW_SENTINEL` and `upperLeaf <= HIGH_SENTINEL`.
 * 8. The query hash is not equal to LOW_SENTINEL or HIGH_SENTINEL.
 *
 * @param proof          The non-membership proof to verify.
 * @param queryEventId   The event ID whose absence is being verified.
 * @param queryData      The event data (same as used when building the tree).
 * @param expectedRoot   The trusted Merkle root to check against.
 * @returns `true` if the proof is valid, `false` otherwise.
 */
export function verifyNonMembership(
  proof: NonMembershipProof,
  queryEventId: string,
  queryData: Readonly<Record<string, unknown>>,
  expectedRoot: Hash
): boolean {
  try {
    const {
      queryHash,
      lowerLeaf,
      upperLeaf,
      lowerIndex,
      upperIndex,
      lowerProof,
      upperProof,
      root: proofRoot,
    } = proof;

    // 0. Root in proof must match trusted root.
    if (!bytesEqual(proofRoot, expectedRoot)) return false;

    // 1. Re-derive query hash from queryEventId + queryData.
    const recomputedQueryHash = hashLeafData(queryEventId, queryData);
    if (!bytesEqual(queryHash, recomputedQueryHash)) return false;

    // 2. Query hash must not be a sentinel.
    if (bytesEqual(queryHash, LOW_SENTINEL)) return false;
    if (bytesEqual(queryHash, HIGH_SENTINEL)) return false;

    // 3. Strict ordering: lowerLeaf < queryHash < upperLeaf.
    if (compareBytes(lowerLeaf, queryHash) >= 0) return false;
    if (compareBytes(queryHash, upperLeaf) >= 0) return false;

    // 4. Adjacency: leaves must be consecutive in the sorted array.
    if (lowerIndex + 1 !== upperIndex) return false;

    // 5. Proof leafIndex fields must match the claimed indices.
    if (lowerProof.leafIndex !== lowerIndex) return false;
    if (upperProof.leafIndex !== upperIndex) return false;

    // 6. Proof leaf fields must match the claimed leaf hashes.
    if (!bytesEqual(lowerProof.leaf, lowerLeaf)) return false;
    if (!bytesEqual(upperProof.leaf, upperLeaf)) return false;

    // 7. Lower bound must be >= LOW_SENTINEL, upper bound <= HIGH_SENTINEL.
    if (compareBytes(lowerLeaf, LOW_SENTINEL) < 0) return false;
    if (compareBytes(upperLeaf, HIGH_SENTINEL) > 0) return false;

    // 8. Both inclusion proofs must verify against the same expected root.
    if (!verifyInclusion(lowerProof, expectedRoot)) return false;
    if (!verifyInclusion(upperProof, expectedRoot)) return false;

    // All checks passed.
    return true;
  } catch {
    return false;
  }
}

/**
 * Convenience overload that accepts a pre-computed query hash instead of
 * re-deriving it from eventId + data.
 *
 * The verifier still checks that `queryHash` matches the embedded hash in the
 * proof, so the caller cannot substitute an arbitrary hash.
 */
export function verifyNonMembershipByHash(
  proof: NonMembershipProof,
  expectedRoot: Hash
): boolean {
  try {
    const {
      queryHash,
      lowerLeaf,
      upperLeaf,
      lowerIndex,
      upperIndex,
      lowerProof,
      upperProof,
      root: proofRoot,
    } = proof;

    // 0. Root in proof must match trusted root.
    if (!bytesEqual(proofRoot, expectedRoot)) return false;

    // 1. Query hash must match what is embedded in the proof itself.
    if (!bytesEqual(queryHash, proof.queryHash)) return false;

    // 2. Query hash must not be a sentinel.
    if (bytesEqual(queryHash, LOW_SENTINEL)) return false;
    if (bytesEqual(queryHash, HIGH_SENTINEL)) return false;

    // 3. Strict ordering: lowerLeaf < queryHash < upperLeaf.
    if (compareBytes(lowerLeaf, queryHash) >= 0) return false;
    if (compareBytes(queryHash, upperLeaf) >= 0) return false;

    // 4. Adjacency.
    if (lowerIndex + 1 !== upperIndex) return false;

    // 5. Proof leafIndex consistency.
    if (lowerProof.leafIndex !== lowerIndex) return false;
    if (upperProof.leafIndex !== upperIndex) return false;

    // 6. Leaf hash consistency in proofs.
    if (!bytesEqual(lowerProof.leaf, lowerLeaf)) return false;
    if (!bytesEqual(upperProof.leaf, upperLeaf)) return false;

    // 7. Sentinel bounds.
    if (compareBytes(lowerLeaf, LOW_SENTINEL) < 0) return false;
    if (compareBytes(upperLeaf, HIGH_SENTINEL) > 0) return false;

    // 8. Both inclusion proofs must verify.
    if (!verifyInclusion(lowerProof, expectedRoot)) return false;
    if (!verifyInclusion(upperProof, expectedRoot)) return false;

    return true;
  } catch {
    return false;
  }
}

/**
 * Hex-encode a hash for display. Re-exported from sorted-merkle for
 * convenience so callers can import everything from verify.ts.
 */
export { toHex };
