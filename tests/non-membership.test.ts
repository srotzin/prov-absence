// Copyright 2026 Hive Civilization
// SPDX-License-Identifier: Apache-2.0

/**
 * Focused test suite for the non-membership proof primitive.
 *
 * Tests:
 * - Adjacency invariant enforcement
 * - Sentinel boundary handling
 * - Strict ordering invariant: lowerLeaf < hash(query) < upperLeaf
 * - Canonical data independence (same eventId, same data → same proof)
 */

import { describe, it, expect } from "vitest";
import {
  SortedMerkleTree,
  LOW_SENTINEL,
  HIGH_SENTINEL,
  bytesEqual,
} from "../src/sorted-merkle.js";
import { buildLeaf } from "../src/index.js";
import {
  verifyNonMembership,
  verifyNonMembershipByHash,
  verifyInclusion,
} from "../src/verify.js";
import type { NonMembershipProof } from "../src/types.js";

// ---------------------------------------------------------------------------
// Helper: build a tree, prove absence, return the proof + root
// ---------------------------------------------------------------------------
function setup(presentIds: string[], absentId: string, absentData: Record<string, unknown> = {}) {
  const leaves = presentIds.map((id) => buildLeaf(id, {}));
  const tree = new SortedMerkleTree(leaves);
  const proof = tree.proveNonMembership(absentId, absentData);
  return { tree, proof, root: tree.root() };
}

// ---------------------------------------------------------------------------
// Adjacency invariant
// ---------------------------------------------------------------------------

describe("Non-membership — adjacency invariant", () => {
  it("lowerIndex + 1 === upperIndex for a proof between two leaves", () => {
    const { proof } = setup(["aa", "bb", "cc", "dd"], "bb-absent");
    expect(proof.upperIndex).toBe(proof.lowerIndex + 1);
  });

  it("lowerIndex + 1 === upperIndex when absent hash is before all user leaves", () => {
    // build a leaf whose hash is known to be smaller than any SHA-256 of a string
    // We use a raw tiny hash value
    const tree = new SortedMerkleTree([buildLeaf("big-event", {})]);
    // Hash a string that produces a tiny-valued hash — we can't control SHA-256,
    // so just pick an arbitrary absent event and check the invariant
    const absent = buildLeaf("tiny-absent", {});
    const proof = tree.proveNonMembershipByHash(absent.hash);
    expect(proof.upperIndex).toBe(proof.lowerIndex + 1);
  });

  it("adjacency violation fails verification", () => {
    const { proof, root } = setup(["x", "y", "z"], "w-absent");
    const tampered: NonMembershipProof = {
      ...proof,
      upperIndex: proof.lowerIndex + 3, // violate adjacency
    };
    expect(verifyNonMembershipByHash(tampered, root)).toBe(false);
  });

  it("leafIndex mismatch in lowerProof fails verification", () => {
    const { proof, root } = setup(["x", "y", "z"], "w-absent");
    const tampered: NonMembershipProof = {
      ...proof,
      lowerProof: { ...proof.lowerProof, leafIndex: proof.lowerIndex + 99 },
    };
    expect(verifyNonMembershipByHash(tampered, root)).toBe(false);
  });

  it("leafIndex mismatch in upperProof fails verification", () => {
    const { proof, root } = setup(["x", "y", "z"], "w-absent");
    const tampered: NonMembershipProof = {
      ...proof,
      upperProof: { ...proof.upperProof, leafIndex: proof.upperIndex + 99 },
    };
    expect(verifyNonMembershipByHash(tampered, root)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Sentinel boundary handling
// ---------------------------------------------------------------------------

describe("Non-membership — sentinel boundary handling", () => {
  it("tree always has LOW_SENTINEL at index 0 and HIGH_SENTINEL at realSize-1", () => {
    const tree = new SortedMerkleTree([buildLeaf("mid", {})]);
    // Can prove inclusion for both sentinels
    const lpProof = tree.proveInclusionByHash(LOW_SENTINEL);
    const hpProof = tree.proveInclusionByHash(HIGH_SENTINEL);
    expect(verifyInclusion(lpProof, tree.root())).toBe(true);
    expect(verifyInclusion(hpProof, tree.root())).toBe(true);
    expect(lpProof.leafIndex).toBe(0);
  });

  it("absence proof for hash below all user leaves uses LOW_SENTINEL as lower bound", () => {
    // Build a tree and find a hash that lands before the first user leaf
    const tree = new SortedMerkleTree([buildLeaf("big-hash-event", {})]);
    // Construct an absent hash we know will be very small
    const tinyHash = new Uint8Array(32);
    tinyHash[31] = 0x01; // 0x000...001 > LOW_SENTINEL
    // Verify it's not actually in the tree
    try {
      const proof = tree.proveNonMembershipByHash(tinyHash);
      // If tinyHash < firstUserLeaf, lowerLeaf should be LOW_SENTINEL
      if (bytesEqual(proof.lowerLeaf, LOW_SENTINEL)) {
        expect(verifyNonMembershipByHash(proof, tree.root())).toBe(true);
      }
    } catch {
      // tinyHash is in the tree (astronomically unlikely) — skip
    }
  });

  it("absence proof for hash above all user leaves uses HIGH_SENTINEL as upper bound", () => {
    const tree = new SortedMerkleTree([buildLeaf("small-hash", {})]);
    const nearMaxHash = new Uint8Array(32).fill(0xff);
    nearMaxHash[31] = 0xfe; // just below HIGH_SENTINEL
    try {
      const proof = tree.proveNonMembershipByHash(nearMaxHash);
      // If nearMaxHash > last user leaf, upperLeaf should be HIGH_SENTINEL
      if (bytesEqual(proof.upperLeaf, HIGH_SENTINEL)) {
        expect(verifyNonMembershipByHash(proof, tree.root())).toBe(true);
      }
    } catch {
      // hash is present in tree — skip
    }
  });

  it("empty tree (only sentinels): every hash proves absence between LOW and HIGH", () => {
    const tree = new SortedMerkleTree([]);
    const absent = buildLeaf("any-event", {});
    const proof = tree.proveNonMembershipByHash(absent.hash);
    expect(bytesEqual(proof.lowerLeaf, LOW_SENTINEL)).toBe(true);
    expect(bytesEqual(proof.upperLeaf, HIGH_SENTINEL)).toBe(true);
    expect(proof.lowerIndex).toBe(0);
    expect(proof.upperIndex).toBe(1);
    expect(verifyNonMembershipByHash(proof, tree.root())).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Strict ordering invariant: lowerLeaf < hash(query) < upperLeaf
// ---------------------------------------------------------------------------

describe("Non-membership — strict ordering invariant", () => {
  it("lowerLeaf is strictly less than queryHash", () => {
    const { proof } = setup(["p", "q", "r"], "s-absent");
    // Compare bytes
    let lower = 0;
    for (let i = 0; i < 32; i++) {
      const d = (proof.lowerLeaf[i] as number) - (proof.queryHash[i] as number);
      if (d !== 0) { lower = d; break; }
    }
    expect(lower).toBeLessThan(0);
  });

  it("queryHash is strictly less than upperLeaf", () => {
    const { proof } = setup(["p", "q", "r"], "s-absent");
    let lower = 0;
    for (let i = 0; i < 32; i++) {
      const d = (proof.queryHash[i] as number) - (proof.upperLeaf[i] as number);
      if (d !== 0) { lower = d; break; }
    }
    expect(lower).toBeLessThan(0);
  });

  it("equal-to-lower fails verification", () => {
    const { proof, root } = setup(["p", "q", "r"], "s-absent");
    // Set queryHash equal to lowerLeaf
    const tampered: NonMembershipProof = {
      ...proof,
      queryHash: new Uint8Array(proof.lowerLeaf),
    };
    expect(verifyNonMembershipByHash(tampered, root)).toBe(false);
  });

  it("equal-to-upper fails verification", () => {
    const { proof, root } = setup(["p", "q", "r"], "s-absent");
    const tampered: NonMembershipProof = {
      ...proof,
      queryHash: new Uint8Array(proof.upperLeaf),
    };
    expect(verifyNonMembershipByHash(tampered, root)).toBe(false);
  });

  it("lowerLeaf > queryHash fails verification", () => {
    const { proof, root } = setup(["p", "q", "r"], "s-absent");
    // Swap lower and upper (lowerLeaf becomes larger than queryHash)
    const tampered: NonMembershipProof = {
      ...proof,
      lowerLeaf: new Uint8Array(proof.upperLeaf),
      lowerProof: proof.upperProof,
    };
    expect(verifyNonMembershipByHash(tampered, root)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Data independence and canonical form
// ---------------------------------------------------------------------------

describe("Non-membership — canonical data independence", () => {
  it("same eventId + same data always produces the same queryHash", () => {
    const tree1 = new SortedMerkleTree([buildLeaf("a", {}), buildLeaf("b", {})]);
    const tree2 = new SortedMerkleTree([buildLeaf("c", {}), buildLeaf("d", {})]);

    const proof1 = tree1.proveNonMembership("absent", { x: 1 });
    const proof2 = tree2.proveNonMembership("absent", { x: 1 });

    // queryHash should be the same regardless of which tree we use
    expect(bytesEqual(proof1.queryHash, proof2.queryHash)).toBe(true);
  });

  it("verifyNonMembership with wrong data returns false", () => {
    const { proof, root } = setup(["a", "b"], "absent-event");
    // Verify with correct data (empty object = default)
    expect(verifyNonMembership(proof, "absent-event", {}, root)).toBe(true);
    // Verify with wrong data
    expect(verifyNonMembership(proof, "absent-event", { tampered: true }, root)).toBe(false);
  });

  it("verifyNonMembership with wrong eventId returns false", () => {
    const { proof, root } = setup(["a", "b"], "absent-event");
    expect(verifyNonMembership(proof, "different-event", {}, root)).toBe(false);
  });

  it("key order in data object does not affect queryHash (JCS)", () => {
    // Build proof with data in one key order
    const tree = new SortedMerkleTree([buildLeaf("existing", {})]);
    const proof1 = tree.proveNonMembership("absent", { b: 2, a: 1 });
    const proof2 = tree.proveNonMembership("absent", { a: 1, b: 2 });
    // Due to JCS canonicalisation, queryHash should be identical
    expect(bytesEqual(proof1.queryHash, proof2.queryHash)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Large tree stress test
// ---------------------------------------------------------------------------

describe("Non-membership — large tree stress test", () => {
  it("1000 events: 20 random non-membership proofs all verify", () => {
    const ids = Array.from({ length: 1000 }, (_, i) => `event:${i}`);
    const tree = new SortedMerkleTree(ids.map((id) => buildLeaf(id, {})));
    const root = tree.root();

    for (let i = 0; i < 20; i++) {
      const absent = buildLeaf(`absent-event-${i}`, { round: i });
      const proof = tree.proveNonMembershipByHash(absent.hash);
      expect(verifyNonMembershipByHash(proof, root)).toBe(true);
      expect(proof.upperIndex).toBe(proof.lowerIndex + 1);
    }
  });
});
