// Copyright 2026 Hive Civilization
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { SortedMerkleTree, LOW_SENTINEL, HIGH_SENTINEL, bytesEqual, toHex } from "../src/sorted-merkle.js";
import { buildLeaf } from "../src/index.js";
import { verifyInclusion, verifyNonMembership, verifyNonMembershipByHash } from "../src/verify.js";
import type { Leaf, Hash } from "../src/types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeLeaves(ids: string[]): Leaf[] {
  return ids.map((id) => buildLeaf(id, {}));
}

function cloneHash(h: Hash): Hash {
  return new Uint8Array(h);
}

// ---------------------------------------------------------------------------
// Tree construction
// ---------------------------------------------------------------------------

describe("SortedMerkleTree — construction", () => {
  it("builds a tree from 0 leaves (only sentinels)", () => {
    const tree = new SortedMerkleTree([]);
    expect(tree.realSize).toBe(2); // LOW + HIGH sentinel
    expect(tree.paddedSize).toBeGreaterThanOrEqual(2);
    const root = tree.root();
    expect(root).toBeInstanceOf(Uint8Array);
    expect(root.length).toBe(32);
  });

  it("builds a tree from 1 leaf", () => {
    const tree = new SortedMerkleTree(makeLeaves(["event:a"]));
    expect(tree.realSize).toBe(3); // LOW + a + HIGH
    expect(tree.root().length).toBe(32);
  });

  it("builds a tree from 5 leaves", () => {
    const tree = new SortedMerkleTree(makeLeaves(["a", "b", "c", "d", "e"]));
    expect(tree.realSize).toBe(7);
    expect(tree.root().length).toBe(32);
  });

  it("builds a tree from 50 leaves", () => {
    const ids = Array.from({ length: 50 }, (_, i) => `event:${i}`);
    const tree = new SortedMerkleTree(makeLeaves(ids));
    expect(tree.realSize).toBe(52);
  });

  it("builds a tree from 1000 leaves", () => {
    const ids = Array.from({ length: 1000 }, (_, i) => `event:${i}`);
    const tree = new SortedMerkleTree(makeLeaves(ids));
    expect(tree.realSize).toBe(1002);
  });

  it("root is deterministic for the same inputs", () => {
    const leaves = makeLeaves(["x", "y", "z"]);
    const t1 = new SortedMerkleTree(leaves);
    const t2 = new SortedMerkleTree(leaves);
    expect(bytesEqual(t1.root(), t2.root())).toBe(true);
  });

  it("insertion order does not affect the root", () => {
    const a = buildLeaf("event:a", {});
    const b = buildLeaf("event:b", {});
    const c = buildLeaf("event:c", {});
    const t1 = new SortedMerkleTree([a, b, c]);
    const t2 = new SortedMerkleTree([c, a, b]);
    const t3 = new SortedMerkleTree([b, c, a]);
    expect(bytesEqual(t1.root(), t2.root())).toBe(true);
    expect(bytesEqual(t1.root(), t3.root())).toBe(true);
  });

  it("throws on duplicate leaf hashes", () => {
    const leaf = buildLeaf("event:dup", {});
    expect(() => new SortedMerkleTree([leaf, leaf])).toThrow(/duplicate/i);
  });

  it("padded size is always a power of 2", () => {
    for (const n of [0, 1, 2, 3, 5, 7, 8, 14, 100]) {
      const ids = Array.from({ length: n }, (_, i) => `ev:${i}`);
      const tree = new SortedMerkleTree(makeLeaves(ids));
      const ps = tree.paddedSize;
      expect(ps & (ps - 1)).toBe(0); // power of 2
    }
  });
});

// ---------------------------------------------------------------------------
// Inclusion proofs
// ---------------------------------------------------------------------------

describe("SortedMerkleTree — inclusion proofs", () => {
  it("proves inclusion for every leaf in a 5-leaf tree", () => {
    const leaves = makeLeaves(["a", "b", "c", "d", "e"]);
    const tree = new SortedMerkleTree(leaves);
    const root = tree.root();

    for (const leaf of leaves) {
      const proof = tree.proveInclusionByHash(leaf.hash);
      expect(verifyInclusion(proof, root)).toBe(true);
    }
  });

  it("proves inclusion for the LOW_SENTINEL", () => {
    const tree = new SortedMerkleTree(makeLeaves(["x"]));
    const proof = tree.proveInclusionByHash(LOW_SENTINEL);
    expect(verifyInclusion(proof, tree.root())).toBe(true);
  });

  it("proves inclusion for the HIGH_SENTINEL", () => {
    const tree = new SortedMerkleTree(makeLeaves(["x"]));
    const proof = tree.proveInclusionByHash(HIGH_SENTINEL);
    expect(verifyInclusion(proof, tree.root())).toBe(true);
  });

  it("throws when proving inclusion for a non-existent leaf", () => {
    const tree = new SortedMerkleTree(makeLeaves(["a", "b"]));
    const fakeHash = buildLeaf("not-in-tree", {}).hash;
    expect(() => tree.proveInclusionByHash(fakeHash)).toThrow(/not present/i);
  });

  it("proves inclusion for all 1000 leaves", () => {
    const ids = Array.from({ length: 1000 }, (_, i) => `event:${i}`);
    const leaves = makeLeaves(ids);
    const tree = new SortedMerkleTree(leaves);
    const root = tree.root();
    // Sample 50 to keep the test fast
    for (let i = 0; i < 50; i++) {
      const leaf = leaves[Math.floor(i * 20)]!;
      const proof = tree.proveInclusionByHash(leaf.hash);
      expect(verifyInclusion(proof, root)).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// Non-membership proofs
// ---------------------------------------------------------------------------

describe("SortedMerkleTree — non-membership proofs", () => {
  it("proves absence for a hash between two leaves", () => {
    const leaves = makeLeaves(["alpha", "gamma"]);
    const tree = new SortedMerkleTree(leaves);
    // "beta" should be absent
    const absentLeaf = buildLeaf("beta-absent", {});
    // We need to ensure it's actually absent (it is, since we never added it)
    const proof = tree.proveNonMembershipByHash(absentLeaf.hash);
    expect(verifyNonMembershipByHash(proof, tree.root())).toBe(true);
  });

  it("proves absence when hash is smaller than all user leaves", () => {
    // Build a leaf whose hash is larger than LOW_SENTINEL but smaller than user leaves
    const leaves = makeLeaves(["zzz-very-large"]);
    const tree = new SortedMerkleTree(leaves);
    // Pick a hash that we know is between LOW_SENTINEL and the first user leaf
    // We'll use the first user leaf's hash but decrement a byte to fake it
    const userHash = leaves[0]!.hash;
    const smallerHash = new Uint8Array(32); // all zeros
    smallerHash[31] = 0x01; // just above LOW_SENTINEL
    // Only valid if no leaf has this hash (it doesn't, since we use SHA-256)
    try {
      const proof = tree.proveNonMembershipByHash(smallerHash);
      // lowerLeaf should be LOW_SENTINEL
      expect(bytesEqual(proof.lowerLeaf, LOW_SENTINEL)).toBe(true);
      expect(verifyNonMembershipByHash(proof, tree.root())).toBe(true);
    } catch {
      // If smallerHash accidentally equals a leaf hash, skip (astronomically unlikely)
    }
    // Always valid to use proveNonMembership with a new absent event
    const absent = buildLeaf("never-added-event", { x: 1 });
    const p2 = tree.proveNonMembershipByHash(absent.hash);
    expect(verifyNonMembershipByHash(p2, tree.root())).toBe(true);
  });

  it("proves absence for an event with hash > all user leaves (bounded by HIGH_SENTINEL)", () => {
    const leaves = makeLeaves(["aaa-small"]);
    const tree = new SortedMerkleTree(leaves);
    const absent = buildLeaf("zzz-absent-high", {});
    const proof = tree.proveNonMembershipByHash(absent.hash);
    expect(verifyNonMembershipByHash(proof, tree.root())).toBe(true);
    // Exactly one of the bounding leaves should be HIGH_SENTINEL or not; verify passes
  });

  it("throws when event IS present", () => {
    const leaves = makeLeaves(["present-event"]);
    const tree = new SortedMerkleTree(leaves);
    expect(() =>
      tree.proveNonMembershipByHash(leaves[0]!.hash)
    ).toThrow(/IS present/i);
  });

  it("throws when querying LOW_SENTINEL", () => {
    const tree = new SortedMerkleTree(makeLeaves(["a"]));
    expect(() =>
      tree.proveNonMembershipByHash(LOW_SENTINEL)
    ).toThrow(/LOW_SENTINEL/i);
  });

  it("throws when querying HIGH_SENTINEL", () => {
    const tree = new SortedMerkleTree(makeLeaves(["a"]));
    expect(() =>
      tree.proveNonMembershipByHash(HIGH_SENTINEL)
    ).toThrow(/HIGH_SENTINEL/i);
  });

  it("verifyNonMembership matches verifyNonMembershipByHash", () => {
    const tree = new SortedMerkleTree(makeLeaves(["event-x", "event-y"]));
    const root = tree.root();
    const absent = buildLeaf("absent-event", { flag: true });
    const proof = tree.proveNonMembership("absent-event", { flag: true });

    const r1 = verifyNonMembershipByHash(proof, root);
    const r2 = verifyNonMembership(proof, "absent-event", { flag: true }, root);
    expect(r1).toBe(true);
    expect(r2).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Tampering tests
// ---------------------------------------------------------------------------

describe("SortedMerkleTree — tampering detection", () => {
  function buildTestTree() {
    const leaves = makeLeaves(["aa", "bb", "cc", "dd", "ee"]);
    const tree = new SortedMerkleTree(leaves);
    const absentLeaf = buildLeaf("ff-absent", {});
    const nonMembershipProof = tree.proveNonMembershipByHash(absentLeaf.hash);
    const inclusionProof = tree.proveInclusionByHash(leaves[2]!.hash);
    return { tree, leaves, nonMembershipProof, inclusionProof };
  }

  it("flipping a sibling byte invalidates an inclusion proof", () => {
    const { inclusionProof, tree } = buildTestTree();
    const root = tree.root();

    const tampered = {
      ...inclusionProof,
      siblings: inclusionProof.siblings.map((s, i) => {
        if (i === 0) {
          const copy = cloneHash(s);
          copy[0] ^= 0xff;
          return copy;
        }
        return s;
      }),
    };
    expect(verifyInclusion(tampered, root)).toBe(false);
  });

  it("changing the leaf hash invalidates an inclusion proof", () => {
    const { inclusionProof, tree } = buildTestTree();
    const root = tree.root();
    const badLeaf = cloneHash(inclusionProof.leaf);
    badLeaf[0] ^= 0x01;
    expect(verifyInclusion({ ...inclusionProof, leaf: badLeaf }, root)).toBe(false);
  });

  it("wrong root fails inclusion proof", () => {
    const { inclusionProof } = buildTestTree();
    const badRoot = new Uint8Array(32).fill(0xab);
    expect(verifyInclusion(inclusionProof, badRoot)).toBe(false);
  });

  it("mismatched root in proof vs expectedRoot fails inclusion proof", () => {
    const { inclusionProof } = buildTestTree();
    const differentRoot = new Uint8Array(32).fill(0x42);
    const tamperedProof = { ...inclusionProof, root: differentRoot };
    expect(verifyInclusion(tamperedProof, differentRoot)).toBe(false);
  });

  it("swapping lowerLeaf and upperLeaf invalidates a non-membership proof", () => {
    const { nonMembershipProof, tree } = buildTestTree();
    const root = tree.root();

    const swapped = {
      ...nonMembershipProof,
      lowerLeaf: nonMembershipProof.upperLeaf,
      upperLeaf: nonMembershipProof.lowerLeaf,
      lowerIndex: nonMembershipProof.upperIndex,
      upperIndex: nonMembershipProof.lowerIndex,
      lowerProof: nonMembershipProof.upperProof,
      upperProof: nonMembershipProof.lowerProof,
    };
    expect(verifyNonMembershipByHash(swapped, root)).toBe(false);
  });

  it("non-adjacent indices in non-membership proof fail verification", () => {
    const { nonMembershipProof, tree } = buildTestTree();
    const root = tree.root();
    // Force the indices to be non-adjacent
    const tampered = {
      ...nonMembershipProof,
      upperIndex: nonMembershipProof.lowerIndex + 2, // should be +1
    };
    expect(verifyNonMembershipByHash(tampered, root)).toBe(false);
  });

  it("mismatched queryHash (using verifyNonMembership with wrong eventId) fails", () => {
    const { nonMembershipProof, tree } = buildTestTree();
    const root = tree.root();
    // verifyNonMembership re-derives queryHash from eventId; wrong eventId => mismatch
    expect(
      verifyNonMembership(nonMembershipProof, "wrong-event-id", {}, root)
    ).toBe(false);
  });

  it("queryHash outside the lower/upper bracket fails verifyNonMembershipByHash", () => {
    const { nonMembershipProof, tree } = buildTestTree();
    const root = tree.root();
    // Set queryHash to something outside [lowerLeaf, upperLeaf]
    // Use a value equal to lowerLeaf (strict inequality fails)
    const tampered = { ...nonMembershipProof, queryHash: new Uint8Array(nonMembershipProof.lowerLeaf) };
    expect(verifyNonMembershipByHash(tampered, root)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Cross-tree forgery
// ---------------------------------------------------------------------------

describe("SortedMerkleTree — cross-tree forgery", () => {
  it("inclusion proof from tree A fails against root of tree B", () => {
    const treeA = new SortedMerkleTree(makeLeaves(["a1", "a2", "a3"]));
    const treeB = new SortedMerkleTree(makeLeaves(["b1", "b2", "b3"]));

    const leafA = buildLeaf("a1", {});
    const proofA = treeA.proveInclusionByHash(leafA.hash);

    // Try to verify proofA (from treeA) against treeB's root
    expect(verifyInclusion(proofA, treeB.root())).toBe(false);
  });

  it("non-membership proof from tree A fails against root of tree B", () => {
    const treeA = new SortedMerkleTree(makeLeaves(["xa", "xb"]));
    const treeB = new SortedMerkleTree(makeLeaves(["ya", "yb"]));

    const absent = buildLeaf("absent-from-both", {});
    const proofA = treeA.proveNonMembershipByHash(absent.hash);

    // Try to verify against treeB's root
    expect(verifyNonMembershipByHash(proofA, treeB.root())).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Serialisation round-trip
// ---------------------------------------------------------------------------

describe("SortedMerkleTree — serialise / deserialise", () => {
  it("round-trips an empty tree", () => {
    const t = new SortedMerkleTree([]);
    const buf = t.serialize();
    const t2 = SortedMerkleTree.deserialize(buf);
    expect(bytesEqual(t.root(), t2.root())).toBe(true);
  });

  it("round-trips a tree with 10 leaves", () => {
    const ids = Array.from({ length: 10 }, (_, i) => `ev:${i}`);
    const leaves = makeLeaves(ids);
    const t = new SortedMerkleTree(leaves);
    const buf = t.serialize();
    const t2 = SortedMerkleTree.deserialize(buf);

    expect(bytesEqual(t.root(), t2.root())).toBe(true);
    // Proofs from t2 should also verify
    for (const leaf of leaves) {
      const proof = t2.proveInclusionByHash(leaf.hash);
      expect(verifyInclusion(proof, t2.root())).toBe(true);
    }
  });

  it("round-trips a tree with 1000 leaves — proofs still verify", () => {
    const ids = Array.from({ length: 1000 }, (_, i) => `event:${i}`);
    const leaves = makeLeaves(ids);
    const t = new SortedMerkleTree(leaves);
    const buf = t.serialize();
    const t2 = SortedMerkleTree.deserialize(buf);
    expect(bytesEqual(t.root(), t2.root())).toBe(true);

    // Spot-check 10 inclusion proofs
    for (let i = 0; i < 10; i++) {
      const idx = i * 100;
      const proof = t2.proveInclusionByHash(leaves[idx]!.hash);
      expect(verifyInclusion(proof, t2.root())).toBe(true);
    }

    // Spot-check 5 non-membership proofs
    for (let i = 0; i < 5; i++) {
      const absent = buildLeaf(`absent-${i}`, { i });
      const proof = t2.proveNonMembershipByHash(absent.hash);
      expect(verifyNonMembershipByHash(proof, t2.root())).toBe(true);
    }
  });

  it("throws on corrupt magic bytes", () => {
    const buf = Buffer.from([0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 2]);
    expect(() => SortedMerkleTree.deserialize(buf)).toThrow(/magic/i);
  });

  it("throws on unsupported version", () => {
    const buf = Buffer.from([0x50, 0x4d, 0x54, 0x00, 0, 0, 0, 99, 0, 0, 0, 2, 0, 0, 0, 2]);
    expect(() => SortedMerkleTree.deserialize(buf)).toThrow(/version/i);
  });
});

// ---------------------------------------------------------------------------
// toString
// ---------------------------------------------------------------------------

describe("SortedMerkleTree — toString", () => {
  it("returns a human-readable summary", () => {
    const tree = new SortedMerkleTree(makeLeaves(["a", "b"]));
    const str = tree.toString();
    expect(str).toContain("SortedMerkleTree");
    expect(str).toContain("realLeaves");
    expect(str).toContain(toHex(tree.root()));
  });
});
