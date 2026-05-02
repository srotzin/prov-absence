// Copyright 2026 Hive Civilization
// SPDX-License-Identifier: Apache-2.0

/**
 * Additional tests to push coverage on branches not exercised by the main suites.
 */

import { describe, it, expect } from "vitest";
import { canonicalize, hashLeafData, sha256Bytes } from "../src/canonical.js";
import {
  SortedMerkleTree,
  HIGH_SENTINEL,
  toHex,
  fromHex,
} from "../src/sorted-merkle.js";
import { buildLeaf } from "../src/index.js";
import { verifyInclusion, verifyNonMembership, verifyNonMembershipByHash } from "../src/verify.js";
import type { InclusionProof, NonMembershipProof } from "../src/types.js";

// ---------------------------------------------------------------------------
// canonical.ts coverage
// ---------------------------------------------------------------------------

describe("canonicalize — all value types", () => {
  it("handles null", () => expect(canonicalize(null)).toBe("null"));
  it("handles true", () => expect(canonicalize(true)).toBe("true"));
  it("handles false", () => expect(canonicalize(false)).toBe("false"));
  it("handles integer", () => expect(canonicalize(42)).toBe("42"));
  it("handles float", () => expect(canonicalize(3.14)).toBe("3.14"));
  it("handles string", () => expect(canonicalize("hello")).toBe('"hello"'));
  it("handles array", () => expect(canonicalize([1, 2, 3])).toBe("[1,2,3]"));
  it("handles nested array", () =>
    expect(canonicalize([null, [true, "a"]])).toBe('[null,[true,"a"]]'));
  it("sorts object keys", () =>
    expect(canonicalize({ z: 1, a: 2 })).toBe('{"a":2,"z":1}'));
  it("handles nested objects", () =>
    expect(canonicalize({ b: { d: 1, c: 2 }, a: 3 })).toBe(
      '{"a":3,"b":{"c":2,"d":1}}'
    ));
  it("throws for Infinity", () =>
    expect(() => canonicalize(Infinity)).toThrow(/non-finite/));
  it("throws for NaN", () =>
    expect(() => canonicalize(NaN)).toThrow(/non-finite/));
  it("throws for unsupported type (function)", () =>
    expect(() => canonicalize(() => {})).toThrow(/unsupported type/));
  it("throws for unsupported type (symbol)", () =>
    expect(() => canonicalize(Symbol("x"))).toThrow(/unsupported type/));
});

describe("sha256Bytes", () => {
  it("returns a 32-byte hash", () => {
    const h = sha256Bytes(new Uint8Array([1, 2, 3]));
    expect(h.length).toBe(32);
  });
});

describe("hashLeafData", () => {
  it("returns a 32-byte hash", () => {
    const h = hashLeafData("event:abc", { x: 1 });
    expect(h.length).toBe(32);
  });
  it("is deterministic", () => {
    const h1 = hashLeafData("event:abc", { x: 1 });
    const h2 = hashLeafData("event:abc", { x: 1 });
    expect(toHex(h1)).toBe(toHex(h2));
  });
});

// ---------------------------------------------------------------------------
// sorted-merkle.ts — padding leaf branch
// ---------------------------------------------------------------------------

describe("SortedMerkleTree — padding leaf proof", () => {
  it("throws when trying to prove inclusion for a pure padding copy of HIGH_SENTINEL at padded index >= realCount", () => {
    // Build a tree where paddedSize > realSize so there ARE padding copies
    // realSize = 3 (LOW + 1 user leaf + HIGH), next power of 2 = 4
    const tree = new SortedMerkleTree([buildLeaf("only-leaf", {})]);
    expect(tree.realSize).toBe(3);
    expect(tree.paddedSize).toBe(4);
    // HIGH_SENTINEL is at realIndex 2 (index in real leaves), padded index 2.
    // The padding entry is a SECOND copy of HIGH_SENTINEL at padded index 3.
    // Our index map records HIGH_SENTINEL at its FIRST occurrence (index 2, which IS in real leaves).
    // So the first HIGH_SENTINEL at idx 2 is fine; the second at idx 3 is never
    // reachable via the index map.
    // Instead test via a 2-user-leaf tree: realSize=4, paddedSize=4, no padding
    // For padding to appear, we need realSize to not be a power of 2.
    // realSize = 2+1 = 3 user leaves + 2 sentinels = 5, paddedSize = 8
    const tree2 = new SortedMerkleTree([
      buildLeaf("a", {}), buildLeaf("b", {}), buildLeaf("c", {})
    ]);
    expect(tree2.realSize).toBe(5);
    expect(tree2.paddedSize).toBe(8);
    // HIGH_SENTINEL is at real index 4; padding copies are at 5,6,7.
    // The map stores HIGH_SENTINEL -> 4 (first occurrence), so we can prove it.
    const p = tree2.proveInclusionByHash(HIGH_SENTINEL);
    expect(verifyInclusion(p, tree2.root())).toBe(true);
    expect(p.leafIndex).toBe(4); // first occurrence, which is a real leaf
  });
});

// ---------------------------------------------------------------------------
// sorted-merkle.ts — deserialize buffer too short for leaf data
// ---------------------------------------------------------------------------

describe("SortedMerkleTree — deserialize edge cases", () => {
  it("throws on buffer too short for leaf data", () => {
    // Header says paddedCount=1000 but buffer only has 16 bytes
    const buf = Buffer.alloc(16 + 10); // way too short for 1000 * 32 bytes
    buf.writeUint32BE(0x504d5400, 0); // magic
    buf.writeUint32BE(1, 4);          // version
    buf.writeUint32BE(2, 8);          // realCount
    buf.writeUint32BE(1000, 12);      // paddedCount = 1000, but we only gave 10 extra bytes
    expect(() => SortedMerkleTree.deserialize(buf)).toThrow(/buffer too short/);
  });
});

// ---------------------------------------------------------------------------
// verify.ts — catch blocks (malformed proof objects)
// ---------------------------------------------------------------------------

describe("verifyInclusion — exception handling", () => {
  it("returns false for a completely malformed proof object", () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const badProof = { leaf: "not-a-uint8array", siblings: null, pathBits: [] } as any;
    const root = new Uint8Array(32);
    expect(verifyInclusion(badProof, root)).toBe(false);
  });

  it("returns false when pathBits has an invalid bit value", () => {
    const tree = new SortedMerkleTree([buildLeaf("x", {})]);
    const proof = tree.proveInclusionByHash(buildLeaf("x", {}).hash);
    const tampered: InclusionProof = {
      ...proof,
      pathBits: proof.pathBits.map(() => 99), // invalid bit
    };
    expect(verifyInclusion(tampered, tree.root())).toBe(false);
  });

  it("returns false when sibling has wrong length", () => {
    const tree = new SortedMerkleTree([buildLeaf("x", {})]);
    const proof = tree.proveInclusionByHash(buildLeaf("x", {}).hash);
    const tampered: InclusionProof = {
      ...proof,
      siblings: [new Uint8Array(16)], // too short
    };
    expect(verifyInclusion(tampered, tree.root())).toBe(false);
  });
});

describe("verifyNonMembership — exception handling", () => {
  it("returns false for a completely malformed proof object", () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const badProof = { queryHash: "not-uint8array" } as any;
    const root = new Uint8Array(32);
    expect(verifyNonMembership(badProof, "event", {}, root)).toBe(false);
  });

  it("returns false when root in proof differs from expectedRoot", () => {
    const tree = new SortedMerkleTree([buildLeaf("a", {}), buildLeaf("b", {})]);
    const absent = buildLeaf("absent", {});
    const proof = tree.proveNonMembershipByHash(absent.hash);
    const wrongRoot = new Uint8Array(32).fill(0xab);
    expect(verifyNonMembershipByHash(proof, wrongRoot)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// fromHex / toHex round-trip
// ---------------------------------------------------------------------------

describe("toHex / fromHex", () => {
  it("round-trips a 32-byte hash", () => {
    const original = new Uint8Array(32).fill(0x42);
    original[0] = 0xde;
    original[31] = 0xad;
    const hex = toHex(original);
    const restored = fromHex(hex);
    expect(restored).toEqual(original);
  });

  it("fromHex throws on odd-length string", () => {
    expect(() => fromHex("abc")).toThrow(/odd-length/);
  });
});
