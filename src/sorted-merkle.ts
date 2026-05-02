// Copyright 2026 Hive Civilization
// SPDX-License-Identifier: Apache-2.0

/**
 * SortedMerkleTree — a Merkle tree whose leaves are kept in lexicographically
 * sorted order by their 32-byte hash, enabling cryptographic non-membership
 * proofs ("I did NOT see X in this window").
 *
 * ## Tree structure
 *
 * 1. Each observed event produces a 32-byte leaf hash via `hashLeafData`.
 * 2. Two sentinel leaves are prepended/appended:
 *    - LOW_SENTINEL  = 0x00 * 32  (always the smallest possible hash)
 *    - HIGH_SENTINEL = 0xff * 32  (always the largest possible hash)
 * 3. Leaves are sorted lexicographically: LOW_SENTINEL, ...user leaves...,
 *    HIGH_SENTINEL.
 * 4. The leaf array is padded with copies of HIGH_SENTINEL to reach the next
 *    power-of-2 length.
 * 5. Internal nodes are hashed with domain separation:
 *    - Leaf node:     SHA-256( 0x00 || leafHash )
 *    - Internal node: SHA-256( 0x01 || left || right )
 *    This prevents second-preimage attacks where an attacker could present an
 *    internal node as a leaf or vice-versa.
 *
 * ## Non-membership proof
 *
 * To prove event X is absent, locate the two adjacent leaves (L_i, L_{i+1})
 * such that L_i < hash(X) < L_{i+1}. Return inclusion proofs for both.
 * Because the tree is sorted and the leaves are adjacent (no gap), X cannot
 * appear anywhere in the tree.
 *
 * @see SPEC.md for the full formal specification.
 */

import { sha256 } from "@noble/hashes/sha256";
import { hashLeafData } from "./canonical.js";
import type {
  Hash,
  InclusionProof,
  Leaf,
  MerkleProof,
  NonMembershipProof,
} from "./types.js";

// ---------------------------------------------------------------------------
// Sentinel constants
// ---------------------------------------------------------------------------

/** The smallest possible 32-byte hash value. Always the first leaf. */
export const LOW_SENTINEL: Hash = new Uint8Array(32).fill(0x00);

/** The largest possible 32-byte hash value. Always the last real leaf. */
export const HIGH_SENTINEL: Hash = new Uint8Array(32).fill(0xff);

// ---------------------------------------------------------------------------
// Domain-separated hashing helpers
// ---------------------------------------------------------------------------

const LEAF_PREFIX = new Uint8Array([0x00]);
const NODE_PREFIX = new Uint8Array([0x01]);

/** Hash a leaf using the domain-separated leaf prefix. */
function hashLeafNode(leafHash: Hash): Hash {
  const input = new Uint8Array(1 + 32);
  input.set(LEAF_PREFIX, 0);
  input.set(leafHash, 1);
  return sha256(input);
}

/** Hash two child nodes into a parent using the domain-separated node prefix. */
function hashInternalNode(left: Hash, right: Hash): Hash {
  const input = new Uint8Array(1 + 32 + 32);
  input.set(NODE_PREFIX, 0);
  input.set(left, 1);
  input.set(right, 33);
  return sha256(input);
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/** Lexicographic comparison of two equal-length byte arrays. Returns <0, 0, >0. */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const diff = (a[i] as number) - (b[i] as number);
    if (diff !== 0) return diff;
  }
  return a.length - b.length;
}

/** Deep equality check for two byte arrays. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/** Hex-encode a byte array. */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Hex-decode a string to bytes. */
export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("fromHex: odd-length hex string");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Smallest power of 2 >= n (minimum 1). */
function nextPow2(n: number): number {
  if (n <= 1) return 1;
  let p = 1;
  while (p < n) p <<= 1;
  return p;
}

// ---------------------------------------------------------------------------
// SortedMerkleTree
// ---------------------------------------------------------------------------

export class SortedMerkleTree {
  /**
   * Sorted, padded leaf hashes (length is a power of 2).
   * Index 0 = LOW_SENTINEL, last real leaf = HIGH_SENTINEL, trailing = padding.
   */
  private readonly _leaves: readonly Hash[];

  /**
   * Number of real leaves (sentinels + user leaves, before padding).
   * paddedLeaves.slice(0, _realCount) are the canonical sorted leaves.
   */
  private readonly _realCount: number;

  /**
   * Pre-computed Merkle tree stored as a flat array.
   * Layer 0 (bottom): hashed leaf nodes, length = paddedLeafCount
   * Layer 1: length = paddedLeafCount / 2
   * ...
   * Layer k (root): length = 1
   *
   * _tree[layerIndex][nodeIndex]
   */
  private readonly _tree: readonly (readonly Hash[])[];

  /**
   * Map from hex(leafHash) → paddedLeafIndex for fast lookup.
   */
  private readonly _leafIndex: ReadonlyMap<string, number>;

  // -------------------------------------------------------------------------
  // Construction
  // -------------------------------------------------------------------------

  /**
   * Build a SortedMerkleTree from an array of Leaf objects.
   *
   * @param leaves  Events to commit. May be empty. Order does not matter.
   * @throws        If any two leaves share the same eventId.
   */
  constructor(leaves: readonly Leaf[]) {
    // 1. Collect user leaf hashes.
    const userHashes: Hash[] = leaves.map((l) => l.hash);

    // 2. Sort user hashes lexicographically.
    userHashes.sort(compareBytes);

    // 3. Deduplicate (identical hashes are not allowed — they would break
    //    the adjacency invariant and likely indicate a programming error).
    for (let i = 1; i < userHashes.length; i++) {
      if (bytesEqual(userHashes[i - 1] as Hash, userHashes[i] as Hash)) {
        throw new Error(
          `SortedMerkleTree: duplicate leaf hash ${toHex(userHashes[i] as Hash)}`
        );
      }
    }

    // 4. Prepend LOW_SENTINEL and append HIGH_SENTINEL.
    const realLeaves: Hash[] = [LOW_SENTINEL, ...userHashes, HIGH_SENTINEL];
    this._realCount = realLeaves.length;

    // 5. Pad to the next power of 2 by appending copies of HIGH_SENTINEL.
    //    Padding leaves are NOT real leaves; they do not appear in proofs
    //    as candidates for non-membership bounds. They exist only to make
    //    the tree a perfect binary tree.
    const paddedCount = nextPow2(this._realCount);
    const paddedLeaves: Hash[] = [...realLeaves];
    while (paddedLeaves.length < paddedCount) {
      paddedLeaves.push(HIGH_SENTINEL);
    }
    this._leaves = paddedLeaves;

    // 6. Build index map (only for real leaves).
    const idx = new Map<string, number>();
    for (let i = 0; i < paddedLeaves.length; i++) {
      const h = paddedLeaves[i] as Hash;
      const key = toHex(h);
      // Only record the first occurrence; padding duplicates are intentionally
      // ignored for the purpose of proof generation.
      if (!idx.has(key)) {
        idx.set(key, i);
      }
    }
    this._leafIndex = idx;

    // 7. Compute the tree bottom-up.
    this._tree = SortedMerkleTree._buildTree(paddedLeaves);
  }

  /** Build the multi-layer tree array from the padded leaf hashes. */
  private static _buildTree(
    paddedLeaves: readonly Hash[]
  ): readonly (readonly Hash[])[] {
    const layers: Hash[][] = [];

    // Layer 0: apply leaf-node hashing with domain separation.
    const leafLayer = paddedLeaves.map(hashLeafNode);
    layers.push(leafLayer);

    let current = leafLayer;
    while (current.length > 1) {
      const next: Hash[] = [];
      for (let i = 0; i < current.length; i += 2) {
        next.push(
          hashInternalNode(current[i] as Hash, current[i + 1] as Hash)
        );
      }
      layers.push(next);
      current = next;
    }

    return layers;
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /** The Merkle root of this tree. */
  root(): Hash {
    const rootLayer = this._tree[this._tree.length - 1];
    if (!rootLayer || rootLayer.length === 0) {
      throw new Error("SortedMerkleTree: tree is empty (internal error)");
    }
    return rootLayer[0] as Hash;
  }

  /** Total number of padded leaves (power of 2). */
  get paddedSize(): number {
    return this._leaves.length;
  }

  /** Number of real leaves including sentinels. */
  get realSize(): number {
    return this._realCount;
  }

  /**
   * Prove that an event is included in the tree.
   *
   * @param eventId  The event identifier to look up.
   * @throws         If the event is not present in the tree.
   */
  proveInclusion(eventId: string): InclusionProof {
    // We need the leaf hash to look it up in the index.
    // We search the real leaves for a match by eventId through the hash.
    // Since we only store hashes, we recompute from the leaf array passed to
    // the constructor — but wait, the constructor only takes Leaf[].
    // We need to find the leaf whose hash we know.
    //
    // Actually: the index maps leafHash -> paddedIndex. To prove inclusion by
    // eventId, we need the Leaf object. We keep a separate eventId map.
    throw new Error(
      "proveInclusion by eventId requires a Leaf lookup. Use proveInclusionByHash or rebuild from Leaf[]."
    );
  }

  /**
   * Prove that a specific leaf hash is included in the tree.
   *
   * @param leafHash  32-byte hash to prove inclusion for.
   * @throws          If the hash is not a real leaf in this tree.
   */
  proveInclusionByHash(leafHash: Hash): InclusionProof {
    const key = toHex(leafHash);
    const leafIdx = this._leafIndex.get(key);
    if (leafIdx === undefined) {
      throw new Error(
        `proveInclusionByHash: leaf ${key} is not present in this tree`
      );
    }
    // Only allow proofs for real leaves (not pure padding beyond _realCount).
    if (leafIdx >= this._realCount) {
      throw new Error(
        `proveInclusionByHash: leaf ${key} is a padding leaf, not a real leaf`
      );
    }
    return {
      ...this._buildMerkleProof(leafIdx),
      leaf: leafHash,
    };
  }

  /**
   * Build an inclusion proof for the leaf at `paddedIndex`.
   */
  private _buildMerkleProof(paddedIndex: number): MerkleProof {
    const depth = this._tree.length - 1; // number of layers above leaf layer
    const siblings: Hash[] = [];
    const pathBits: number[] = [];

    let idx = paddedIndex;
    for (let layer = 0; layer < depth; layer++) {
      const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
      const layerNodes = this._tree[layer] as readonly Hash[];
      siblings.push(layerNodes[siblingIdx] as Hash);
      pathBits.push(idx % 2); // 0 = left child, 1 = right child
      idx = Math.floor(idx / 2);
    }

    return {
      siblings,
      pathBits,
      leafIndex: paddedIndex,
      root: this.root(),
    };
  }

  /**
   * Prove that an event is NOT a member of this tree.
   *
   * @param queryHash  SHA-256 of the queried event's canonical serialisation.
   * @throws           If the event IS present (use proveInclusionByHash instead).
   * @throws           If the query hash equals LOW_SENTINEL or HIGH_SENTINEL.
   */
  proveNonMembershipByHash(queryHash: Hash): NonMembershipProof {
    const key = toHex(queryHash);

    // Reject sentinels as query targets.
    if (bytesEqual(queryHash, LOW_SENTINEL)) {
      throw new Error(
        "proveNonMembershipByHash: queryHash equals LOW_SENTINEL (0x00...00)"
      );
    }
    if (bytesEqual(queryHash, HIGH_SENTINEL)) {
      throw new Error(
        "proveNonMembershipByHash: queryHash equals HIGH_SENTINEL (0xff...ff)"
      );
    }

    // Reject if the leaf IS present.
    if (this._leafIndex.has(key)) {
      throw new Error(
        `proveNonMembershipByHash: event ${key} IS present in this tree; use proveInclusionByHash instead`
      );
    }

    // Binary search through the real leaves to find the bracketing pair.
    // The real leaves (indices 0.._realCount-1) are sorted.
    // We find the largest real index i such that realLeaf[i] < queryHash.
    let lo = 0;
    let hi = this._realCount - 1; // inclusive

    while (lo < hi - 1) {
      const mid = (lo + hi) >> 1;
      const midLeaf = this._leaves[mid] as Hash;
      if (compareBytes(midLeaf, queryHash) < 0) {
        lo = mid;
      } else {
        hi = mid;
      }
    }

    // After the loop: _leaves[lo] < queryHash < _leaves[hi]
    // (guaranteed because LOW_SENTINEL ≤ all and HIGH_SENTINEL ≥ all)
    const lowerIndex = lo;
    const upperIndex = hi;
    const lowerLeaf = this._leaves[lowerIndex] as Hash;
    const upperLeaf = this._leaves[upperIndex] as Hash;

    const lowerProof: InclusionProof = {
      ...this._buildMerkleProof(lowerIndex),
      leaf: lowerLeaf,
    };
    const upperProof: InclusionProof = {
      ...this._buildMerkleProof(upperIndex),
      leaf: upperLeaf,
    };

    return {
      queryHash,
      lowerLeaf,
      upperLeaf,
      lowerIndex,
      upperIndex,
      lowerProof,
      upperProof,
      root: this.root(),
    };
  }

  /**
   * Convenience wrapper: hash the event data and call `proveNonMembershipByHash`.
   *
   * @param eventId  Event ID to prove absent.
   * @param data     Event data (must match what would be used when building).
   */
  proveNonMembership(
    eventId: string,
    data: Readonly<Record<string, unknown>> = {}
  ): NonMembershipProof {
    const queryHash = hashLeafData(eventId, data);
    return this.proveNonMembershipByHash(queryHash);
  }

  // -------------------------------------------------------------------------
  // Serialisation
  // -------------------------------------------------------------------------

  /**
   * Serialise the tree to a compact binary format.
   *
   * Format:
   *   [4 bytes: magic 0x504D5400 "PMT\0"]
   *   [4 bytes: version = 1, big-endian uint32]
   *   [4 bytes: realCount, big-endian uint32]
   *   [4 bytes: paddedCount, big-endian uint32]
   *   [paddedCount * 32 bytes: padded leaf hashes in order]
   */
  serialize(): Buffer {
    const magic = Buffer.from([0x50, 0x4d, 0x54, 0x00]); // "PMT\0"
    const version = Buffer.alloc(4);
    version.writeUint32BE(1, 0);
    const realCount = Buffer.alloc(4);
    realCount.writeUint32BE(this._realCount, 0);
    const paddedCount = Buffer.alloc(4);
    paddedCount.writeUint32BE(this._leaves.length, 0);

    const leafData = Buffer.alloc(this._leaves.length * 32);
    for (let i = 0; i < this._leaves.length; i++) {
      leafData.set(this._leaves[i] as Hash, i * 32);
    }

    return Buffer.concat([magic, version, realCount, paddedCount, leafData]);
  }

  /**
   * Deserialise a tree from the binary format produced by `serialize`.
   * The tree is reconstructed from leaves only; all proof machinery is rebuilt.
   */
  static deserialize(buf: Buffer): SortedMerkleTree {
    if (buf.length < 16) throw new Error("deserialize: buffer too short");

    const magic = buf.readUint32BE(0);
    if (magic !== 0x504d5400) {
      throw new Error(
        `deserialize: invalid magic bytes (expected 0x504D5400, got 0x${magic.toString(16).toUpperCase()})`
      );
    }

    const version = buf.readUint32BE(4);
    if (version !== 1) {
      throw new Error(
        `deserialize: unsupported version ${version} (only version 1 is supported)`
      );
    }

    const realCount = buf.readUint32BE(8);
    const paddedCount = buf.readUint32BE(12);

    if (buf.length < 16 + paddedCount * 32) {
      throw new Error("deserialize: buffer too short for leaf data");
    }

    // Read padded leaves.
    const paddedLeaves: Hash[] = [];
    for (let i = 0; i < paddedCount; i++) {
      const leaf = new Uint8Array(32);
      buf.copy(leaf, 0, 16 + i * 32, 16 + (i + 1) * 32);
      paddedLeaves.push(leaf);
    }

    // Reconstruct directly (bypass normal constructor to avoid re-sorting).
    return SortedMerkleTree._fromPaddedLeaves(paddedLeaves, realCount);
  }

  /**
   * Reconstruct a SortedMerkleTree from a pre-sorted, pre-padded leaf array.
   * Used internally by deserialize.
   */
  private static _fromPaddedLeaves(
    paddedLeaves: readonly Hash[],
    realCount: number
  ): SortedMerkleTree {
    // Use Object.create to bypass the constructor's sorting logic.
    // We use `unknown` casts to assign to private fields from a static method.
    const t = Object.create(SortedMerkleTree.prototype) as unknown;
    (t as { _leaves: readonly Hash[] })._leaves = paddedLeaves;
    (t as { _realCount: number })._realCount = realCount;
    (t as { _tree: readonly (readonly Hash[])[] })._tree =
      SortedMerkleTree._buildTree(paddedLeaves);

    const idx = new Map<string, number>();
    for (let i = 0; i < paddedLeaves.length; i++) {
      const h = paddedLeaves[i] as Hash;
      const key = toHex(h);
      if (!idx.has(key)) idx.set(key, i);
    }
    (t as { _leafIndex: ReadonlyMap<string, number> })._leafIndex = idx;
    return t as SortedMerkleTree;
  }

  // -------------------------------------------------------------------------
  // Debug helpers
  // -------------------------------------------------------------------------

  /** Return a human-readable summary of the tree structure. */
  toString(): string {
    const lines: string[] = [
      `SortedMerkleTree {`,
      `  realLeaves:   ${this._realCount}`,
      `  paddedLeaves: ${this._leaves.length}`,
      `  depth:        ${this._tree.length - 1}`,
      `  root:         ${toHex(this.root())}`,
      `}`,
    ];
    return lines.join("\n");
  }
}
