// Copyright 2026 Hive Civilization
// SPDX-License-Identifier: Apache-2.0

/**
 * A 32-byte SHA-256 digest.
 */
export type Hash = Uint8Array;

/**
 * A single observed event that can be committed to a SortedMerkleTree.
 */
export interface Leaf {
  /** Stable, unique identifier for the event (e.g. "llm-call:uuid:..."). */
  readonly eventId: string;
  /** Arbitrary structured data attached to the event. */
  readonly data: Readonly<Record<string, unknown>>;
  /** SHA-256 of the canonical JSON serialisation of { eventId, data }. */
  readonly hash: Hash;
}

/**
 * A Merkle authentication path from a leaf up to the root.
 *
 * - `siblings[i]` is the sibling node at depth `i` (0 = leaf level).
 * - `pathBits[i]` is 0 if the current node is the LEFT child at depth `i`,
 *   1 if it is the RIGHT child.
 * - `leafIndex` is the 0-based position of the leaf in the padded leaf array.
 * - `root` is the tree root at the time the proof was generated.
 */
export interface MerkleProof {
  readonly siblings: readonly Hash[];
  readonly pathBits: readonly number[];
  readonly leafIndex: number;
  readonly root: Hash;
}

/**
 * A proof that a specific leaf hash is included in the Merkle tree.
 */
export interface InclusionProof extends MerkleProof {
  /** The 32-byte hash of the committed leaf. */
  readonly leaf: Hash;
}

/**
 * A proof that an event identified by `queryHash` is NOT a member of the tree.
 *
 * The proof consists of two adjacent leaves `lowerLeaf` and `upperLeaf` such
 * that `lowerLeaf < queryHash < upperLeaf`, together with inclusion proofs for
 * both. Because the tree is sorted and the leaves are adjacent, there is no
 * room for `queryHash` to exist in the tree.
 */
export interface NonMembershipProof {
  /** SHA-256 of the queried event's canonical serialisation. */
  readonly queryHash: Hash;
  /** The largest committed leaf hash strictly less than `queryHash`. */
  readonly lowerLeaf: Hash;
  /** The smallest committed leaf hash strictly greater than `queryHash`. */
  readonly upperLeaf: Hash;
  /** 0-based index of `lowerLeaf` in the padded leaf array. */
  readonly lowerIndex: number;
  /** 0-based index of `upperLeaf` in the padded leaf array. */
  readonly upperIndex: number;
  /** Merkle inclusion proof for `lowerLeaf`. */
  readonly lowerProof: InclusionProof;
  /** Merkle inclusion proof for `upperLeaf`. */
  readonly upperProof: InclusionProof;
  /** Tree root at the time the proof was generated. */
  readonly root: Hash;
}
