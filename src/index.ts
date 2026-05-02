// Copyright 2026 Hive Civilization
// SPDX-License-Identifier: Apache-2.0

/**
 * @hivecivilization/prov-absence
 *
 * Sorted-Merkle non-membership proofs — cryptographic attestations that an
 * event did NOT occur in a given observation window.
 *
 * @see SPEC.md for the formal specification.
 * @see README.md for quick-start and usage examples.
 */

export type {
  Hash,
  Leaf,
  MerkleProof,
  InclusionProof,
  NonMembershipProof,
} from "./types.js";

export {
  SortedMerkleTree,
  LOW_SENTINEL,
  HIGH_SENTINEL,
  bytesEqual,
  toHex,
  fromHex,
} from "./sorted-merkle.js";

export { canonicalize, hashLeafData, sha256Bytes } from "./canonical.js";

export {
  verifyInclusion,
  verifyNonMembership,
  verifyNonMembershipByHash,
} from "./verify.js";

import { hashLeafData } from "./canonical.js";
import type { Leaf } from "./types.js";

/**
 * Synchronously build a Leaf object from an eventId and arbitrary data.
 * This is the standard way to create leaves for SortedMerkleTree.
 *
 * @example
 * const leaf = buildLeaf("llm-call:abc123", { model: "gpt-4o", tokens: 512 });
 * const tree = new SortedMerkleTree([leaf]);
 */
export function buildLeaf(
  eventId: string,
  data: Readonly<Record<string, unknown>> = {}
): Leaf {
  return { eventId, data, hash: hashLeafData(eventId, data) };
}
