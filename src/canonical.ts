// Copyright 2026 Hive Civilization
// SPDX-License-Identifier: Apache-2.0

/**
 * Canonical JSON serialisation (RFC 8785 / JCS) and SHA-256 leaf hashing.
 *
 * We inline a minimal JCS implementation here to avoid runtime dependencies
 * beyond @noble/hashes. The full RFC 8785 spec is at
 * https://www.rfc-editor.org/rfc/rfc8785
 */

import { sha256 } from "@noble/hashes/sha256";
import type { Hash } from "./types.js";

// ---------------------------------------------------------------------------
// JCS (JSON Canonicalization Scheme) — RFC 8785
// ---------------------------------------------------------------------------

/**
 * Recursively produce the RFC 8785 canonical JSON byte string for any JSON
 * value. The output is deterministic regardless of original key order.
 *
 * Supported types: null, boolean, number (finite), string, array, object.
 * Functions, symbols, undefined values, and BigInts are not supported and
 * will throw.
 */
export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";

  if (typeof value === "number") {
    if (!isFinite(value)) {
      throw new TypeError(
        `canonicalize: non-finite numbers are not allowed in JSON (got ${value})`
      );
    }
    // Reproduce ECMAScript's number-to-string algorithm (same as JSON.stringify).
    return JSON.stringify(value);
  }

  if (typeof value === "string") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    const items = value.map((v) => canonicalize(v));
    return `[${items.join(",")}]`;
  }

  if (typeof value === "object") {
    // Sort object keys lexicographically by Unicode code unit, per RFC 8785 §3.2.3.
    const obj = value as Record<string, unknown>;
    const sortedKeys = Object.keys(obj).sort();
    const pairs = sortedKeys.map(
      (k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`
    );
    return `{${pairs.join(",")}}`;
  }

  throw new TypeError(
    `canonicalize: unsupported type "${typeof value}" (value: ${String(value)})`
  );
}

// ---------------------------------------------------------------------------
// Leaf hashing
// ---------------------------------------------------------------------------

/**
 * The canonical form of a leaf is the JSON object
 *   { "data": <data>, "eventId": <eventId> }
 * with keys in lexicographic order (so "data" comes before "eventId").
 *
 * We wrap the leaf fields explicitly rather than calling canonicalize on the
 * Leaf struct so that the hash is independent of any runtime-added fields.
 */
export function hashLeafData(
  eventId: string,
  data: Readonly<Record<string, unknown>>
): Hash {
  const canonical = canonicalize({ data, eventId });
  const bytes = new TextEncoder().encode(canonical);
  return sha256(bytes);
}

/**
 * Hash a raw byte string directly (for internal node hashing helpers).
 */
export function sha256Bytes(input: Uint8Array): Hash {
  return sha256(input);
}
