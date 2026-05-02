#!/usr/bin/env node
// Copyright 2026 Hive Civilization
// SPDX-License-Identifier: Apache-2.0

/**
 * prov-absence CLI
 *
 * Commands:
 *   build <events.jsonl>                         Build a tree from a JSONL file
 *   prove-inclusion <event-id> [--data <json>]   Prove a leaf is present
 *   prove-absence <event-id> [--data <json>]     Prove a leaf is absent
 *   verify-inclusion <proof.json> <root-hex>     Verify an inclusion proof
 *   verify-absence <proof.json> <event-id> <root-hex>   Verify absence proof
 *
 * JSONL format: one JSON object per line, each with at minimum { "eventId": "..." }
 * plus optional "data" field.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { buildLeaf } from "./index.js";
import { hashLeafData } from "./canonical.js";
import { SortedMerkleTree, toHex, fromHex } from "./sorted-merkle.js";
import {
  verifyInclusion,
  verifyNonMembership,
} from "./verify.js";
import type { InclusionProof, NonMembershipProof, Hash } from "./types.js";

// ---------------------------------------------------------------------------
// JSON serialisation helpers for proofs (Uint8Array ↔ hex string)
// ---------------------------------------------------------------------------

function hashToHex(h: Hash): string {
  return toHex(h);
}

function hexToHash(s: string): Hash {
  return fromHex(s);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function proofToJSON(proof: InclusionProof | NonMembershipProof): any {
  return JSON.parse(
    JSON.stringify(proof, (_key, value: unknown) => {
      if (value instanceof Uint8Array) return hashToHex(value);
      return value;
    })
  );
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function inclusionProofFromJSON(obj: any): InclusionProof {
  return {
    leaf: hexToHash(obj.leaf as string),
    siblings: (obj.siblings as string[]).map(hexToHash),
    pathBits: obj.pathBits as number[],
    leafIndex: obj.leafIndex as number,
    root: hexToHash(obj.root as string),
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function nonMembershipProofFromJSON(obj: any): NonMembershipProof {
  return {
    queryHash: hexToHash(obj.queryHash as string),
    lowerLeaf: hexToHash(obj.lowerLeaf as string),
    upperLeaf: hexToHash(obj.upperLeaf as string),
    lowerIndex: obj.lowerIndex as number,
    upperIndex: obj.upperIndex as number,
    lowerProof: inclusionProofFromJSON(obj.lowerProof),
    upperProof: inclusionProofFromJSON(obj.upperProof),
    root: hexToHash(obj.root as string),
  };
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

function cmdBuild(eventsPath: string): void {
  const abs = resolve(eventsPath);
  const lines = readFileSync(abs, "utf8")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  const leaves = lines.map((line) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const obj = JSON.parse(line) as { eventId: string; data?: Record<string, unknown> };
    if (typeof obj.eventId !== "string") {
      throw new Error(`build: each JSONL line must have an "eventId" string field. Got: ${line}`);
    }
    return buildLeaf(obj.eventId, obj.data ?? {});
  });

  const tree = new SortedMerkleTree(leaves);
  const buf = tree.serialize();

  writeFileSync("tree.bin", buf);
  const rootHex = toHex(tree.root());
  writeFileSync("root.txt", rootHex + "\n");

  process.stdout.write(
    `Built tree from ${leaves.length} events.\n` +
    `  Real leaves (with sentinels): ${tree.realSize}\n` +
    `  Padded leaves:                ${tree.paddedSize}\n` +
    `  Root:                         ${rootHex}\n` +
    `  Wrote: tree.bin, root.txt\n`
  );
}

function cmdProveInclusion(eventId: string, dataJson: string | undefined): void {
  const treeBuf = readFileSync("tree.bin");
  const tree = SortedMerkleTree.deserialize(treeBuf);

  const data: Record<string, unknown> = dataJson ? JSON.parse(dataJson) : {};
  const leafHash = hashLeafData(eventId, data);

  const proof = tree.proveInclusionByHash(leafHash);
  process.stdout.write(JSON.stringify(proofToJSON(proof), null, 2) + "\n");
}

function cmdProveAbsence(eventId: string, dataJson: string | undefined): void {
  const treeBuf = readFileSync("tree.bin");
  const tree = SortedMerkleTree.deserialize(treeBuf);

  const data: Record<string, unknown> = dataJson ? JSON.parse(dataJson) : {};
  const proof = tree.proveNonMembership(eventId, data);
  process.stdout.write(JSON.stringify(proofToJSON(proof), null, 2) + "\n");
}

function cmdVerifyInclusion(proofPath: string, expectedRootHex: string): void {
  const proofObj = JSON.parse(readFileSync(resolve(proofPath), "utf8"));
  const proof = inclusionProofFromJSON(proofObj);
  const expectedRoot = hexToHash(expectedRootHex);

  const valid = verifyInclusion(proof, expectedRoot);
  if (valid) {
    process.stdout.write("VALID: inclusion proof verified.\n");
    process.exit(0);
  } else {
    process.stderr.write("INVALID: inclusion proof failed verification.\n");
    process.exit(1);
  }
}

function cmdVerifyAbsence(
  proofPath: string,
  eventId: string,
  dataJson: string | undefined,
  expectedRootHex: string
): void {
  const proofObj = JSON.parse(readFileSync(resolve(proofPath), "utf8"));
  const proof = nonMembershipProofFromJSON(proofObj);
  const expectedRoot = hexToHash(expectedRootHex);
  const data: Record<string, unknown> = dataJson ? JSON.parse(dataJson) : {};

  const valid = verifyNonMembership(proof, eventId, data, expectedRoot);
  if (valid) {
    process.stdout.write(`VALID: "${eventId}" is proven absent.\n`);
    process.exit(0);
  } else {
    process.stderr.write(`INVALID: absence proof for "${eventId}" failed verification.\n`);
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

function printUsage(): void {
  process.stdout.write(
    `prov-absence — sorted-Merkle non-membership proof tool
Copyright 2026 Hive Civilization — Apache 2.0

Usage:
  prov-absence build <events.jsonl>
  prov-absence prove-inclusion <event-id> [--data <json-object>]
  prov-absence prove-absence   <event-id> [--data <json-object>]
  prov-absence verify-inclusion <proof.json> <root-hex>
  prov-absence verify-absence   <proof.json> <event-id> <root-hex> [--data <json>]

JSONL format: one JSON object per line with at minimum { "eventId": "..." }.
The optional "data" field contains arbitrary event metadata.
tree.bin and root.txt are read/written in the current working directory.
`
  );
}

const args = process.argv.slice(2);
const command = args[0];

try {
  switch (command) {
    case "build": {
      if (!args[1]) { printUsage(); process.exit(1); }
      cmdBuild(args[1]);
      break;
    }
    case "prove-inclusion": {
      if (!args[1]) { printUsage(); process.exit(1); }
      const dataIdx = args.indexOf("--data");
      const dataJson = dataIdx >= 0 ? args[dataIdx + 1] : undefined;
      cmdProveInclusion(args[1], dataJson);
      break;
    }
    case "prove-absence": {
      if (!args[1]) { printUsage(); process.exit(1); }
      const dataIdx = args.indexOf("--data");
      const dataJson = dataIdx >= 0 ? args[dataIdx + 1] : undefined;
      cmdProveAbsence(args[1], dataJson);
      break;
    }
    case "verify-inclusion": {
      if (!args[1] || !args[2]) { printUsage(); process.exit(1); }
      cmdVerifyInclusion(args[1], args[2]);
      break;
    }
    case "verify-absence": {
      // verify-absence <proof.json> <event-id> <root-hex> [--data <json>]
      if (!args[1] || !args[2] || !args[3]) { printUsage(); process.exit(1); }
      const dataIdx = args.indexOf("--data");
      const dataJson = dataIdx >= 0 ? args[dataIdx + 1] : undefined;
      cmdVerifyAbsence(args[1], args[2], dataJson, args[3]);
      break;
    }
    default: {
      printUsage();
      if (command) {
        process.stderr.write(`Unknown command: ${command}\n`);
        process.exit(1);
      }
      process.exit(0);
    }
  }
} catch (err) {
  process.stderr.write(
    `Error: ${err instanceof Error ? err.message : String(err)}\n`
  );
  process.exit(1);
}
