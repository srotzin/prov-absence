#!/usr/bin/env tsx
// Copyright 2026 Hive Civilization
// SPDX-License-Identifier: Apache-2.0

/**
 * audit-window.ts
 *
 * Demonstration: simulate 10,000 LLM calls in a 1-hour observation window,
 * build a SortedMerkleTree over those calls, then prove that a specific
 * "malicious" event ID was NOT observed in that window.
 *
 * This is the answer to: "what does @hivecivilization/prov-absence buy you?"
 *
 * Run: npx tsx examples/audit-window.ts
 */

import { SortedMerkleTree, toHex } from "../src/sorted-merkle.js";
import { buildLeaf } from "../src/index.js";
import { verifyNonMembership, verifyNonMembershipByHash } from "../src/verify.js";
import type { Leaf } from "../src/types.js";

// ---------------------------------------------------------------------------
// Brand constants
// ---------------------------------------------------------------------------
const GOLD = "\x1b[38;2;255;184;0m"; // #FFB800
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const GREEN = "\x1b[32m";

function gold(s: string) { return `${GOLD}${BOLD}${s}${RESET}`; }
function dim(s: string) { return `${DIM}${s}${RESET}`; }
function green(s: string) { return `${GREEN}${s}${RESET}`; }

// ---------------------------------------------------------------------------
// Simulate LLM call events
// ---------------------------------------------------------------------------

/** Generate a realistic LLM call event leaf. */
function makeLLMCallLeaf(index: number, windowStartMs: number): Leaf {
  const timestampMs = windowStartMs + Math.floor((index / 10_000) * 3_600_000);
  const models = ["gpt-4o", "gpt-4o-mini", "claude-3-5-sonnet", "llama-3.1-70b"];
  const model = models[index % models.length]!;
  const tokensIn = 100 + (index % 1900);
  const tokensOut = 50 + (index % 450);

  return buildLeaf(`llm-call:${timestampMs}:idx-${index}`, {
    model,
    timestamp_ms: timestampMs,
    tokens_in: tokensIn,
    tokens_out: tokensOut,
    session_id: `sess-${Math.floor(index / 100)}`,
  });
}

/** The malicious event we want to prove was NOT in the window. */
function makeMaliciousEvent() {
  return {
    eventId: "llm-call:MALICIOUS:exfil-to-sanctioned-endpoint",
    data: {
      model: "gpt-4o",
      destination: "sanctioned-llm-provider.example.com",
      data_category: "PII",
      action: "exfiltration",
    },
  };
}

// ---------------------------------------------------------------------------
// Timing helper
// ---------------------------------------------------------------------------

function hrMs(): number {
  const [s, ns] = process.hrtime();
  return s * 1000 + ns / 1e6;
}

// ---------------------------------------------------------------------------
// Main demo
// ---------------------------------------------------------------------------

async function main() {
  const EVENT_COUNT = 10_000;
  const windowStartMs = Date.now() - 3_600_000;
  const malicious = makeMaliciousEvent();

  console.log(`\n${gold("prov.absence")} — Negative-Fact Receipt Demo`);
  console.log(dim("Observation window: 1 hour, 10,000 simulated LLM calls\n"));
  console.log("━".repeat(60));

  // ── Step 1: Build the tree ───────────────────────────────────────────────
  console.log(`\n${BOLD}Step 1: Building event tree${RESET}`);
  process.stdout.write(`  Generating ${EVENT_COUNT.toLocaleString()} event leaves... `);

  const t0 = hrMs();
  const leaves: Leaf[] = [];
  for (let i = 0; i < EVENT_COUNT; i++) {
    leaves.push(makeLLMCallLeaf(i, windowStartMs));
  }
  const leafGenMs = hrMs() - t0;
  process.stdout.write(`done (${leafGenMs.toFixed(1)} ms)\n`);

  process.stdout.write("  Building SortedMerkleTree... ");
  const t1 = hrMs();
  const tree = new SortedMerkleTree(leaves);
  const buildMs = hrMs() - t1;
  process.stdout.write(`done (${buildMs.toFixed(1)} ms)\n`);

  const root = tree.root();
  const rootHex = toHex(root);
  const serialized = tree.serialize();

  console.log(`\n  ${BOLD}Tree stats:${RESET}`);
  console.log(`    Events committed:  ${EVENT_COUNT.toLocaleString()}`);
  console.log(`    Real leaves (+ sentinels): ${tree.realSize.toLocaleString()}`);
  console.log(`    Padded leaves (power-of-2): ${tree.paddedSize.toLocaleString()}`);
  console.log(`    Tree depth:        ${Math.log2(tree.paddedSize).toFixed(0)} levels`);
  console.log(`    Binary size:       ${(serialized.byteLength / 1024).toFixed(1)} KB`);
  console.log(`    Root:              ${dim(rootHex.slice(0, 16) + "..." + rootHex.slice(-8))}`);

  // ── Step 2: Prove non-membership ─────────────────────────────────────────
  console.log(`\n${BOLD}Step 2: Proving the malicious event was NOT in the window${RESET}`);
  console.log(`  Query:  ${dim(malicious.eventId)}`);

  const t2 = hrMs();
  const proof = tree.proveNonMembership(malicious.eventId, malicious.data);
  const proofGenMs = hrMs() - t2;

  // Measure proof size (JSON)
  const proofJSON = JSON.stringify(proof, (_k, v) =>
    v instanceof Uint8Array ? toHex(v) : v
  );
  const proofSizeBytes = Buffer.byteLength(proofJSON, "utf8");
  const proofSizeCompact = proofSizeBytes; // uncompressed

  console.log(`\n  ${BOLD}Proof stats:${RESET}`);
  console.log(`    Proof generation:  ${proofGenMs.toFixed(2)} ms`);
  console.log(`    Proof size (JSON): ${(proofSizeBytes / 1024).toFixed(2)} KB`);
  console.log(`    Sibling count:     ${proof.lowerProof.siblings.length} per inclusion proof`);
  console.log(`    Lower bound idx:   ${proof.lowerIndex}`);
  console.log(`    Upper bound idx:   ${proof.upperIndex}`);
  console.log(`    Lower leaf:        ${dim(toHex(proof.lowerLeaf).slice(0, 16) + "...")}`);
  console.log(`    Upper leaf:        ${dim(toHex(proof.upperLeaf).slice(0, 16) + "...")}`);

  // ── Step 3: Verify ────────────────────────────────────────────────────────
  console.log(`\n${BOLD}Step 3: Verifying the non-membership proof${RESET}`);

  const t3 = hrMs();
  const valid = verifyNonMembership(
    proof,
    malicious.eventId,
    malicious.data,
    root
  );
  const verifyMs = hrMs() - t3;

  if (valid) {
    console.log(`  ${green("✓ VERIFIED")} — "${malicious.eventId}" was NOT in the 1-hour window.`);
  } else {
    console.error("  ✗ VERIFICATION FAILED — this should not happen in the demo.");
    process.exit(1);
  }
  console.log(`    Verification time: ${verifyMs.toFixed(2)} ms`);

  // ── Step 4: Verify tampered proof fails ───────────────────────────────────
  console.log(`\n${BOLD}Step 4: Tamper-resistance check${RESET}`);
  const tamperedProof = {
    ...proof,
    upperIndex: proof.lowerIndex + 2, // violate adjacency
  };
  const tamperedValid = verifyNonMembershipByHash(tamperedProof, root);
  if (!tamperedValid) {
    console.log(`  ${green("✓ CORRECT")} — tampered proof (broken adjacency) correctly rejected.`);
  } else {
    console.error("  ✗ TAMPERED PROOF ACCEPTED — security failure.");
    process.exit(1);
  }

  // ── Step 5: Round-trip serialisation ──────────────────────────────────────
  console.log(`\n${BOLD}Step 5: Serialisation round-trip${RESET}`);
  const t4 = hrMs();
  const buf = tree.serialize();
  const tree2 = SortedMerkleTree.deserialize(buf);
  const rtMs = hrMs() - t4;
  const proof2 = tree2.proveNonMembershipByHash(proof.queryHash);
  const valid2 = verifyNonMembershipByHash(proof2, tree2.root());
  console.log(`  Serialise + deserialise: ${rtMs.toFixed(1)} ms`);
  if (valid2) {
    console.log(`  ${green("✓")} Proof from deserialised tree also verifies.`);
  }

  // ── Summary ───────────────────────────────────────────────────────────────
  console.log(`\n${"━".repeat(60)}`);
  console.log(`${gold("Performance Summary")} (10,000-event window)`);
  console.log(`  Leaf generation:    ${leafGenMs.toFixed(1)} ms`);
  console.log(`  Tree build:         ${buildMs.toFixed(1)} ms`);
  console.log(`  Proof generation:   ${proofGenMs.toFixed(2)} ms`);
  console.log(`  Proof verification: ${verifyMs.toFixed(2)} ms`);
  console.log(`  Serialised size:    ${(serialized.byteLength / 1024).toFixed(1)} KB`);
  console.log(`  Proof JSON size:    ${(proofSizeCompact / 1024).toFixed(2)} KB`);
  console.log();

  // Output machine-readable numbers for README injection
  console.log("PERF_NUMBERS_JSON=" + JSON.stringify({
    eventCount: EVENT_COUNT,
    leafGenMs: parseFloat(leafGenMs.toFixed(1)),
    buildMs: parseFloat(buildMs.toFixed(1)),
    proofGenMs: parseFloat(proofGenMs.toFixed(2)),
    verifyMs: parseFloat(verifyMs.toFixed(2)),
    treeSizeKB: parseFloat((serialized.byteLength / 1024).toFixed(1)),
    proofSizeKB: parseFloat((proofSizeCompact / 1024).toFixed(2)),
    treeDepth: Math.log2(tree.paddedSize),
    siblingCount: proof.lowerProof.siblings.length,
  }));
}

main().catch((err) => {
  console.error("Demo failed:", err);
  process.exit(1);
});
