#!/usr/bin/env node
/**
 * lob-mcp entry point.
 *
 * Boots an MCP server over stdio that wraps the Lob.com API. Reads dual keys
 * (`LOB_TEST_API_KEY` required, `LOB_LIVE_API_KEY` optional) plus safety knobs
 * from the environment, prints a startup banner to stderr that reflects the
 * full safety posture, registers every tool, then connects the stdio transport.
 *
 * If invoked as `lob-mcp init`, runs the interactive setup wizard and exits
 * before any env loading happens.
 *
 * stderr is the only legal place to log here — stdout is reserved for the
 * JSON-RPC framed messages the MCP transport reads from the child process.
 */
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { runWizardIfRequested } from "./init/wizard.js";
import { loadEnv, type LobEnv } from "./env.js";
import { InMemoryTokenStore } from "./preview/token-store.js";
import { PieceCounter } from "./safety/piece-counter.js";
import { buildLobServer } from "./server-factory.js";

async function main(): Promise<void> {
  if (await runWizardIfRequested(process.argv.slice(2))) return;

  const env = loadEnv();
  printBanner(env);

  const tokenStore = new InMemoryTokenStore();
  const pieceCounter = new PieceCounter(env.maxPiecesPerRun);

  const cleanupTimer = setInterval(() => tokenStore.cleanup(), 60_000);
  cleanupTimer.unref();

  const server = buildLobServer(env, tokenStore, pieceCounter);

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[lob-mcp] connected via stdio");
}

function printBanner(env: LobEnv): void {
  const liveCommits = env.effectiveCommitMode === "live";
  const liveReads = env.effectiveReadMode === "live";
  console.error(
    `[lob-mcp] commits: ${
      liveCommits
        ? "LIVE — REAL physical mail and REAL charges for billable creates"
        : "TEST — no real mail, no charges"
    }`,
  );
  console.error(
    `[lob-mcp] reads:   ${
      liveReads
        ? "LIVE — list/get/search query the real account"
        : "TEST — list/get/search query the test account"
    }`,
  );
  if (env.liveApiKey && env.effectiveReadMode === "test") {
    console.error(
      "[lob-mcp]   ℹ LOB_READS_USE_TEST=true — reads forced to test key despite live key being configured.",
    );
  } else if (env.liveApiKey && !env.liveModeEnabled) {
    console.error(
      "[lob-mcp]   ℹ Live key configured, LOB_LIVE_MODE != true — commits stay test, reads use live.",
    );
  }
  console.error("[lob-mcp] safety state:");
  console.error(
    `[lob-mcp]   • Confirmation required (live commits): ${env.requireConfirmation ? "yes" : "no"}`,
  );
  console.error(`[lob-mcp]   • Confirmation TTL: ${env.confirmationTtlSeconds}s`);
  console.error(
    `[lob-mcp]   • Max pieces per run: ${
      env.maxPiecesPerRun ?? "(no cap — consider setting LOB_MAX_PIECES_PER_RUN)"
    }`,
  );
  const checksThr = env.requireElicitationForChecksOverUsd;
  const bulkThr = env.requireElicitationForBulkOverPieces;
  console.error(
    `[lob-mcp]   • Elicitation: checks > $${checksThr ?? "(off)"}, bulk > ${
      bulkThr ?? "(off)"
    } pieces`,
  );
}

main().catch((err) => {
  console.error("[lob-mcp] fatal:", err instanceof Error ? err.stack ?? err.message : err);
  process.exit(1);
});
