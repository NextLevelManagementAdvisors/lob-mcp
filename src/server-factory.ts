/**
 * Shared McpServer factory.
 *
 * Both entry points — `index.ts` (stdio) and `http.ts` (Streamable HTTP) — build
 * the exact same MCP server through this function so the tool surface, safety
 * gating, and instructions can never drift between transports.
 *
 * The caller owns the `TokenStore` and `PieceCounter` lifetimes:
 *   • stdio: one process == one client, so index.ts makes one of each.
 *   • http:  the stores are created once at process scope and shared across all
 *     sessions, so the preview/commit token binding survives across requests and
 *     the LOB_MAX_PIECES_PER_RUN cap is a true process-wide ceiling (resets only
 *     on restart), not a per-session one.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { LobEnv } from "./env.js";
import { LobClient } from "./lob/client.js";
import type { TokenStore } from "./preview/token-store.js";
import type { PieceCounter } from "./safety/piece-counter.js";
import { registerAllTools } from "./tools/register.js";
import { SERVER_VERSION } from "./version.js";

export const SERVER_INSTRUCTIONS =
  "Lob MCP server. Preview/commit gated, idempotent, mode-aware.\n\n" +
  "FLOW:\n" +
  "• For mail-piece sends (postcards, letters, self-mailers, checks) and bulk inventory orders " +
  "(buckslips, cards), call `lob_<resource>_preview` first. The response includes a " +
  "`confirmation_token` and (for postcards/letters/self-mailers) a real Lob proof PDF URL.\n" +
  "• Then call `lob_<resource>_create` with the same payload plus `confirmation_token`. " +
  "In live commit mode the token is required; in test mode it is optional.\n\n" +
  "SAFETY:\n" +
  "• Two modes route operations to the right key: COMMIT mode gates billable mail-piece sends " +
  "and inventory orders; READ mode covers everything else (lists, gets, searches, cancels, " +
  "non-billable creates). Commit mode is TEST unless BOTH `LOB_LIVE_API_KEY` AND `LOB_LIVE_MODE=true` " +
  "are set. Read mode is LIVE whenever `LOB_LIVE_API_KEY` is configured (set `LOB_READS_USE_TEST=true` " +
  "to opt out). Reads have no billing risk — analytics like 'how many letters last week?' should " +
  "see live data.\n" +
  "• `LOB_MAX_PIECES_PER_RUN` caps total pieces this process may create. Resets on restart.\n" +
  "• Address fields are PII — avoid echoing them unnecessarily into chat history.";

export function buildLobServer(
  env: LobEnv,
  tokenStore: TokenStore,
  pieceCounter: PieceCounter,
): McpServer {
  const lob = new LobClient(env);
  const server = new McpServer(
    { name: "lob-mcp", version: SERVER_VERSION },
    { instructions: SERVER_INSTRUCTIONS },
  );
  registerAllTools(server, lob, tokenStore, pieceCounter);
  return server;
}
