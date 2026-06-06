#!/usr/bin/env node
/**
 * lob-mcp Streamable HTTP entry point.
 *
 * Serves the same MCP server as `index.ts`, but over HTTP behind a bearer-token
 * gate so it can run as a hosted service (lob.nlma.io) instead of a stdio child.
 *
 * Transport: StreamableHTTPServerTransport, one transport+server per MCP session
 * (session id round-tripped via the `mcp-session-id` header). The TokenStore and
 * PieceCounter are created ONCE at process scope and shared across every session
 * so the preview→commit token binding survives across separate HTTP requests and
 * the LOB_MAX_PIECES_PER_RUN cap is a true process-wide ceiling (resets only on
 * restart).
 *
 * Routing of test vs live keys is unchanged — it is driven entirely by loadEnv()
 * exactly as in the stdio entry.
 *
 * Auth: two paths share the `bearerAuth` gate on /mcp — the static MCP_AUTH_TOKEN
 * (header or ?token=) and OAuth access tokens. The OAuth 2.0 authorization server
 * (discovery docs, /register DCR, /authorize, /token, /revoke) is mounted via
 * mcpAuthRouter so the claude.ai web connector — which refuses bare-bearer remote
 * servers — can attach. See oauth.ts / oauth-store.ts.
 */
import express, { type Request, type Response } from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { randomUUID } from "node:crypto";
import { loadEnv } from "./env.js";
import { InMemoryTokenStore } from "./preview/token-store.js";
import { PieceCounter } from "./safety/piece-counter.js";
import { buildLobServer } from "./server-factory.js";
import { bearerAuth } from "./auth.js";
import { oauthProvider } from "./oauth.js";
import { createGoogleGate } from "./google-gate.js";
import { SERVER_VERSION } from "./version.js";

const PORT = parseInt(process.env.PORT ?? "3018", 10);
const HOST = process.env.HOST ?? "0.0.0.0";
const ISSUER_URL = new URL(process.env.OAUTH_ISSUER ?? "https://lob.nlma.io");

interface Session {
  server: McpServer;
  transport: StreamableHTTPServerTransport;
}

const sessions = new Map<string, Session>();
let draining = false;

function headerSessionId(req: Request): string | undefined {
  const raw = req.headers["mcp-session-id"];
  if (Array.isArray(raw)) return raw[0];
  return raw;
}

function main(): void {
  // Validate keys + safety knobs up front — throws (and exits non-zero) on a
  // misconfigured environment, which is what we want under systemd.
  const env = loadEnv();

  const tokenStore = new InMemoryTokenStore();
  const pieceCounter = new PieceCounter(env.maxPiecesPerRun);
  const cleanupTimer = setInterval(() => tokenStore.cleanup(), 60_000);
  cleanupTimer.unref();

  console.error(
    `[lob-mcp] http starting — commits: ${
      env.effectiveCommitMode === "live"
        ? "LIVE (real mail + charges)"
        : "TEST (no real mail)"
    }, reads: ${env.effectiveReadMode.toUpperCase()}, max pieces/run: ${
      env.maxPiecesPerRun ?? "(no cap)"
    }`,
  );

  const app = express();
  app.set("trust proxy", 1);

  app.use((_req, res, next) => {
    res.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    res.set("X-Frame-Options", "DENY");
    res.set("X-Content-Type-Options", "nosniff");
    res.set("Referrer-Policy", "strict-origin-when-cross-origin");
    next();
  });

  app.use(express.json({ limit: "10mb" }));
  app.use(express.urlencoded({ extended: false }));

  app.get("/health", (_req, res) => {
    res.json({
      status: draining ? "draining" : "ok",
      server: "lob-mcp",
      version: SERVER_VERSION,
      commitMode: env.effectiveCommitMode,
      readMode: env.effectiveReadMode,
    });
  });

  // Human-identity gate (Google sign-in + MCP_AUTH_TOKEN password fallback).
  // Mounts /login, /oauth/google/*, /logout and guards /authorize: a valid
  // lob_authed cookie falls through to the OAuth provider; otherwise → /login.
  const gate = createGoogleGate();
  app.use(gate.routes);
  app.use("/authorize", gate.gate);
  console.error(
    `[lob-mcp] human gate — google: ${gate.googleEnabled ? "on" : "off"}, password fallback: on`,
  );

  // OAuth 2.0 authorization server (well-known discovery, /register DCR,
  // /authorize, /token, /revoke). Public — no bearerAuth. /authorize is fronted
  // by the gate above; once authenticated, oauthProvider.authorize issues the code.
  app.use(
    mcpAuthRouter({
      provider: oauthProvider,
      issuerUrl: ISSUER_URL,
      resourceName: "Lob MCP",
    }),
  );

  app.post("/mcp", bearerAuth, async (req: Request, res: Response) => {
    const sessionId = headerSessionId(req);

    if (sessionId && sessions.has(sessionId)) {
      await sessions.get(sessionId)!.transport.handleRequest(req, res, req.body);
      return;
    }
    if (draining) {
      res.status(503).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "Server draining; please retry." },
        id: null,
      });
      return;
    }

    const body: unknown = req.body;
    const isInitialize =
      (body as { method?: string } | undefined)?.method === "initialize" ||
      (Array.isArray(body) && body.some((m) => (m as { method?: string })?.method === "initialize"));

    // Stale session id (process restarted, in-memory map empty). Allow a fresh
    // initialize to mint a new session; otherwise tell the client to re-init.
    if (sessionId && !sessions.has(sessionId) && !isInitialize) {
      res.status(404).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "Session not found. Please re-initialize." },
        id: null,
      });
      return;
    }

    const server = buildLobServer(env, tokenStore, pieceCounter);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (sid) => {
        sessions.set(sid, { server, transport });
      },
    });
    transport.onclose = () => {
      if (transport.sessionId) sessions.delete(transport.sessionId);
    };

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  app.get("/mcp", bearerAuth, async (req: Request, res: Response) => {
    const sessionId = headerSessionId(req);
    if (sessionId && sessions.has(sessionId)) {
      await sessions.get(sessionId)!.transport.handleRequest(req, res);
      return;
    }
    res.status(400).json({ error: "Missing or invalid session ID" });
  });

  app.delete("/mcp", bearerAuth, async (req: Request, res: Response) => {
    const sessionId = headerSessionId(req);
    if (sessionId && sessions.has(sessionId)) {
      await sessions.get(sessionId)!.transport.handleRequest(req, res);
      sessions.delete(sessionId);
      return;
    }
    res.status(400).json({ error: "Missing or invalid session ID" });
  });

  app.use((_req, res) => {
    res.status(404).json({ error: "Not found" });
  });

  const httpServer = app.listen(PORT, HOST, () => {
    console.error(`[lob-mcp] http listening on ${HOST}:${PORT}`);
  });

  const shutdown = (signal: string): void => {
    if (draining) return;
    draining = true;
    console.error(`[lob-mcp] shutdown starting (${signal}), active sessions: ${sessions.size}`);
    httpServer.close(() => console.error("[lob-mcp] http closed"));
    const deadline = Date.now() + 10_000;
    const checkDone = (): void => {
      if (sessions.size === 0 || Date.now() >= deadline) {
        process.exit(0);
      } else {
        setTimeout(checkDone, 250);
      }
    };
    checkDone();
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

main();
