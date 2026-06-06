/**
 * Bearer-token auth middleware for the Streamable HTTP transport.
 *
 * Two accepted credentials:
 *   1. The shared secret in MCP_AUTH_TOKEN — supplied as `Authorization: Bearer
 *      <t>` or a `?token=<t>` query param. Used by curl, Claude Desktop, and
 *      Claude Code (header form), and any client that can paste a self-contained
 *      URL (query form). Compared in constant time.
 *   2. An opaque OAuth access token minted by the /authorize → /token flow and
 *      held in the file-backed store (see oauth.ts / oauth-store.ts). Used by
 *      claude.ai web, which requires OAuth 2.0 + dynamic client registration for
 *      custom remote connectors and will not attach with a bare bearer URL.
 *
 * The 401 challenge advertises `resource_metadata`; that endpoint is served by
 * mcpAuthRouter (http.ts), so an OAuth-capable client can discover the
 * authorization server and complete the flow.
 */
import { timingSafeEqual } from "node:crypto";
import type { Request, Response, NextFunction } from "express";
import { isValidOauthAccessToken } from "./oauth.js";

function extractBearer(req: Request): string | null {
  const h = req.headers.authorization;
  if (typeof h === "string") {
    const m = h.match(/^Bearer\s+(.+)$/i);
    if (m && m[1]) return m[1].trim();
  }
  const q = req.query?.token;
  if (typeof q === "string" && q.length > 0) return q.trim();
  return null;
}

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

const REALM = "lob-mcp";
const RESOURCE_META = `${process.env.OAUTH_ISSUER ?? "https://lob.nlma.io"}/.well-known/oauth-protected-resource`;

function challenge(res: Response, invalid: boolean): void {
  const errPart = invalid ? `, error="invalid_token"` : "";
  res.set(
    "WWW-Authenticate",
    `Bearer realm="${REALM}"${errPart}, resource_metadata="${RESOURCE_META}"`,
  );
  res.status(401).json({ error: "Unauthorized" });
}

export function bearerAuth(req: Request, res: Response, next: NextFunction): void {
  const expected = process.env.MCP_AUTH_TOKEN;
  if (!expected) {
    res.status(500).json({ error: "Server misconfigured: MCP_AUTH_TOKEN unset" });
    return;
  }
  const token = extractBearer(req);
  if (!token) {
    challenge(res, false);
    return;
  }
  if (safeEqual(token, expected) || isValidOauthAccessToken(token)) {
    next();
    return;
  }
  challenge(res, true);
}
