/**
 * Bearer-token auth middleware for the Streamable HTTP transport.
 *
 * Single shared secret in `MCP_AUTH_TOKEN`, compared in constant time. Mirrors
 * the proven pattern from the other nlma.io MCP servers, minus the OAuth path
 * (this server is single-tenant — just one operator). A token may arrive as an
 * `Authorization: Bearer <t>` header or a `?token=<t>` query param.
 */
import { timingSafeEqual } from "node:crypto";
import type { Request, Response, NextFunction } from "express";

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

export function bearerAuth(req: Request, res: Response, next: NextFunction): void {
  const expected = process.env.MCP_AUTH_TOKEN;
  if (!expected) {
    res.status(500).json({ error: "Server misconfigured: MCP_AUTH_TOKEN unset" });
    return;
  }
  const token = extractBearer(req);
  if (!token) {
    res.set("WWW-Authenticate", `Bearer realm="${REALM}", resource_metadata="${RESOURCE_META}"`);
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  if (safeEqual(token, expected)) {
    next();
    return;
  }
  res.set(
    "WWW-Authenticate",
    `Bearer realm="${REALM}", error="invalid_token", resource_metadata="${RESOURCE_META}"`,
  );
  res.status(401).json({ error: "Unauthorized" });
}
