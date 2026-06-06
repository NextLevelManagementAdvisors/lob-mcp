/**
 * OAuth 2.0 authorization-server provider for the claude.ai web connector.
 *
 * claude.ai (web) only attaches to remote MCP servers that speak OAuth 2.0 with
 * dynamic client registration — a bare bearer token / `?token=` URL is rejected
 * with "Couldn't register with the sign-in service". This module supplies the
 * `OAuthServerProvider` that `mcpAuthRouter` (wired in http.ts) uses to serve
 * the discovery docs, `/register`, `/authorize`, `/token`, and `/revoke`.
 *
 * Because lob-mcp is single-tenant, the "login" is not a per-user credential
 * exchange (as in hospitable-mcp, which collects a Hospitable PAT). Instead the
 * operator proves identity by entering the existing shared MCP_AUTH_TOKEN; the
 * flow then mints an opaque access token that `bearerAuth` accepts. Lob API
 * calls always use the keys in the environment regardless of who authorized.
 *
 * Persistence lives in oauth-store.ts (JSON file). Mirrors the hospitable-mcp
 * provider shape against the same @modelcontextprotocol/sdk version, minus the
 * Postgres + PAT-encryption layers.
 */
import { randomUUID, timingSafeEqual } from "node:crypto";
import type { Response } from "express";
import type { OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type {
  OAuthClientInformationFull,
  OAuthTokenRevocationRequest,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import {
  getStoredClient,
  putStoredClient,
  putAuthCode,
  peekAuthCode,
  takeAuthCode,
  putAccessToken,
  getAccessToken,
  putRefreshToken,
  getRefreshToken,
  deleteTokens,
} from "./oauth-store.js";

const ACCESS_TOKEN_TTL_S = 60 * 60;
const REFRESH_TOKEN_TTL_S = 30 * 24 * 60 * 60;
const AUTH_CODE_TTL_MS = 10 * 60 * 1000;

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/** Single-tenant gate: the operator proves identity with the shared secret. */
export function validateOperatorSecret(secret: string): void {
  const expected = process.env.MCP_AUTH_TOKEN;
  if (!expected) throw new Error("Server misconfigured: MCP_AUTH_TOKEN unset");
  if (!safeEqual(secret, expected)) throw new Error("Incorrect access token.");
}

/** True iff `token` is an opaque token minted by this flow and still valid. */
export function isValidOauthAccessToken(token: string): boolean {
  if (!UUID_RE.test(token)) return false;
  return getAccessToken(token) !== null;
}

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

export function loginForm(opts: {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  state?: string;
  error?: string;
}): string {
  const { clientId, redirectUri, codeChallenge, state, error } = opts;
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Lob MCP — Authorize</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh; margin: 0; background: #f3f4f6;
    }
    .card {
      background: #fff; padding: 2rem; border-radius: 10px;
      box-shadow: 0 4px 16px rgba(0,0,0,.1); width: 420px;
    }
    h1 { margin: 0 0 .25rem; font-size: 1.25rem; }
    .sub { color: #6b7280; font-size: .875rem; margin: 0 0 1.5rem; line-height: 1.5; }
    label { display: block; font-size: .875rem; font-weight: 500; margin-bottom: .35rem; }
    input[type=password] {
      width: 100%; padding: .5rem .75rem; border: 1px solid #d1d5db;
      border-radius: 6px; font-size: .85rem; outline: none; font-family: monospace;
    }
    input:focus { border-color: #2563eb; box-shadow: 0 0 0 3px rgba(37,99,235,.15); }
    button {
      margin-top: 1rem; width: 100%; padding: .6rem;
      background: #2563eb; color: #fff; border: none;
      border-radius: 6px; font-size: 1rem; cursor: pointer; font-weight: 500;
    }
    button:hover { background: #1d4ed8; }
    .error { color: #dc2626; font-size: .85rem; margin-top: .5rem; }
    .hint { color: #6b7280; font-size: .75rem; margin-top: .5rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Lob MCP</h1>
    <p class="sub">
      Enter the lob-mcp access token to authorize this connector.<br/>
      This is the operator shared secret (<code>MCP_AUTH_TOKEN</code>) for
      <strong>lob.nlma.io</strong> — direct mail, checks, and address verification.
    </p>
    <form method="POST" action="/oauth/callback">
      <input type="hidden" name="client_id"      value="${esc(clientId)}" />
      <input type="hidden" name="redirect_uri"   value="${esc(redirectUri)}" />
      <input type="hidden" name="code_challenge" value="${esc(codeChallenge)}" />
      ${state ? `<input type="hidden" name="state" value="${esc(state)}" />` : ""}
      <label for="api_key">lob-mcp access token</label>
      <input type="password" id="api_key" name="api_key" autofocus autocomplete="off"
             placeholder="paste the MCP_AUTH_TOKEN here" />
      ${error ? `<div class="error">${esc(error)}</div>` : ""}
      <button type="submit">Authorize</button>
      <div class="hint">Grants this client a short-lived bearer token tied to your Lob account.</div>
    </form>
  </div>
</body>
</html>`;
}

export function createAuthCode(
  clientId: string,
  redirectUri: string,
  codeChallenge: string,
): string {
  const code = randomUUID();
  putAuthCode(code, {
    clientId,
    redirectUri,
    codeChallenge,
    expiresAtMs: Date.now() + AUTH_CODE_TTL_MS,
  });
  return code;
}

const clientsStore: OAuthRegisteredClientsStore = {
  async getClient(clientId) {
    const existing = getStoredClient(clientId);
    if (existing) return existing;
    // Fallback: accept any UUID-shaped client id with the standard MCP web
    // callbacks, so a registered client surviving in claude.ai but lost here
    // (e.g. store file reset) still completes the flow.
    if (UUID_RE.test(clientId)) {
      return {
        client_id: clientId,
        client_id_issued_at: Math.floor(Date.now() / 1000),
        redirect_uris: [
          "https://claude.ai/api/mcp/auth_callback",
          "https://claude.com/api/mcp/auth_callback",
          "http://localhost/callback",
        ],
      } as OAuthClientInformationFull;
    }
    return undefined;
  },
  async registerClient(client) {
    const full: OAuthClientInformationFull = {
      ...client,
      client_id: randomUUID(),
      client_id_issued_at: Math.floor(Date.now() / 1000),
    };
    putStoredClient(full);
    return full;
  },
};

export const oauthProvider: OAuthServerProvider = {
  get clientsStore() {
    return clientsStore;
  },

  async authorize(client, params, res: Response) {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(
      loginForm({
        clientId: client.client_id,
        redirectUri: params.redirectUri,
        codeChallenge: params.codeChallenge,
        state: params.state,
      }),
    );
  },

  async challengeForAuthorizationCode(_client, authorizationCode) {
    const rec = peekAuthCode(authorizationCode);
    if (!rec) throw new Error("Authorization code not found or expired");
    return rec.codeChallenge;
  },

  async exchangeAuthorizationCode(client, authorizationCode) {
    const pending = takeAuthCode(authorizationCode);
    if (!pending) throw new Error("Authorization code not found or expired");

    const accessToken = randomUUID();
    const refreshToken = randomUUID();
    const now = Math.floor(Date.now() / 1000);
    putAccessToken(accessToken, {
      clientId: client.client_id,
      scopes: [],
      expiresAtSec: now + ACCESS_TOKEN_TTL_S,
    });
    putRefreshToken(refreshToken, {
      clientId: client.client_id,
      scopes: [],
      expiresAtSec: now + REFRESH_TOKEN_TTL_S,
    });
    return {
      access_token: accessToken,
      token_type: "bearer",
      expires_in: ACCESS_TOKEN_TTL_S,
      refresh_token: refreshToken,
    } satisfies OAuthTokens;
  },

  async exchangeRefreshToken(client, refreshToken) {
    const entry = getRefreshToken(refreshToken);
    if (!entry) throw new Error("Refresh token not found or expired");
    const now = Math.floor(Date.now() / 1000);
    const accessToken = randomUUID();
    putAccessToken(accessToken, {
      clientId: client.client_id,
      scopes: entry.scopes,
      expiresAtSec: now + ACCESS_TOKEN_TTL_S,
    });
    return {
      access_token: accessToken,
      token_type: "bearer",
      expires_in: ACCESS_TOKEN_TTL_S,
      refresh_token: refreshToken,
    } satisfies OAuthTokens;
  },

  async verifyAccessToken(token): Promise<AuthInfo> {
    const rec = getAccessToken(token);
    if (!rec) throw new Error("Invalid or expired access token");
    return {
      token,
      clientId: rec.clientId,
      scopes: rec.scopes,
      expiresAt: rec.expiresAtSec,
      extra: {},
    };
  },

  async revokeToken(_client, request: OAuthTokenRevocationRequest) {
    deleteTokens(request.token);
  },
};
