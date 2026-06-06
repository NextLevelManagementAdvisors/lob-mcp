/**
 * File-backed persistence for the OAuth 2.0 authorization-server state.
 *
 * lob-mcp is single-tenant, so this is deliberately tiny: a few clients, a
 * handful of short-lived auth codes, and the access/refresh tokens claude.ai
 * holds. Postgres (as in hospitable-mcp) would be overkill — instead the whole
 * store is one JSON document loaded once into memory and written back through a
 * temp-file + atomic rename on every mutation. Volume is low enough that the
 * synchronous write is irrelevant, and persisting to disk means a service
 * restart does NOT invalidate claude.ai's connector token (the common failure
 * mode of an in-memory-only store).
 *
 * No secrets beyond the issued tokens themselves are stored — there is no
 * per-user PAT to encrypt (unlike hospitable). The issued opaque tokens ARE the
 * credential, so the file is written 0600.
 */
import { readFileSync, writeFileSync, renameSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";

export interface AuthCodeRec {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  expiresAtMs: number;
}

export interface TokenRec {
  clientId: string;
  scopes: string[];
  expiresAtSec: number;
}

interface StoreShape {
  clients: Record<string, OAuthClientInformationFull>;
  authCodes: Record<string, AuthCodeRec>;
  accessTokens: Record<string, TokenRec>;
  refreshTokens: Record<string, TokenRec>;
}

const FILE = process.env.OAUTH_STORE_PATH ?? "/opt/lob-mcp/.oauth-store.json";

function empty(): StoreShape {
  return { clients: {}, authCodes: {}, accessTokens: {}, refreshTokens: {} };
}

let cache: StoreShape | null = null;

function load(): StoreShape {
  if (cache) return cache;
  try {
    const parsed = JSON.parse(readFileSync(FILE, "utf8")) as Partial<StoreShape>;
    cache = { ...empty(), ...parsed };
  } catch {
    cache = empty();
  }
  return cache;
}

function persist(): void {
  const data = JSON.stringify(load());
  try {
    mkdirSync(dirname(FILE), { recursive: true });
  } catch {
    /* directory already exists */
  }
  const tmp = `${FILE}.tmp`;
  writeFileSync(tmp, data, { mode: 0o600 });
  renameSync(tmp, FILE);
}

const nowSec = (): number => Math.floor(Date.now() / 1000);

// ─── clients ─────────────────────────────────────────────────────────────────

export function getStoredClient(clientId: string): OAuthClientInformationFull | undefined {
  return load().clients[clientId];
}

export function putStoredClient(client: OAuthClientInformationFull): void {
  load().clients[client.client_id] = client;
  persist();
}

// ─── authorization codes (single-use, short TTL) ─────────────────────────────

export function putAuthCode(code: string, rec: AuthCodeRec): void {
  load().authCodes[code] = rec;
  persist();
}

export function peekAuthCode(code: string): AuthCodeRec | null {
  const s = load();
  const rec = s.authCodes[code];
  if (!rec) return null;
  if (rec.expiresAtMs < Date.now()) {
    delete s.authCodes[code];
    persist();
    return null;
  }
  return rec;
}

export function takeAuthCode(code: string): AuthCodeRec | null {
  const s = load();
  const rec = s.authCodes[code];
  if (!rec) return null;
  delete s.authCodes[code];
  persist();
  if (rec.expiresAtMs < Date.now()) return null;
  return rec;
}

// ─── access tokens ───────────────────────────────────────────────────────────

export function putAccessToken(token: string, rec: TokenRec): void {
  load().accessTokens[token] = rec;
  persist();
}

export function getAccessToken(token: string): TokenRec | null {
  const s = load();
  const rec = s.accessTokens[token];
  if (!rec) return null;
  if (rec.expiresAtSec < nowSec()) {
    delete s.accessTokens[token];
    persist();
    return null;
  }
  return rec;
}

// ─── refresh tokens ──────────────────────────────────────────────────────────

export function putRefreshToken(token: string, rec: TokenRec): void {
  load().refreshTokens[token] = rec;
  persist();
}

export function getRefreshToken(token: string): TokenRec | null {
  const s = load();
  const rec = s.refreshTokens[token];
  if (!rec) return null;
  if (rec.expiresAtSec < nowSec()) {
    delete s.refreshTokens[token];
    persist();
    return null;
  }
  return rec;
}

export function deleteTokens(token: string): void {
  const s = load();
  delete s.accessTokens[token];
  delete s.refreshTokens[token];
  persist();
}
