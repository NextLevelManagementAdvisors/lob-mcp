/**
 * Human-identity gate in front of the OAuth 2.0 `/authorize` endpoint.
 *
 * The OAuth authorization server (oauth.ts + mcpAuthRouter) handles the
 * machine-to-machine handshake with claude.ai (DCR, PKCE, code→token). This
 * module adds the HUMAN step: before `/authorize` will issue a code, the person
 * must prove identity once — via "Sign in with Google" (allowlisted to
 * GOOGLE_ALLOWED_EMAILS / GOOGLE_ALLOWED_DOMAINS) or, as break-glass, the
 * operator shared secret (MCP_AUTH_TOKEN) typed into the login form. Success
 * mints a short-lived HMAC-signed `lob_authed` cookie that the `/authorize`
 * gate trusts; the provider then issues the code without any further prompt.
 *
 * Online access only — scope `openid email`, no Google refresh token, no Google
 * API calls beyond /userinfo. Stack-agnostic pattern shared with the other
 * nlma.io services (vin/attom/matterport); see skill add-google-oauth.
 *
 * Zero new dependencies: node:crypto for the cookie HMAC, global fetch (Node
 * ≥18) for the two Google calls, Express Router for the routes.
 */
import express, {
  type Request,
  type Response,
  type NextFunction,
  type Router,
} from "express";
import { createHmac, timingSafeEqual, randomUUID } from "node:crypto";

const COOKIE_NAME = "lob_authed";
const COOKIE_TTL_S = 12 * 60 * 60; // 12h
const STATE_TTL_MS = 5 * 60 * 1000; // 5m CSRF window
const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo";

export interface GoogleGate {
  /** Always true here — the password fallback guarantees a usable gate. */
  enabled: boolean;
  /** Whether Google sign-in (not just password) is configured. */
  googleEnabled: boolean;
  /** Express router mounting /login, /oauth/google/*, /logout. */
  routes: Router;
  /** Middleware guarding /authorize: valid cookie → next(), else → /login. */
  gate: (req: Request, res: Response, next: NextFunction) => void;
}

interface GateConfig {
  googleClientId: string | null;
  googleClientSecret: string | null;
  googleRedirectUri: string;
  allowedEmails: string[];
  allowedDomains: string[];
  ownerPassword: string | null;
  allowPasswordFallback: boolean;
  sessionSecret: string;
}

function loadConfig(): GateConfig {
  const issuer = (process.env.OAUTH_ISSUER ?? "https://lob.nlma.io").replace(/\/+$/, "");
  const split = (v: string | undefined): string[] =>
    (v ?? "")
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);
  return {
    googleClientId: process.env.GOOGLE_WEB_CLIENT_ID?.trim() || null,
    googleClientSecret: process.env.GOOGLE_WEB_CLIENT_SECRET?.trim() || null,
    googleRedirectUri:
      process.env.GOOGLE_OAUTH_REDIRECT_URI?.trim() ||
      `${issuer}/oauth/google/callback`,
    allowedEmails: split(process.env.GOOGLE_ALLOWED_EMAILS),
    allowedDomains: split(process.env.GOOGLE_ALLOWED_DOMAINS),
    // MCP_AUTH_TOKEN doubles as the break-glass operator password.
    ownerPassword: process.env.MCP_AUTH_TOKEN?.trim() || null,
    allowPasswordFallback: !/^(0|false|no|off)$/i.test(
      process.env.ALLOW_PASSWORD_FALLBACK?.trim() ?? "true",
    ),
    // Dedicated cookie-signing key; falls back to the shared secret so the gate
    // still works if SESSION_SECRET wasn't set (rotating either invalidates
    // outstanding cookies, which is acceptable).
    sessionSecret:
      process.env.SESSION_SECRET?.trim() ||
      process.env.MCP_AUTH_TOKEN?.trim() ||
      "lob-mcp-insecure-dev-secret",
  };
}

// ─── cookie (HMAC-signed, stateless) ─────────────────────────────────────────

function b64urlEncode(s: string): string {
  return Buffer.from(s, "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
function b64urlDecode(s: string): string {
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
}
function sign(body: string, secret: string): string {
  return createHmac("sha256", secret).update(body).digest("hex");
}

function mintCookie(email: string, secret: string): string {
  const exp = Math.floor(Date.now() / 1000) + COOKIE_TTL_S;
  const body = b64urlEncode(JSON.stringify({ email, exp }));
  return `${body}.${sign(body, secret)}`;
}

function verifyCookie(value: string | undefined, secret: string): string | null {
  if (!value) return null;
  const dot = value.lastIndexOf(".");
  if (dot < 0) return null;
  const body = value.slice(0, dot);
  const sig = value.slice(dot + 1);
  const expected = sign(body, secret);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try {
    const { email, exp } = JSON.parse(b64urlDecode(body)) as { email: string; exp: number };
    if (typeof exp !== "number" || exp < Math.floor(Date.now() / 1000)) return null;
    return email;
  } catch {
    return null;
  }
}

function readCookie(req: Request, name: string): string | undefined {
  const header = req.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) {
      return decodeURIComponent(part.slice(eq + 1).trim());
    }
  }
  return undefined;
}

function setAuthCookie(res: Response, email: string, secret: string): void {
  res.cookie(COOKIE_NAME, mintCookie(email, secret), {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: COOKIE_TTL_S * 1000,
    path: "/",
  });
}

// ─── allowlist (fail-closed) ─────────────────────────────────────────────────

function emailAllowed(email: string, cfg: GateConfig): boolean {
  const e = email.toLowerCase();
  const domain = e.includes("@") ? e.slice(e.indexOf("@") + 1) : "";
  if (cfg.allowedEmails.length === 0 && cfg.allowedDomains.length === 0) return false;
  return cfg.allowedEmails.includes(e) || (domain !== "" && cfg.allowedDomains.includes(domain));
}

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

// ─── pages ───────────────────────────────────────────────────────────────────

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function page(title: string, inner: string): string {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/><title>${esc(title)}</title>
<style>*,*::before,*::after{box-sizing:border-box}body{font-family:system-ui,-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f3f4f6}
.card{background:#fff;padding:2rem;border-radius:10px;box-shadow:0 4px 16px rgba(0,0,0,.1);width:420px}
h1{margin:0 0 .25rem;font-size:1.25rem}.sub{color:#6b7280;font-size:.875rem;margin:0 0 1.25rem;line-height:1.5}
.gbtn{display:flex;align-items:center;justify-content:center;gap:.6rem;width:100%;padding:.6rem;border:1px solid #d1d5db;border-radius:6px;background:#fff;color:#3c4043;font-size:.95rem;font-weight:500;text-decoration:none;cursor:pointer}
.gbtn:hover{background:#f8f9fa}.gbtn svg{width:18px;height:18px}
.divider{display:flex;align-items:center;gap:.5rem;color:#9ca3af;font-size:.75rem;margin:1rem 0}
.divider::before,.divider::after{content:"";flex:1;height:1px;background:#e5e7eb}
label{display:block;font-size:.875rem;font-weight:500;margin:.35rem 0}
input[type=password]{width:100%;padding:.5rem .75rem;border:1px solid #d1d5db;border-radius:6px;font-size:.85rem;outline:none;font-family:monospace}
input:focus{border-color:#2563eb;box-shadow:0 0 0 3px rgba(37,99,235,.15)}
button.submit{margin-top:.75rem;width:100%;padding:.6rem;background:#2563eb;color:#fff;border:none;border-radius:6px;font-size:1rem;cursor:pointer;font-weight:500}
button.submit:hover{background:#1d4ed8}.error{color:#dc2626;font-size:.85rem;margin-top:.5rem}.hint{color:#6b7280;font-size:.75rem;margin-top:.75rem}</style>
</head><body><div class="card"><h1>Lob MCP</h1>${inner}</div></body></html>`;
}

const GOOGLE_SVG =
  '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.27-4.74 3.27-8.1z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.99.66-2.26 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84A11 11 0 0 0 12 23z"/><path fill="#FBBC05" d="M5.84 14.1a6.6 6.6 0 0 1 0-4.2V7.06H2.18a11 11 0 0 0 0 9.88l3.66-2.84z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84C6.71 7.31 9.14 5.38 12 5.38z"/></svg>';

function loginPage(opts: {
  cfg: GateConfig;
  ret: string;
  error?: string;
}): string {
  const { cfg, ret, error } = opts;
  const retParam = encodeURIComponent(ret);
  const google = cfg.googleClientId
    ? `<a class="gbtn" href="/oauth/google/start?return=${retParam}">${GOOGLE_SVG}<span>Sign in with Google</span></a>`
    : "";
  const pwd =
    cfg.allowPasswordFallback && cfg.ownerPassword
      ? `${google ? '<div class="divider">or</div>' : ""}
      <form method="POST" action="/login">
        <input type="hidden" name="return" value="${esc(ret)}"/>
        <label for="password">Operator access token</label>
        <input type="password" id="password" name="password" autocomplete="off" placeholder="paste the MCP_AUTH_TOKEN"/>
        <button class="submit" type="submit">Authorize</button>
      </form>`
      : "";
  const err = error ? `<div class="error">${esc(error)}</div>` : "";
  return page(
    "Lob MCP — Sign in",
    `<p class="sub">Authorize this connector to <strong>lob.nlma.io</strong> — direct mail, checks, and address verification.</p>
     ${google}${pwd}${err}
     <div class="hint">Grants a short-lived session, then issues the connector its OAuth token.</div>`,
  );
}

function deniedPage(email: string): string {
  return page(
    "Lob MCP — Not authorized",
    `<p class="sub"><strong>${esc(email)}</strong> is not authorized for this connector.</p>
     <a class="gbtn" href="/login">Try a different account</a>`,
  );
}

// ─── factory ─────────────────────────────────────────────────────────────────

function safeReturn(raw: unknown): string {
  // Only allow same-origin relative paths to avoid open-redirect.
  if (typeof raw !== "string" || !raw.startsWith("/") || raw.startsWith("//")) return "/authorize";
  return raw;
}

export function createGoogleGate(): GoogleGate {
  const cfg = loadConfig();
  const googleEnabled = Boolean(cfg.googleClientId && cfg.googleClientSecret);
  const states = new Map<string, { ret: string; exp: number }>();

  const sweepStates = (): void => {
    const now = Date.now();
    for (const [k, v] of states) if (v.exp < now) states.delete(k);
  };

  const routes = express.Router();

  routes.get("/login", (req, res) => {
    const ret = safeReturn(req.query.return);
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(loginPage({ cfg, ret }));
  });

  routes.post("/login", (req, res) => {
    const ret = safeReturn((req.body as Record<string, string>)?.return);
    const pwd = (req.body as Record<string, string>)?.password?.trim() ?? "";
    if (!cfg.allowPasswordFallback || !cfg.ownerPassword) {
      res.status(403).setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(loginPage({ cfg, ret, error: "Password sign-in is disabled." }));
      return;
    }
    if (!pwd || !safeEqual(pwd, cfg.ownerPassword)) {
      res.status(401).setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(loginPage({ cfg, ret, error: "Incorrect access token." }));
      return;
    }
    setAuthCookie(res, "operator@lob-mcp", cfg.sessionSecret);
    res.redirect(ret);
  });

  routes.get("/oauth/google/start", (req, res) => {
    if (!googleEnabled) {
      res.status(404).json({ error: "Google sign-in not configured" });
      return;
    }
    sweepStates();
    const ret = safeReturn(req.query.return);
    const state = randomUUID();
    states.set(state, { ret, exp: Date.now() + STATE_TTL_MS });
    const p = new URLSearchParams({
      response_type: "code",
      client_id: cfg.googleClientId!,
      redirect_uri: cfg.googleRedirectUri,
      scope: "openid email",
      access_type: "online",
      prompt: "select_account",
      state,
    });
    res.redirect(`${GOOGLE_AUTH_URL}?${p.toString()}`);
  });

  routes.get("/oauth/google/callback", async (req, res) => {
    const sendErr = (status: number, msg: string): void => {
      res.status(status).setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(loginPage({ cfg, ret: "/authorize", error: msg }));
    };
    if (!googleEnabled) {
      res.status(404).json({ error: "Google sign-in not configured" });
      return;
    }
    const code = typeof req.query.code === "string" ? req.query.code : "";
    const state = typeof req.query.state === "string" ? req.query.state : "";
    const entry = states.get(state);
    states.delete(state);
    if (!code || !entry || entry.exp < Date.now()) {
      sendErr(400, "Sign-in expired or invalid. Please try again.");
      return;
    }
    try {
      const tokenResp = await fetch(GOOGLE_TOKEN_URL, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          code,
          client_id: cfg.googleClientId!,
          client_secret: cfg.googleClientSecret!,
          redirect_uri: cfg.googleRedirectUri,
          grant_type: "authorization_code",
        }).toString(),
      });
      if (!tokenResp.ok) {
        sendErr(502, "Google token exchange failed.");
        return;
      }
      const tok = (await tokenResp.json()) as { access_token?: string };
      if (!tok.access_token) {
        sendErr(502, "Google did not return an access token.");
        return;
      }
      const uiResp = await fetch(GOOGLE_USERINFO_URL, {
        headers: { authorization: `Bearer ${tok.access_token}` },
      });
      if (!uiResp.ok) {
        sendErr(502, "Could not read Google profile.");
        return;
      }
      const ui = (await uiResp.json()) as { email?: string; email_verified?: boolean };
      const email = (ui.email ?? "").toLowerCase();
      if (!email || ui.email_verified === false) {
        sendErr(403, "Your Google account has no verified email.");
        return;
      }
      if (!emailAllowed(email, cfg)) {
        res.status(403).setHeader("Content-Type", "text/html; charset=utf-8");
        res.send(deniedPage(email));
        return;
      }
      setAuthCookie(res, email, cfg.sessionSecret);
      res.redirect(303, entry.ret);
    } catch {
      sendErr(502, "Google sign-in failed. Please try again.");
    }
  });

  routes.get("/logout", (_req, res) => {
    res.clearCookie(COOKIE_NAME, { path: "/" });
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(page("Lob MCP — Signed out", '<p class="sub">Signed out.</p><a class="gbtn" href="/login">Sign in</a>'));
  });

  const gate = (req: Request, res: Response, next: NextFunction): void => {
    const email = verifyCookie(readCookie(req, COOKIE_NAME), cfg.sessionSecret);
    if (email) {
      next();
      return;
    }
    res.redirect(`/login?return=${encodeURIComponent(req.originalUrl)}`);
  };

  return { enabled: true, googleEnabled, routes, gate };
}
