/**
 * Background-refreshed domain registry, unioned with the statically
 * configured `GOOGLE_ALLOWED_DOMAINS` list in the human-identity gate.
 *
 * Mirrors qbo-oauth's `registry_domains()`: `AUTHORIZED_DOMAINS_URL` (default
 * `https://status.nlma.io/domains.json`, empty string disables the registry
 * entirely) is polled every `AUTHORIZED_DOMAINS_TTL` seconds (default 60).
 * The last successful fetch is cached and reused on failure; before the
 * first successful fetch, only the env-configured (baked-in) domains apply.
 * The fetch never sits on a request's hot path — it's a background timer,
 * and `domains()` only ever reads the in-memory cache.
 */

const DEFAULT_REGISTRY_URL = "https://status.nlma.io/domains.json";
const DEFAULT_TTL_S = 60;
const FETCH_TIMEOUT_MS = 5_000;

export interface DomainRegistry {
  /** Env domains unioned with the last-known-good registry fetch. */
  domains: () => string[];
  /** Stops the background refresh timer. */
  stop: () => void;
}

function normalizeDomains(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((d): d is string => typeof d === "string")
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean);
}

export function createDomainRegistry(envDomains: string[]): DomainRegistry {
  const url = (process.env.AUTHORIZED_DOMAINS_URL ?? DEFAULT_REGISTRY_URL).trim();
  const ttlS = Math.max(1, parseInt(process.env.AUTHORIZED_DOMAINS_TTL ?? "", 10) || DEFAULT_TTL_S);

  let registryCache: string[] = [];
  let timer: ReturnType<typeof setInterval> | undefined;

  const fetchOnce = async (): Promise<void> => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const res = await fetch(url, { signal: controller.signal });
      if (!res.ok) return;
      const body = (await res.json()) as { domains?: unknown };
      const next = normalizeDomains(body?.domains);
      if (next.length > 0) registryCache = next;
    } catch {
      // Network/parse failure — keep the last-known-good cache.
    } finally {
      clearTimeout(timeout);
    }
  };

  if (url) {
    void fetchOnce();
    timer = setInterval(() => void fetchOnce(), ttlS * 1000);
    timer.unref();
  }

  return {
    domains: () => [...new Set([...envDomains, ...registryCache])],
    stop: () => {
      if (timer) clearInterval(timer);
    },
  };
}
