/**
 * Resolves saved-address IDs (`adr_…`) in `to`/`from` to inline address objects
 * for the sole purpose of rendering a `/resource_proofs` preview.
 *
 * Previews always call `/resource_proofs` with `keyMode: "test"`, but saved
 * addresses created with a live key live in the live address book — the test
 * and live address books are entirely separate. A `to`/`from` that references
 * a live-only `adr_…` id therefore 404s against the test key. Fetching the
 * address with the live key (falling back to the test key when no live key is
 * configured — same as any other read) and substituting its inline fields
 * sidesteps that without touching the token-bound payload: this function
 * returns a new object when it resolves anything, leaving the caller's
 * original payload (and therefore the payload hash and the eventual commit)
 * carrying the original `adr_…` id.
 */
import type { LobClient } from "../lob/client.js";
import { compact } from "../schemas/common.js";

const ADDRESS_REF_FIELDS = ["to", "from"] as const;

const INLINE_ADDRESS_FIELDS = [
  "name",
  "company",
  "address_line1",
  "address_line2",
  "address_city",
  "address_state",
  "address_zip",
  "address_country",
  "phone",
  "email",
] as const;

function isAddressId(value: unknown): value is string {
  return typeof value === "string" && value.startsWith("adr_");
}

function toInlineAddress(address: Record<string, unknown>): Record<string, unknown> {
  const inline: Record<string, unknown> = {};
  for (const field of INLINE_ADDRESS_FIELDS) inline[field] = address[field];
  return compact(inline);
}

/**
 * Returns a shallow copy of `payload` with any `adr_…` string in `to`/`from`
 * replaced by its resolved inline address, suitable for a `/resource_proofs`
 * call. Returns the original `payload` reference unchanged if neither field
 * needs resolving — callers must not mutate the result in place.
 */
export async function resolveAddressRefsForProof(
  lob: LobClient,
  payload: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  let resolved: Record<string, unknown> | undefined;
  for (const field of ADDRESS_REF_FIELDS) {
    const value = payload[field];
    if (!isAddressId(value)) continue;
    const address = (await lob.request({
      method: "GET",
      path: `/addresses/${value}`,
      keyMode: "live",
    })) as Record<string, unknown>;
    resolved ??= { ...payload };
    resolved[field] = toInlineAddress(address);
  }
  return resolved ?? payload;
}
