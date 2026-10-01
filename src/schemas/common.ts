/**
 * Zod schemas shared across multiple resource groups: address payloads, list/
 * pagination params, idempotency, metadata, and the generic `extra` escape hatch
 * that lets callers pass any Lob field not enumerated in a tool schema.
 *
 * Also exports two payload-shaping helpers — `compact` (drop undefined keys) and
 * `withExtra` (merge user-provided extras into the typed payload). Precedence
 * choice: `withExtra` REJECTS an `extra` call with a `LOB_EXTRA_PARAM_COLLISION`
 * error if any key also appears as a defined typed field, rather than silently
 * letting one side win. A typed field exists precisely so the schema can
 * validate that value; an `extra` key with the same name is almost always a
 * caller trying to override it (e.g. to work around a validation bug), and a
 * silent override — whichever direction — hides that from the caller. Fix the
 * typed field or omit it instead of routing the same key through `extra`.
 */
import { z } from "zod";
import { randomUUID } from "node:crypto";
import { LobMcpError, LobMcpErrorCodes } from "../lob/errors.js";

/**
 * An inline US/international address payload accepted by Lob create endpoints.
 * Either provide a saved address `id` (`adr_…`) on the parent object, or this inline shape.
 *
 * A function, not a const: the JSON-schema converter dedupes reused Zod schema
 * *instances* (by object identity) into `$ref`s. Two fields that both read a
 * shared const end up as `{ "$ref": "#/properties/<other-field>/..." }` — the
 * second field's advertised schema points at the first instead of describing
 * itself. Calling this factory fresh for each field keeps every field's schema
 * self-contained. See `addressRefSchema` below, which has the same requirement.
 */
export function inlineAddressSchema() {
  return z
    .object({
      name: z.string().max(40).optional().describe("Recipient name (max 40 chars)."),
      company: z.string().max(40).optional().describe("Company name (max 40 chars)."),
      address_line1: z.string().max(200).describe("Primary street address line."),
      address_line2: z.string().max(200).optional().describe("Apartment/suite/unit line."),
      address_city: z.string().max(200).optional(),
      address_state: z
        .string()
        .max(50)
        .optional()
        .describe("Two-letter US state code, or full state/province/region name for international."),
      address_zip: z.string().max(40).optional().describe("ZIP/postal code."),
      address_country: z
        .string()
        .length(2)
        .optional()
        .describe("Two-letter ISO country code. Omit or use 'US' for domestic."),
      phone: z.string().max(40).optional(),
      email: z.string().email().max(100).optional(),
    })
    .describe("Inline address. At minimum, address_line1 plus city/state/zip (or country) are required by Lob.");
}

/**
 * Either a Lob saved-address ID (`adr_…`) or an inline address object.
 * A function for the same reason as `inlineAddressSchema` — see its comment.
 * Callers that embed this in more than one field of the same object (e.g.
 * `to`/`from`) MUST call it once per field so each gets its own schema
 * instance; reusing one call's return value across fields reintroduces the
 * `$ref` collision this factory exists to avoid.
 */
export function addressRefSchema() {
  return z
    .union([
      z.string().regex(/^adr_/).describe("Existing Lob address ID."),
      inlineAddressSchema(),
    ])
    .describe("A Lob saved-address ID (`adr_…`) or an inline address object.");
}

export const idempotencyKeySchema = z
  .string()
  .min(1)
  .max(256)
  .optional()
  .describe(
    "Optional idempotency key. Forwarded as the `Idempotency-Key` header so retries do not duplicate billable mail. " +
      "Use a UUID per logical request and reuse it on retries.",
  );

/**
 * Auto-generating variant: server fills in a UUIDv4 if the caller doesn't pass
 * one. Lob deduplicates identical keys for 24 hours. The preview/commit helper
 * derives this from the confirmation_token when one is consumed, so retries
 * carrying the same token de-dupe at Lob automatically.
 */
export const idempotencyKeyAutoSchema = z
  .string()
  .min(1)
  .max(256)
  .optional()
  .describe(
    "Idempotency key (max 256 chars). If omitted, the server auto-generates a value derived from the " +
      "confirmation_token when present, otherwise a fresh UUIDv4. Lob deduplicates identical keys for 24 hours.",
  );

/** Convenience UUIDv4 generator — exported so callers can pre-generate keys for cross-tool correlation. */
export const generateIdempotencyKey = (): string => randomUUID();

/** Lob date-range filter shape: { gt, gte, lt, lte } each an ISO 8601 timestamp. */
export const dateFilterSchema = z
  .record(z.string())
  .describe(
    "ISO8601 date filter object with gt/gte/lt/lte keys, e.g. { gt: '2026-04-23T00:00:00Z' } " +
      "for 'last 7 days'. Combine with include:['total_count'] and limit:1 for date-bounded counts.",
  );

export const listParamsSchema = z
  .object({
    limit: z
      .number()
      .int()
      .min(1)
      .max(100)
      .optional()
      .describe("How many results to return (default 10, max 100)."),
    before: z.string().optional().describe("Cursor for the previous page."),
    after: z.string().optional().describe("Cursor for the next page."),
    include: z
      .array(z.string())
      .optional()
      .describe(
        "Response add-ons. Pass ['total_count'] alongside any filters and limit:1 to answer 'how many?' " +
          "questions in a single call — far cheaper than paginating to count. " +
          "Not accepted on nested order endpoints (buckslip/card orders) or /webhooks.",
      ),
    date_created: dateFilterSchema.optional(),
    metadata: z
      .record(z.string())
      .optional()
      .describe("Filter by metadata key/value pairs."),
  })
  .describe("Common Lob list/pagination parameters.");

export type ListParams = z.infer<typeof listParamsSchema>;

/** Generic escape hatch for Lob parameters not explicitly enumerated by a tool schema. */
export const extraParamsSchema = z
  .record(z.unknown())
  .optional()
  .describe(
    "Additional Lob API parameters not enumerated above. Merged into the request body verbatim. " +
      "A key here that duplicates a typed parameter above (e.g. 'to' or 'from') is rejected with " +
      "LOB_EXTRA_PARAM_COLLISION — use the typed field for that value instead. " +
      "See https://docs.lob.com for the full parameter list per resource.",
  );

export const sendDateSchema = z
  .string()
  .optional()
  .describe(
    "ISO 8601 timestamp (e.g. '2026-05-01T00:00:00Z') to schedule the send. " +
      "Must be at most 180 days in the future.",
  );

export const mailTypeSchema = z
  .enum(["usps_first_class", "usps_standard"])
  .optional()
  .describe("Mail class. Defaults to usps_first_class for most pieces.");

export const mergeVariablesSchema = z
  .record(z.unknown())
  .optional()
  .describe(
    "Key/value pairs substituted into Handlebars-style {{variables}} in your HTML/template content.",
  );

export const metadataSchema = z
  .record(z.string())
  .optional()
  .describe("Up to 20 string key/value pairs of arbitrary metadata to attach to the resource.");

/**
 * Strip undefined values from an object before sending. Lob treats explicit nulls and undefineds
 * differently in some places; we want clean payloads.
 */
export function compact<T extends object>(obj: T): Partial<T> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined) out[k] = v;
  }
  return out as Partial<T>;
}

/**
 * Merge an `extra` record into a typed payload. Rejects the call if any `extra`
 * key collides with a defined typed field — see the module-level comment for
 * why collisions error instead of one side silently winning.
 */
export function withExtra(
  payload: object,
  extra: Record<string, unknown> | undefined,
): Record<string, unknown> {
  const compacted = compact(payload);
  if (extra) {
    const collisions = Object.keys(extra).filter((k) => k in compacted);
    if (collisions.length > 0) {
      throw new LobMcpError(
        LobMcpErrorCodes.EXTRA_PARAM_COLLISION,
        `extra.${collisions.join(", ")} collides with a typed parameter of the same name.`,
        `Pass ${collisions.length > 1 ? "these values" : "this value"} via the typed field instead of extra.`,
      );
    }
  }
  return { ...(extra ?? {}), ...compacted };
}
