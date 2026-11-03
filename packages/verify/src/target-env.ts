// DR-0016 decision 3: the demo-specific values a run may override, from flags and from an optional verify-target.json next to the route manifest.
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { TargetEnv } from "./probes.ts";

export const TARGET_CONFIG_FILE = "verify-target.json";
const KEYS = ["cookieName", "hostSuffix", "webhookSecret"] as const;
type Overrides = Pick<TargetEnv, (typeof KEYS)[number]>;

const COOKIE_TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const HOST_SUFFIX = /^(?!-)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*$/;

/** Validates a config object. Unknown keys are refused: a typo must not silently leave the demo's default in place. */
export function parseTargetConfig(text: string, source = TARGET_CONFIG_FILE): Overrides {
  let data: unknown;
  try { data = JSON.parse(text); } catch (e) { throw new Error(`${source} is not valid JSON: ${(e as Error).message}`); }
  if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error(`${source} must be a JSON object`);
  const out: Overrides = {};
  for (const [k, v] of Object.entries(data)) {
    if (!(KEYS as readonly string[]).includes(k)) throw new Error(`${source}: unknown key "${k}" (allowed: ${KEYS.join(", ")})`);
    if (typeof v !== "string" || v === "") throw new Error(`${source}: "${k}" must be a non-empty string`);
    if (k === "cookieName" && !COOKIE_TOKEN.test(v)) throw new Error(`${source}: "cookieName" is not a valid cookie name`);
    if (k === "hostSuffix" && !HOST_SUFFIX.test(v)) throw new Error(`${source}: "hostSuffix" must be a bare domain such as demo.localhost (no scheme, port or leading dot)`);
    out[k as keyof Overrides] = v;
  }
  return out;
}

/** Config file next to the manifest (if any), then flags on top. Flags win. */
export function resolveTargetOverrides(opts: { manifestPath?: string; cookieName?: string; hostSuffix?: string; webhookSecret?: string }): Overrides {
  let fromFile: Overrides = {};
  if (opts.manifestPath) {
    const file = join(dirname(opts.manifestPath), TARGET_CONFIG_FILE);
    if (existsSync(file)) fromFile = parseTargetConfig(readFileSync(file, "utf8"), file);
  }
  const flags = parseTargetConfig(JSON.stringify(Object.fromEntries(Object.entries({ cookieName: opts.cookieName, hostSuffix: opts.hostSuffix, webhookSecret: opts.webhookSecret }).filter(([, v]) => v !== undefined))), "command-line flags");
  return { ...fromFile, ...flags };
}
