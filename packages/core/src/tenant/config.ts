import type { Config, D1Like, Environment, TenantNamespaceLike } from "./types.ts";

export class ConfigError extends Error {}

const ENVS: readonly Environment[] = ["development", "staging", "production"];

/** BOOT-1: fail closed. Any missing or contradictory value throws; the app serves nothing. */
export function loadConfig(env: Record<string, unknown>): Config {
  const environment = env.BULKHEAD_ENV;
  if (typeof environment !== "string" || !ENVS.includes(environment as Environment))
    throw new ConfigError(`BULKHEAD_ENV must be one of ${ENVS.join(", ")}`);
  const baseDomain = env.BULKHEAD_BASE_DOMAIN;
  if (typeof baseDomain !== "string" || !/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(baseDomain))
    throw new ConfigError("BULKHEAD_BASE_DOMAIN must be a lowercase hostname");
  const db = env.BULKHEAD_DB as D1Like | undefined;
  if (!db || typeof db.prepare !== "function") throw new ConfigError("BULKHEAD_DB (D1 control plane) binding is missing");
  const tenants = env.BULKHEAD_TENANT as TenantNamespaceLike | undefined;
  if (!tenants || typeof tenants.idFromName !== "function" || typeof tenants.get !== "function")
    throw new ConfigError("BULKHEAD_TENANT (Durable Object namespace) binding is missing");
  const auto = env.BULKHEAD_AUTO_PROVISION;
  if (auto !== undefined && auto !== "true" && auto !== "false") throw new ConfigError("BULKHEAD_AUTO_PROVISION must be true or false");
  if (auto === "true" && environment !== "development") throw new ConfigError("BULKHEAD_AUTO_PROVISION=true is only allowed when BULKHEAD_ENV=development");
  return { environment: environment as Environment, baseDomain, db, tenants, autoProvision: auto === "true" };
}
