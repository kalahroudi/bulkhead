import type { Classification } from "../crypto/classification.ts";
import type { MasterKeys } from "../crypto/keys.ts";

// Structural stand-ins for the Cloudflare bindings core uses, so core typechecks and unit-tests without workers-types.
export interface D1Like {
  prepare(sql: string): {
    bind(...values: unknown[]): { first<T = unknown>(): Promise<T | null>; run(): Promise<unknown>; all<T = unknown>(): Promise<{ results: T[] }> };
    first<T = unknown>(): Promise<T | null>;
    run(): Promise<unknown>;
  };
}

export interface TenantStub {
  exec(tenantId: string, schema: readonly string[], sql: string, params: unknown[], classification?: Classification): Promise<{ rows: Record<string, unknown>[]; changes: number }>;
  /** Reserves the next nonce counter for a key version (CRYPTO-4). */
  nonce(tenantId: string, schema: readonly string[], keyVersion: number, classification?: Classification): Promise<number>;
}

export interface TenantNamespaceLike {
  idFromName(name: string): unknown;
  get(id: unknown): TenantStub;
}

export interface Tenant {
  /** Opaque ID. Durable Objects are addressed by this, never by slug, so a reused slug cannot reach old data. */
  readonly id: string;
  readonly slug: string;
}

export type Environment = "development" | "staging" | "production";

export interface Config {
  environment: Environment;
  baseDomain: string;
  db: D1Like;
  tenants: TenantNamespaceLike;
  /** Development stopgap until Phase 6 provisioning. Only ever true in development. */
  autoProvision: boolean;
  /** Present only when the app declares classified data; then required (BOOT-1). */
  masterKeys?: MasterKeys;
}
