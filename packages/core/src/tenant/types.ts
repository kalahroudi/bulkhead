// Structural stand-ins for the Cloudflare bindings core uses, so core typechecks and unit-tests without workers-types.
export interface D1Like {
  prepare(sql: string): {
    bind(...values: unknown[]): { first<T = unknown>(): Promise<T | null>; run(): Promise<unknown>; all<T = unknown>(): Promise<{ results: T[] }> };
    first<T = unknown>(): Promise<T | null>;
    run(): Promise<unknown>;
  };
}

export interface TenantStub {
  exec(tenantId: string, schema: readonly string[], sql: string, params: unknown[]): Promise<{ rows: Record<string, unknown>[]; changes: number }>;
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
}
