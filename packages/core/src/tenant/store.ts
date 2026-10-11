// Logic behind each tenant's Durable Object. Pure over an injected SQL executor so it is unit-testable on node:sqlite.
export type SqlExec = (sql: string, params: unknown[]) => { rows: Record<string, unknown>[]; changes: number };

const RESERVED = /_bulkhead_/i;

export class TenantStore {
  private exec: SqlExec;
  private ready = false;
  constructor(exec: SqlExec) {
    this.exec = exec;
  }

  /** Binds the database to one tenant on first use and applies schema steps in order. A different tenant ID is refused. */
  private init(tenantId: string, schema: readonly string[]) {
    this.exec("create table if not exists _bulkhead_meta (key text primary key, value text not null)", []);
    const bound = this.exec("select value from _bulkhead_meta where key = 'tenant_id'", []).rows[0]?.value;
    if (bound === undefined) this.exec("insert into _bulkhead_meta (key, value) values ('tenant_id', ?)", [tenantId]);
    else if (bound !== tenantId) throw new Error("tenant mismatch");
    const applied = Number(this.exec("select value from _bulkhead_meta where key = 'schema_version'", []).rows[0]?.value ?? 0);
    for (let i = applied; i < schema.length; i++) {
      this.exec(schema[i] as string, []);
      this.exec("insert or replace into _bulkhead_meta (key, value) values ('schema_version', ?)", [String(i + 1)]);
    }
    this.ready = true;
  }

  run(tenantId: string, schema: readonly string[], sql: string, params: unknown[]) {
    if (RESERVED.test(sql)) throw new Error("reserved table");
    if (!this.ready) this.init(tenantId, schema);
    else if (this.exec("select value from _bulkhead_meta where key = 'tenant_id'", []).rows[0]?.value !== tenantId) throw new Error("tenant mismatch");
    return this.exec(sql, params);
  }
}
