// Classification (CRYPTO-1, CRYPTO-5): the app's `bulkhead.classification.json`, parsed here and enforced where the data lives.
import type { SqlExec } from "../tenant/store.ts";

export const DATA_CLASSES = ["public", "internal", "personal", "sensitive", "secret"] as const;
export type DataClass = (typeof DATA_CLASSES)[number];
const ENCRYPTED: readonly DataClass[] = ["sensitive", "secret"];

export interface ClassifiedField {
  table: string;
  field: string;
  class: DataClass;
  writeOnly?: boolean;
}
export interface Classification {
  version: 1;
  fields: readonly ClassifiedField[];
}

export class ClassificationError extends Error {}

const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;
export const isEncryptedClass = (c: DataClass) => ENCRYPTED.includes(c);

/**
 * The CHECK a sealed column must carry: the shape of a real envelope (`bk1:<version>:<16-char nonce>:<base64url>`), case-sensitive, base64url
 * characters only. A plaintext insert fails in the database itself. Shape is not authenticity: a forged but well-formed value still passes,
 * which is why the sealed write path exists and the verify canary stays the backstop. Use it in the column definition.
 */
export const sealedCheck = (column: string) =>
  `check ("${column}" glob 'bk1:[1-9]*:????????????????:*' and "${column}" not glob '*[^A-Za-z0-9_:-]*')`;

/** Fails closed: anything malformed throws. Same rules as the spec package's validator (a secret must be write-only; no duplicates). */
export function parseClassification(input: unknown): Classification {
  const o = input as { version?: unknown; fields?: unknown } | null;
  if (!o || typeof o !== "object" || o.version !== 1 || !Array.isArray(o.fields)) throw new ClassificationError("classification must be { version: 1, fields: [...] }");
  const seen = new Set<string>();
  for (const [i, f] of (o.fields as Record<string, unknown>[]).entries()) {
    if (!f || typeof f.table !== "string" || typeof f.field !== "string" || !IDENT.test(f.table) || !IDENT.test(f.field)) throw new ClassificationError(`fields[${i}]: table and field must be identifiers`);
    if (!DATA_CLASSES.includes(f.class as DataClass)) throw new ClassificationError(`fields[${i}]: unknown class`);
    if (f.class === "secret" && f.writeOnly !== true) throw new ClassificationError(`fields[${i}]: secret fields must be writeOnly`);
    const k = `${f.table}.${f.field}`;
    if (seen.has(k)) throw new ClassificationError(`duplicate classification for ${k}`);
    seen.add(k);
  }
  return { version: 1, fields: o.fields as ClassifiedField[] };
}

export function lookupField(c: Classification, table: string, field: string): ClassifiedField | undefined {
  return c.fields.find((f) => f.table === table && f.field === field);
}

const normalise = (sql: string) => sql.toLowerCase().replace(/["'`\s]/g, "");

/**
 * Run once when a tenant's database initialises, after the schema steps. Refuses (throws) when
 *  - a column of any app table has no classification (unclassified data is a bug),
 *  - a classified column does not exist (stale classification),
 *  - an encrypted-class column lacks the `bk1:` CHECK, so a plaintext insert would not fail in the database itself.
 */
export function enforceClassification(exec: SqlExec, c: Classification) {
  // The runtime's own tables (SQLite's, Durable Objects' `_cf_*`, local miniflare's `__miniflare*`) and ours are not app data.
  const tables = (exec("select name, sql from sqlite_master where type = 'table'", []).rows as { name: string; sql: string }[]).filter((t) => !/^(_bulkhead_|sqlite_|_cf_|__miniflare)/.test(t.name));
  const columns = new Set<string>();
  for (const t of tables) {
    const sql = normalise(t.sql ?? "");
    for (const col of exec("select name from pragma_table_info(?)", [t.name]).rows as { name: string }[]) {
      const key = `${t.name}.${col.name}`;
      columns.add(key);
      const f = lookupField(c, t.name, col.name);
      if (!f) throw new ClassificationError(`unclassified column ${key}: the tenant refuses to initialise`);
      if (isEncryptedClass(f.class) && !sql.includes(normalise(sealedCheck(col.name)))) throw new ClassificationError(`column ${key} is ${f.class} but has no sealed-value CHECK; the tenant refuses to initialise`);
    }
  }
  for (const f of c.fields) if (!columns.has(`${f.table}.${f.field}`)) throw new ClassificationError(`classified column ${f.table}.${f.field} does not exist`);
}
