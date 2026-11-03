// DR-0011 spike: a Better Auth database adapter whose only way to reach storage is a TenantDb (TENANT-1/3).
// The adapter is built per request around that request's handle, so there is no module-level state to leak between tenants.
import { createAdapterFactory, type CleanedWhere } from "better-auth/adapters";
import type { TenantDb } from "@kalahroudi/bulkhead-core/tenant";

// Table and column names come from Better Auth's own schema, never from request data, but they are still checked before
// they are spliced into SQL: an identifier that is not a plain word is a bug, and it fails closed.
const IDENT = /^[A-Za-z][A-Za-z0-9_]{0,62}$/;
const ident = (s: string) => {
  if (!IDENT.test(s)) throw new Error(`refusing to build SQL with identifier ${JSON.stringify(s)}`);
  return `"${s}"`;
};

type Param = string | number | null;
const param = (v: unknown): Param => {
  if (v === null || v === undefined) return null;
  if (typeof v === "string" || typeof v === "number") return v;
  if (typeof v === "boolean") return v ? 1 : 0;
  if (v instanceof Date) return v.getTime();
  throw new Error(`unsupported parameter type ${typeof v}`);
};

function whereSql(where: CleanedWhere[] | undefined): { sql: string; params: Param[] } {
  if (!where || where.length === 0) return { sql: "", params: [] };
  const parts: { sql: string; p: Param[]; or: boolean }[] = [];
  where.forEach((w) => {
    const params: Param[] = []; // this clause's own parameters: grouping below reorders the SQL, so the values must travel with their clause
    const col = ident(w.field);
    const ci = w.mode === "insensitive" && typeof w.value === "string";
    const lhs = ci ? `lower(${col})` : col;
    const val = (v: unknown) => (ci && typeof v === "string" ? v.toLowerCase() : v);
    let clause: string;
    switch (w.operator) {
      case "eq":
        if (w.value === null) clause = `${col} is null`;
        else { clause = `${lhs} = ?`; params.push(param(val(w.value))); }
        break;
      case "ne":
        if (w.value === null) clause = `${col} is not null`;
        else { clause = `${lhs} <> ?`; params.push(param(val(w.value))); }
        break;
      case "lt": case "lte": case "gt": case "gte":
        clause = `${col} ${{ lt: "<", lte: "<=", gt: ">", gte: ">=" }[w.operator]} ?`;
        params.push(param(w.value));
        break;
      case "in": case "not_in": {
        const list = Array.isArray(w.value) ? w.value : [];
        if (list.length === 0) { clause = w.operator === "in" ? "0" : "1"; break; }
        clause = `${lhs} ${w.operator === "in" ? "in" : "not in"} (${list.map(() => "?").join(", ")})`;
        for (const v of list) params.push(param(val(v)));
        break;
      }
      case "contains": case "starts_with": case "ends_with": {
        const raw = String(val(w.value) ?? "").replace(/[\\%_]/g, (c) => `\\${c}`);
        clause = `${lhs} like ? escape '\\'`;
        params.push(w.operator === "contains" ? `%${raw}%` : w.operator === "starts_with" ? `${raw}%` : `%${raw}`);
        break;
      }
      default:
        throw new Error(`unsupported where operator ${String(w.operator)}`);
    }
    parts.push({ sql: clause, p: params, or: w.connector === "OR" });
  });
  // Better Auth's own adapters build (every AND clause) AND (any OR clause). Chaining them in order would let SQL precedence change the meaning.
  const ands = parts.filter((p) => !p.or);
  const ors = parts.filter((p) => p.or);
  const groups = [ands.length ? `(${ands.map((p) => p.sql).join(" and ")})` : "", ors.length ? `(${ors.map((p) => p.sql).join(" or ")})` : ""].filter(Boolean);
  return { sql: ` where ${groups.join(" and ")}`, params: [...ands, ...ors].flatMap((p) => p.p) };
}

/** A write with no condition would hit the whole table. Better Auth guards only some of its own calls, so every write here refuses. */
function writeWhere(where: CleanedWhere[] | undefined): { sql: string; params: Param[] } {
  if (!where || where.length === 0) throw new Error("refusing a write with an empty where clause");
  return whereSql(where);
}

function selectList(select: string[] | undefined) {
  return select && select.length > 0 ? select.map(ident).join(", ") : "*";
}

/** One adapter per request. `db` is that request's TenantDb; there is no other way in. */
export function tenantDbAdapter(db: TenantDb) {
  return createAdapterFactory({
    config: {
      adapterId: "bulkhead-tenant-db",
      adapterName: "Bulkhead TenantDb adapter",
      usePlural: false,
      supportsJSON: false,
      supportsDates: false,
      supportsBooleans: false,
      supportsArrays: false,
      // The Durable Object runs each request's calls one after another; there is no multi-statement transaction through TenantDb.
      transaction: false,
    },
    adapter: () => ({
      async create({ model, data }) {
        const keys = Object.keys(data);
        await db.run(`insert into ${ident(model)} (${keys.map(ident).join(", ")}) values (${keys.map(() => "?").join(", ")})`, ...keys.map((k) => param(data[k])));
        return data;
      },
      async findOne({ model, where, select }) {
        const w = whereSql(where);
        const rows = await db.query(`select ${selectList(select)} from ${ident(model)}${w.sql} limit 1`, ...w.params);
        return (rows[0] ?? null) as never;
      },
      async findMany({ model, where, limit, select, sortBy, offset }) {
        const w = whereSql(where);
        const order = sortBy ? ` order by ${ident(sortBy.field)} ${sortBy.direction === "desc" ? "desc" : "asc"}` : "";
        const lim = Number.isInteger(limit) && limit > 0 ? limit : 100;
        const off = offset && Number.isInteger(offset) && offset > 0 ? ` offset ${offset}` : "";
        return (await db.query(`select ${selectList(select)} from ${ident(model)}${w.sql}${order} limit ${lim}${off}`, ...w.params)) as never;
      },
      async count({ model, where }) {
        const w = whereSql(where);
        const rows = await db.query<{ n: number }>(`select count(*) as n from ${ident(model)}${w.sql}`, ...w.params);
        return Number(rows[0]?.n ?? 0);
      },
      async update({ model, where, update }) {
        const set = Object.entries(update as Record<string, unknown>);
        if (set.length === 0) return null;
        const w = writeWhere(where);
        // Find the row first and update it by id, so changing a column the condition filters on cannot make the read-back miss it.
        const found = await db.query<{ id: string }>(`select id from ${ident(model)}${w.sql} limit 1`, ...w.params);
        const id = found[0]?.id;
        if (id === undefined) return null;
        await db.run(`update ${ident(model)} set ${set.map(([k]) => `${ident(k)} = ?`).join(", ")} where id = ?`, ...set.map(([, v]) => param(v)), id);
        const rows = await db.query(`select * from ${ident(model)} where id = ?`, id);
        return (rows[0] ?? null) as never;
      },
      async updateMany({ model, where, update }) {
        const set = Object.entries(update);
        if (set.length === 0) return 0;
        const w = writeWhere(where);
        return (await db.run(`update ${ident(model)} set ${set.map(([k]) => `${ident(k)} = ?`).join(", ")}${w.sql}`, ...set.map(([, v]) => param(v)), ...w.params)).changes;
      },
      async delete({ model, where }) {
        const w = writeWhere(where);
        await db.run(`delete from ${ident(model)}${w.sql}`, ...w.params);
      },
      async deleteMany({ model, where }) {
        const w = writeWhere(where);
        return (await db.run(`delete from ${ident(model)}${w.sql}`, ...w.params)).changes;
      },
    }),
  });
}
