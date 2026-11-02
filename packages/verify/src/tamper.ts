// Disk-write attacker for the CRYPTO-2 transplant scenario (DR-0010). The inspector (inspector.ts) is strictly read-only and stays
// so; this is the one module that writes, and only into a tenant database the caller names, only one cell at a time, and only to
// put an envelope that the running app itself produced somewhere else. It imports no app code (VERIFY-1).
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

const ident = (s: string) => `"${s.replaceAll('"', '""')}"`;

/** Overwrites one cell of a persisted tenant database while the app keeps running. Returns false when SQLite refused (locked, missing). */
export function overwriteCell(dir: string, cell: { file: string; table: string; column: string; rowid: number }, value: string): { ok: boolean; detail: string } {
  let db: DatabaseSync | undefined;
  try {
    db = new DatabaseSync(join(dir, cell.file), { timeout: 5000 });
    const r = db.prepare(`update ${ident(cell.table)} set ${ident(cell.column)} = ? where rowid = ?`).run(value, cell.rowid);
    return Number(r.changes) === 1 ? { ok: true, detail: "written" } : { ok: false, detail: `${r.changes} row(s) changed, expected 1` };
  } catch (e) {
    return { ok: false, detail: (e as Error).message };
  } finally {
    try { db?.close(); } catch { /* nothing to do */ }
  }
}
