// Storage inspector (DR-0010 step a, CRYPTO-1/CRYPTO-3). Looks at the locally persisted tenant SQLite files the way an
// attacker with disk access would: every table and column through SQL, and every raw byte of every file (pages, WAL,
// journals, anything else under the directory). It opens databases READ-ONLY and never imports app or core code (VERIFY-1).
// Local persisted files only: on a non-local target there is no directory, and callers must report "unverified".
import { closeSync, openSync, readSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

export interface StorageHit {
  /** Path relative to the inspected directory. */
  file: string;
  /** "column": found by reading a table cell through SQL. "raw": found in the file's bytes (free pages, WAL, side files). */
  layer: "column" | "raw";
  /** For a column hit, `table.column`; for a raw hit, the marker's byte offset. */
  where: string;
  marker: string;
}

export interface StorageScan {
  filesScanned: number;
  sqliteOpened: number;
  tablesScanned: number;
  rowsScanned: number;
  hits: StorageHit[];
  /** Anything that stopped a layer from being complete (a database that would not open, a table that would not read). Never ignored by callers. */
  incomplete: string[];
}

const SQLITE_MAGIC = Buffer.from("SQLite format 3\0");

function filesUnder(dir: string, rel = ""): string[] {
  const out: string[] = [];
  for (const e of readdirSync(join(dir, rel), { withFileTypes: true })) {
    const p = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDirectory()) out.push(...filesUnder(dir, p));
    else if (e.isFile()) out.push(p);
  }
  return out.sort();
}

function isSqlite(path: string): boolean {
  const fd = openSync(path, "r");
  try {
    const head = Buffer.alloc(SQLITE_MAGIC.length);
    return readSync(fd, head, 0, head.length, 0) === head.length && head.equals(SQLITE_MAGIC);
  } finally {
    closeSync(fd);
  }
}

/** The only way this module opens a database. Read-only is enforced by SQLite itself, not by convention. */
export function openReadOnly(path: string): DatabaseSync {
  return new DatabaseSync(path, { readOnly: true });
}

const ident = (s: string) => `"${s.replaceAll('"', '""')}"`;

function cellContains(v: unknown, needle: Buffer): boolean {
  if (v === null || v === undefined) return false;
  if (v instanceof Uint8Array) return Buffer.from(v).includes(needle);
  return Buffer.from(String(v), "utf8").includes(needle);
}

/**
 * Scans `dir` for any of `markers`. Raises when `dir` is not a readable directory (a wrong path is a configuration error,
 * not "nothing found"). Hits are reported per layer so a leak only the raw layer sees (a deleted row, a WAL frame) is visible.
 */
export function scanStorage(dir: string, markers: readonly string[]): StorageScan {
  if (!statSync(dir).isDirectory()) throw new Error(`${dir} is not a directory`);
  const needles = markers.map((m) => ({ m, b: Buffer.from(m, "utf8") }));
  const scan: StorageScan = { filesScanned: 0, sqliteOpened: 0, tablesScanned: 0, rowsScanned: 0, hits: [], incomplete: [] };
  for (const file of filesUnder(dir)) {
    const path = join(dir, file);
    const bytes = readFileSync(path);
    scan.filesScanned++;
    for (const { m, b } of needles) {
      let at = bytes.indexOf(b);
      while (at !== -1) {
        scan.hits.push({ file, layer: "raw", where: `byte ${at}`, marker: m });
        at = bytes.indexOf(b, at + b.length);
      }
    }
    if (!isSqlite(path)) continue;
    let db: DatabaseSync | undefined;
    try {
      db = openReadOnly(path);
      scan.sqliteOpened++;
      const tables = db.prepare("select name from sqlite_master where type = 'table'").all() as { name: string }[];
      for (const { name } of tables) {
        try {
          scan.tablesScanned++;
          for (const row of db.prepare(`select * from ${ident(name)}`).iterate() as Iterable<Record<string, unknown>>) {
            scan.rowsScanned++;
            for (const [col, v] of Object.entries(row)) for (const { m, b } of needles) if (cellContains(v, b)) scan.hits.push({ file, layer: "column", where: `${name}.${col}`, marker: m });
          }
        } catch (e) {
          scan.incomplete.push(`${file}: table ${name} unreadable: ${(e as Error).message}`);
        }
      }
    } catch (e) {
      void (`${file}: SQLite open failed: ${(e as Error).message}`);
    } finally {
      db?.close();
    }
  }
  return scan;
}
