import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { mutations, UNMUTATABLE, type Edit } from "../src/mutations.ts";
import { probes } from "../src/probes.ts";

const repo = fileURLToPath(new URL("../../../", import.meta.url));
const editsOf = (m: (typeof mutations)[number]): Edit[] => [{ file: m.file, find: m.find, replace: m.replace }, ...(m.also ?? [])];

test("catalog ids are unique and every edit changes something", () => {
  assert.equal(new Set(mutations.map((m) => m.id)).size, mutations.length);
  for (const m of mutations) for (const e of editsOf(m)) assert.notEqual(e.find, e.replace, `${m.id}: edit is a no-op`);
});

test("every expected probe id is a real probe", () => {
  const ids = new Set(probes.map((p) => p.id));
  for (const m of mutations) for (const p of m.expect) assert.ok(ids.has(p), `${m.id}: unknown probe ${p}`);
  for (const p of Object.keys(UNMUTATABLE)) assert.ok(ids.has(p), `UNMUTATABLE names unknown probe ${p}`);
});

test("gap entries expect nothing and name their reason; every other entry expects at least one probe", () => {
  for (const m of mutations) {
    if (m.gap !== undefined) { assert.ok(m.gap.trim().length > 20, `${m.id}: gap needs a reason`); assert.deepEqual(m.expect, [], `${m.id}: a gap expects no probe`); }
    else assert.ok(m.expect.length > 0, `${m.id}: expects no probe and records no gap`);
  }
});

test("each find string occurs exactly once in the real source file", () => {
  for (const m of mutations) for (const e of editsOf(m)) {
    const path = repo + e.file;
    assert.ok(existsSync(path), `${m.id}: ${e.file} does not exist`);
    assert.equal(readFileSync(path, "utf8").split(e.find).length - 1, 1, `${m.id}: find must match exactly once in ${e.file}`);
  }
});

test("DR-0007 item 4: every probe is broken by some catalog entry, or is exempted with a reason", () => {
  const covered = new Set(mutations.flatMap((m) => m.expect));
  for (const p of probes) {
    if (UNMUTATABLE[p.id] !== undefined) {
      assert.ok(UNMUTATABLE[p.id]!.trim().length > 20, `${p.id}: exemption needs a reason`);
      assert.ok(!covered.has(p.id), `${p.id}: has a catalog entry, so remove the exemption`);
    } else assert.ok(covered.has(p.id), `probe ${p.id} (${p.ruleId}) has no mutation catalog entry; add one or record why none can exist`);
  }
});
