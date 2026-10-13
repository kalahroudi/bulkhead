import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { decisionItems } from "@kalahroudi/bulkhead-spec";
import { mutations } from "../src/mutations.ts";
import { probes } from "../src/probes.ts";

const repo = fileURLToPath(new URL("../../../", import.meta.url));
const gates = Object.keys((JSON.parse(readFileSync(repo + "package.json", "utf8")) as { scripts: Record<string, string> }).scripts);

/** Returns why a ref does not resolve, or null when it points at something real. */
function unresolved(ref: string): string | null {
  const [kind, rest] = [ref.slice(0, ref.indexOf(":")), ref.slice(ref.indexOf(":") + 1)];
  switch (kind) {
    case "probe": return probes.some((p) => p.id === rest) ? null : "no such probe";
    case "mutation": return mutations.some((m) => m.id === rest) ? null : "no such catalog entry";
    case "gate": return gates.includes(`gate:${rest}`) ? null : "no such gate script in package.json";
    case "script": return !rest.includes("..") && existsSync(repo + rest) && statSync(repo + rest).isFile() ? null : "not an existing file inside the repo";
    case "test": {
      const [path, title] = rest.split("::");
      if (!path || path.includes("..") || !existsSync(repo + path) || !statSync(repo + path).isFile()) return "test file does not exist";
      if (!title?.trim()) return "a test ref must name a test title after '::'";
      // The title must sit on a real assertion: a `test("...")` declaration, or a `check(..., "...")` line in a self-test script.
      // A comment or an unrelated string does not count.
      const declared = readFileSync(repo + path, "utf8").split("\n").some((l) => (/^\s*test\(\s*["'`]/.test(l) || (/\bcheck\(/.test(l) && !/^\s*\/\//.test(l))) && l.includes(title));
      return declared ? null : `no test(...) declaration or check(...) assertion in ${path} contains "${title}"`;
    }
    default: return "unknown ref kind";
  }
}

test("every ref a decision record cites resolves to a real probe, catalog entry, test, script or gate", () => {
  const dir = repo + "docs/decisions/";
  let checked = 0;
  for (const f of readdirSync(dir).filter((n) => /^DR-\d+.*\.md$/.test(n))) {
    for (const item of decisionItems(readFileSync(dir + f, "utf8"))?.items ?? [])
      for (const ref of item.refs) {
        checked++;
        assert.equal(unresolved(ref), null, `${f} decision ${item.number}: \`${ref}\` ${unresolved(ref)}`);
      }
  }
  assert.ok(checked > 20, "expected the records to cite their checks");
});

test("the resolver itself rejects bad refs", () => {
  for (const bad of ["probe:nope", "mutation:nope", "gate:phase99", "script:scripts/nope.ts", "test:packages/auth/test/auth.test.ts::no such title", "test:scripts/release-selftest.ts::no such assertion", "test:packages/nope.test.ts", "test:packages/auth/test/auth.test.ts", "test:packages/auth/test/auth.test.ts::", "script:scripts", "script:../etc/passwd", "vibes:x"])
    assert.notEqual(unresolved(bad), null, bad);
  for (const good of ["probe:csrf-origin", "mutation:csrf-origin-ignored", "gate:phase4", "script:scripts/verify-mutations.ts", "test:packages/auth/test/auth.test.ts::bootstrap"])
    assert.equal(unresolved(good), null, good);
});
