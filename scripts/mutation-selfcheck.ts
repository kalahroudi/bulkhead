// Proves the mutation gate can fail (VERIFY-4 applied to the gate itself). Feeds the runner a catalog of deliberately
// wrong entries and requires it to exit non-zero and to name each defect. If the runner ever called one of these fine,
// `gate:phase4` would be a stub, so this check fails first.
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = mkdtempSync(join(tmpdir(), "bulkhead-canary-"));
const catalog = join(dir, "canary-catalog.ts");
const AUTH = "packages/auth/src/authenticate.ts";
writeFileSync(catalog, `export const mutations = [
  // Survivor: a comment edit breaks nothing, so the claimed probe cannot fail.
  { id: "canary-survivor", rule: "AUTH-2", file: ${JSON.stringify(AUTH)}, find: "// Compare against a hash even when the key is unknown so lookups take the same path.", replace: "// edited", expect: ["csrf-origin"] },
  // Mis-attribution: a real CSRF break, claimed to be caught by a different probe.
  { id: "canary-misattributed", rule: "AUTH-2", file: ${JSON.stringify(AUTH)}, find: "return new URL(origin).host === new URL(req.url).host;", replace: "return true;", expect: ["cookie-flags"] },
  // Stale entry: the line it targets does not exist, which must error instead of being skipped.
  { id: "canary-stale", rule: "AUTH-2", file: ${JSON.stringify(AUTH)}, find: "this text is not in the file", replace: "x", expect: ["csrf-origin"] },
];\n`);

const must: [string, RegExp][] = [
  ["a survivor", /FAIL canary-survivor .*SURVIVED/],
  ["a mis-attributed kill", /FAIL canary-misattributed .*SURVIVED.*mis-attributed/],
  ["a stale find string", /FAIL canary-stale: find string matched 0 time/],
];
try {
  const r = spawnSync(process.execPath, [join(import.meta.dirname, "verify-mutations.ts"), "--catalog", catalog], { encoding: "utf8", timeout: 600_000 });
  const out = `${r.stdout}\n${r.stderr}`;
  let bad = 0;
  if (r.status === 0) { console.error("FAIL runner exited 0 on a catalog of broken entries: the gate is a stub"); bad++; }
  for (const [what, re] of must) {
    if (re.test(out)) console.log(`ok   runner rejected ${what}`);
    else { console.error(`FAIL runner did not report ${what}`); bad++; }
  }
  if (bad) console.error("\nrunner output:\n" + out);
  console.log(bad ? `mutation gate self-check FAILED (${bad})` : "mutation gate self-check passed: the runner fails on survivors, mis-attribution and stale entries");
  process.exitCode = bad ? 1 : 0;
} finally {
  rmSync(dir, { recursive: true, force: true });
}
