// Phase 4 gate (DR-0007): applies each catalog mutation to a scratch copy of the workspace, boots the demo Worker
// against it with scripts/verify-kernel.ts, and checks that exactly the named probes fail. The working tree is never edited.
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mutations, type Mutation } from "./mutations.ts";

const RULES = "TENANT-1,TENANT-4,TENANT-5,AUTH-1,AUTH-2,AUTH-3,AUTH-4";
const root = new URL("..", import.meta.url).pathname;
const only = (() => { const i = process.argv.indexOf("--only"); return i >= 0 ? process.argv[i + 1]?.split(",") : undefined; })();

const ids = mutations.map((m) => m.id);
if (new Set(ids).size !== ids.length) { console.error("duplicate mutation id in catalog"); process.exit(1); }
const selected = only ? mutations.filter((m) => only.includes(m.id)) : mutations;
if (only && selected.length !== only.length) { console.error(`unknown mutation id in --only: ${only.filter((o) => !ids.includes(o)).join(", ")}`); process.exit(1); }

const scratch = mkdtempSync(join(tmpdir(), "bulkhead-mutate-"));
// verbatimSymlinks keeps pnpm's relative links pointing inside the copy, so the mutated packages are what workerd bundles.
cpSync(root, scratch, { recursive: true, verbatimSymlinks: true, filter: (src) => !/\/(\.git|\.bulkhead|\.wrangler)(\/|$)/.test(src.slice(root.length - 1)) });

/** Runs verify against the scratch copy; returns the failing probe ids, or an error string when the run itself broke. */
function runVerify(): { failed: string[] } | { error: string } {
  const r = spawnSync(process.execPath, [join(scratch, "scripts/verify-kernel.ts"), "--rules", RULES], { cwd: scratch, encoding: "utf8", timeout: 400_000 });
  const out = `${r.stdout ?? ""}\n${r.stderr ?? ""}`;
  const lines = out.split("\n");
  const results = lines.filter((l) => /^(pass|FAIL) [A-Z]+-\d+ /.test(l));
  if (r.error || results.length === 0) return { error: `verify run did not produce results (exit ${r.status}):\n${out.split("\n").slice(-20).join("\n")}` };
  return { failed: results.filter((l) => l.startsWith("FAIL")).map((l) => l.split(" ")[2]!.replace(/:$/, "")).sort() };
}

/** Runs a package's unit tests in the scratch copy (same files as its `test` script); true when they pass. */
function unitTestsPass(pkg: string): boolean {
  const dir = join(scratch, pkg, "test");
  const files = readdirSync(dir).filter((f) => f.endsWith(".test.ts")).map((f) => join("test", f));
  if (files.length === 0) return false;
  return spawnSync(process.execPath, ["--test", ...files], { cwd: join(scratch, pkg), encoding: "utf8", timeout: 200_000 }).status === 0;
}

let bad = 0;
const report = (ok: boolean, msg: string) => { console.log(`${ok ? "ok  " : "FAIL"} ${msg}`); if (!ok) bad++; };

try {
  const base = runVerify();
  if ("error" in base) { report(false, `baseline: ${base.error}`); }
  else if (base.failed.length) { report(false, `baseline already fails [${base.failed}], mutation results would be meaningless`); }
  else {
    report(true, "baseline: unmutated copy passes every probe");
    for (const m of selected) {
      const path = join(scratch, m.file);
      const original = readFileSync(path, "utf8");
      const hits = original.split(m.find).length - 1;
      if (hits !== 1) { report(false, `${m.id}: find string matched ${hits} time(s) in ${m.file}, must be exactly 1`); continue; }
      writeFileSync(path, original.replace(m.find, () => m.replace));
      const res = runVerify();
      writeFileSync(path, original);
      if ("error" in res) { report(false, `${m.id}: ${res.error}`); continue; }
      if (m.gap) {
        if (m.expect.length) { report(false, `${m.id}: a gap entry must have an empty expect list`); continue; }
        if (res.failed.length) { report(false, `${m.id}: a probe now catches this ([${res.failed}]); promote it from gap to expect`); continue; }
        const pkg = m.file.split("/").slice(0, 2).join("/");
        if (!unitTestsPass(pkg)) { report(false, `${m.id}: unit tests of ${pkg} fail or are missing on the unmutated copy, so a gap cannot be judged`); continue; }
        writeFileSync(path, original.replace(m.find, () => m.replace));
        const unitSurvived = unitTestsPass(pkg);
        writeFileSync(path, original);
        if (!unitSurvived) console.log(`gap  ${m.id} (${m.rule}): survives black-box verify, killed by ${pkg} unit tests. Gap: ${m.gap}`);
        else report(false, `${m.id} (${m.rule}): SURVIVED verify and unit tests, nothing protects this line`);
        continue;
      }
      if (m.expect.length === 0) { report(false, `${m.id}: empty expect without a gap reason`); continue; }
      const want = [...m.expect].sort();
      const missing = want.filter((p) => !res.failed.includes(p));
      const extra = res.failed.filter((p) => !want.includes(p));
      if (missing.length === 0 && extra.length === 0) report(true, `${m.id} (${m.rule}): killed by [${res.failed}]`);
      else report(false, `${m.id} (${m.rule}): ${missing.length ? `SURVIVED, scenario(s) worthless: [${missing}]` : ""}${extra.length ? ` unexpected failures, mis-attributed: [${extra}]` : ""} (failed: [${res.failed}])`);
    }
  }
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
console.log(`${selected.length} mutation(s) run, ${bad} problem(s). A killed mutation shows a probe can fail; it does not prove correctness.`);
process.exit(bad ? 1 : 0);
