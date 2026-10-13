// Phase 4 gate (DR-0007): applies each catalog mutation to a scratch copy of the workspace, boots the demo Worker
// against it with scripts/verify-kernel.ts, and checks that exactly the named probes fail. The working tree is never edited.
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import type { Edit, Mutation } from "../packages/verify/src/mutations.ts";

const RULES = "TENANT-1,TENANT-4,TENANT-5,AUTH-1,AUTH-2,AUTH-3,AUTH-4";
const root = fileURLToPath(new URL("..", import.meta.url)); // decoded, so a path with spaces works
const only = (() => { const i = process.argv.indexOf("--only"); return i >= 0 ? process.argv[i + 1]?.split(",") : undefined; })();

// `--catalog <module>` swaps the catalog; the gate's own self-check uses it to feed deliberately broken entries.
const catalogArg = (() => { const i = process.argv.indexOf("--catalog"); return i >= 0 ? process.argv[i + 1] : undefined; })();
const catalogUrl = catalogArg ? pathToFileURL(catalogArg).href : new URL("../packages/verify/src/mutations.ts", import.meta.url).href;
const { mutations } = (await import(catalogUrl)) as { mutations: Mutation[] };

const ids = mutations.map((m) => m.id);
if (new Set(ids).size !== ids.length) { console.error("duplicate mutation id in catalog"); process.exit(1); }
if (only) console.log("PARTIAL RUN (--only): not gate-grade; the full catalog was not run.");
const selected = only ? mutations.filter((m) => only.includes(m.id)) : mutations;
if (only && selected.length !== only.length) { console.error(`unknown mutation id in --only: ${only.filter((o) => !ids.includes(o)).join(", ")}`); process.exit(1); }

const scratch = mkdtempSync(join(tmpdir(), "bulkhead-mutate-"));
// An interrupted run must not leave a full copy of the workspace behind.
const removeScratch = () => rmSync(scratch, { recursive: true, force: true });
process.on("SIGINT", () => { removeScratch(); process.exit(130); });
process.on("SIGTERM", () => { removeScratch(); process.exit(143); });
// verbatimSymlinks keeps pnpm's relative links pointing inside the copy, so the mutated packages are what workerd bundles.
// Files that can hold secrets are never copied: the scratch copy lives in a shared temp directory.
const SECRET_FILES = /\/(\.dev\.vars|\.env(\.[^/]*)?|\.npmrc|[^/]*\.(pem|key))$/;
cpSync(root, scratch, { recursive: true, verbatimSymlinks: true, filter: (src) => { const rel = src.slice(root.length - 1); return !/\/(\.git|\.bulkhead|\.wrangler)(\/|$)/.test(rel) && !SECRET_FILES.test(rel); } });

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
/** Runs a package's unit tests in the scratch copy. `failures` counts real failing tests; `crashed` means the run died without one (a syntax error, a missing file). */
function unitTests(pkg: string): { passed: boolean; failures: number; crashed: boolean } {
  const dir = join(scratch, pkg, "test");
  const files = readdirSync(dir).filter((f) => f.endsWith(".test.ts")).map((f) => join("test", f));
  if (files.length === 0) return { passed: false, failures: 0, crashed: true };
  const r = spawnSync(process.execPath, ["--test", ...files], { cwd: join(scratch, pkg), encoding: "utf8", timeout: 200_000 });
  const failures = Number(/^# fail (\d+)/m.exec(r.stdout ?? "")?.[1] ?? 0);
  return { passed: r.status === 0, failures, crashed: r.status !== 0 && (failures === 0 || /SyntaxError|ERR_MODULE_NOT_FOUND|ERR_UNSUPPORTED/.test(`${r.stdout}${r.stderr}`)) };
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
      const edits: Edit[] = [{ file: m.file, find: m.find, replace: m.replace }, ...(m.also ?? [])];
      const originals = new Map(edits.map((e) => [e.file, readFileSync(join(scratch, e.file), "utf8")]));
      // Edits are applied in order and each find must match exactly once in the text as it is at that moment, so a later edit
      // whose target an earlier edit consumed or duplicated is an error, not a silent no-op.
      const planned = new Map(originals);
      let planError = "";
      for (const [i, e] of edits.entries()) {
        const current = planned.get(e.file) as string;
        const hits = current.split(e.find).length - 1;
        if (hits !== 1) { planError = `find string matched ${hits} time(s) in ${e.file} (edit ${i + 1}), must be exactly 1`; break; }
        planned.set(e.file, current.replace(e.find, () => e.replace));
      }
      const apply = () => { for (const [f, t] of planned) writeFileSync(join(scratch, f), t); };
      const restore = () => { for (const [f, t] of originals) writeFileSync(join(scratch, f), t); };
      // Each `find` must match exactly once in the file as it stands before any edit, so none can be silently inert.
      if (planError) { report(false, `${m.id}: ${planError}`); continue; }
      apply();
      const res = runVerify();
      restore();
      if ("error" in res) { report(false, `${m.id}: ${res.error}`); continue; }
      if (m.gap) {
        if (m.expect.length) { report(false, `${m.id}: a gap entry must have an empty expect list`); continue; }
        if (res.failed.length) { report(false, `${m.id}: a probe now catches this ([${res.failed}]); promote it from gap to expect`); continue; }
        const pkg = m.file.split("/").slice(0, 2).join("/");
        if (!unitTests(pkg).passed) { report(false, `${m.id}: unit tests of ${pkg} fail or are missing on the unmutated copy, so a gap cannot be judged`); continue; }
        apply();
        const unit = unitTests(pkg);
        restore();
        // Killed only by a test that really failed: a crash or syntax error says nothing about which test protects the line.
        const unitSurvived = !(unit.failures > 0 && !unit.crashed);
        if (!unitSurvived) console.log(`gap  ${m.id} (${m.rule}): survives black-box verify, killed by ${pkg} unit tests. Gap: ${m.gap}`);
        else report(false, `${m.id} (${m.rule}): SURVIVED verify and unit tests, nothing protects this line`);
        continue;
      }
      if (m.expect.length === 0) { report(false, `${m.id}: empty expect without a gap reason (observed failures: [${res.failed}])`); continue; }
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
