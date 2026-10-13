// Shows the release machinery can fail (and does the right thing when it should not). Runs against the committed repo and a local
// bare git repository standing in for the public remote; nothing is pushed anywhere real.
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FIXES, buildExport, publicCatalog, publicRuleIds, changelogSection, commitToPublicRepo, git, npmTag, scanForLeaks, shippable, validVersion, walk } from "../release/lib.ts";

const root = join(import.meta.dirname, "..");
const CATALOG = "packages/spec/src/rules.ts";
let bad = 0;
const check = (ok: boolean, msg: string) => { console.log(`${ok ? "ok  " : "FAIL"} ${msg}`); if (!ok) bad++; };
const throws = (fn: () => unknown, re: RegExp) => { try { fn(); return false; } catch (e) { return re.test((e as Error).message); } };
const tmp = mkdtempSync(join(tmpdir(), "bulkhead-release-selftest-"));
Object.assign(process.env, { GIT_AUTHOR_NAME: "selftest", GIT_AUTHOR_EMAIL: "t@example.com", GIT_COMMITTER_NAME: "selftest", GIT_COMMITTER_EMAIL: "t@example.com" });

try {
  // 1. The allowlist: private files can never be exported, however they got tracked.
  for (const p of ["SPEC.md", "CLAUDE.md", "AGENTS.md", "FROZEN_PATHS", "CODEOWNERS", "CONTRIBUTING.md", "docs/decisions/DR-0001-x.md", "release/lib.ts", "scripts/release.ts", "scripts/verify-mutations.ts", "scripts/mutation-selfcheck.ts", ".github/workflows/ci.yml", "packages/verify/src/mutations.ts", "packages/verify/test/decisions.test.ts", "packages/spec/scripts/generate-catalog.ts", "packages/core/node_modules/x.js", "NOTES.md"])
    check(!shippable(p), `not shippable: ${p}`);
  for (const p of ["packages/core/src/api/app.ts", "examples/demo-app/src/routes.ts", "README.md", "CHANGELOG.md", "scripts/consumer-test.ts"]) check(shippable(p), `shippable: ${p}`);

  // 2. The leak scan catches every class of private material, and passes a clean tree.
  const planted: [string, string][] = [
    ["a private doc", "see docs/decisions/x"], ["SPEC.md", "read SPEC.md"], ["a record id", "per DR-0007"], ["a roadmap phase", "arrives in Phase 5"],
    ["the private repo url", "https://github.com/kalahroudi/bulkhead"], ["agent provenance", "built by Claude"], ["a personal address", "bermouda@gmail.com"], ["an owner todo", "<!-- TODO(owner): x -->"],
  ];
  for (const [what, text] of planted) {
    const d = join(tmp, `leak-${what.replace(/\W/g, "")}`); mkdirSync(d, { recursive: true });
    writeFileSync(join(d, "note.md"), `hello\n${text}\n`);
    check(scanForLeaks(d).length === 1, `scan catches ${what}`);
  }
  // A shipped file citing a rule that is not in the public catalog points at the private spec.
  const refDir = join(tmp, "refs"); mkdirSync(join(refDir, "packages/spec/src"), { recursive: true });
  writeFileSync(join(refDir, CATALOG), 'seeds\n    id: "TENANT-1",\n');
  writeFileSync(join(refDir, "a.ts"), "// ok TENANT-1\n// private VERIFY-4\n");
  check(scanForLeaks(refDir).length === 1 && /VERIFY-4/.test(scanForLeaks(refDir)[0] as string), "scan catches a citation of a rule that is not in the public catalog");
  const clean = join(tmp, "clean"); mkdirSync(clean);
  writeFileSync(join(clean, "a.md"), "A package called @kalahroudi/bulkhead-core, fixture DR-9999, https://github.com/flamingosh/bulkhead\n");
  check(scanForLeaks(clean).length === 0, "scan passes a clean tree (public scope, fixture ids and the public URL are allowed)");

  // 3. Versions and changelog.
  check(validVersion("0.1.0-preview.1") && validVersion("1.0.0") && !validVersion("v1.0.0") && !validVersion("1.0") && !validVersion("1.0.0; rm -rf /"), "version syntax");
  check(npmTag("0.1.0-preview.1") === "preview" && npmTag("1.0.0-rc.2") === "rc" && npmTag("1.0.0") === "latest", "npm dist-tag from version");
  const log = "# Changelog\n\n## [Unreleased]\n\n## [0.2.0] - x\n\n### Added\n- thing\n\n## [0.1.0-preview.0] - y\nold\n";
  check(changelogSection(log, "0.2.0")?.includes("- thing") === true && changelogSection(log, "9.9.9") === null && changelogSection(log, "0.1.0") === null && changelogSection(log, "0.1.0-preview.0") === "old", "changelog section lookup");
  check(changelogSection("## [1.0.0] - z\n\n## [0.9.0]\nx", "1.0.0") === null, "an empty changelog section counts as missing");

  // 4. The real export of the committed repo is clean, complete and versioned.
  const out = join(tmp, "export");
  const files = buildExport({ root, out, version: "9.8.7-preview.3" });
  check(scanForLeaks(out).length === 0, `real export has no private material (${files.length} files)${scanForLeaks(out).length ? "\n  " + scanForLeaks(out).slice(0, 8).join("\n  ") : ""}`);
  check(["README.md", "CHANGELOG.md", "LICENSE", "SECURITY.md", "CONTRIBUTING.md", "site/index.html", ".github/workflows/ci.yml", ".github/workflows/pages.yml", "packages/core/src/api/app.ts", "examples/demo-app/src/routes.ts", "pnpm-lock.yaml"].every((f) => files.includes(f)), "export has the public files (README, CHANGELOG, site, workflows, packages, demo, lockfile)");
  check(!files.some((f) => /^(SPEC\.md|CLAUDE\.md|AGENTS\.md|FROZEN_PATHS|CODEOWNERS)$|^docs\/|^release\/|^scripts\/(release|verify-mutations|mutation)|mutations\.ts$/.test(f)), "export has no private docs, records, specs, release tooling or mutation catalog");
  const coreManifest = JSON.parse(readFileSync(join(out, "packages/core/package.json"), "utf8"));
  check(coreManifest.version === "9.8.7-preview.3" && coreManifest.repository.url.includes("flamingosh/bulkhead") && coreManifest.bugs.url.includes("flamingosh"), "export sets the release version and the public URLs");
  const rootManifest = JSON.parse(readFileSync(join(out, "package.json"), "utf8"));
  check(!JSON.stringify(rootManifest.scripts).match(/phase|mutation|catalog|decision/) && "gate:release" in rootManifest.scripts, "export root scripts reference no private gates");
  check(!JSON.stringify(JSON.parse(readFileSync(join(out, "packages/spec/package.json"), "utf8")).scripts).match(/catalog|decisions/), "export spec scripts reference no SPEC.md or decision lint");

  // The public catalog holds product guarantees only.
  const rulesText = readFileSync(join(out, CATALOG), "utf8");
  const ids = [...publicRuleIds(rulesText)];
  check(ids.length > 20 && ids.every((i) => /^(TENANT|ROUTE|AUTH|CRYPTO|BOOT|BILL|DOMAIN|HTTP|LIFE)-/.test(i)) && !ids.includes("ROUTE-3"), `public catalog has only product-guarantee rules (${ids.length} of the private catalog)`);
  check(!/development plane|attestation|harness|human key|keychain|ledger/i.test(rulesText), "public catalog text has no internal process wording");
  check(throws(() => publicCatalog("no markers here"), /layout changed/), "a restructured catalog aborts the export instead of leaking");

  // 5. A stale text fix aborts the export instead of being skipped.
  FIXES.push({ file: "packages/core/src/api/app.ts", find: "this text is not in the file", replace: "x" });
  check(throws(() => buildExport({ root, out: join(tmp, "stale"), version: "1.0.0" }), /matched 0 time/), "a fix that no longer matches aborts the export");
  FIXES.pop();

  // 6. The git step against a local bare repo standing in for the public remote.
  const bare = join(tmp, "public.git");
  git(["init", "--quiet", "--bare", "-b", "trunk", bare], tmp);
  const remote = `file://${bare}`;
  const fake = (name: string, body: string) => { const d = join(tmp, name); rmSync(d, { recursive: true, force: true }); mkdirSync(d, { recursive: true }); writeFileSync(join(d, "README.md"), body); return d; };
  const release = (version: string, dir: string, push = true) => commitToPublicRepo({ exportDir: dir, remote, version, notes: `notes for ${version}`, push, workdir: join(tmp, "wd") });
  const heads = () => String(git(["ls-remote", "--heads", remote], tmp).stdout);

  check(!/refs\/heads\/main/.test(heads()), "remote starts with no main");
  const dry = release("0.1.0", fake("e1", "one"), false);
  check(dry.created && !/refs\/heads\/main/.test(heads()), "dry run creates nothing on the remote");
  const first = release("0.1.0", fake("e1", "one"));
  check(first.created && /refs\/heads\/main/.test(heads()) && String(git(["ls-remote", "--tags", remote], tmp).stdout).includes("refs/tags/v0.1.0"), "first release creates main and the tag");
  check(String(git(["rev-list", "--count", "main"], bare).stdout).trim() === "1", "the public history starts clean: one commit");
  const second = release("0.2.0", fake("e2", "two"));
  check(!second.created && String(git(["rev-list", "--count", "main"], bare).stdout).trim() === "2", "second release adds one commit on main, no rewrite");
  check(throws(() => release("0.3.0", fake("e3", "two")), /nothing to release/), "a release with no changes is refused");
  check(throws(() => release("0.2.0", fake("e4", "three")), /tag v0\.2\.0 already exists/), "an existing tag is refused");
  check(String(git(["show", "main:README.md"], bare).stdout) === "two" && !String(git(["ls-tree", "-r", "--name-only", "main"], bare).stdout).includes(".git/"), "the pushed tree is exactly the export");
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
console.log(bad ? `release self-test FAILED (${bad})` : "release self-test passed: the export is clean, the scan and fixes can fail, and the git flow behaves");
process.exit(bad ? 1 : 0);
