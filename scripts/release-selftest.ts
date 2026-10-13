// Shows the release machinery can fail (and does the right thing when it should not). Runs against the committed repo and a local
// bare git repository standing in for the public remote; nothing is pushed anywhere real.
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync as run } from "node:child_process";
import { FIXES, RELEASE_MARKER, assertCleanObjects, planPublicRepo, refuseIfPrivateRemote, snapshot, buildExport, publicCatalog, publicRuleIds, changelogSection, commitToPublicRepo, git, npmTag, redact, remoteHasBranch, resolveIdentity, scanForLeaks, scanTarball, shippable, validVersion, verifyTagMatchesExport, walk } from "../release/lib.ts";

const root = join(import.meta.dirname, "..");
const CATALOG = "packages/spec/src/rules.ts";
let bad = 0;
const check = (ok: boolean, msg: string) => { console.log(`${ok ? "ok  " : "FAIL"} ${msg}`); if (!ok) bad++; };
const throws = (fn: () => unknown, re: RegExp) => { try { fn(); return false; } catch (e) { return re.test((e as Error).message); } };
const tmp = mkdtempSync(join(tmpdir(), "bulkhead-release-selftest-"));
// Commits standing in for other people's work on the public repo come from a human identity, whatever the environment says.
const human = { ...process.env, GIT_AUTHOR_NAME: "Other Person", GIT_AUTHOR_EMAIL: "other@example.org", GIT_COMMITTER_NAME: "Other Person", GIT_COMMITTER_EMAIL: "other@example.org" };
// A tool identity in the environment must NOT end up in the public history: the explicit identity has to win.
Object.assign(process.env, { GIT_AUTHOR_NAME: "Claude", GIT_AUTHOR_EMAIL: "noreply@anthropic.com", GIT_COMMITTER_NAME: "Claude", GIT_COMMITTER_EMAIL: "noreply@anthropic.com" });

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
  writeFileSync(join(clean, "a.md"), "A package called @kalahroudi/bulkhead-core, fixture DR-9999, https://github.com/kalahroudi/bulkhead-oss\n");
  check(scanForLeaks(clean).length === 0, "scan passes a clean tree (public scope, fixture ids and the public URL are allowed)");

  // 3. Versions, dist-tags, identity, redaction and changelog.
  for (const v of ["0.1.0-preview.1", "1.0.0", "1.0.0-rc.1", "10.20.30"]) check(validVersion(v), `valid version ${v}`);
  for (const v of ["v1.0.0", "1.0", "01.0.0", "1.0.0-a..b", "1.0.0-", "1.0.0-1", "1.0.0-latest.1", "1.0.0-Preview.1", "1.0.0+build", "1.0.0; rm -rf /"]) check(!validVersion(v), `rejected version ${JSON.stringify(v)}`);
  check(npmTag("0.1.0-preview.1") === "preview" && npmTag("1.0.0-rc.2") === "rc" && npmTag("1.0.0") === "latest" && throws(() => npmTag("1.0.0-1"), /cannot be an npm dist-tag/), "npm dist-tag from version, and a numeric or latest label is refused");
  check(throws(() => resolveIdentity(undefined, (k) => (k === "user.name" ? "Claude" : "noreply@anthropic.com")), /tool identity/), "a tool git identity is refused");
  check(throws(() => resolveIdentity(undefined, () => ""), /not set/) && throws(() => resolveIdentity("nonsense"), /must look like/) && throws(() => resolveIdentity("Claude <c@example.com>"), /tool identity/), "missing, malformed and tool identities are refused");
  check(resolveIdentity("Ada Lovelace <ada@example.org>").email === "ada@example.org" && resolveIdentity(undefined, (k) => (k === "user.name" ? "Ada" : "ada@example.org")).name === "Ada", "an explicit or configured human identity is accepted");
  check(!redact("https://user:ghp_secret@github.com/x/y.git").includes("ghp_secret") && redact("https://github.com/x/y.git") === "https://github.com/x/y.git", "credentials in a remote URL are redacted");
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
  check(coreManifest.version === "9.8.7-preview.3" && coreManifest.repository.url === "git+https://github.com/kalahroudi/bulkhead-oss.git" && coreManifest.bugs.url === "https://github.com/kalahroudi/bulkhead-oss/issues" && !JSON.stringify(coreManifest).includes("bulkhead-oss-oss"), "export sets the release version and the public URLs");
  const siteHtml = readFileSync(join(out, "site/index.html"), "utf8");
  check(siteHtml.includes('href="https://github.com/kalahroudi/bulkhead-oss"') && !siteHtml.includes("@@") && !/bulkhead-oss-oss/.test(siteHtml) && !/github\.com\/kalahroudi\/bulkhead(?![-\w])/.test(siteHtml), "the site links follow the public repository constant, with no leftover tokens, no doubled suffix and no private URL");
  const otherOut = join(tmp, "other-slug"); buildExport({ root, out: otherOut, version: "1.0.0", slug: "someone/else" });
  check(JSON.parse(readFileSync(join(otherOut, "packages/core/package.json"), "utf8")).repository.url === "git+https://github.com/someone/else.git" && readFileSync(join(otherOut, "site/index.html"), "utf8").includes("https://github.com/someone/else"), "--repo changes the package metadata and the site links together");
  const rootManifest = JSON.parse(readFileSync(join(out, "package.json"), "utf8"));
  check(!JSON.stringify(rootManifest.scripts).match(/phase|mutation|catalog|decision/) && "gate:release" in rootManifest.scripts, "export root scripts reference no private gates");
  check(!JSON.stringify(JSON.parse(readFileSync(join(out, "packages/spec/package.json"), "utf8")).scripts).match(/catalog|decisions/), "export spec scripts reference no SPEC.md or decision lint");

  // The public catalog holds product guarantees only.
  const rulesText = readFileSync(join(out, CATALOG), "utf8");
  const ids = [...publicRuleIds(rulesText)];
  check(ids.length >= 12 && ids.every((i) => /^(TENANT|ROUTE|AUTH|BOOT|BILL)-/.test(i)) && !["CRYPTO-1", "BILL-1", "DOMAIN-1", "LIFE-1"].some((i) => ids.includes(i)), `public catalog has only product-guarantee rules that exist today (${ids.length} of the private catalog; unbuilt crypto, billing, domain, HTTP and lifecycle rules do not ship)`);
  check(ids.includes("ROUTE-3") && !/human|agent|review queue/i.test(rulesText) && !/principle/.test(rulesText), "the public catalog has no gap where a private rule was (ROUTE-3 is reworded) and no internal fields");
  const formatsText = readFileSync(join(out, "packages/spec/src/formats.ts"), "utf8");
  check(!/Decision record|Attestation|validateAttestation|validateDecisionRecord|validateClassification|DATA_CLASSES/.test(formatsText) && /validateFinding/.test(formatsText) && /EVENT_TYPES = \["verify\.run", "finding\.recorded"\]/.test(formatsText), "public formats keep findings and events, and drop classification, decision records and attestations");
  check(!/development plane|attestation|harness|human key|keychain|ledger/i.test(rulesText), "public catalog text has no internal process wording");
  check(throws(() => publicCatalog("no markers here"), /layout changed/), "a restructured catalog aborts the export instead of leaking");

  // 5. A stale text fix aborts the export instead of being skipped.
  FIXES.push({ file: "packages/core/src/api/app.ts", find: "this text is not in the file", replace: "x" });
  check(throws(() => buildExport({ root, out: join(tmp, "stale"), version: "1.0.0" }), /matched 0 time/), "a fix that no longer matches aborts the export");
  FIXES.pop();

  // 6. The git step against a local bare repo standing in for the public remote.
  const person = { name: "Release Person", email: "person@example.org" };
  const bare = join(tmp, "public.git");
  git(["init", "--quiet", "--bare", "-b", "trunk", bare], tmp);
  const remote = `file://${bare}`;
  const fake = (name: string, body: string) => { const d = join(tmp, name); rmSync(d, { recursive: true, force: true }); mkdirSync(d, { recursive: true }); writeFileSync(join(d, "README.md"), body); return d; };
  const snap = (d: string) => ({ exportDir: d, snapshot: snapshot(d) });
  const release = (version: string, dir: string, push = true, extra = {}) => commitToPublicRepo({ ...snap(dir), remote, version, notes: `notes for ${version}`, push, workdir: join(tmp, "wd"), identity: person, ...extra });
  const refs = () => String(git(["ls-remote", remote], tmp).stdout);

  check(!/refs\/heads\/main/.test(refs()), "remote starts with no main");
  release("0.1.0", fake("e1", "one"), false);
  check(!/refs\/heads\/main/.test(refs()) && !/refs\/tags/.test(refs()), "dry run creates neither the branch nor the tag on the remote");
  const first = release("0.1.0", fake("e1", "one"));
  check(first.created && /refs\/heads\/main/.test(refs()) && /refs\/tags\/v0\.1\.0$/m.test(refs()), "first release creates main and the tag together");
  check(String(git(["rev-list", "--count", "main"], bare).stdout).trim() === "1", "the public history starts clean: one commit");
  const who = String(git(["log", "-1", "--format=%an <%ae> / %cn <%ce>", "main"], bare).stdout).trim();
  check(who === "Release Person <person@example.org> / Release Person <person@example.org>" && !/claude|anthropic/i.test(who), `the public commit carries the releaser's identity, not the environment's tool identity (${who})`);
  check(/Author|Release Person/.test(String(git(["for-each-ref", "--format=%(taggername) %(taggeremail)", "refs/tags/v0.1.0"], bare).stdout)) && !/claude|anthropic/i.test(String(git(["for-each-ref", "--format=%(taggername) %(taggeremail)", "refs/tags/v0.1.0"], bare).stdout)), "the annotated tag carries it too");
  check(String(git(["log", "-1", "--format=%B", "main"], bare).stdout).includes(RELEASE_MARKER), "release commits carry the tool marker");
  const second = release("0.2.0", fake("e2", "two"));
  check(!second.created && String(git(["rev-list", "--count", "main"], bare).stdout).trim() === "2", "second release adds one commit on main, no rewrite");
  check(throws(() => release("0.3.0", fake("e3", "two")), /nothing to release/), "a release with no changes is refused");
  check(throws(() => release("0.2.0", fake("e4", "three")), /tag v0\.2\.0 already exists/), "an existing tag is refused");
  check(String(git(["show", "main:README.md"], bare).stdout) === "two" && !String(git(["ls-tree", "-r", "--name-only", "main"], bare).stdout).includes(".git/"), "the pushed tree is exactly the export");

  // The public tag must hold exactly the tree about to be published to npm (after a partial failure, with --skip-git).
  check(!throws(() => verifyTagMatchesExport(remote, "v0.2.0", snapshot(fake("e2", "two")).tree, join(tmp, "vt")), /./), "skip-git rerun: the tag matches an identical export");
  check(throws(() => verifyTagMatchesExport(remote, "v0.2.0", snapshot(fake("e5", "different")).tree, join(tmp, "vt")), /differs from what v0\.2\.0 holds/), "skip-git rerun: a different export is refused");
  check(throws(() => verifyTagMatchesExport(remote, "v9.9.9", snapshot(fake("e2", "two")).tree, join(tmp, "vt")), /does not exist/), "skip-git rerun: a missing tag is refused");

  // Branch lookup is exact: `feature/main` is not `main`.
  const bare2 = join(tmp, "other.git"); git(["init", "--quiet", "--bare", "-b", "trunk", bare2], tmp);
  const seed = join(tmp, "seed"); mkdirSync(seed); git(["init", "--quiet", "-b", "feature/main"], seed); writeFileSync(join(seed, "a"), "x");
  git(["add", "-A"], seed); git(["-c", "user.name=t", "-c", "user.email=t@t", "commit", "--quiet", "-m", "seed"], seed, { env: human }); git(["push", "--quiet", `file://${bare2}`, "feature/main"], seed);
  check(!remoteHasBranch(`file://${bare2}`, "main") && remoteHasBranch(`file://${bare2}`, "feature/main"), "a branch named feature/main is not mistaken for main");

  // An existing main that this tool did not write is never silently replaced.
  const bare3 = join(tmp, "foreign.git"); git(["init", "--quiet", "--bare", "-b", "trunk", bare3], tmp);
  const seed3 = join(tmp, "seed3"); mkdirSync(seed3); git(["init", "--quiet", "-b", "main"], seed3); writeFileSync(join(seed3, "THEIRS.md"), "someone else's file");
  git(["add", "-A"], seed3); git(["-c", "user.name=t", "-c", "user.email=t@t", "commit", "--quiet", "-m", "their work"], seed3, { env: human }); git(["push", "--quiet", `file://${bare3}`, "main"], seed3);
  const foreign = (extra = {}) => commitToPublicRepo({ ...snap(fake("e6", "mine")), remote: `file://${bare3}`, version: "1.0.0", notes: "n", push: true, workdir: join(tmp, "wd3"), identity: person, ...extra });
  check(throws(() => foreign(), /holds 1 commit\(s\) this tool did not write.*REPLACES/), "an existing main written by someone else is refused");
  const adopted = foreign({ adopt: true });
  check(adopted.removed.includes("THEIRS.md") && String(git(["ls-tree", "--name-only", "main"], bare3).stdout).trim() === "README.md", "with --adopt-existing it replaces main and reports exactly what it removed");

  // 7. Tarball scan: what npm would serve is checked as files.
  const mk = (name: string, files: Record<string, string>) => {
    const d = join(tmp, name); rmSync(d, { recursive: true, force: true });
    for (const [f, body] of Object.entries(files)) { mkdirSync(join(d, "package", join(f, "..")), { recursive: true }); writeFileSync(join(d, "package", f), body); }
    const t = join(tmp, `${name}.tgz`); spawnSync("tar", ["-czf", t, "-C", d, "package"]); return t;
  };
  const okTar = mk("okpkg", { "package.json": '{"name":"x"}', "README.md": "hi", LICENSE: "l", "dist/index.js": "export const a = 1;" });
  check(scanTarball(okTar, tmp).length === 0, "a clean tarball passes the scan");
  const badTar = mk("badpkg", { "package.json": "{}", "src/index.ts": "x", "dist/index.js": "// see docs/decisions/x\n", "dist/decisions.js": "x" });
  const badHits = scanTarball(badTar, tmp).join("\n");
  check(/src\/index\.ts/.test(badHits) && /docs\/decisions/.test(badHits) && /decisions\.js/.test(badHits), "a tarball with source, private text or a private file name is caught");
  // 8. Git configuration on the releaser's machine cannot reach the public commit: a tool signing key and a trailer-adding hook.
  const hostile = join(tmp, "hostile"); mkdirSync(join(hostile, "hooks"), { recursive: true });
  writeFileSync(join(hostile, "hooks/prepare-commit-msg"), '#!/bin/sh\nprintf "\\nCo-Authored-By: Some Tool <noreply@example.com>\\n" >> "$1"\n', { mode: 0o755 });
  writeFileSync(join(hostile, "gitconfig"), `[user]\n  name = Claude\n  email = noreply@anthropic.com\n  signingkey = /nonexistent/key.pub\n[commit]\n  gpgsign = true\n[tag]\n  gpgsign = true\n[gpg]\n  format = ssh\n  program = /nonexistent/sign\n[core]\n  hooksPath = ${join(hostile, "hooks")}\n`);
  const savedConfig = process.env.GIT_CONFIG_GLOBAL;
  process.env.GIT_CONFIG_GLOBAL = join(hostile, "gitconfig");
  try {
    const bare4 = join(tmp, "hostile.git"); git(["init", "--quiet", "--bare", "-b", "trunk", bare4], tmp);
    const notes = "### Added\n- a thing\n\n### Known limits\n- another";
    commitToPublicRepo({ ...snap(fake("e7", "seven")), remote: `file://${bare4}`, version: "1.0.0", notes, push: true, workdir: join(tmp, "wd4"), identity: person });
    const commitObj = String(git(["cat-file", "-p", "main"], bare4).stdout);
    check(!/gpgsig/.test(commitObj) && !/Co-Authored-By|Claude|anthropic/i.test(commitObj) && /author Release Person <person@example\.org>/.test(commitObj), "a tool signing key, tool identity and trailer-adding hook in the machine's git config do not reach the public commit");
    const tagObj = String(git(["cat-file", "-p", "refs/tags/v1.0.0"], bare4).stdout);
    check(!/BEGIN (PGP|SSH) SIGNATURE/.test(tagObj) && /tagger Release Person/.test(tagObj) && tagObj.includes("### Added") && tagObj.includes("### Known limits"), "the tag is unsigned, by the releaser, and keeps the changelog headings");
    // Planted alteration: an object that carries something else must stop the push.
    const wd = join(tmp, "wd4");
    git(["-c", "user.name=Claude", "-c", "user.email=noreply@anthropic.com", "commit", "--quiet", "--amend", "--no-edit", "--allow-empty", "--author", "Claude <noreply@anthropic.com>"], wd, { env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_COMMITTER_NAME: "Claude", GIT_COMMITTER_EMAIL: "noreply@anthropic.com" } });
    check(throws(() => assertCleanObjects(wd, "v1.0.0", person, false, "x"), /not authored by/), "the read-back refuses a commit that carries another identity");
  } finally { if (savedConfig === undefined) delete process.env.GIT_CONFIG_GLOBAL; else process.env.GIT_CONFIG_GLOBAL = savedConfig; }

  // 9. The public repo is a mirror: commits written by someone else are listed and refused, with the removals named before anything happens.
  const bare5 = join(tmp, "mirror.git"); git(["init", "--quiet", "--bare", "-b", "trunk", bare5], tmp);
  commitToPublicRepo({ ...snap(fake("e8", "eight")), remote: `file://${bare5}`, version: "1.0.0", notes: "n", push: true, workdir: join(tmp, "wd5"), identity: person });
  const contrib = join(tmp, "contrib"); git(["clone", "--quiet", "--branch", "main", `file://${bare5}`, contrib], tmp); writeFileSync(join(contrib, "CONTRIBUTED.md"), "outside work");
  git(["add", "-A"], contrib); git(["-c", "user.name=Other", "-c", "user.email=o@o", "commit", "--quiet", "-m", "A pull request"], contrib, { env: human }); git(["push", "--quiet", "origin", "main"], contrib);
  let refusal = ""; try { planPublicRepo({ files: snapshot(fake("e9", "nine")).files, remote: `file://${bare5}`, workdir: join(tmp, "plan5") }); } catch (e) { refusal = (e as Error).message; }
  check(/1 commit\(s\) this tool did not write.*A pull request.*CONTRIBUTED\.md/.test(refusal), "a later outside commit is named, and the files that would be removed are listed in the refusal, before any push");
  const planned = planPublicRepo({ files: snapshot(fake("e9", "nine")).files, remote: `file://${bare5}`, workdir: join(tmp, "plan5"), adopt: true });
  check(planned.exists && planned.foreign.length === 1 && planned.removed.includes("CONTRIBUTED.md"), "with --adopt-existing the plan reports the same, and still changes nothing");

  // 10. The scan has no blind spots: every file is read, binary files and unusual extensions included, and phase wording is case-insensitive.
  const blind = join(tmp, "blind"); mkdirSync(join(blind, "packages/core"), { recursive: true });
  writeFileSync(join(blind, "packages/core/notes.sh"), "# the phase 2 gate\n"); writeFileSync(join(blind, "packages/core/x.mjs"), "// see the decision record\n");
  writeFileSync(join(blind, "packages/core/blob.bin"), Buffer.from([1, 0, 2])); writeFileSync(join(blind, "packages/core/ok.ts"), "// Phase-3 and the roadmap and a session_01ABCDEFGHIJ id\n");
  const blindHits = scanForLeaks(blind).join("\n");
  check(/notes\.sh.*roadmap phase/.test(blindHits) && /x\.mjs.*decision/i.test(blindHits) && /blob\.bin.*binary/.test(blindHits) && /ok\.ts.*(roadmap phase|private gate or roadmap)/.test(blindHits) && /session_01/.test(blindHits), "the scan reads every file type, flags binaries, and matches phase and roadmap wording case-insensitively");
  // Tarballs get the same rule-citation check as the tree, against the compiled catalog inside the package.
  const citeTar = mk("citepkg", { "package.json": "{}", "dist/rules.js": '  id: "TENANT-1",\n', "dist/other.js": "// per VERIFY-4\n" });
  check(/VERIFY-4/.test(scanTarball(citeTar, tmp).join("\n")), "a tarball citing a rule that is not in its own catalog is caught");

  // 11. A fix matching more than once is as wrong as one matching never.
  FIXES.push({ file: "packages/core/src/api/app.ts", find: "const", replace: "const" });
  check(throws(() => buildExport({ root, out: join(tmp, "dup"), version: "1.0.0" }), /matched \d+ time\(s\), must be exactly 1/), "a fix that matches more than once aborts the export");
  FIXES.pop();

  // 12. The command itself refuses before doing any real work.
  const cli = (...args: string[]) => run(process.execPath, [join(root, "scripts/release.ts"), ...args], { encoding: "utf8", cwd: root, timeout: 60_000 });
  const bad1 = cli("v1.0");
  check(bad1.status === 1 && /usage/.test(bad1.stderr), "the command rejects a malformed version");
  const bad2 = cli("9.9.9", "--dry-run", "--author", "Claude <c@example.com>");
  check(bad2.status === 1 && /(tool identity|no non-empty|uncommitted)/.test(bad2.stderr), "the command refuses a tool identity, a missing changelog section, or a dirty tree, before exporting");
  const bad4 = cli("9.9.9", "--dry-run", "--author", "Ada <ada@example.org>", "--repo", "kalahroudi/bulkhead");
  check(bad4.status === 1 && /(private repository|uncommitted|no non-empty)/.test(bad4.stderr), "the command refuses the private repository as --repo");
  const bad5 = cli("9.9.9", "--dry-run", "--repo", "not a repo");
  check(bad5.status === 1 && /--repo must look like owner\/name/.test(bad5.stderr), "the command rejects a malformed --repo");
  const bad3 = cli("9.9.9", "--dry-run", "--author", "Ada <ada@example.org>");
  check(bad3.status === 1 && /(no non-empty|uncommitted)/.test(bad3.stderr) && !/Export the public tree/.test(bad3.stdout), "the command stops on a missing changelog section or a dirty tree before exporting anything");
  // 13. Round-3 hardening, each with a test that can fail.
  check(["https://github.com/kalahroudi/bulkhead.git", "https://github.com/Kalahroudi/bulkhead", "git@github.com:kalahroudi/bulkhead.git", "ssh://git@github.com/kalahroudi/bulkhead.git/", "https://user:tok@github.com/kalahroudi/bulkhead.git", "git+https://github.com/kalahroudi/bulkhead.git"].every((r) => throws(() => refuseIfPrivateRemote(r), /private repository/)) && !throws(() => refuseIfPrivateRemote("https://github.com/kalahroudi/bulkhead-oss.git"), /./) && !throws(() => refuseIfPrivateRemote(`file://${bare}`), /./), "the private repository is refused as a target in every spelling, and the public one is not");
  check(throws(() => resolveIdentity("Ann <x> Lee <ann@example.org>"), /must look like/) && throws(() => resolveIdentity("Copilot <c@example.org>"), /tool identity/), "an author name git would mangle, or another tool's identity, is refused");

  // Verbatim message: trailing spaces, double blank lines and '#' headings survive, and the read-back does not misfire on them.
  const bare6 = join(tmp, "verbatim.git"); git(["init", "--quiet", "--bare", "-b", "trunk", bare6], tmp);
  const tricky = "### Added\n- hard break  \n\n\n- after two blank lines";
  commitToPublicRepo({ ...snap(fake("e10", "ten")), remote: `file://${bare6}`, version: "1.0.0", notes: tricky, push: true, workdir: join(tmp, "wd6"), identity: person });
  const msg = String(git(["log", "-1", "--format=%B", "main"], bare6).stdout);
  check(msg.includes("- hard break  \n\n\n- after two blank lines") && msg.includes("### Added"), "the commit message is stored verbatim (trailing spaces, blank lines and # headings), and the read-back accepts it");

  // Signing: --sign must really ask for a signature, so with no usable key the release stops instead of publishing unsigned.
  const bare7 = join(tmp, "signed.git"); git(["init", "--quiet", "--bare", "-b", "trunk", bare7], tmp);
  const noKey = join(tmp, "nokey.gitconfig"); writeFileSync(noKey, "[gpg]\n  format = ssh\n  program = /nonexistent/sign\n[user]\n  signingkey = /nonexistent/key.pub\n");
  const saved2 = process.env.GIT_CONFIG_GLOBAL; process.env.GIT_CONFIG_GLOBAL = noKey;
  try { check(throws(() => commitToPublicRepo({ ...snap(fake("e11", "eleven")), remote: `file://${bare7}`, version: "1.0.0", notes: "n", push: true, workdir: join(tmp, "wd7"), identity: person, sign: true }), /commit failed/) && !/refs\/heads\/main/.test(String(git(["ls-remote", `file://${bare7}`], tmp).stdout)), "--sign asks for a signature: with no usable key the release fails and pushes nothing"); }
  finally { if (saved2 === undefined) delete process.env.GIT_CONFIG_GLOBAL; else process.env.GIT_CONFIG_GLOBAL = saved2; }

  // The read-back, branch by branch, on hand-made objects.
  const rb = join(tmp, "rb"); rmSync(rb, { recursive: true, force: true }); mkdirSync(rb); git(["init", "--quiet", "-b", "main"], rb); writeFileSync(join(rb, "a"), "x"); git(["add", "-A"], rb);
  const mkCommit = (author: string, message: string, extraHeader = "") => {
    const tree = String(git(["write-tree"], rb).stdout).trim();
    const body = `tree ${tree}\nauthor ${author} 1700000000 +0000\ncommitter ${author} 1700000000 +0000\n${extraHeader}\n${message}`;
    const sha = String(run("git", ["hash-object", "-t", "commit", "-w", "--stdin"], { cwd: rb, input: body, encoding: "utf8" }).stdout).trim();
    git(["update-ref", "HEAD", sha], rb); return sha;
  };
  const mkTag = (tagger: string, signature = "") => {
    const head = String(git(["rev-parse", "HEAD"], rb).stdout).trim();
    const body = `object ${head}\ntype commit\ntag v1\ntagger ${tagger} 1700000000 +0000\n\nv1\n${signature}`;
    const sha = String(run("git", ["hash-object", "-t", "tag", "-w", "--stdin"], { cwd: rb, input: body, encoding: "utf8" }).stdout).trim();
    git(["update-ref", "refs/tags/v1", sha], rb);
  };
  const me = "Release Person <person@example.org>";
  mkCommit(me, "msg\n"); mkTag(me);
  check(!throws(() => assertCleanObjects(rb, "v1", person, false, "msg\n"), /./), "the read-back accepts a clean commit and tag");
  mkCommit(me, "msg\n", "gpgsig -----BEGIN SSH SIGNATURE-----\n abc\n -----END SSH SIGNATURE-----\n"); 
  check(throws(() => assertCleanObjects(rb, "v1", person, false, "msg\n"), /carries a signature, but signing was not requested/), "the read-back refuses a signature nobody asked for");
  mkCommit(me, "msg\n"); 
  check(throws(() => assertCleanObjects(rb, "v1", person, true, "msg\n"), /signing was requested but the commit is not signed/), "the read-back refuses a missing signature when one was requested");
  mkCommit(me, "msg\n\nCo-Authored-By: Some Tool <t@example.com>\n");
  check(throws(() => assertCleanObjects(rb, "v1", person, false, "msg\n"), /message differs/), "the read-back refuses an altered message (a hook-added trailer)");
  mkCommit(me, "msg\n"); mkTag("Claude <noreply@anthropic.com>");
  check(throws(() => assertCleanObjects(rb, "v1", person, false, "msg\n"), /the tag is not by/), "the read-back refuses a tag by another identity");
  mkTag(me, "-----BEGIN SSH SIGNATURE-----\nabc\n-----END SSH SIGNATURE-----\n");
  check(throws(() => assertCleanObjects(rb, "v1", person, false, "msg\n"), /tag carries a signature/), "the read-back refuses a signed tag nobody asked for");
  const libSource = readFileSync(join(root, "release/lib.ts"), "utf8");
  check(libSource.indexOf("assertCleanObjects(o.workdir") > 0 && libSource.indexOf("assertCleanObjects(o.workdir") < libSource.indexOf('git(["push", "--atomic"'), "the read-back runs before the push (deleting that call fails this test)");

  // Content that changes after the scan is caught before the commit: the snapshot is taken early on purpose.
  const drift = fake("e12", "twelve"); const driftSnap = { exportDir: drift, snapshot: snapshot(drift) };
  writeFileSync(join(drift, "README.md"), "now mentions docs/decisions/DR-0042\n");
  const bare8 = join(tmp, "drift.git"); git(["init", "--quiet", "--bare", "-b", "trunk", bare8], tmp);
  check(throws(() => commitToPublicRepo({ ...driftSnap, remote: `file://${bare8}`, version: "1.0.0", notes: "n", push: true, workdir: join(tmp, "wd8"), identity: person }), /private material/) && !/refs\/heads\/main/.test(String(git(["ls-remote", `file://${bare8}`], tmp).stdout)), "a file that changed after the scan is re-scanned and refused before any push");
  const drift2 = fake("e13", "thirteen"); const drift2Snap = { exportDir: drift2, snapshot: snapshot(drift2) };
  writeFileSync(join(drift2, "README.md"), "changed but clean\n");
  check(throws(() => commitToPublicRepo({ ...drift2Snap, remote: `file://${bare8}`, version: "1.0.0", notes: "n", push: true, workdir: join(tmp, "wd8"), identity: person }), /differs from the scanned export/), "content that changed after the snapshot, even if clean, does not match the scanned tree");
  const extra = fake("e14", "fourteen"); const extraSnap = snapshot(extra); writeFileSync(join(extra, "debug.log"), "leftover"); writeFileSync(join(extra, "NOTES.md"), "left behind by the gate");
  commitToPublicRepo({ exportDir: extra, snapshot: extraSnap, remote: `file://${bare8}`, version: "1.0.0", notes: "n", push: true, workdir: join(tmp, "wd8"), identity: person });
  check(String(git(["ls-tree", "-r", "--name-only", "main"], bare8).stdout).trim() === "README.md", "files that appear after the snapshot (gate leftovers) are never committed");

  // A user-level ignore file must not silently drop files from the public commit.
  const xdg = join(tmp, "xdg"); mkdirSync(join(xdg, "git"), { recursive: true }); writeFileSync(join(xdg, "git/ignore"), "*.md\n");
  const savedXdg = process.env.XDG_CONFIG_HOME; process.env.XDG_CONFIG_HOME = xdg;
  try {
    const bare9 = join(tmp, "xdg.git"); git(["init", "--quiet", "--bare", "-b", "trunk", bare9], tmp);
    commitToPublicRepo({ ...snap(fake("e15", "fifteen")), remote: `file://${bare9}`, version: "1.0.0", notes: "n", push: true, workdir: join(tmp, "wd9"), identity: person });
    check(String(git(["ls-tree", "-r", "--name-only", "main"], bare9).stdout).trim() === "README.md", "the releaser's global git ignore file does not drop files from the public commit");
  } finally { if (savedXdg === undefined) delete process.env.XDG_CONFIG_HOME; else process.env.XDG_CONFIG_HOME = savedXdg; }

  // Adopting an existing main keeps its history, so that history is checked too.
  const bare10 = join(tmp, "history.git"); git(["init", "--quiet", "--bare", "-b", "trunk", bare10], tmp);
  const seed10 = join(tmp, "seed10"); mkdirSync(seed10); git(["init", "--quiet", "-b", "main"], seed10); writeFileSync(join(seed10, "a"), "x"); git(["add", "-A"], seed10);
  git(["-c", "user.name=Claude", "-c", "user.email=noreply@anthropic.com", "commit", "--quiet", "-m", "first commit"], seed10, { env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null" } }); git(["push", "--quiet", `file://${bare10}`, "main"], seed10);
  check(throws(() => planPublicRepo({ files: ["README.md"], remote: `file://${bare10}`, workdir: join(tmp, "plan10"), adopt: true }), /carries a tool identity/), "--adopt-existing still refuses history that carries a tool identity");
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
console.log(bad ? `release self-test FAILED (${bad})` : "release self-test passed: the export is clean, the scan and fixes can fail, and the git flow behaves");
process.exit(bad ? 1 : 0);
