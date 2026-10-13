// Publishes a release: exports a clean public copy of the repo, checks it, pushes it to the public GitHub repo (creating `main`
// when the remote has none), tags it, and publishes the four packages to npm. You run it by hand.
//
//   node scripts/release.ts <version> [--dry-run] [--yes] [--author "Name <email>"]  (default author: kalahroudi)
//                           [--repo owner/name] [--remote=<git url>] [--out=<dir>] [--skip-git] [--skip-npm] [--adopt-existing] [--sign]
//
// Needs: git 2.32+, git push access to the public repo, `npm login` as a member of the @kalahroudi scope (npm prompts for your
// one-time code at each publish; it is never passed on a command line),
// and a section `## [<version>]` in CHANGELOG.md. --dry-run does everything except push and publish.
// Order: export, scan, pack once, scan the tarballs, run the public gate on those exact tarballs, then git (branch and tag in one
// atomic push), then npm. A rerun after a partial npm failure uses --skip-git and first proves the public tag holds this exact tree.
// macOS and Linux only. The public repo is a mirror: its contents are replaced on every release, and commits made there by anyone else
// are listed and refused unless you pass --adopt-existing. Commits and tags are unsigned and isolated from your git config unless --sign.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { parseArgs } from "node:util";
import { PACKAGES, PUBLIC_SLUG, publicUrlOf, buildExport, catalogIdsFromTarball, changelogSection, commitToPublicRepo, git, gitVersionOk, npmTag, planPublicRepo, redact, refuseIfPrivateRemote, resolveIdentity, scanForLeaks, scanTarball, snapshot, tarballManifest, validVersion, verifyTagMatchesExport } from "../release/lib.ts";

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    "dry-run": { type: "boolean", default: false }, yes: { type: "boolean", default: false }, author: { type: "string" },
    repo: { type: "string", default: PUBLIC_SLUG }, remote: { type: "string" }, out: { type: "string" },
    "skip-git": { type: "boolean", default: false }, "skip-npm": { type: "boolean", default: false },
    "adopt-existing": { type: "boolean", default: false }, sign: { type: "boolean", default: false },
  },
});
const root = join(import.meta.dirname, "..");
const version = positionals[0] as string;
const dry = values["dry-run"] as boolean;
const slug = values.repo as string;
if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(slug)) { console.error("\nrelease aborted: --repo must look like owner/name"); process.exit(1); }
// `--remote` overrides the git URL only (for a local rehearsal); package metadata and site links always follow --repo.
const remote = (values.remote as string | undefined) ?? `${publicUrlOf(slug)}.git`;
const say = (m: string) => console.log(`\n== ${m}`);
// Anything that may hold a credential or a full copy of the export is removed when the command ends, however it ends.
const scratch: string[] = [];
const cleanup = () => { for (const d of scratch) rmSync(d, { recursive: true, force: true }); };
process.on("SIGINT", () => { cleanup(); process.exit(130); });
process.on("SIGTERM", () => { cleanup(); process.exit(143); });
process.on("uncaughtException", (e) => { console.error(`\nrelease aborted: ${redact(String(e instanceof Error ? e.message : e))}`); cleanup(); process.exit(1); });
const die = (m: string): never => { console.error(`\nrelease aborted: ${redact(m)}`); cleanup(); process.exit(1); };
const run = (cmd: string, args: string[], cwd: string, extra: { quiet?: boolean; env?: NodeJS.ProcessEnv } = {}) =>
  spawnSync(cmd, args, { cwd, encoding: "utf8", stdio: extra.quiet ? "pipe" : "inherit", env: { ...process.env, ...extra.env } });
const sha256 = (file: string) => createHash("sha256").update(readFileSync(file)).digest("hex");
const integrity = (file: string) => `sha512-${createHash("sha512").update(readFileSync(file)).digest("base64")}`;

if (!version || !validVersion(version)) die("usage: node scripts/release.ts <version>  (strict semver, for example 0.1.0-preview.1 or 1.0.0; a prerelease label must be a lowercase word such as preview or rc)");
const tag = `v${version}`;
const dist = npmTag(version);

say(`Preconditions for ${tag} (npm tag "${dist}")${dry ? " [dry run]" : ""}`);
const status = git(["status", "--porcelain"], root);
if (status.status !== 0) die(`git status failed: ${String(status.stderr).trim()}`);
if (String(status.stdout).trim()) die("the working tree has uncommitted changes; commit or stash them so the export is exactly a commit");
const sha = String(git(["rev-parse", "--short", "HEAD"], root).stdout).trim();
const notes = changelogSection(readFileSync(join(root, "CHANGELOG.md"), "utf8"), version);
if (!notes) die(`CHANGELOG.md has no non-empty "## [${version}]" section; write the release notes first`);
let identity;
try { identity = resolveIdentity(values.author as string | undefined); refuseIfPrivateRemote(remote); } catch (e) { die((e as Error).message); }
if (!gitVersionOk()) die("git 2.32 or newer is required (the isolation of the public commit depends on it)");
console.log(`source commit ${sha}; changelog section found (${notes!.split("\n").length} lines)\npublic commits and the tag will be authored by: ${identity!.name} <${identity!.email}>`);

say("Export the public tree");
const base = values.out ? resolve(values.out as string) : mkdtempSync(join(tmpdir(), "bulkhead-release-"));
mkdirSync(base, { recursive: true });
const exportDir = join(base, "export");
scratch.push(join(base, "public-repo"), join(base, "public-plan"), join(base, "public-check"), join(base, ".empty-template"));
if (!values.out) scratch.push(base);
const files = buildExport({ root, out: exportDir, version, slug });
console.log(`${files.length} files exported to ${exportDir}`);

say("Scan the export for private material");
const leaks = scanForLeaks(exportDir);
if (leaks.length) die(`the export contains private material (${leaks.length}):\n  ${leaks.slice(0, 40).join("\n  ")}`);
console.log("clean: no private paths, record ids, roadmap phases, private URLs, process wording, unknown rule citations or owner TODOs");
// Taken now, before install and the gate can leave anything behind: this exact file list and tree is what gets committed.
const snap = snapshot(exportDir);
console.log(`snapshot: ${snap.files.length} files, tree ${snap.tree.slice(0, 12)}`);

say("Install, then pack the tarballs once");
if (run("pnpm", ["install", "--frozen-lockfile"], exportDir).status !== 0) die("pnpm install --frozen-lockfile failed in the export");
const tarDir = join(base, "tarballs");
rmSync(tarDir, { recursive: true, force: true });
mkdirSync(tarDir, { recursive: true });
for (const p of PACKAGES) if (run("pnpm", ["pack", "--pack-destination", tarDir], join(exportDir, p.dir)).status !== 0) die(`pnpm pack failed for ${p.name}`);
const tarballs = readdirSync(tarDir).sort();
if (tarballs.length !== PACKAGES.length) die(`expected ${PACKAGES.length} tarballs, found ${tarballs.length}`);
const tarFor = (name: string) => {
  const matches = tarballs.filter((t) => tarballManifest(join(tarDir, t)).name === name);
  if (matches.length !== 1) die(`expected exactly one tarball for ${name}, found ${matches.length}`);
  return join(tarDir, matches[0] as string);
};
const hashes = new Map<string, string>();
for (const p of PACKAGES) {
  const tgz = tarFor(p.name);
  const m = tarballManifest(tgz);
  if (m.version !== version || m.publishConfig?.tag !== dist) die(`${p.name}: tarball says ${m.version} / tag ${m.publishConfig?.tag}, expected ${version} / ${dist}`);
  hashes.set(tgz, sha256(tgz));
  console.log(`${tgz.split("/").pop()}  ${hashes.get(tgz)!.slice(0, 16)}`);
}

say("Scan the tarballs (what npm would serve)");
const knownRules = catalogIdsFromTarball(tarFor("@kalahroudi/bulkhead-spec"));
const tarLeaks = PACKAGES.flatMap((p) => scanTarball(tarFor(p.name), base, knownRules));
if (tarLeaks.length) die(`the tarballs contain private material or stray files (${tarLeaks.length}):\n  ${tarLeaks.slice(0, 40).join("\n  ")}`);
console.log("clean: only dist, README, LICENSE and package.json, with no private material");

say("Run the public gate on those exact tarballs (typecheck, tests, verify, installed-package consumer test)");
if (run("pnpm", ["gate:release"], exportDir, { env: { CONSUMER_TARBALL_DIR: tarDir } }).status !== 0) die("pnpm gate:release failed in the export");
for (const [tgz, h] of hashes) if (sha256(tgz) !== h) die(`${tgz} changed after it was tested`);
console.log("the tarballs tested are the tarballs that will be published (hashes unchanged)");

const registryIntegrity = (name: string) => String(run("npm", ["view", `${name}@${version}`, "dist.integrity"], exportDir, { quiet: true }).stdout ?? "").trim();
if (!values["skip-npm"]) {
  say("npm preflight (before anything irreversible)");
  const taken: string[] = [];
  for (const p of PACKAGES) {
    const there = registryIntegrity(p.name);
    if (!there) continue;
    if (there !== integrity(tarFor(p.name))) die(`${p.name}@${version} is already on npm but is NOT the tarball that was just tested; do not republish, investigate`);
    taken.push(p.name);
  }
  if (taken.length === PACKAGES.length) die(`all four packages are already published at ${version}`);
  if (taken.length) console.log(`already on npm at ${version}, identical to the tested tarball (will be skipped): ${taken.join(", ")}`);
  if (!dry && run("npm", ["whoami"], exportDir, { quiet: true }).status !== 0) die("not logged in to npm; run `npm login` first");
  for (const p of PACKAGES.filter((x) => !taken.includes(x.name)))
    if (run("npm", ["publish", tarFor(p.name), "--dry-run", "--access", "public", "--tag", dist], exportDir, { quiet: true }).status !== 0) die(`npm publish --dry-run failed for ${p.name}; fix that before anything is pushed`);
  console.log("npm accepts all packages in a dry run");
}

let plan = { exists: false, removed: [] as string[], foreign: [] as string[] };
if (!values["skip-git"]) {
  say("Public repo plan");
  try { plan = planPublicRepo({ files: snap.files, remote, workdir: join(base, "public-plan"), adopt: values["adopt-existing"] as boolean }); } catch (e) { die((e as Error).message); }
  console.log(plan.exists ? `main exists (${plan.foreign.length} commit(s) not written by this tool). It will be replaced by the export; files removed: ${plan.removed.length ? plan.removed.join(", ") : "none"}` : "the public repo has no main; it will be created");
}

say("Summary");
console.log([
  `version      ${version}   (tag ${tag}, npm dist-tag "${dist}")`,
  `source       commit ${sha} of the private repo (not pushed anywhere)`,
  `author       ${identity!.name} <${identity!.email}>`,
  `public repo  ${redact(remote)}   ${values["skip-git"] ? "[skipped; will first prove the public tag holds this exact tree]" : dry ? "[dry run: push --dry-run]" : "[atomic push of main + tag]"}`,
  `npm          ${PACKAGES.map((p) => p.name).join(", ")}   ${values["skip-npm"] ? "[skipped]" : dry ? "[dry run: publish --dry-run]" : `[publish --tag ${dist}]`}`,
  "",
  values.sign ? "Commit and tag will be SIGNED with the key from your own git configuration." : "Commit and tag are created unsigned and isolated from your git configuration (the push itself uses your credentials).",
  "",
  "One-time setup the script cannot do for you:",
  "  - the public repo exists (an empty one is fine; `main` is created if missing)",
  "  - Settings > Code security: enable private vulnerability reporting (SECURITY.md depends on it)",
  "  - Settings > Pages > Source: GitHub Actions (the first Pages run fails until this is set; re-run it afterwards)",
  "  - npm: you are logged in and a member of the @kalahroudi scope, with 2FA on",
].join("\n"));
if (!dry && !values.yes) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const answer = await rl.question(`\nThis cannot be fully undone. Type the version (${version}) to continue: `);
  rl.close();
  if (answer.trim() !== version) die("confirmation did not match");
}

if (values["skip-git"]) {
  if (!values["skip-npm"]) { say("Verify the public tag against this export"); try { verifyTagMatchesExport(remote, tag, snap.tree, join(base, "public-check")); } catch (e) { die((e as Error).message); } console.log(`${tag} on the public repo holds exactly this tree`); }
} else {
  say(`Public repo: ${redact(remote)}`);
  try {
    const r = commitToPublicRepo({ exportDir, snapshot: snap, remote, version, notes: notes as string, push: !dry, workdir: join(base, "public-repo"), identity: identity!, adopt: values["adopt-existing"] as boolean, sign: values.sign as boolean });
    if (r.removed.length) console.log(`replaced the previous contents of main; removed ${r.removed.length} file(s): ${r.removed.slice(0, 20).join(", ")}${r.removed.length > 20 ? ", ..." : ""}`);
    console.log(`${r.created ? "created main with" : "added a release commit to main:"} ${r.commit.slice(0, 10)}, tagged ${tag}${dry ? " (dry run: nothing pushed)" : ""}`);
  } catch (e) { die((e as Error).message); }
}

if (!values["skip-npm"]) {
  say(`npm publish (${dry ? "dry run" : "for real"})`);
  for (const [tgz, h] of hashes) if (sha256(tgz) !== h) die(`${tgz} changed after it was tested; nothing was published`);
  for (const p of PACKAGES) {
    const local = integrity(tarFor(p.name));
    if (registryIntegrity(p.name) === local) { console.log(`skip ${p.name}@${version}: already published, identical to the tested tarball`); continue; }
    const args = ["publish", tarFor(p.name), "--access", "public", "--tag", dist, ...(dry ? ["--dry-run"] : [])];
    if (run("npm", args, exportDir).status !== 0) die(`npm publish failed for ${p.name}. Fix it and rerun the same command with --skip-git (it proves the tag matches, and packages already published are skipped).`);
    if (!dry) {
      // The registry is eventually consistent, so give it a few tries; what it serves must be byte-identical to what was tested.
      let served = "";
      for (let i = 0; i < 6 && served !== local; i++) { if (i) await new Promise((r) => setTimeout(r, 5000)); served = registryIntegrity(p.name); }
      if (served !== local) die(`${p.name}@${version} was published, but the registry serves different bytes than the tested tarball (${served || "nothing yet"}). Investigate before telling anyone.`);
      console.log(`verified on the registry: ${p.name}@${version}`);
    }
  }
}

say("Done");
cleanup();
console.log(dry ? "Dry run complete: nothing was pushed or published." : [
  `${values["skip-git"] ? "" : `Pushed ${tag} to the public repo. `}${values["skip-npm"] ? "" : "Published the packages. "}`.trim(),
  ...(values["skip-npm"] ? [`npm was skipped: publish later by rerunning the same command with --skip-git.`] : [`Check it from a clean directory: npm install @kalahroudi/bulkhead-core@${dist}`]),
].join("\n"));
