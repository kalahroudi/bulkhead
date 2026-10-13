// Publishes a release: exports a clean public copy of the repo, checks it, pushes it to the public GitHub repo (creating `main`
// when the remote has none), tags it, and publishes the four packages to npm. You run it by hand.
//
//   node scripts/release.ts <version> [--dry-run] [--yes] [--author "Name <you@example.com>"] [--otp=123456]
//                           [--remote=<git url>] [--out=<dir>] [--skip-git] [--skip-npm] [--adopt-existing] [--sign]
//
// Needs: git push access to the public repo, `npm login` as a member of the @kalahroudi scope (2FA prompts pass through),
// and a section `## [<version>]` in CHANGELOG.md. --dry-run does everything except push and publish.
// Order: export, scan, pack once, scan the tarballs, run the public gate on those exact tarballs, then git (branch and tag in one
// atomic push), then npm. A rerun after a partial npm failure uses --skip-git and first proves the public tag holds this exact tree.
// macOS and Linux only. The public repo is a mirror: its contents are replaced on every release, and commits made there by anyone else
// are listed and refused unless you pass --adopt-existing. Commits and tags are unsigned and isolated from your git config unless --sign.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline/promises";
import { parseArgs } from "node:util";
import { PACKAGES, PUBLIC_REPO, buildExport, changelogSection, commitToPublicRepo, git, npmTag, planPublicRepo, redact, resolveIdentity, scanForLeaks, scanTarball, tarballManifest, validVersion, verifyTagMatchesExport } from "../release/lib.ts";

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    "dry-run": { type: "boolean", default: false }, yes: { type: "boolean", default: false }, otp: { type: "string" }, author: { type: "string" },
    remote: { type: "string", default: PUBLIC_REPO }, out: { type: "string" },
    "skip-git": { type: "boolean", default: false }, "skip-npm": { type: "boolean", default: false },
    "adopt-existing": { type: "boolean", default: false }, sign: { type: "boolean", default: false },
  },
});
const root = join(import.meta.dirname, "..");
const version = positionals[0] as string;
const dry = values["dry-run"] as boolean;
const remote = values.remote as string;
const say = (m: string) => console.log(`\n== ${m}`);
// Anything that may hold a credential or a full copy of the export is removed when the command ends, however it ends.
const scratch: string[] = [];
const cleanup = () => { for (const d of scratch) rmSync(d, { recursive: true, force: true }); };
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
try { identity = resolveIdentity(values.author as string | undefined); } catch (e) { die((e as Error).message); }
console.log(`source commit ${sha}; changelog section found (${notes!.split("\n").length} lines)\npublic commits and the tag will be authored by: ${identity!.name} <${identity!.email}>`);

say("Export the public tree");
const base = values.out ?? mkdtempSync(join(tmpdir(), "bulkhead-release-"));
mkdirSync(base, { recursive: true });
const exportDir = join(base, "export");
scratch.push(join(base, "public-repo"), join(base, "public-plan"), join(base, "public-check"), join(base, ".empty-template"));
if (!values.out) scratch.push(base);
const files = buildExport({ root, out: exportDir, version });
console.log(`${files.length} files exported to ${exportDir}`);

say("Scan the export for private material");
const leaks = scanForLeaks(exportDir);
if (leaks.length) die(`the export contains private material (${leaks.length}):\n  ${leaks.slice(0, 40).join("\n  ")}`);
console.log("clean: no private paths, record ids, roadmap phases, private URLs, process wording, unknown rule citations or owner TODOs");

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
const tarLeaks = PACKAGES.flatMap((p) => scanTarball(tarFor(p.name), base));
if (tarLeaks.length) die(`the tarballs contain private material or stray files (${tarLeaks.length}):\n  ${tarLeaks.slice(0, 40).join("\n  ")}`);
console.log("clean: only dist, README, LICENSE and package.json, with no private material");

say("Run the public gate on those exact tarballs (typecheck, tests, verify, installed-package consumer test)");
if (run("pnpm", ["gate:release"], exportDir, { env: { CONSUMER_TARBALL_DIR: tarDir } }).status !== 0) die("pnpm gate:release failed in the export");
for (const [tgz, h] of hashes) if (sha256(tgz) !== h) die(`${tgz} changed after it was tested`);
console.log("the tarballs tested are the tarballs that will be published (hashes unchanged)");

const registryIntegrity = (name: string) => String(run("npm", ["view", `${name}@${version}`, "dist.integrity"], exportDir, { quiet: true }).stdout ?? "").trim();
const otpEnv = values.otp ? { NPM_CONFIG_OTP: values.otp as string } : {}; // via the environment, so it never shows in `ps`
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
  try { plan = planPublicRepo({ exportDir, remote, workdir: join(base, "public-plan"), adopt: values["adopt-existing"] as boolean }); } catch (e) { die((e as Error).message); }
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
  "Commits and the tag are unsigned and isolated from your git config" + (values.sign ? " [EXCEPT: --sign uses your config]" : "") + ".",
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
  if (!values["skip-npm"]) { say("Verify the public tag against this export"); try { verifyTagMatchesExport(remote, tag, exportDir, join(base, "public-check")); } catch (e) { die((e as Error).message); } console.log(`${tag} on the public repo holds exactly this tree`); }
} else {
  say(`Public repo: ${redact(remote)}`);
  try {
    const r = commitToPublicRepo({ exportDir, remote, version, notes: notes as string, push: !dry, workdir: join(base, "public-repo"), identity: identity!, adopt: values["adopt-existing"] as boolean, sign: values.sign as boolean });
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
    if (run("npm", args, exportDir, { env: otpEnv }).status !== 0) die(`npm publish failed for ${p.name}. Fix it and rerun the same command with --skip-git (it proves the tag matches, and packages already published are skipped).`);
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
  `Released ${tag}.`,
  `Check it from a clean directory: npm install @kalahroudi/bulkhead-core@${dist}`,
].join("\n"));
