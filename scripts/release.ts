// Publishes a release: exports a clean public copy of the repo, checks it, pushes it to the public GitHub repo (creating `main`
// when the remote has none), tags it, and publishes the four packages to npm. You run it by hand.
//
//   node scripts/release.ts <version> [--dry-run] [--yes] [--author "Name <you@example.com>"] [--otp=123456]
//                           [--remote=<git url>] [--out=<dir>] [--skip-git] [--skip-npm] [--adopt-existing] [--no-sign]
//
// Needs: git push access to the public repo, `npm login` as a member of the @kalahroudi scope (2FA prompts pass through),
// and a section `## [<version>]` in CHANGELOG.md. --dry-run does everything except push and publish.
// Order: export, scan, pack once, scan the tarballs, run the public gate on those exact tarballs, then git (branch and tag in one
// atomic push), then npm. A rerun after a partial npm failure uses --skip-git and first proves the public tag holds this exact tree.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline/promises";
import { parseArgs } from "node:util";
import { PACKAGES, PUBLIC_REPO, buildExport, changelogSection, commitToPublicRepo, git, npmTag, redact, resolveIdentity, scanForLeaks, scanTarball, tarballManifest, validVersion, verifyTagMatchesExport } from "../release/lib.ts";

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    "dry-run": { type: "boolean", default: false }, yes: { type: "boolean", default: false }, otp: { type: "string" }, author: { type: "string" },
    remote: { type: "string", default: PUBLIC_REPO }, out: { type: "string" },
    "skip-git": { type: "boolean", default: false }, "skip-npm": { type: "boolean", default: false },
    "adopt-existing": { type: "boolean", default: false }, "no-sign": { type: "boolean", default: false },
  },
});
const root = join(import.meta.dirname, "..");
const version = positionals[0] as string;
const dry = values["dry-run"] as boolean;
const remote = values.remote as string;
const say = (m: string) => console.log(`\n== ${m}`);
const die = (m: string): never => { console.error(`\nrelease aborted: ${m}`); process.exit(1); };
const run = (cmd: string, args: string[], cwd: string, extra: { quiet?: boolean; env?: NodeJS.ProcessEnv } = {}) =>
  spawnSync(cmd, args, { cwd, encoding: "utf8", stdio: extra.quiet ? "pipe" : "inherit", env: { ...process.env, ...extra.env } });
const sha256 = (file: string) => createHash("sha256").update(readFileSync(file)).digest("hex");

if (!version || !validVersion(version)) die("usage: node scripts/release.ts <version>  (strict semver, for example 0.1.0-preview.1 or 1.0.0; a prerelease label must be a lowercase word such as preview or rc)");
const tag = `v${version}`;
const dist = npmTag(version);

say(`Preconditions for ${tag} (npm tag "${dist}")${dry ? " [dry run]" : ""}`);
if (git(["status", "--porcelain"], root).stdout.toString().trim()) die("the working tree has uncommitted changes; commit or stash them so the export is exactly a commit");
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

const alreadyPublished = (name: string) => run("npm", ["view", `${name}@${version}`, "version"], exportDir, { quiet: true }).stdout?.toString().trim() === version;
if (!values["skip-npm"]) {
  const taken = PACKAGES.filter((p) => alreadyPublished(p.name)).map((p) => p.name);
  if (taken.length === PACKAGES.length) die(`all four packages are already published at ${version}`);
  if (taken.length) console.log(`already on npm at ${version} (will be skipped): ${taken.join(", ")}`);
  if (!dry && run("npm", ["whoami"], exportDir, { quiet: true }).status !== 0) die("not logged in to npm; run `npm login` first");
}

say("Summary");
console.log([
  `version      ${version}   (tag ${tag}, npm dist-tag "${dist}")`,
  `source       commit ${sha} of the private repo (not pushed anywhere)`,
  `author       ${identity!.name} <${identity!.email}>`,
  `public repo  ${redact(remote)}   ${values["skip-git"] ? "[skipped; will first prove the public tag holds this exact tree]" : dry ? "[dry run: push --dry-run]" : "[atomic push of main + tag]"}`,
  `npm          ${PACKAGES.map((p) => p.name).join(", ")}   ${values["skip-npm"] ? "[skipped]" : dry ? "[dry run: publish --dry-run]" : `[publish --tag ${dist}]`}`,
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
    const r = commitToPublicRepo({ exportDir, remote, version, notes: notes as string, push: !dry, workdir: join(base, "public-repo"), identity: identity!, adopt: values["adopt-existing"] as boolean, noSign: values["no-sign"] as boolean });
    if (r.removed.length) console.log(`replaced the previous contents of main; removed ${r.removed.length} file(s): ${r.removed.slice(0, 20).join(", ")}${r.removed.length > 20 ? ", ..." : ""}`);
    console.log(`${r.created ? "created main with" : "added a release commit to main:"} ${r.commit.slice(0, 10)}, tagged ${tag}${dry ? " (dry run: nothing pushed)" : ""}`);
  } catch (e) { die((e as Error).message); }
}

if (!values["skip-npm"]) {
  say(`npm publish (${dry ? "dry run" : "for real"})`);
  for (const p of PACKAGES) {
    if (alreadyPublished(p.name)) { console.log(`skip ${p.name}@${version}: already published`); continue; }
    const args = ["publish", tarFor(p.name), "--access", "public", "--tag", dist, ...(values.otp ? ["--otp", values.otp as string] : []), ...(dry ? ["--dry-run"] : [])];
    if (run("npm", args, exportDir).status !== 0) die(`npm publish failed for ${p.name}. Fix it and rerun the same command with --skip-git (it proves the tag matches, and packages already published are skipped).`);
  }
}

say("Done");
console.log(dry ? "Dry run complete: nothing was pushed or published." : [
  `Released ${tag}.`,
  `Check it from a clean directory: npm install @kalahroudi/bulkhead-core@${dist}`,
].join("\n"));
