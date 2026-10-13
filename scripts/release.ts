// Publishes a release: exports a clean public copy of the repo, checks it, pushes it to the public GitHub repo (creating `main`
// when the remote has none), tags it, and publishes the four packages to npm. You run it by hand.
//
//   node scripts/release.ts <version> [--dry-run] [--yes] [--otp=123456] [--remote=<git url>] [--out=<dir>]
//                           [--skip-checks] [--skip-git] [--skip-npm]
//
// Needs: git push access to the public repo, `npm login` as a member of the @kalahroudi scope (2FA prompts pass through),
// and a section `## [<version>]` in CHANGELOG.md. --dry-run does everything except push and publish.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline/promises";
import { parseArgs } from "node:util";
import { PACKAGES, PUBLIC_REPO, buildExport, changelogSection, commitToPublicRepo, git, npmTag, scanForLeaks, validVersion } from "../release/lib.ts";

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    "dry-run": { type: "boolean", default: false }, yes: { type: "boolean", default: false }, otp: { type: "string" },
    remote: { type: "string", default: PUBLIC_REPO }, out: { type: "string" },
    "skip-checks": { type: "boolean", default: false }, "skip-git": { type: "boolean", default: false }, "skip-npm": { type: "boolean", default: false },
  },
});
const root = join(import.meta.dirname, "..");
const version = positionals[0];
const dry = values["dry-run"] as boolean;
const say = (m: string) => console.log(`\n== ${m}`);
const die = (m: string): never => { console.error(`\nrelease aborted: ${m}`); process.exit(1); };
const run = (cmd: string, args: string[], cwd: string, extra: { quiet?: boolean } = {}) =>
  spawnSync(cmd, args, { cwd, encoding: "utf8", stdio: extra.quiet ? "pipe" : "inherit", env: process.env });

if (!version || !validVersion(version)) die("usage: node scripts/release.ts <version>  (for example 0.1.0-preview.1 or 1.0.0)");
const tag = `v${version}`;
const dist = npmTag(version as string);

say(`Preconditions for ${tag} (npm tag "${dist}")${dry ? " [dry run]" : ""}`);
if (git(["status", "--porcelain"], root).stdout.toString().trim()) die("the working tree has uncommitted changes; commit or stash them so the export is exactly a commit");
const sha = String(git(["rev-parse", "--short", "HEAD"], root).stdout).trim();
const notes = changelogSection(readFileSync(join(root, "CHANGELOG.md"), "utf8"), version as string);
if (!notes) die(`CHANGELOG.md has no non-empty "## [${version}]" section; write the release notes first`);
console.log(`source commit ${sha}; changelog section found (${notes!.split("\n").length} lines)`);

say("Export the public tree");
const base = values.out ?? mkdtempSync(join(tmpdir(), "bulkhead-release-"));
mkdirSync(base, { recursive: true });
const exportDir = join(base, "export");
const files = buildExport({ root, out: exportDir, version: version as string });
console.log(`${files.length} files exported to ${exportDir}`);

say("Scan the export for private material");
const leaks = scanForLeaks(exportDir);
if (leaks.length) die(`the export contains private material (${leaks.length}):\n  ${leaks.slice(0, 40).join("\n  ")}`);
console.log("clean: no private paths, record ids, roadmap phases, private URLs, provenance or owner TODOs");

if (!values["skip-checks"]) {
  say("Run the public gate inside the export (typecheck, tests, verify, packed-package consumer test)");
  for (const [cmd, args] of [["pnpm", ["install", "--frozen-lockfile"]], ["pnpm", ["gate:release"]]] as const)
    if (run(cmd, [...args], exportDir).status !== 0) die(`${cmd} ${args.join(" ")} failed in the export`);
}

say("Pack the packages");
const tarDir = join(base, "tarballs");
mkdirSync(tarDir, { recursive: true });
for (const p of PACKAGES) if (run("pnpm", ["pack", "--pack-destination", tarDir], join(exportDir, p.dir)).status !== 0) die(`pnpm pack failed for ${p.name}`);
const tarballs = readdirSync(tarDir).sort();
console.log(tarballs.join("\n"));

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
  `public repo  ${values.remote}   ${values["skip-git"] ? "[skipped]" : dry ? "[dry run: push --dry-run]" : "[push main + tag]"}`,
  `npm          ${PACKAGES.map((p) => p.name).join(", ")}   ${values["skip-npm"] ? "[skipped]" : dry ? "[dry run: publish --dry-run]" : "[publish]"}`,
].join("\n"));
if (!dry && !values.yes) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const answer = await rl.question(`\nThis cannot be fully undone. Type the version (${version}) to continue: `);
  rl.close();
  if (answer.trim() !== version) die("confirmation did not match");
}

if (!values["skip-git"]) {
  say(`Public repo: ${values.remote}`);
  const r = commitToPublicRepo({ exportDir, remote: values.remote as string, version: version as string, notes: notes as string, push: !dry, workdir: join(base, "public-repo") });
  console.log(`${r.created ? "created main with" : "added a release commit to main:"} ${r.commit.slice(0, 10)}, tagged ${tag}${dry ? " (dry run: nothing pushed)" : ""}`);
}

if (!values["skip-npm"]) {
  say(`npm publish (${dry ? "dry run" : "for real"})`);
  for (const p of PACKAGES) {
    if (alreadyPublished(p.name)) { console.log(`skip ${p.name}@${version}: already published`); continue; }
    const tgz = tarballs.find((t) => t.startsWith(p.name.replace("@", "").replace("/", "-") + "-"));
    if (!tgz) die(`no tarball for ${p.name}`);
    const args = ["publish", join(tarDir, tgz as string), "--access", "public", "--tag", dist, ...(values.otp ? ["--otp", values.otp] : []), ...(dry ? ["--dry-run"] : [])];
    if (run("npm", args, exportDir).status !== 0) die(`npm publish failed for ${p.name}. Fix it and rerun with --skip-git; packages already published are skipped.`);
  }
}

say("Done");
console.log(dry ? "Dry run complete: nothing was pushed or published." : [
  `Released ${tag}.`,
  "Next, once: enable GitHub Pages (Settings > Pages > Source: GitHub Actions) so the site workflow can deploy.",
  `Check it from a clean directory: npm install @kalahroudi/bulkhead-core@${dist}`,
].join("\n"));
