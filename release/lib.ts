// Everything the public release does, as functions, so scripts/release.ts runs it and scripts/release-selftest.ts proves it can fail.
// The public repo is a separate, clean export: an allowlist of files, exact text fixes, templates, a leak scan, then git and npm.
import { spawnSync, type SpawnSyncOptions } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";

export const PUBLIC_REPO = "https://github.com/flamingosh/bulkhead.git";
export const PRIVATE_URL = "https://github.com/kalahroudi/bulkhead";
export const PUBLIC_URL = "https://github.com/flamingosh/bulkhead";
/** Publish order matters: each package depends on the ones before it. */
export const PACKAGES = [
  { dir: "packages/spec", name: "@kalahroudi/bulkhead-spec" },
  { dir: "packages/core", name: "@kalahroudi/bulkhead-core" },
  { dir: "packages/auth", name: "@kalahroudi/bulkhead-auth" },
  { dir: "packages/verify", name: "@kalahroudi/bulkhead-verify" },
] as const;

// --- What ships: an allowlist, so a new private file can never leak by being added. ---
const ALLOW = [
  /^packages\/(spec|core|auth|verify|plane)\//,
  /^examples\/demo-app\//,
  /^(README\.md|CHANGELOG\.md|LICENSE|package\.json|pnpm-lock\.yaml|pnpm-workspace\.yaml|tsconfig\.base\.json|\.gitignore)$/,
  /^scripts\/(build-package|consumer-test|verify-kernel)\.ts$/,
];
// Inside the allowed packages, these are private tooling and never ship.
const DENY = [
  /(^|\/)node_modules\//, /(^|\/)dist\//, /(^|\/)\.wrangler\//, /(^|\/)\.bulkhead\//,
  /^packages\/verify\/src\/mutations\.ts$/,
  /^packages\/verify\/test\/(mutations|decisions)\.test\.ts$/,
  /^packages\/spec\/scripts\/(generate-catalog|lint-decisions)\.ts$/,
];
export const shippable = (path: string) => ALLOW.some((r) => r.test(path)) && !DENY.some((r) => r.test(path));

// --- Exact text fixes. Each must match exactly once, or the export aborts; a stale fix is never silently skipped. ---
export interface Fix { file: string; find: string; replace: string }
export const FIXES: Fix[] = [
  { file: "packages/auth/src/routes.ts", find: "Phase 6 provisioning will create owners directly; until then this is the only way in.", replace: "Tenant provisioning (planned) will create owners directly; until then this is the only way in." },
  { file: "packages/core/src/tenant/types.ts", find: "Development stopgap until Phase 6 provisioning.", replace: "Development stopgap until tenant provisioning exists." },
  { file: "packages/core/src/api/app.ts", find: "Plan entitlements arrive in Phase 5.", replace: "Plan entitlements are planned." },
  { file: "packages/spec/src/types.ts", find: "The scenario is written in Phase 1+.", replace: "The scenario is written as the rule is verified." },
  { file: "packages/spec/src/formats.ts", find: "arrive in Phase 1+.", replace: "are planned." },
  { file: "packages/spec/src/rules.ts", find: " (Phase 1+).", replace: "." },
  { file: "examples/demo-app/scripts/manifest.ts", find: "which CODEOWNERS routes to the owner (ROUTE-3)", replace: "so that review can see it (ROUTE-3)" },
  { file: "packages/spec/test/spec.test.ts", find: '"DR-0001"', replace: '"DR-9001"' },
];

// --- Leak scan: anything that points at the private repo, its records, its docs, or how it is built. ---
export const LEAK_PATTERNS: [string, RegExp][] = [
  ["private doc or path", /docs\/decisions|SPEC\.md|CLAUDE\.md|AGENTS\.md|FROZEN_PATHS/],
  ["private decision record id", /\bDR-(?!9\d{3}\b)\d{4}\b/],
  ["roadmap phase reference", /\bPhase \d/],
  ["private repository url", /kalahroudi\/bulkhead(?![-\w])/],
  ["agent or session provenance", /claude|anthropic|Co-Authored-By|Claude-Session|attacker session/i],
  ["personal address", /bermouda/i],
  ["unfinished owner todo", /TODO\(owner\)/],
];
const TEXT = /\.(ts|js|json|jsonc|md|yml|yaml|html|css|txt|toml)$|(^|\/)(\.gitignore|LICENSE)$/;

export function scanForLeaks(dir: string): string[] {
  const hits: string[] = [];
  for (const file of walk(dir)) {
    const rel = relative(dir, file);
    if (/(^|\/)(pnpm-lock\.yaml)$/.test(rel) || !TEXT.test(rel)) continue;
    const lines = readFileSync(file, "utf8").split("\n");
    lines.forEach((line, i) => {
      for (const [why, re] of LEAK_PATTERNS) if (re.test(line)) hits.push(`${rel}:${i + 1} [${why}] ${line.trim().slice(0, 140)}`);
    });
  }
  return hits;
}

export function walk(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.name === ".git" ? [] : e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)]));
}

// --- Export ---
export function git(args: string[], cwd: string, opts: SpawnSyncOptions = {}) {
  return spawnSync("git", args, { cwd, encoding: "utf8", ...opts });
}

export function trackedFiles(root: string): string[] {
  const r = git(["ls-files", "-z"], root);
  if (r.status !== 0) throw new Error(`git ls-files failed: ${r.stderr}`);
  return String(r.stdout).split("\0").filter(Boolean);
}

export interface ExportOptions { root: string; out: string; version: string; templates?: string }

/** Builds the public tree in `out` from the private repo's tracked files. Returns the list of exported files. */
export function buildExport({ root, out, version, templates = join(root, "release") }: ExportOptions): string[] {
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  const files = trackedFiles(root).filter(shippable).filter((f) => existsSync(join(root, f)));
  for (const f of files) { mkdirSync(dirname(join(out, f)), { recursive: true }); cpSync(join(root, f), join(out, f)); }

  for (const fix of FIXES) {
    const p = join(out, fix.file);
    if (!existsSync(p)) throw new Error(`fix targets a file that is not exported: ${fix.file}`);
    const text = readFileSync(p, "utf8");
    const hits = text.split(fix.find).length - 1;
    if (hits !== 1) throw new Error(`fix for ${fix.file} matched ${hits} time(s), must be exactly 1: ${fix.find}`);
    writeFileSync(p, text.replace(fix.find, () => fix.replace));
  }

  // The private repo's own URL becomes the public one everywhere it is written out in full.
  for (const file of walk(out)) {
    if (!TEXT.test(relative(out, file))) continue;
    const text = readFileSync(file, "utf8");
    if (text.includes(PRIVATE_URL)) writeFileSync(file, text.split(PRIVATE_URL).join(PUBLIC_URL));
  }

  // package.json files: release version, public URLs, and scripts that only make sense in the private repo removed.
  for (const dir of [...PACKAGES.map((p) => p.dir), "packages/plane", "examples/demo-app", "."]) {
    const p = join(out, dir, "package.json");
    if (!existsSync(p)) continue;
    const j = JSON.parse(readFileSync(p, "utf8"));
    if (PACKAGES.some((x) => x.dir === dir)) {
      j.version = version;
      j.homepage = `${PUBLIC_URL}#readme`;
      j.bugs = { url: `${PUBLIC_URL}/issues` };
      j.repository = { type: "git", url: `git+${PUBLIC_URL}.git`, directory: dir };
    }
    if (dir === "packages/spec") { j.scripts = { typecheck: j.scripts.typecheck, test: j.scripts.test, lint: "node scripts/lint-spec.ts", build: j.scripts.build, prepack: j.scripts.prepack }; }
    if (dir === "packages/verify" && j.exports) delete j.exports["./mutations"];
    if (dir === ".") {
      j.name = "bulkhead-monorepo";
      j.scripts = {
        typecheck: "pnpm -r typecheck",
        test: "pnpm -r test",
        build: "pnpm -r --filter './packages/*' build",
        gate: "pnpm typecheck && pnpm test && pnpm --filter @kalahroudi/bulkhead-spec lint && pnpm --filter @kalahroudi/bulkhead-verify selfcheck && pnpm --filter bulkhead-demo-app manifest:check && node scripts/verify-kernel.ts --rules TENANT-1,TENANT-4,TENANT-5,AUTH-1,AUTH-2,AUTH-3,AUTH-4",
        "gate:release": "pnpm gate && node scripts/consumer-test.ts",
      };
    }
    writeFileSync(p, JSON.stringify(j, null, 2) + "\n");
  }

  // Templates: public-facing files that replace the private repo's versions (or have none).
  const copyTree = (from: string, to: string) => { if (existsSync(from)) cpSync(from, to, { recursive: true }); };
  copyTree(join(templates, "templates/SECURITY.md"), join(out, "SECURITY.md"));
  copyTree(join(templates, "templates/CONTRIBUTING.md"), join(out, "CONTRIBUTING.md"));
  copyTree(join(templates, "templates/ISSUE_TEMPLATE"), join(out, ".github/ISSUE_TEMPLATE"));
  copyTree(join(templates, "templates/workflows"), join(out, ".github/workflows"));
  copyTree(join(templates, "site"), join(out, "site"));
  return walk(out).map((f) => relative(out, f)).sort();
}

// --- Changelog ---
/** The body of the `## [version]` section, or null when it is missing or empty. */
export function changelogSection(changelog: string, version: string): string | null {
  const lines = changelog.split("\n");
  const start = lines.findIndex((l) => new RegExp(`^## \\[${version.replace(/[.+]/g, "\\$&")}\\]`).test(l));
  if (start < 0) return null;
  const end = lines.findIndex((l, i) => i > start && /^## \[/.test(l));
  const body = lines.slice(start + 1, end < 0 ? undefined : end).join("\n").trim();
  return body.length > 0 ? body : null;
}

// --- Versions and tags ---
const SEMVER = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/;
export const validVersion = (v: string) => SEMVER.test(v);
/** `1.2.3` -> latest; `0.1.0-preview.2` -> preview; `1.0.0-rc.1` -> rc. */
export const npmTag = (v: string) => (v.includes("-") ? (v.split("-")[1] as string).split(".")[0] as string : "latest");

// --- Git: publish the export to the public repo, creating `main` when the remote has none. ---
export interface PublishGitOptions { exportDir: string; remote: string; version: string; notes: string; push: boolean; workdir: string }

export function remoteHasBranch(remote: string, branch: string): boolean {
  const r = git(["ls-remote", "--heads", remote, branch], process.cwd());
  if (r.status !== 0) throw new Error(`cannot reach ${remote}: ${r.stderr.trim()}`);
  return String(r.stdout).trim().length > 0;
}
export function remoteHasTag(remote: string, tag: string): boolean {
  const r = git(["ls-remote", "--tags", remote, tag], process.cwd());
  if (r.status !== 0) throw new Error(`cannot reach ${remote}: ${r.stderr.trim()}`);
  return String(r.stdout).trim().length > 0;
}

export function commitToPublicRepo(o: PublishGitOptions): { created: boolean; commit: string } {
  const tag = `v${o.version}`;
  if (remoteHasTag(o.remote, tag)) throw new Error(`the tag ${tag} already exists on ${o.remote}; pick a new version`);
  const exists = remoteHasBranch(o.remote, "main");
  rmSync(o.workdir, { recursive: true, force: true });
  if (exists) {
    const c = git(["clone", "--quiet", "--branch", "main", o.remote, o.workdir], process.cwd());
    if (c.status !== 0) throw new Error(`clone failed: ${c.stderr}`);
    for (const e of readdirSync(o.workdir)) if (e !== ".git") rmSync(join(o.workdir, e), { recursive: true, force: true });
  } else {
    mkdirSync(o.workdir, { recursive: true });
    for (const args of [["init", "--quiet", "-b", "main"], ["remote", "add", "origin", o.remote]]) {
      const r = git(args, o.workdir);
      if (r.status !== 0) throw new Error(`git ${args[0]} failed: ${r.stderr}`);
    }
  }
  cpSync(o.exportDir, o.workdir, { recursive: true, filter: (src) => !/(^|\/)\.git$/.test(src) });
  for (const args of [["add", "-A"]]) git(args, o.workdir);
  if (exists && git(["diff", "--cached", "--quiet"], o.workdir).status === 0) throw new Error("the public repo already has exactly this content; nothing to release");
  const message = `${exists ? "Release" : "Initial release"} ${tag}\n\n${o.notes}\n`;
  const c = git(["commit", "--quiet", "-m", message], o.workdir);
  if (c.status !== 0) throw new Error(`commit failed (is git user.name/user.email set?): ${c.stderr}`);
  const t = git(["tag", "-a", tag, "-m", `${tag}\n\n${o.notes}`], o.workdir);
  if (t.status !== 0) throw new Error(`tag failed: ${t.stderr}`);
  const commit = String(git(["rev-parse", "HEAD"], o.workdir).stdout).trim();
  // Never force: a rejected push means the remote moved, and a human should look.
  const push = (args: string[]) => git(["push", ...(o.push ? [] : ["--dry-run"]), ...args], o.workdir, { stdio: "inherit" });
  if (push(["-u", "origin", "main"]).status !== 0) throw new Error("git push of main failed");
  if (push(["origin", tag]).status !== 0) throw new Error(`git push of ${tag} failed`);
  return { created: !exists, commit };
}

export const isDir = (p: string) => existsSync(p) && statSync(p).isDirectory();
