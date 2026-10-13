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
  /^packages\/(spec|core|auth|verify)\//,
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
  // The decision-record linter and its tests are the project's own process tooling; the public spec package has its own test file.
  /^packages\/spec\/src\/decisions\.ts$/,
  /^packages\/spec\/test\/(spec|decisions)\.test\.ts$/,
];
export const shippable = (path: string) => ALLOW.some((r) => r.test(path)) && !DENY.some((r) => r.test(path));

/** Internal-roadmap file names become neutral ones in the export. */
export const RENAMES: Record<string, string> = {
  "scripts/verify-kernel.ts": "scripts/verify-demo.ts",
  "packages/core/test/kernel.test.ts": "packages/core/test/api-and-tenant.test.ts",
};

// --- Exact text fixes. Each must match exactly once, or the export aborts; a stale fix is never silently skipped. ---
export interface Fix { file: string; find: string; replace: string }
export const FIXES: Fix[] = [
  { file: "packages/auth/src/routes.ts", find: "Phase 6 provisioning will create owners directly; until then this is the only way in.", replace: "Tenant provisioning (planned) will create owners directly; until then this is the only way in." },
  { file: "packages/core/src/tenant/types.ts", find: "Development stopgap until Phase 6 provisioning.", replace: "Development stopgap until tenant provisioning exists." },
  { file: "packages/core/src/api/app.ts", find: "Plan entitlements arrive in Phase 5.", replace: "Plan entitlements are planned." },
  { file: "packages/spec/src/types.ts", find: "The scenario is written in Phase 1+.", replace: "The scenario is written as the rule is verified." },
  { file: "packages/spec/src/formats.ts", find: "arrive in Phase 1+.", replace: "are planned." },
  { file: "packages/spec/src/rules.ts", find: " (Phase 1+).", replace: "." },
  { file: "examples/demo-app/scripts/manifest.ts", find: "which CODEOWNERS routes to the owner (ROUTE-3)", replace: "so that review can see it" },
  { file: "packages/verify/src/oracles.ts", find: "Phase 1 implements the three the probes need; metamorphic and state land with their packs.", replace: "Three are implemented today because the probes need them; metamorphic and state land with their packs." },
  { file: "packages/verify/test/verify.test.ts", find: " (Phase 1 gate)", replace: "" },
  { file: "scripts/verify-demo.ts", find: "// Phase 2 gate harness:", replace: "// Gate harness:" },
  // The event-log viewer is internal tooling and does not ship, so its workspace entry leaves the lockfile too.
  { file: "pnpm-lock.yaml", find: "  packages/plane:\n    dependencies:\n      '@kalahroudi/bulkhead-spec':\n        specifier: workspace:*\n        version: link:../spec\n    devDependencies:\n      '@kalahroudi/bulkhead-verify':\n        specifier: workspace:*\n        version: link:../verify\n\n", replace: "" },
  { file: "packages/spec/src/formats.ts", find: "Signature by the human key on accepted records.", replace: "Signature on accepted records." },
  { file: "packages/spec/src/formats.ts", find: "/** Signature by the human key. */", replace: "/** Signature. */" },
  { file: "packages/verify/test/verify.test.ts", find: '["TENANT-9"]', replace: '["NOSUCH-9"]' },
  { file: "packages/verify/src/targets.ts", find: "// VERIFY-5: only loopback", replace: "// Only loopback" },
  // The public spec package: rule catalog, classification, findings and the event log. Decision records, attestations and
  // agent or review events are the project's own workflow and do not ship.
  { file: "packages/spec/src/index.ts", find: 'export { CHECK_KINDS, decisionItems, lintDecisionRecord, type DecisionItem } from "./decisions.ts";\n', replace: "" },
  { file: "packages/spec/src/formats.ts", find: "// Format definitions: data classification, decision records, attestations, events.", replace: "// Format definitions: data classification, findings, events." },
  { file: "packages/spec/src/formats.ts", find: 'export const EVENT_TYPES = [\n  "commit.scan",\n  "verify.run",\n  "finding.recorded",\n  "review.requested",\n  "review.signed",\n  "agent.blocked",\n  "agent.question",\n  "fleet.run",\n  "attestation.issued",\n  "deploy.checked",\n] as const;', replace: 'export const EVENT_TYPES = ["verify.run", "finding.recorded"] as const;' },
  { file: "packages/spec/src/formats.ts", find: "e.g. `verify`, `cli`, `hook`.", replace: "e.g. `verify`." },
  { file: "packages/spec/src/types.ts", find: "contract: changes by proposal and human sign-off. default: agents may change freely.", replace: "contract: changes only by an explicit proposal. default: may change freely." },
  { file: "packages/spec/src/types.ts", find: "The check is approved before the implementation exists.", replace: "A rule's check exists before its implementation." },
  { file: "packages/spec/src/types.ts", find: "/** Which of the nine principles a rule serves (1-9, see the architecture document). */\nexport type Principle = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9;\n\n", replace: "" },
  { file: "packages/spec/src/types.ts", find: "  principle: Principle;\n", replace: "" },
  { file: "packages/spec/src/types.ts", find: " An attestation names the spec version it was issued against.", replace: "" },
  { file: "packages/spec/src/lint.ts", find: '    if (!Number.isInteger(r.principle) || r.principle < 1 || r.principle > 9) add(r.id, "bad-principle", "principle must be 1-9");\n', replace: "" },
  { file: "packages/spec/src/rules.ts", find: "Commit-tier route manifest check;", replace: "Route manifest check;" },
  { file: "packages/spec/README.md", find: "data-classification and decision-record formats, and linters (`lintSpec`, `lintDecisionRecord`).", replace: "data-classification, finding and event-log formats, and a linter (`lintSpec`)." },
  { file: "packages/core/src/tenant/directory.ts", find: "arrive in later phases (TENANT-3).", replace: "arrive later (TENANT-3)." },
  { file: ".gitignore", find: "\n.commandcode/", replace: "" },
  { file: "packages/verify/src/run.ts", find: "/** VERIFY-3: the run is invalid", replace: "/** The run is invalid" },
  { file: "packages/spec/src/formats.ts", find: " (GATE-1).", replace: "." },
  { file: "packages/spec/src/formats.ts", find: "honest-limits statement (SPEC-4).", replace: "honest-limits statement." },
  { file: "packages/spec/src/formats.ts", find: "all seeded bugs found (VERIFY-3)", replace: "all seeded bugs found" },
  { file: "packages/spec/src/formats.ts", find: "open confirmed findings (VERIFY-6)", replace: "open confirmed findings" },
  { file: "packages/spec/src/formats.ts", find: "A human may reject one with a reason; it keeps its reproduction (VERIFY-2).", replace: "A finding may be rejected with a reason; it keeps its reproduction." },
  { file: "packages/spec/src/formats.ts", find: "Unsigned producers are untrusted (PLANE-2).", replace: "Unsigned producers are untrusted." },
  { file: "packages/spec/src/formats.ts", find: "(unsigned events are untrusted, PLANE-2)", replace: "(unsigned events are untrusted)" },
];

// --- The public rule catalog: product guarantees only. How the project is built, attested and supervised stays private. ---
const CATALOG_FILE = "packages/spec/src/rules.ts";
/** Rewrites ROUTE-3 as a product guarantee, drops every rule from the Verify section to the end, and removes the internal `principle` field. */
export function publicCatalog(text: string): string {
  const swap = (from: string, to: string, replacement: string, what: string) => {
    const a = text.indexOf(from);
    const b = text.indexOf(to, a + from.length);
    if (a < 0 || b < 0 || text.indexOf(from, a + 1) >= 0) throw new Error(`rule catalog layout changed: cannot find ${what} exactly once`);
    text = text.slice(0, a) + replacement + text.slice(b);
  };
  swap('  {\n    id: "ROUTE-3",', '  {\n    id: "ROUTE-4",', `  {
    id: "ROUTE-3",
    statement: "Lowering a route's policy is a visible change to the committed route manifest.",
    reason: "A weakened policy must not slip in unnoticed.",
    enforcement: "The route manifest is committed; any policy change changes it, so review sees it.",
    tier: "invariant",
    oracle: "spec",
    scenario: "api/lowered-policy-needs-review",
  },
`, "the ROUTE-3 block");
  swap("  // --- Verify ---", "];\n\nexport const SPEC_VERSION", "", "the Verify..Plane sections");
  text = text.replace(/^\s+principle: \d,\n/gm, "");
  if (/principle/.test(text)) throw new Error("rule catalog still mentions principle after the cut");
  return text;
}
export const publicRuleIds = (rulesText: string) => new Set([...rulesText.matchAll(/^\s+id: "([A-Z]+-\d+)"/gm)].map((m) => m[1] as string));
const RULE_REF = /\b(TENANT|ROUTE|AUTH|CRYPTO|BOOT|BILL|DOMAIN|HTTP|LIFE|VERIFY|GATE|SPEC|PLANE)-\d+\b/g;

// --- Leak scan: anything that points at the private repo, its records, its docs, or how it is built. ---
export const LEAK_PATTERNS: [string, RegExp][] = [
  ["private doc or path", /docs\/decisions|SPEC\.md|CLAUDE\.md|AGENTS\.md|FROZEN_PATHS/],
  ["private decision record id", /\bDR-(?!9\d{3}\b)\d{4}\b/],
  ["roadmap phase reference", /\bPhase \d/],
  ["private repository url", /kalahroudi\/bulkhead(?![-\w])/],
  ["agent or session provenance", /claude|anthropic|Co-Authored-By|Claude-Session|attacker session/i],
  ["personal address", /bermouda/i],
  ["unfinished owner todo", /TODO\(owner\)/],
  ["internal process wording", /development plane|agent[- ]harness|signed human review|human key|human sign-off|keychain|frozen path|architecture document|\bfleet\b|attestation|commandcode/i],
  ["private gate or roadmap name", /gate:phase\d|\bkernel\b/i],
  ["agent wording", /\bagents?\b(?!\s+header)/i],
];
/** File and directory names that point at the private build, checked as paths too. */
export const PATH_PATTERNS: [string, RegExp][] = [["private-build file name", /kernel|phase\d|decision|attest|mutation|plane|SPEC\.md|\.commandcode/i]];
const TEXT = /\.(ts|js|json|jsonc|md|yml|yaml|html|css|txt|toml)$|(^|\/)(\.gitignore|LICENSE)$/;

export function scanForLeaks(dir: string): string[] {
  const hits: string[] = [];
  const catalog = join(dir, CATALOG_FILE);
  const known = existsSync(catalog) ? publicRuleIds(readFileSync(catalog, "utf8")) : null;
  for (const file of walk(dir)) {
    const rel = relative(dir, file);
    for (const [why, re] of PATH_PATTERNS) if (re.test(rel)) hits.push(`${rel} [${why}]`);
    if (/(^|\/)(pnpm-lock\.yaml)$/.test(rel) || !TEXT.test(rel)) continue;
    const lines = readFileSync(file, "utf8").split("\n");
    lines.forEach((line, i) => {
      for (const [why, re] of LEAK_PATTERNS) if (re.test(line)) hits.push(`${rel}:${i + 1} [${why}] ${line.trim().slice(0, 140)}`);
      // A shipped file may only cite rules that exist in the public catalog; anything else points at the private spec.
      if (known && rel !== CATALOG_FILE)
        for (const m of line.matchAll(RULE_REF)) if (!known.has(m[0])) hits.push(`${rel}:${i + 1} [rule id not in the public catalog] ${m[0]}`);
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
  for (const f of files) { const to = RENAMES[f] ?? f; mkdirSync(dirname(join(out, to)), { recursive: true }); cpSync(join(root, f), join(out, to)); }

  for (const fix of FIXES) {
    const p = join(out, fix.file);
    if (!existsSync(p)) throw new Error(`fix targets a file that is not exported: ${fix.file}`);
    const text = readFileSync(p, "utf8");
    const hits = text.split(fix.find).length - 1;
    if (hits !== 1) throw new Error(`fix for ${fix.file} matched ${hits} time(s), must be exactly 1: ${fix.find}`);
    writeFileSync(p, text.replace(fix.find, () => fix.replace));
  }

  // formats.ts: the decision-record and attestation formats are the project's own workflow and do not ship.
  const formatsPath = join(out, "packages/spec/src/formats.ts");
  const formats = readFileSync(formatsPath, "utf8");
  const from = formats.indexOf("// --- Decision record ---");
  const to = formats.indexOf("// --- Findings ---");
  if (from < 0 || to < from || formats.indexOf("// --- Decision record ---", from + 1) >= 0) throw new Error("formats.ts layout changed: cannot find the decision-record..attestation sections exactly once");
  writeFileSync(formatsPath, formats.slice(0, from) + formats.slice(to));

  const catalogPath = join(out, CATALOG_FILE);
  writeFileSync(catalogPath, publicCatalog(readFileSync(catalogPath, "utf8")));

  // The private repo's own URL becomes the public one everywhere it is written out in full.
  for (const file of walk(out)) {
    if (!TEXT.test(relative(out, file))) continue;
    const text = readFileSync(file, "utf8");
    if (text.includes(PRIVATE_URL)) writeFileSync(file, text.split(PRIVATE_URL).join(PUBLIC_URL));
  }

  // package.json files: release version, public URLs, and scripts that only make sense in the private repo removed.
  for (const dir of [...PACKAGES.map((p) => p.dir), "examples/demo-app", "."]) {
    const p = join(out, dir, "package.json");
    if (!existsSync(p)) continue;
    const j = JSON.parse(readFileSync(p, "utf8"));
    if (PACKAGES.some((x) => x.dir === dir)) {
      j.version = version;
      j.homepage = `${PUBLIC_URL}#readme`;
      j.bugs = { url: `${PUBLIC_URL}/issues` };
      j.repository = { type: "git", url: `git+${PUBLIC_URL}.git`, directory: dir };
      j.publishConfig = { ...j.publishConfig, tag: npmTag(version) };
    }
    if (dir === "packages/spec") { j.scripts = { typecheck: j.scripts.typecheck, test: j.scripts.test, lint: "node scripts/lint-spec.ts", build: j.scripts.build, prepack: j.scripts.prepack }; }
    if (dir === "packages/verify" && j.exports) delete j.exports["./mutations"];
    if (dir === ".") {
      j.name = "bulkhead-monorepo";
      j.scripts = {
        typecheck: "pnpm -r typecheck",
        test: "pnpm -r test",
        build: "pnpm -r --filter './packages/*' build",
        gate: "pnpm typecheck && pnpm test && pnpm --filter @kalahroudi/bulkhead-spec lint && pnpm --filter @kalahroudi/bulkhead-verify selfcheck && pnpm --filter bulkhead-demo-app manifest:check && node scripts/verify-demo.ts --rules TENANT-1,TENANT-4,TENANT-5,AUTH-1,AUTH-2,AUTH-3,AUTH-4",
        "gate:release": "pnpm gate && node scripts/consumer-test.ts",
      };
    }
    writeFileSync(p, JSON.stringify(j, null, 2) + "\n");
  }

  // Templates: public-facing files that replace the private repo's versions (or have none).
  const copyTree = (from: string, to: string) => { if (existsSync(from)) cpSync(from, to, { recursive: true }); };
  copyTree(join(templates, "templates/spec.test.ts"), join(out, "packages/spec/test/spec.test.ts"));
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
// Strict semver (no leading zeros, no empty identifiers, no build metadata), because the version becomes a git tag and an npm version.
const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?$/;
const TAG_ID = /^[a-z][a-z0-9-]*$/;
export const validVersion = (v: string) => SEMVER.test(v) && (!v.includes("-") || npmTagOrNull(v) !== null);
function npmTagOrNull(v: string): string | null {
  if (!v.includes("-")) return "latest";
  const id = (v.split("-")[1] as string).split(".")[0] as string;
  // A dist-tag must not look like a version or a range, and a prerelease must never land on `latest`.
  return TAG_ID.test(id) && id !== "latest" ? id : null;
}
/** `1.2.3` -> latest; `0.1.0-preview.2` -> preview; `1.0.0-rc.1` -> rc. Throws for a prerelease that cannot be a safe dist-tag. */
export function npmTag(v: string): string {
  const t = npmTagOrNull(v);
  if (!t) throw new Error(`the prerelease label of ${v} cannot be an npm dist-tag (use a lowercase word such as preview or rc)`);
  return t;
}

/** Hides credentials embedded in a remote URL before it is printed or put in an error. */
export const redact = (s: string) => s.replace(/\/\/[^/@\s]+@/g, "//***@");

// --- Git identity: the public history must carry the releaser's own name, never a tool's. ---
export interface Identity { name: string; email: string }
const AGENT_IDENTITY = /claude|anthropic|noreply@anthropic/i;
export function resolveIdentity(author: string | undefined, read: (key: string) => string = (k) => String(git(["config", "--get", k], process.cwd()).stdout).trim()): Identity {
  let name: string, email: string;
  if (author) {
    const m = /^\s*(.+?)\s*<([^<>\s]+@[^<>\s]+)>\s*$/.exec(author);
    if (!m) throw new Error('--author must look like "Your Name <you@example.com>"');
    [name, email] = [m[1] as string, m[2] as string];
  } else {
    [name, email] = [read("user.name"), read("user.email")];
    if (!name || !email) throw new Error("git user.name and user.email are not set; set them or pass --author \"Your Name <you@example.com>\"");
  }
  if (AGENT_IDENTITY.test(name) || AGENT_IDENTITY.test(email)) throw new Error(`the git identity "${name} <${email}>" is a tool identity; pass --author "Your Name <you@example.com>" so the public history carries yours`);
  return { name, email };
}
const identityEnv = (id: Identity) => ({ ...process.env, GIT_AUTHOR_NAME: id.name, GIT_AUTHOR_EMAIL: id.email, GIT_COMMITTER_NAME: id.name, GIT_COMMITTER_EMAIL: id.email, GIT_TERMINAL_PROMPT: process.env.GIT_TERMINAL_PROMPT ?? "1" });

// --- Git: publish the export to the public repo, creating `main` when the remote has none. ---
export const RELEASE_MARKER = "Release-Tool: bulkhead-release";
export interface PublishGitOptions { exportDir: string; remote: string; version: string; notes: string; push: boolean; workdir: string; identity: Identity; adopt?: boolean; noSign?: boolean }

function lsRemote(remote: string, ref: string): boolean {
  const r = git(["ls-remote", remote, ref], process.cwd());
  if (r.status !== 0) throw new Error(`cannot reach ${redact(remote)}: ${redact(String(r.stderr).trim())}`);
  // Exact match only: a pattern like `main` also matches `feature/main`.
  return String(r.stdout).split("\n").some((l) => l.split("\t")[1] === ref);
}
export const remoteHasBranch = (remote: string, branch: string) => lsRemote(remote, `refs/heads/${branch}`);
export const remoteHasTag = (remote: string, tag: string) => lsRemote(remote, `refs/tags/${tag}`);

/** Git tree id of a directory's content, independent of any repository. */
export function treeHash(dir: string): string {
  const tmp = join(dir, "..", `.treehash-${process.pid}-${Date.now()}`);
  mkdirSync(tmp, { recursive: true });
  try {
    cpSync(dir, join(tmp, "t"), { recursive: true, filter: (src) => !/(^|\/)\.git$/.test(src) });
    const w = join(tmp, "t");
    git(["init", "--quiet"], w);
    git(["add", "-A"], w, { env: { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" } });
    return String(git(["write-tree"], w).stdout).trim();
  } finally { rmSync(tmp, { recursive: true, force: true }); }
}

/** After a partial release: the tag on the public repo must hold exactly the tree we are about to publish to npm. */
export function verifyTagMatchesExport(remote: string, tag: string, exportDir: string, workdir: string): void {
  if (!remoteHasTag(remote, tag)) throw new Error(`${tag} does not exist on ${redact(remote)}; run without --skip-git first`);
  rmSync(workdir, { recursive: true, force: true });
  const c = git(["clone", "--quiet", "--depth", "1", "--branch", tag, remote, workdir], process.cwd());
  if (c.status !== 0) throw new Error(`clone of ${tag} failed: ${redact(String(c.stderr))}`);
  const tagged = String(git(["rev-parse", "HEAD^{tree}"], workdir).stdout).trim();
  if (tagged !== treeHash(exportDir)) throw new Error(`the export from this checkout differs from what ${tag} holds on the public repo; publish from the commit that was tagged, not from here`);
}

export function commitToPublicRepo(o: PublishGitOptions): { created: boolean; commit: string; removed: string[] } {
  const tag = `v${o.version}`;
  if (remoteHasTag(o.remote, tag)) throw new Error(`the tag ${tag} already exists on ${redact(o.remote)}; pick a new version`);
  const exists = remoteHasBranch(o.remote, "main");
  const env = identityEnv(o.identity);
  rmSync(o.workdir, { recursive: true, force: true });
  let removed: string[] = [];
  if (exists) {
    const c = git(["clone", "--quiet", "--branch", "main", o.remote, o.workdir], process.cwd());
    if (c.status !== 0) throw new Error(`clone failed: ${redact(String(c.stderr))}`);
    const last = String(git(["log", "-1", "--format=%B"], o.workdir).stdout);
    const existing = String(git(["ls-files"], o.workdir).stdout).split("\n").filter(Boolean);
    const incoming = new Set(walk(o.exportDir).map((f) => relative(o.exportDir, f)));
    removed = existing.filter((f) => !incoming.has(f));
    // `main` is replaced wholesale, so refuse to do that to history this tool did not write.
    if (!last.includes(RELEASE_MARKER) && !o.adopt) throw new Error(`main already exists on ${redact(o.remote)} and was not created by this tool; it would be REPLACED (${removed.length} existing file(s) removed). Review it, then rerun with --adopt-existing if that is intended`);
    for (const e of readdirSync(o.workdir)) if (e !== ".git") rmSync(join(o.workdir, e), { recursive: true, force: true });
  } else {
    mkdirSync(o.workdir, { recursive: true });
    for (const args of [["init", "--quiet", "-b", "main"], ["remote", "add", "origin", o.remote]]) {
      const r = git(args, o.workdir);
      if (r.status !== 0) throw new Error(`git ${args[0]} failed: ${redact(String(r.stderr))}`);
    }
  }
  cpSync(o.exportDir, o.workdir, { recursive: true, filter: (src) => !/(^|\/)\.git$/.test(src) });
  git(["add", "-A"], o.workdir, { env });
  if (exists && git(["diff", "--cached", "--quiet"], o.workdir).status === 0) throw new Error("the public repo already has exactly this content; nothing to release");
  const sign = o.noSign ? ["-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"] : [];
  const message = `${exists ? "Release" : "Initial release"} ${tag}\n\n${o.notes}\n\n${RELEASE_MARKER}\n`;
  const c = git([...sign, "commit", "--quiet", "-m", message], o.workdir, { env });
  if (c.status !== 0) throw new Error(`commit failed: ${String(c.stderr)}`);
  const t = git([...sign, "tag", "-a", tag, "-m", `${tag}\n\n${o.notes}`], o.workdir, { env });
  if (t.status !== 0) throw new Error(`tag failed: ${String(t.stderr)}`);
  const commit = String(git(["rev-parse", "HEAD"], o.workdir).stdout).trim();
  if (String(git(["rev-parse", "HEAD^{tree}"], o.workdir).stdout).trim() !== treeHash(o.exportDir)) throw new Error("internal check failed: the commit tree differs from the export");
  // One atomic push of the branch and the tag together: either both land or neither does. Never forced.
  const push = git(["push", "--atomic", ...(o.push ? [] : ["--dry-run"]), ...(exists ? [] : ["-u"]), "origin", "main", `refs/tags/${tag}`], o.workdir, { stdio: "inherit", env });
  if (push.status !== 0) throw new Error("git push failed (nothing was force-pushed)");
  return { created: !exists, commit, removed };
}

// --- Tarballs: what npm will actually serve, checked as files and not only as a source tree. ---
export function tarballManifest(tgz: string): { name: string; version: string; publishConfig?: { tag?: string } } {
  const r = spawnSync("tar", ["-xzOf", tgz, "package/package.json"], { encoding: "utf8" });
  if (r.status !== 0) throw new Error(`cannot read ${tgz}`);
  return JSON.parse(r.stdout);
}
export function scanTarball(tgz: string, scratch: string): string[] {
  const dir = join(scratch, `tar-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(dir, { recursive: true });
  try {
    if (spawnSync("tar", ["-xzf", tgz, "-C", dir], { encoding: "utf8" }).status !== 0) return [`${tgz}: cannot extract`];
    const hits = walk(dir).map((f) => relative(join(dir, "package"), f)).filter((f) => !/^(dist\/|README\.md$|LICENSE$|package\.json$)/.test(f)).map((f) => `${f} [file that should not ship in a tarball]`);
    return [...hits, ...scanForLeaks(dir)];
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

export const isDir = (p: string) => existsSync(p) && statSync(p).isDirectory();
