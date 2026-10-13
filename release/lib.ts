// Everything the public release does, as functions, so scripts/release.ts runs it and scripts/release-selftest.ts proves it can fail.
// The public repo is a separate, clean export: an allowlist of files, exact text fixes, templates, a leak scan, then git and npm.
import { spawnSync, type SpawnSyncOptions } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
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
  { file: "packages/spec/src/formats.ts", find: " Hashing, signing and chain verification arrive in Phase 1+.", replace: "" },
  { file: "packages/spec/src/rules.ts", find: " (Phase 1+).", replace: "." },
  { file: "examples/demo-app/scripts/manifest.ts", find: "which CODEOWNERS routes to the owner (ROUTE-3)", replace: "so that review can see it" },
  { file: "packages/verify/src/oracles.ts", find: " Phase 1 implements the three the probes need; metamorphic and state land with their packs.", replace: "" },
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
  { file: "packages/spec/src/formats.ts", find: "// Format definitions: data classification, decision records, attestations, events.", replace: "// Format definitions: findings and events." },
  { file: "packages/spec/src/formats.ts", find: 'export const EVENT_TYPES = [\n  "commit.scan",\n  "verify.run",\n  "finding.recorded",\n  "review.requested",\n  "review.signed",\n  "agent.blocked",\n  "agent.question",\n  "fleet.run",\n  "attestation.issued",\n  "deploy.checked",\n] as const;', replace: 'export const EVENT_TYPES = ["verify.run", "finding.recorded"] as const;' },
  { file: "packages/spec/src/formats.ts", find: "e.g. `verify`, `cli`, `hook`.", replace: "e.g. `verify`." },
  { file: "packages/spec/src/types.ts", find: "contract: changes by proposal and human sign-off. default: agents may change freely.", replace: "contract: changes only by an explicit proposal. default: may change freely." },
  { file: "packages/spec/src/types.ts", find: "The check is approved before the implementation exists.", replace: "A rule's check exists before its implementation." },
  { file: "packages/spec/src/types.ts", find: "/** Which of the nine principles a rule serves (1-9, see the architecture document). */\nexport type Principle = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9;\n\n", replace: "" },
  { file: "packages/spec/src/types.ts", find: "  principle: Principle;\n", replace: "" },
  { file: "packages/spec/src/types.ts", find: " An attestation names the spec version it was issued against.", replace: "" },
  { file: "packages/spec/src/lint.ts", find: '    if (!Number.isInteger(r.principle) || r.principle < 1 || r.principle > 9) add(r.id, "bad-principle", "principle must be 1-9");\n', replace: "" },
  { file: "packages/spec/src/rules.ts", find: "Commit-tier route manifest check;", replace: "Route manifest check;" },
  { file: "packages/spec/src/rules.ts", find: "Verify session and cookie scenario pack.", replace: "Verify session and cookie scenarios." },
  { file: "packages/spec/src/rules.ts", find: "Verify token scope scenarios and storage inspector.", replace: "Verify token scope scenarios." },
  { file: "packages/spec/src/rules.ts", find: "Verify messaging pack: forged, replayed and out-of-order deliveries.", replace: "Verify scenarios: forged, replayed and out-of-order deliveries." },
  { file: "packages/spec/src/types.ts", find: "startup check, hook, or verify scenario.", replace: "startup check, or verify scenario." },
  { file: "packages/spec/src/formats.ts", find: "Permanent regression scenario (`RS-NNNN`) created when a finding is confirmed.", replace: "Identifier of the regression scenario for a confirmed finding (`RS-NNNN`)." },
  { file: "scripts/build-package.ts", find: "  // The mutation catalog names repo-internal paths and is only used by the repo's own gate, so it is not published.\n  exclude: includeFixture ? [\"src/mutations.ts\"] : [],\n", replace: "" },
  { file: "scripts/consumer-test.ts", find: "    check(!files.some((f) => /mutations\\.(js|d\\.ts)$/.test(f)), `${t.split(\"/\").pop()}: the repo-internal mutation catalog is not shipped`);\n", replace: "" },
  { file: "packages/spec/README.md", find: "data-classification and decision-record formats, and linters (`lintSpec`, `lintDecisionRecord`).", replace: "finding and event-log formats, and a linter (`lintSpec`)." },
  { file: "packages/core/src/tenant/directory.ts", find: " Domains and billing state arrive in later phases (TENANT-3).", replace: " See TENANT-3." },
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
export const UNBUILT_RULES = ["CRYPTO-1", "CRYPTO-2", "CRYPTO-3", "CRYPTO-4", "CRYPTO-5", "BILL-1", "BILL-3", "DOMAIN-1", "HTTP-1", "LIFE-1"];
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
  // Rules for features that do not exist yet are a roadmap, not a guarantee, so they do not ship either.
  for (const id of UNBUILT_RULES) {
    const marker = `  {\n    id: "${id}",`;
    const a = text.indexOf(marker);
    if (a < 0 || text.indexOf(marker, a + 1) >= 0) throw new Error(`rule catalog layout changed: cannot find ${id} exactly once`);
    const end = text.indexOf("\n  },\n", a);
    if (end < 0) throw new Error(`rule catalog layout changed: cannot find the end of ${id}`);
    text = text.slice(0, a) + text.slice(end + "\n  },\n".length);
  }
  text = text.replace(/^  \/\/ --- (Crypto and secrets|Domains and HTTP|Lifecycle) ---\n/gm, "");
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
  ["roadmap phase reference", /\bphase[ -]?\d/i],
  ["private repository url", /kalahroudi\/bulkhead(?![-\w])/],
  ["agent or session provenance", /claude|anthropic|Co-Authored-By|Claude-Session|attacker session/i],
  ["personal address", /bermouda/i],
  ["unfinished owner todo", /TODO\(owner\)/],
  ["internal process wording", /development plane|agent[- ]harness|signed human review|human key|human sign-off|keychain|frozen path|architecture document|\bfleet\b|attestation|commandcode/i],
  ["private gate or roadmap name", /gate:phase\d|\bkernel\b|\broadmap\b|decision records?|mutation (catalog|check)|human review/i],
  ["other tool or session provenance", /built with cursor|cursor\.(sh|com)|copilot|\bcodex\b|\bgemini\b|session_[0-9A-Za-z]{8,}/i],
  ["agent wording", /\bagents?\b(?!\s+header)/i],
];
/** File and directory names that point at the private build, checked as paths too. */
export const PATH_PATTERNS: [string, RegExp][] = [["private-build file name", /kernel|phase\d|decision|attest|mutation|plane|SPEC\.md|\.commandcode/i]];
const TEXT = /\.(ts|js|json|jsonc|md|yml|yaml|html|css|txt|toml)$|(^|\/)(\.gitignore|LICENSE)$/;

export function scanForLeaks(dir: string, catalogRel: string = CATALOG_FILE, knownOverride?: Set<string>): string[] {
  const hits: string[] = [];
  const catalog = join(dir, catalogRel);
  const known = knownOverride ?? (existsSync(catalog) ? publicRuleIds(readFileSync(catalog, "utf8")) : null);
  for (const file of walk(dir)) {
    const rel = relative(dir, file);
    for (const [why, re] of PATH_PATTERNS) if (re.test(rel)) hits.push(`${rel} [${why}]`);
    if (/(^|\/)(pnpm-lock\.yaml)$/.test(rel)) continue;
    const buf = readFileSync(file);
    // Deny by default: a file that cannot be read as text cannot be scanned, so it cannot ship.
    if (buf.includes(0)) { hits.push(`${rel} [binary file cannot be scanned]`); continue; }
    buf.toString("utf8").split("\n").forEach((line, i) => {
      for (const [why, re] of LEAK_PATTERNS) if (re.test(line)) hits.push(`${rel}:${i + 1} [${why}] ${line.trim().slice(0, 140)}`);
      // A shipped file may only cite rules that exist in the public catalog; anything else points at the private spec.
      if (known && rel !== catalogRel && !/(^|\/)rules\.(js|d\.ts)$/.test(rel))
        for (const m of line.matchAll(RULE_REF)) if (!known.has(m[0])) hits.push(`${rel}:${i + 1} [rule id not in the public catalog] ${m[0]}`);
    });
  }
  return hits;
}

export function walk(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.name === ".git" ? [] : e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)]));
}

// --- Export ---
// Variables that would point a git call at some other repository, object store, clock or program. Removed from every call.
const SCRUB = /^GIT_(DIR|WORK_TREE|INDEX_FILE|COMMON_DIR|OBJECT_DIRECTORY|ALTERNATE_OBJECT_DIRECTORIES|EXEC_PATH|NAMESPACE|AUTHOR_DATE|COMMITTER_DATE)$/;
export function git(args: string[], cwd: string, opts: SpawnSyncOptions = {}) {
  const env: NodeJS.ProcessEnv = { ...process.env, ...(opts.env ?? {}) };
  for (const k of Object.keys(env)) if (SCRUB.test(k)) delete env[k];
  return spawnSync("git", args, { cwd, encoding: "utf8", ...opts, env });
}
/** Isolation relies on GIT_CONFIG_GLOBAL, which needs git 2.32 or newer; on older git it would silently do nothing. */
export function gitVersionOk(): boolean {
  const m = /git version (\d+)\.(\d+)/.exec(String(git(["--version"], process.cwd()).stdout));
  return Boolean(m) && (Number(m![1]) > 2 || (Number(m![1]) === 2 && Number(m![2]) >= 32));
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

  // formats.ts: the classification format belongs to an unbuilt feature, and the decision-record and attestation formats are the
  // project's own workflow; none of them ship.
  const formatsPath = join(out, "packages/spec/src/formats.ts");
  const formats = readFileSync(formatsPath, "utf8");
  const from = formats.indexOf("// --- Data classification ---");
  const to = formats.indexOf("// --- Findings ---");
  if (from < 0 || to < from || formats.indexOf("// --- Data classification ---", from + 1) >= 0) throw new Error("formats.ts layout changed: cannot find the classification..attestation sections exactly once");
  writeFileSync(formatsPath, formats.slice(0, from) + formats.slice(to));

  const runPath = join(out, "packages/verify/src/run.ts");
  const run = readFileSync(runPath, "utf8");
  if (run.split('export const VERIFY_VERSION = "0.0.0";').length !== 2) throw new Error("run.ts layout changed: VERIFY_VERSION not found exactly once");
  writeFileSync(runPath, run.replace('export const VERIFY_VERSION = "0.0.0";', () => `export const VERIFY_VERSION = ${JSON.stringify(version)};`));

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
      j.engines = { node: ">=22" };
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


// --- Git identity: the public history must carry the releaser's own name, never a tool's. ---
export interface Identity { name: string; email: string }
const AGENT_IDENTITY = /claude|anthropic|copilot|cursor|codex|gemini|openai|chatgpt/i;
export function resolveIdentity(author: string | undefined, read: (key: string) => string = (k) => String(git(["config", "--get", k], process.cwd()).stdout).trim()): Identity {
  let name: string, email: string;
  if (author) {
    const m = /^\s*([^<>]+?)\s*<([^<>\s]+@[^<>\s]+)>\s*$/.exec(author);
    if (!m) throw new Error('--author must look like "Your Name <you@example.com>" (the name cannot contain < or >, which git strips)');
    [name, email] = [m[1] as string, m[2] as string];
  } else {
    [name, email] = [read("user.name"), read("user.email")];
    if (!name || !email) throw new Error("git user.name and user.email are not set; set them or pass --author \"Your Name <you@example.com>\"");
    if (/[<>]/.test(name)) throw new Error("git user.name contains < or >, which git strips; pass --author instead");
  }
  if (AGENT_IDENTITY.test(name) || AGENT_IDENTITY.test(email)) throw new Error(`the git identity "${name} <${email}>" is a tool identity; pass --author "Your Name <you@example.com>" so the public history carries yours`);
  return { name, email };
}

/** Hides credentials embedded in a remote URL before it is printed or put in an error. */
export const redact = (s: string) => s.replace(/\/\/[^/@\s]+@/g, "//***@");

/** The private repository can never be a release target, however its URL is spelled. */
export function refuseIfPrivateRemote(remote: string): void {
  const norm = remote.toLowerCase().replace(/^git\+/, "").replace(/\/\/[^/@]*@/, "//").replace(/^git@github\.com:/, "github.com/").replace(/^(https?|ssh|git):\/\//, "").replace(/\.git\/?$/, "").replace(/\/$/, "");
  if (/(^|\/)kalahroudi\/bulkhead$/.test(norm)) throw new Error("that remote is the private repository; the release script only ever publishes to the public one");
}

const EMPTY_XDG = mkdtempSync(join(tmpdir(), "bulkhead-empty-xdg-"));
/**
 * The environment for creating the public commit and tag. Unless the releaser opts into signing, nothing from the machine's git
 * configuration can reach them: no global or system config (no signing key, no template hooks, no commit-msg trailers), no user
 * ignore or attributes files, and the identity is set explicitly for author, committer and tagger.
 */
function releaseEnv(id: Identity, sign: boolean): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, GIT_AUTHOR_NAME: id.name, GIT_AUTHOR_EMAIL: id.email, GIT_COMMITTER_NAME: id.name, GIT_COMMITTER_EMAIL: id.email, GIT_TERMINAL_PROMPT: process.env.GIT_TERMINAL_PROMPT ?? "1" };
  if (!sign) {
    for (const k of Object.keys(env)) if (/^GIT_CONFIG/.test(k)) delete env[k];
    env.GIT_CONFIG_GLOBAL = "/dev/null"; env.GIT_CONFIG_NOSYSTEM = "1"; env.XDG_CONFIG_HOME = EMPTY_XDG;
  }
  return env;
}
const isolation = (sign: boolean) => ["-c", "core.hooksPath=/dev/null", "-c", "core.excludesFile=/dev/null", "-c", "core.attributesFile=/dev/null", "-c", "core.autocrlf=false", "-c", "core.fsmonitor=false", ...(sign ? [] : ["-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"])];

// --- Git: publish the export to the public repo, creating `main` when the remote has none. ---
export const RELEASE_MARKER = "Release-Tool: bulkhead-release";
export interface Snapshot { files: string[]; tree: string }
export interface PublishGitOptions { exportDir: string; snapshot: Snapshot; remote: string; version: string; notes: string; push: boolean; workdir: string; identity: Identity; adopt?: boolean; sign?: boolean }

function lsRemote(remote: string, ref: string): boolean {
  const r = git(["ls-remote", remote, ref], process.cwd());
  if (r.status !== 0) throw new Error(`cannot reach ${redact(remote)}: ${redact(String(r.stderr).trim())}`);
  // Exact match only: a pattern like `main` also matches `feature/main`.
  return String(r.stdout).split("\n").some((l) => l.split("\t")[1] === ref);
}
export const remoteHasBranch = (remote: string, branch: string) => lsRemote(remote, `refs/heads/${branch}`);
export const remoteHasTag = (remote: string, tag: string) => lsRemote(remote, `refs/tags/${tag}`);

const sortedUnique = (xs: string[]) => [...new Set(xs)].sort();
/** Git tree id of exactly these files, computed with the same isolation as the real commit. */
export function treeHashFiles(dir: string, files: string[]): string {
  const tmp = mkdtempSync(join(tmpdir(), "bulkhead-treehash-"));
  try {
    for (const f of files) { mkdirSync(dirname(join(tmp, f)), { recursive: true }); cpSync(join(dir, f), join(tmp, f)); }
    const env = releaseEnv({ name: "t", email: "t@t" }, false);
    const run = (args: string[]) => git([...isolation(false), ...args], tmp, { env });
    run(["init", "--quiet"]);
    run(["add", "-A", "-f"]);
    return String(run(["write-tree"]).stdout).trim();
  } finally { rmSync(tmp, { recursive: true, force: true }); }
}
/** What was scanned: the file list and tree of the export as built, taken before install and the gate can add anything. */
export function snapshot(dir: string): Snapshot {
  const files = sortedUnique(walk(dir).map((f) => relative(dir, f)));
  return { files, tree: treeHashFiles(dir, files) };
}

/** After a partial release: the tag on the public repo must hold exactly the tree we are about to publish to npm. */
export function verifyTagMatchesExport(remote: string, tag: string, tree: string, workdir: string): void {
  if (!remoteHasTag(remote, tag)) throw new Error(`${tag} does not exist on ${redact(remote)}; run without --skip-git first`);
  rmSync(workdir, { recursive: true, force: true });
  const c = git(["clone", "--quiet", "--depth", "1", "--branch", tag, remote, workdir], process.cwd());
  if (c.status !== 0) throw new Error(`clone of ${tag} failed: ${redact(String(c.stderr))}`);
  const tagged = String(git(["rev-parse", "HEAD^{tree}"], workdir).stdout).trim();
  if (tagged !== tree) throw new Error(`the export from this checkout differs from what ${tag} holds on the public repo; publish from the commit that was tagged, not from here`);
}

/** What publishing would do to the public repo, found out by looking and not by doing. Throws when `main` holds history this tool did not write. */
export interface PublicRepoPlan { exists: boolean; removed: string[]; foreign: string[] }
export function planPublicRepo(o: { files: string[]; remote: string; workdir: string; adopt?: boolean }): PublicRepoPlan {
  refuseIfPrivateRemote(o.remote);
  if (remoteHasTag(o.remote, "main")) throw new Error("the public repo has a tag named main, which makes the branch ambiguous; delete that tag first");
  if (!remoteHasBranch(o.remote, "main")) return { exists: false, removed: [], foreign: [] };
  const empty = join(o.workdir, "..", ".empty-template");
  mkdirSync(empty, { recursive: true });
  rmSync(o.workdir, { recursive: true, force: true });
  const c = git(["clone", "--quiet", "--template", empty, "--branch", "main", o.remote, o.workdir], process.cwd());
  if (c.status !== 0) throw new Error(`clone failed: ${redact(String(c.stderr))}`);
  const existing = String(git(["ls-files"], o.workdir).stdout).split("\n").filter(Boolean);
  const incoming = new Set(o.files);
  const removed = existing.filter((f) => !incoming.has(f));
  const lg = git(["log", "--format=%H%x1f%an <%ae>%x1f%cn <%ce>%x1f%s%x1f%B%x1e", "main"], o.workdir);
  if (lg.status !== 0) throw new Error(`cannot read the history of main: ${redact(String(lg.stderr))}`);
  const commits = String(lg.stdout).split("\x1e").map((x) => x.trim()).filter(Boolean).map((x) => x.split("\x1f"));
  // A commit counts as ours only if its message has the marker on a line of its own.
  const foreign = commits.filter((c) => !/^Release-Tool: bulkhead-release$/m.test(c[4] ?? ""));
  const label = (c: string[]) => `${(c[0] ?? "").slice(0, 9)} ${c[3]}`;
  if (foreign.length && !o.adopt)
    throw new Error(`main on ${redact(o.remote)} holds ${foreign.length} commit(s) this tool did not write (${foreign.slice(0, 5).map(label).join("; ")}). The public repo is a mirror: publishing REPLACES its contents and would remove ${removed.length} file(s)${removed.length ? ` (${removed.slice(0, 20).join(", ")}${removed.length > 20 ? ", ..." : ""})` : ""}. Review it, port anything worth keeping into the private repo, then rerun with --adopt-existing`);
  // Adopting keeps that history in the public repo, so it must pass the same checks as everything else.
  for (const c of commits) {
    const text = `${c[1]}\n${c[2]}\n${c[4]}`;
    const bad = AGENT_IDENTITY.test(`${c[1]} ${c[2]}`) ? "a tool identity" : LEAK_PATTERNS.find(([, re]) => re.test(text))?.[0];
    if (bad) throw new Error(`commit ${(c[0] ?? "").slice(0, 9)} on the public repo carries ${bad}; history cannot be rewritten by this tool, so clean it first`);
  }
  return { exists: true, removed, foreign: foreign.map(label) };
}

export function commitToPublicRepo(o: PublishGitOptions): { created: boolean; commit: string; removed: string[] } {
  refuseIfPrivateRemote(o.remote);
  if (!gitVersionOk()) throw new Error("git 2.32 or newer is required (config isolation depends on it)");
  const tag = `v${o.version}`;
  if (remoteHasTag(o.remote, tag)) throw new Error(`the tag ${tag} already exists on ${redact(o.remote)}; pick a new version (if an earlier run pushed it but npm publishing failed, rerun that command with --skip-git instead)`);
  const sign = Boolean(o.sign);
  const env = releaseEnv(o.identity, sign);
  const gi = (args: string[], cwd: string, extra: SpawnSyncOptions = {}) => git([...isolation(sign), ...args], cwd, { env, ...extra });
  const empty = join(o.workdir, "..", ".empty-template");
  mkdirSync(empty, { recursive: true });
  const plan = planPublicRepo({ files: o.snapshot.files, remote: o.remote, workdir: o.workdir, adopt: o.adopt });
  if (plan.exists) {
    for (const e of readdirSync(o.workdir)) if (e !== ".git") rmSync(join(o.workdir, e), { recursive: true, force: true });
  } else {
    rmSync(o.workdir, { recursive: true, force: true });
    mkdirSync(o.workdir, { recursive: true });
    for (const args of [["init", "--quiet", "--template", empty, "-b", "main"], ["remote", "add", "origin", o.remote]]) {
      const r = git(args, o.workdir);
      if (r.status !== 0) throw new Error(`git ${args[0]} failed: ${redact(String(r.stderr))}`);
    }
  }
  // Only the files that were scanned are copied, never the whole directory: install and the gate leave node_modules and logs behind.
  for (const f of o.snapshot.files) { mkdirSync(dirname(join(o.workdir, f)), { recursive: true }); cpSync(join(o.exportDir, f), join(o.workdir, f)); }
  const add = gi(["add", "-A", "-f"], o.workdir);
  if (add.status !== 0) throw new Error(`git add failed: ${redact(String(add.stderr))}`);
  const staged = sortedUnique(String(gi(["ls-files"], o.workdir).stdout).split("\n").filter(Boolean));
  if (JSON.stringify(staged) !== JSON.stringify(sortedUnique(o.snapshot.files))) throw new Error("the files staged for the public commit are not exactly the files that were scanned");
  const late = scanForLeaks(o.workdir);
  if (late.length) throw new Error(`the tree about to be committed contains private material (${late.length}): ${late.slice(0, 10).join("; ")}`);
  if (plan.exists && git(["diff", "--cached", "--quiet"], o.workdir).status === 0) throw new Error("the public repo already has exactly this content; nothing to release");
  const message = `${plan.exists ? "Release" : "Initial release"} ${tag}\n\n${o.notes}\n\n${RELEASE_MARKER}\n`;
  // -F with verbatim cleanup for both: `-m` would strip trailing spaces, collapse blank lines and drop every line that starts with `#`.
  const msgFile = join(o.workdir, ".git", "RELEASE_COMMITMSG");
  writeFileSync(msgFile, message);
  const c = gi(["commit", "--quiet", ...(sign ? ["-S"] : []), "-F", msgFile, "--cleanup=verbatim"], o.workdir);
  if (c.status !== 0) throw new Error(`commit failed: ${redact(String(c.stderr))}`);
  const tagFile = join(o.workdir, ".git", "RELEASE_TAGMSG");
  writeFileSync(tagFile, `${tag}\n\n${o.notes}\n`);
  const t = gi(["tag", sign ? "-s" : "-a", tag, "-F", tagFile, "--cleanup=verbatim"], o.workdir);
  if (t.status !== 0) throw new Error(`tag failed: ${redact(String(t.stderr))}`);
  const commit = String(git(["rev-parse", "HEAD"], o.workdir).stdout).trim();
  assertCleanObjects(o.workdir, tag, o.identity, sign, message);
  if (String(git(["rev-parse", "HEAD^{tree}"], o.workdir).stdout).trim() !== o.snapshot.tree) throw new Error("internal check failed: the commit tree differs from the scanned export");
  // One atomic push of the branch and the tag together: either both land or neither does. Never forced. The push uses the
  // releaser's own git configuration on purpose, because that is where their credentials live.
  const push = git(["push", "--atomic", ...(o.push ? [] : ["--dry-run"]), ...(plan.exists ? [] : ["-u"]), "origin", "main", `refs/tags/${tag}`], o.workdir, { stdio: "inherit", env: { ...process.env, GIT_TERMINAL_PROMPT: process.env.GIT_TERMINAL_PROMPT ?? "1" } });
  if (push.status !== 0) throw new Error("git push failed (nothing was force-pushed)");
  return { created: !plan.exists, commit, removed: plan.removed };
}

/** Reads the created commit and tag objects back and refuses to push if they carry anything but the releaser's identity, our message, and a signature only when one was asked for. */
export function assertCleanObjects(repo: string, tag: string, id: Identity, sign: boolean, message: string): void {
  const cat = (ref: string) => String(git(["cat-file", "-p", ref], repo).stdout);
  const commit = cat("HEAD");
  const who = `${id.name} <${id.email}>`;
  const line = (text: string, key: string) => text.split("\n").find((l) => l.startsWith(`${key} `))?.slice(key.length + 1).replace(/ \d+ [+-]\d{4}$/, "");
  if (line(commit, "author") !== who || line(commit, "committer") !== who) throw new Error(`the commit is not authored by ${who} (got author "${line(commit, "author")}", committer "${line(commit, "committer")}")`);
  const signed = /^gpgsig /m.test(commit);
  if (!sign && signed) throw new Error("the commit carries a signature, but signing was not requested");
  if (sign && !signed) throw new Error("signing was requested but the commit is not signed");
  const body = commit.slice(commit.indexOf("\n\n") + 2).replace(/^gpgsig[\s\S]*?-----END [A-Z ]+-----\n\n?/m, "");
  if (body.trim() !== message.trim()) throw new Error("the commit message differs from what was written (altered by a hook or template); refusing to push");
  const tagObj = cat(`refs/tags/${tag}`);
  if (line(tagObj, "tagger") !== who) throw new Error(`the tag is not by ${who} (got "${line(tagObj, "tagger")}")`);
  const tagSigned = /BEGIN (PGP|SSH) SIGNATURE/.test(tagObj);
  if (!sign && tagSigned) throw new Error("the tag carries a signature, but signing was not requested");
  if (sign && !tagSigned) throw new Error("signing was requested but the tag is not signed");
}

// --- Tarballs: what npm will actually serve, checked as files and not only as a source tree. ---
export function tarballManifest(tgz: string): { name: string; version: string; publishConfig?: { tag?: string } } {
  const r = spawnSync("tar", ["-xzOf", tgz, "package/package.json"], { encoding: "utf8" });
  if (r.status !== 0) throw new Error(`cannot read ${tgz}`);
  return JSON.parse(r.stdout);
}
/** The rule ids the spec tarball itself ships, so every other tarball can be checked against them. */
export function catalogIdsFromTarball(tgz: string): Set<string> {
  const r = spawnSync("tar", ["-xzOf", tgz, "package/dist/rules.js"], { encoding: "utf8" });
  if (r.status !== 0) throw new Error(`${tgz} has no dist/rules.js`);
  return publicRuleIds(r.stdout);
}
export function scanTarball(tgz: string, scratch: string, known?: Set<string>): string[] {
  const dir = join(scratch, `tar-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(dir, { recursive: true });
  try {
    if (spawnSync("tar", ["-xzf", tgz, "-C", dir], { encoding: "utf8" }).status !== 0) return [`${tgz}: cannot extract`];
    const hits = walk(dir).map((f) => relative(join(dir, "package"), f)).filter((f) => !/^(dist\/|README\.md$|LICENSE$|package\.json$)/.test(f)).map((f) => `${f} [file that should not ship in a tarball]`);
    return [...hits, ...scanForLeaks(dir, "package/dist/rules.js", known)];
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

export const isDir = (p: string) => existsSync(p) && statSync(p).isDirectory();
