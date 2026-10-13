// Release gate: proves the published packages work for a stranger. Packs the public packages, inspects the tarballs, installs
// them into a clean project outside the repo, typechecks and boots the README quickstart (extracted from README.md so the docs
// cannot drift), drives its HTTP flow in workerd, and runs the installed verifier's self-check.
import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { request } from "node:http";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = join(import.meta.dirname, "..");
const PUBLIC = ["spec", "core", "auth", "verify"];
let bad = 0;
const check = (ok: boolean, msg: string) => { console.log(`${ok ? "ok  " : "FAIL"} ${msg}`); if (!ok) bad++; };
const run = (cmd: string, args: string[], cwd: string, env: NodeJS.ProcessEnv = {}) =>
  spawnSync(cmd, args, { cwd, encoding: "utf8", env: { ...process.env, ...env }, timeout: 600_000 });

// wrangler is pinned to the version the repo already resolves; workers-types takes the range wrangler itself declares as its peer,
// which is the pair a stranger gets from `npm install -D wrangler @cloudflare/workers-types`.
const wranglerManifest = JSON.parse(readFileSync(join(root, "examples/demo-app/node_modules/wrangler/package.json"), "utf8")) as { version: string; peerDependencies?: Record<string, string> };
const wranglerSpec = `wrangler@${wranglerManifest.version}`;
const typesSpec = `@cloudflare/workers-types@${wranglerManifest.peerDependencies?.["@cloudflare/workers-types"] ?? "latest"}`;

const work = mkdtempSync(join(tmpdir(), "bulkhead-consumer-"));
let wrangler: ReturnType<typeof spawn> | undefined;
try {
  // 1. Build and pack, unless the release script hands over the exact tarballs it is about to publish.
  const tarballs: string[] = [];
  const given = process.env.CONSUMER_TARBALL_DIR;
  if (given) {
    for (const f of readdirSync(given).sort()) tarballs.push(join(given, f));
    check(true, `testing the ${tarballs.length} tarballs supplied in CONSUMER_TARBALL_DIR (the same files that get published)`);
  } else {
    mkdirSync(join(work, "tarballs"));
    for (const p of PUBLIC) {
      const dir = join(root, "packages", p);
      const b = run("pnpm", ["build"], dir);
      check(b.status === 0, `${p}: builds${b.status === 0 ? "" : `\n${b.stdout}${b.stderr}`}`);
      const pk = run("pnpm", ["pack", "--pack-destination", join(work, "tarballs")], dir);
      check(pk.status === 0, `${p}: packs${pk.status === 0 ? "" : `\n${pk.stdout}${pk.stderr}`}`);
    }
    for (const f of readdirSync(join(work, "tarballs"))) tarballs.push(join(work, "tarballs", f));
  }
  check(tarballs.length === PUBLIC.length, `${tarballs.length} tarballs to test`);

  const versions = new Set<string>();
  // 2. Tarball contents: only dist, README, LICENSE and package.json; the published manifest points at dist and has no workspace refs.
  for (const t of tarballs) {
    const files = run("tar", ["-tzf", t], work).stdout.split("\n").filter(Boolean).map((f) => f.replace(/^package\//, ""));
    const stray = files.filter((f) => !/^(dist\/|README\.md$|LICENSE$|package\.json$)/.test(f));
    check(stray.length === 0, `${t.split("/").pop()}: contains only dist, README, LICENSE, package.json${stray.length ? ` (stray: ${stray.slice(0, 5)})` : ""}`);
    check(files.some((f) => f === "README.md") && files.some((f) => f === "LICENSE"), `${t.split("/").pop()}: has README and LICENSE`);
    check(!files.some((f) => /\.ts$/.test(f) && !/\.d\.ts$/.test(f)), `${t.split("/").pop()}: no TypeScript source`);
    check(!files.some((f) => /mutations\.(js|d\.ts)$/.test(f)), `${t.split("/").pop()}: the repo-internal mutation catalog is not shipped`);
    const manifest = JSON.parse(run("tar", ["-xzOf", t, "package/package.json"], work).stdout);
    const text = JSON.stringify(manifest);
    const targets = Object.values(manifest.exports ?? {}).flatMap((e) => (typeof e === "string" ? [e] : Object.values(e as Record<string, string>))).concat(Object.values((manifest.bin ?? {}) as Record<string, string>));
    check(!text.includes("workspace:") && targets.length > 0 && targets.every((t) => t.startsWith("./dist/")), `${manifest.name}: no workspace refs, and every export and bin target is under ./dist/`);
    versions.add(manifest.version);
    // The dist-tag follows the version: `1.2.3` -> latest, `0.1.0-preview.2` -> preview, `1.0.0-rc.1` -> rc.
    const expectedTag = manifest.version.includes("-") ? manifest.version.split("-")[1].split(".")[0] : "latest";
    check(/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?$/.test(manifest.version) && manifest.license === "Apache-2.0" && manifest.publishConfig?.access === "public" && manifest.publishConfig?.tag === expectedTag && manifest.publishConfig?.exports === undefined, `${manifest.name}@${manifest.version}: valid version, Apache-2.0, publishes public under the "${expectedTag}" tag`);
  }

  check(versions.size === 1, `all packages carry one version (${[...versions].join(", ")})`);
  // 3. Install into a clean project.
  const app = join(work, "app");
  mkdirSync(join(app, "src"), { recursive: true });
  writeFileSync(join(app, "package.json"), JSON.stringify({ name: "consumer", private: true, type: "module" }));
  const install = run("npm", ["install", "--no-audit", "--no-fund", ...tarballs, wranglerSpec, typesSpec, "typescript@~5.9", "@types/node"], app);
  check(install.status === 0, `clean install of the tarballs${install.status === 0 ? "" : `\n${install.stderr.slice(-800)}`}`);
  if (install.status !== 0) throw new Error("install failed");

  // 4. The README quickstart, extracted verbatim.
  const readme = readFileSync(join(root, "README.md"), "utf8");
  const block = (lang: string) => new RegExp("```" + lang + "\\n([\\s\\S]*?)```").exec(readme)?.[1];
  const wranglerConfig = block("jsonc");
  const indexTs = block("ts");
  check(Boolean(wranglerConfig && indexTs), "README has the wrangler.jsonc and src/index.ts quickstart blocks");
  if (!wranglerConfig || !indexTs) throw new Error("quickstart blocks missing");
  writeFileSync(join(app, "wrangler.jsonc"), wranglerConfig);
  writeFileSync(join(app, "src/index.ts"), indexTs);
  writeFileSync(join(app, "tsconfig.json"), JSON.stringify({ compilerOptions: { target: "ES2023", module: "esnext", moduleResolution: "bundler", strict: true, noEmit: true, skipLibCheck: true, types: ["@cloudflare/workers-types"] }, include: ["src"] }));
  const tsc = run(join(app, "node_modules/.bin/tsc"), ["-p", "tsconfig.json"], app);
  check(tsc.status === 0, `quickstart typechecks against the published declarations${tsc.status === 0 ? "" : `\n${tsc.stdout.slice(-800)}`}`);

  // 5. Boot it in workerd and drive the real flow.
  const port: number = await new Promise((resolve) => { const s = createServer(); s.listen(0, "127.0.0.1", () => { const p = (s.address() as { port: number }).port; s.close(() => resolve(p)); }); });
  const TOKEN = "consumer-bootstrap-secret-0123456789abcdef";
  let log = "";
  wrangler = spawn(join(app, "node_modules/.bin/wrangler"), ["dev", "--local", "--ip", "127.0.0.1", "--port", String(port), "--persist-to", join(work, "state"), "--var", `BULKHEAD_BOOTSTRAP_TOKEN:${TOKEN}`], { cwd: app, env: { ...process.env, WRANGLER_SEND_METRICS: "false", CI: "1" }, stdio: ["ignore", "pipe", "pipe"] });
  wrangler.stdout?.on("data", (d) => (log += d)); wrangler.stderr?.on("data", (d) => (log += d));
  const http = (host: string, method: string, path: string, body?: unknown, cookie?: string) => new Promise<{ status: number; body: string; setCookie: string }>((resolve) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const headers: Record<string, string> = { host };
    if (data) { headers["content-type"] = "application/json"; headers["content-length"] = String(Buffer.byteLength(data)); }
    if (cookie) { headers.cookie = cookie; headers.origin = `http://${host}`; }
    const req = request({ host: "127.0.0.1", port, path, method, headers }, (res) => { let t = ""; res.on("data", (d) => (t += d)); res.on("end", () => resolve({ status: res.statusCode ?? 0, body: t, setCookie: String(res.headers["set-cookie"] ?? "") })); });
    req.on("error", () => resolve({ status: 0, body: "", setCookie: "" })); if (data) req.write(data); req.end();
  });
  const deadline = Date.now() + 120_000;
  while ((await http("ready.localhost", "GET", "/notes")).status === 0) {
    if (Date.now() > deadline || wrangler.exitCode !== null) throw new Error(`quickstart did not boot:\n${log.slice(-1200)}`);
    await new Promise((r) => setTimeout(r, 500));
  }
  const h = "acme.localhost";
  const pw = "correct horse battery";
  check((await http(h, "GET", "/notes")).status === 401, "quickstart: a route with a role refuses an unauthenticated request (401)");
  check((await http(h, "POST", "/auth/bootstrap", { token: "wrong", email: "o@x.io", password: pw })).status === 403, "quickstart: bootstrap refuses a wrong token (403)");
  check((await http(h, "POST", "/auth/bootstrap", { token: TOKEN, email: "o@x.io", password: pw })).status === 201, "quickstart: bootstrap with the secret creates the first owner (201)");
  const login = await http(h, "POST", "/auth/login", { email: "o@x.io", password: pw });
  const cookie = /(__Host-bk_session=[^;]+)/.exec(login.setCookie)?.[1];
  check(login.status === 200 && Boolean(cookie), "quickstart: login returns a session cookie (200)");
  const notes = await http(h, "GET", "/notes", undefined, cookie);
  check(notes.status === 200 && notes.body.includes('"notes"'), "quickstart: the session reaches the protected route (200)");
  check((await http("other.localhost", "GET", "/notes", undefined, cookie)).status === 401, "quickstart: the same cookie is useless on another tenant's hostname (401)");
  check((await http("nope.example.com", "GET", "/notes")).status === 404, "quickstart: an unknown host is indistinguishable from an unknown route (404)");

  // 6. The installed verifier runs its self-check from node_modules.
  const sc = run(process.execPath, [join(app, "node_modules/@kalahroudi/bulkhead-verify/dist/src/cli.js"), "selfcheck", "--log-dir", join(work, "log")], app);
  check(sc.status === 0 && /Oracle healthy/.test(sc.stdout), `installed verifier: selfcheck passes${sc.status === 0 ? "" : `\n${sc.stdout.slice(-600)}${sc.stderr.slice(-400)}`}`);
  const bin = run(join(app, "node_modules/.bin/bulkhead-verify"), ["selfcheck", "--log-dir", join(work, "log2")], app);
  check(bin.status === 0, "installed verifier: the bulkhead-verify bin works");
} catch (e) {
  console.error((e as Error).message);
  bad++;
} finally {
  wrangler?.kill("SIGTERM");
  rmSync(work, { recursive: true, force: true });
}
console.log(bad ? `consumer test FAILED (${bad})` : "consumer test passed: the packed packages install, typecheck, boot and verify from a clean project");
process.exit(bad ? 1 : 0);
