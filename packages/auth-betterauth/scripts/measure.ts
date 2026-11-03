// Reproduces the numbers DR-0015 quotes: per-request costs on Node and the Worker bundle sizes. Run: node packages/auth-betterauth/scripts/measure.ts
// Node timings are not Workers CPU time (local workerd does not enforce CPU limits); they only compare the costs against each other.
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { hashPassword as baScrypt } from "better-auth/crypto";
import { hashPassword as pbkdf2 } from "@kalahroudi/bulkhead-auth";
import { createTenantDb } from "@kalahroudi/bulkhead-core/tenant";
import { fakeNamespace } from "../../auth/test/fakes.ts";
import { createInstance } from "../src/instance.ts";
import { betterAuthSchema, keySchema } from "../src/schema.ts";

const PW = "correct horse battery";
const ms = async (n: number, f: () => unknown) => { const t = performance.now(); for (let i = 0; i < n; i++) await f(); return (performance.now() - t) / n; };

const db = createTenantDb({ id: "t1", slug: "t1" } as never, fakeNamespace(), [...betterAuthSchema, ...keySchema]);
const mk = () => createInstance({ db, secret: "x".repeat(40), origin: "https://t1.demo.localhost" }, { next: "owner" });
await mk().api.signUpEmail({ body: { email: "a@b.co", password: PW, name: "a" } });
const signin = await mk().api.signInEmail({ body: { email: "a@b.co", password: PW }, headers: new Headers({ origin: "https://t1.demo.localhost" }), asResponse: true });
const cookie = signin.headers.getSetCookie()[0]!.split(";")[0]!;
console.log(`build instance + read session (cookie cache off): ${(await ms(50, () => mk().api.getSession({ headers: new Headers({ cookie }), query: { disableCookieCache: true } }))).toFixed(2)} ms`);
console.log(`PBKDF2-SHA256 100k (shipped, and the override):    ${(await ms(5, () => pbkdf2(PW))).toFixed(1)} ms`);
console.log(`Better Auth default scrypt:                         ${(await ms(5, () => baScrypt(PW))).toFixed(1)} ms`);

const root = fileURLToPath(new URL("../../..", import.meta.url));
for (const app of ["demo-app", "demo-betterauth"]) {
  const out = mkdtempSync(join(tmpdir(), "bulkhead-bundle-"));
  const r = spawnSync(join(root, "examples", app, "node_modules/.bin/wrangler"), ["deploy", "--dry-run", "--outdir", out], { cwd: join(root, "examples", app), encoding: "utf8", env: { ...process.env, WRANGLER_SEND_METRICS: "false", CI: "1" } });
  console.log(`${app.padEnd(16)} ${/Total Upload: .*/.exec(`${r.stdout}${r.stderr}`)?.[0] ?? "bundle size not reported"}`);
  rmSync(out, { recursive: true, force: true });
}
