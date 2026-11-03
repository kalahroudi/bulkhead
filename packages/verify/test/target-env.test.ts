// DR-0016 decision 3: cookie name, tenant host suffix and webhook secret are TargetEnv fields; a changed value reaches the probes.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createHmac } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DEFAULT_COOKIE_NAME, DEFAULT_HOST_SUFFIX, DEFAULT_WEBHOOK_SECRET, probes } from "../src/probes.ts";
import { runProbes } from "../src/run.ts";
import { parseTargetConfig, resolveTargetOverrides } from "../src/target-env.ts";

const probe = (id: string) => probes.find((p) => p.id === id)!;
const COOKIE = "custom_sess";
const SUFFIX = "tenants.example.test";
const SECRET = "custom-webhook-secret";

/** A tiny target that follows the contract with non-default values: its own cookie name, host suffix and webhook secret. */
async function customTarget() {
  const hosts: string[] = [];
  const cookies: string[] = [];
  const server = createServer((req, res) => {
    const host = String(req.headers.host);
    hosts.push(host);
    if (req.headers.cookie) cookies.push(String(req.headers.cookie));
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      const send = (status: number, text = "{}", headers: Record<string, string> = {}) => { res.writeHead(status, { "content-type": "application/json", ...headers }); res.end(text); };
      if (!host.endsWith(`.${SUFFIX}`)) return send(404);
      if (req.url === "/auth/bootstrap") return send(201, '{"id":"u1"}');
      if (req.url === "/auth/login") return send(200, '{"ok":true}', { "set-cookie": `${COOKIE}=bks_${"x".repeat(43)}; Path=/; Secure; HttpOnly; SameSite=Lax` });
      if (req.url === "/private/member") return send(String(req.headers.cookie ?? "").startsWith(`${COOKIE}=bks_x`) ? 200 : 401);
      if (req.url === "/plan") return send(200, '{"plan":"free"}');
      if (req.url === "/webhooks/billing") {
        const want = createHmac("sha256", SECRET).update(body).digest("hex");
        return send(req.headers["x-signature"] === want ? 200 : 401);
      }
      return send(404);
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as { port: number }).port;
  return { url: new URL(`http://127.0.0.1:${port}`), hosts, cookies, close: () => new Promise<void>((r) => server.close(() => r())) };
}

test("defaults equal the demo's values", () => {
  assert.equal(DEFAULT_COOKIE_NAME, "__Host-bk_session");
  assert.equal(DEFAULT_HOST_SUFFIX, "demo.localhost");
  assert.equal(DEFAULT_WEBHOOK_SECRET, "whsec_fixture");
});

test("a changed host suffix reaches every request's Host header", async () => {
  const t = await customTarget();
  try {
    const [r] = await runProbes(t.url, [probe("identity-header-differential")], "tok", { hostSuffix: SUFFIX });
    assert.ok(t.hosts.length > 0 && t.hosts.every((h) => h.endsWith(`.${SUFFIX}`)), `hosts seen: ${t.hosts.join(", ")}`);
    assert.ok(!t.hosts.some((h) => h.endsWith(".demo.localhost")));
    assert.equal(r!.skipped, undefined);
  } finally { await t.close(); }
});

test("with the default host suffix the same target is not reached (the override is what made it work)", async () => {
  const t = await customTarget();
  try {
    await runProbes(t.url, [probe("cookie-flags")], "tok", { cookieName: COOKIE });
    assert.ok(t.hosts.every((h) => h.endsWith(".demo.localhost")), t.hosts.join(", "));
  } finally { await t.close(); }
});

test("a changed cookie name is the one the probes read from Set-Cookie and send back", async () => {
  const t = await customTarget();
  try {
    const env = { hostSuffix: SUFFIX, cookieName: COOKIE };
    const [flags] = await runProbes(t.url, [probe("cookie-flags")], "tok", env);
    assert.equal(flags!.passed, true, flags!.evidence);
    const [anon] = await runProbes(t.url, [probe("no-default-role")], "tok", env);
    assert.equal(anon!.passed, true, anon!.evidence);
    assert.ok(t.cookies.some((c) => c.startsWith(`${COOKIE}=bks_`)), `cookies sent: ${t.cookies.join(" | ")}`);
    assert.ok(!t.cookies.some((c) => c.includes(DEFAULT_COOKIE_NAME)));
    // Left at the default, the probe cannot find this target's cookie: it fails, it does not pass.
    const [wrong] = await runProbes(t.url, [probe("cookie-flags")], "tok", { hostSuffix: SUFFIX });
    assert.equal(wrong!.passed, false);
  } finally { await t.close(); }
});

test("a changed webhook secret is the one used to sign the genuine webhook", async () => {
  const t = await customTarget();
  try {
    const env = { hostSuffix: SUFFIX };
    const [ok] = await runProbes(t.url, [probe("forged-signature")], "tok", { ...env, webhookSecret: SECRET });
    assert.equal(ok!.passed, true, ok!.evidence);
    const [wrong] = await runProbes(t.url, [probe("forged-signature")], "tok", env);
    assert.equal(wrong!.passed, false, "signed with the default secret, the genuine webhook must be refused");
  } finally { await t.close(); }
});

test("two concurrent runs with different cookie names do not see each other's name", async () => {
  const t = await customTarget();
  try {
    const [a, b] = await Promise.all([
      runProbes(t.url, [probe("cookie-flags")], "tok", { hostSuffix: SUFFIX, cookieName: COOKIE }),
      runProbes(t.url, [probe("cookie-flags")], "tok", { hostSuffix: SUFFIX, cookieName: "other_name" }),
    ]);
    assert.equal(a[0]!.passed, true);
    assert.equal(b[0]!.passed, false);
  } finally { await t.close(); }
});

test("verify-target.json next to the manifest is read, flags override it, unknown keys and bad values are refused", () => {
  const dir = mkdtempSync(join(tmpdir(), "verify-target-"));
  const manifestPath = join(dir, "route-manifest.json");
  writeFileSync(manifestPath, "[]");
  assert.deepEqual(resolveTargetOverrides({ manifestPath }), {}, "no config file: no overrides");
  writeFileSync(join(dir, "verify-target.json"), JSON.stringify({ cookieName: "from_file", hostSuffix: "file.example", webhookSecret: "file-secret" }));
  assert.deepEqual(resolveTargetOverrides({ manifestPath }), { cookieName: "from_file", hostSuffix: "file.example", webhookSecret: "file-secret" });
  assert.deepEqual(resolveTargetOverrides({ manifestPath, cookieName: "from_flag" }), { cookieName: "from_flag", hostSuffix: "file.example", webhookSecret: "file-secret" });
  assert.deepEqual(resolveTargetOverrides({}), {}, "no manifest, no flags: nothing");
  assert.throws(() => parseTargetConfig('{"cookiename":"x"}'), /unknown key "cookiename"/);
  assert.throws(() => parseTargetConfig('{"cookieName":""}'), /non-empty string/);
  assert.throws(() => parseTargetConfig('{"cookieName":"a b"}'), /valid cookie name/);
  assert.throws(() => parseTargetConfig('{"hostSuffix":"http://x.test"}'), /bare domain/);
  assert.throws(() => parseTargetConfig('{"hostSuffix":".x.test"}'), /bare domain/);
  assert.throws(() => parseTargetConfig("[]"), /JSON object/);
  assert.throws(() => parseTargetConfig("{"), /not valid JSON/);
  writeFileSync(join(dir, "verify-target.json"), '{"typo":"x"}');
  assert.throws(() => resolveTargetOverrides({ manifestPath }), /unknown key "typo"/);
});

test("a probe run outside a run scope throws instead of using the demo's cookie name", async () => {
  const p = probes.find((x) => x.id === "cookie-flags")!;
  const ctx = { req: async () => ({ status: 201, body: "{}", headers: { "set-cookie": ["c=bks_x; Path=/"] } }), host: (t: string) => `${t}.x`, webhookSecret: "s", cookieName: "c", bootstrapToken: "tok" };
  await assert.rejects(() => p.run(ctx as never), /outside a run scope/);
});

test("no-default-role needs a control: a target that ignores the cookie name (401 to everything) is a failure, not a pass", async () => {
  let honour = true;
  const server = createServer((req, res) => {
    req.resume();
    const send = (status: number, headers: Record<string, string> = {}) => { res.writeHead(status, { "content-type": "application/json", ...headers }); res.end("{}"); };
    if (req.url === "/auth/bootstrap") return send(201);
    if (req.url === "/auth/login") return send(200, { "set-cookie": `${COOKIE}=bks_${"x".repeat(43)}; Path=/; Secure; HttpOnly; SameSite=Lax` });
    // Honours the session only under its own cookie name.
    if (req.url === "/private/member") return send(honour && String(req.headers.cookie ?? "").startsWith(`${COOKIE}=bks_x`) ? 200 : 401);
    return send(404);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const url = new URL(`http://127.0.0.1:${(server.address() as { port: number }).port}`);
  try {
    const p = probe("no-default-role");
    const [right] = await runProbes(url, [p], "tok", { cookieName: COOKIE });
    assert.equal(right!.passed, true, right!.evidence);
    // The target sets the cookie under the configured name but never honours it: every 401 below would be for the wrong reason.
    honour = false;
    const [ignored] = await runProbes(url, [p], "tok", { cookieName: COOKIE });
    assert.equal(ignored!.passed, false);
    assert.match(ignored!.evidence, /control failed/);
  } finally { await new Promise<void>((r) => { server.close(() => r()); server.closeAllConnections(); }); }
});
