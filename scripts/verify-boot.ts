// BOOT-1 gate (DR-0010 step e): boots the demo Worker in local workerd with each required key missing or malformed and checks that it
// refuses to serve anything (every route answers 500 "service misconfigured") and persists nothing, with a control run that must serve.
// The control proves the check can fail: if misconfiguration were not the cause of the refusals, the control would be refused too.
import { spawn } from "node:child_process";
import { request } from "node:http";
import { createServer } from "node:net";
import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const demo = join(fileURLToPath(new URL("..", import.meta.url)), "examples/demo-app");
// wrangler loads .dev.vars on its own, which would hand the "no key" cases real keys and make them fail for the wrong reason.
if (existsSync(join(demo, ".dev.vars"))) { console.error("examples/demo-app/.dev.vars exists and would supply keys to every case; move it aside and run again"); process.exit(2); }
const good = randomBytes(32).toString("base64");

interface Case { name: string; vars: Record<string, string>; serves: boolean }
const CASES: Case[] = [
  { name: "control: all keys present", vars: { BULKHEAD_MASTER_KEY_CURRENT: "1", BULKHEAD_MASTER_KEY_V1: good }, serves: true },
  { name: "no master key at all", vars: {}, serves: false },
  { name: "current version not set", vars: { BULKHEAD_MASTER_KEY_V1: good }, serves: false },
  { name: "current version names a missing key", vars: { BULKHEAD_MASTER_KEY_CURRENT: "2", BULKHEAD_MASTER_KEY_V1: good }, serves: false },
  { name: "key too short", vars: { BULKHEAD_MASTER_KEY_CURRENT: "1", BULKHEAD_MASTER_KEY_V1: randomBytes(16).toString("base64") }, serves: false },
  { name: "key not base64", vars: { BULKHEAD_MASTER_KEY_CURRENT: "1", BULKHEAD_MASTER_KEY_V1: "!!!not base64!!!" }, serves: false },
  { name: "key empty", vars: { BULKHEAD_MASTER_KEY_CURRENT: "1", BULKHEAD_MASTER_KEY_V1: "" }, serves: false },
  { name: "an older key is malformed", vars: { BULKHEAD_MASTER_KEY_CURRENT: "2", BULKHEAD_MASTER_KEY_V1: "short", BULKHEAD_MASTER_KEY_V2: good }, serves: false },
];

const freePort = () => new Promise<number>((resolve, reject) => {
  const s = createServer();
  s.on("error", reject);
  s.listen(0, "127.0.0.1", () => { const a = s.address(); s.close(() => resolve(typeof a === "object" && a ? a.port : 0)); });
});

const http = (port: number, method: string, path: string, body?: string) => new Promise<{ status: number; body: string }>((resolve) => {
  const req = request({ host: "127.0.0.1", port, path, method, headers: { host: "boot.demo.localhost", "content-type": "application/json" }, timeout: 5000 }, (res) => {
    let b = "";
    res.on("data", (d) => (b += d));
    res.on("end", () => resolve({ status: res.statusCode ?? 0, body: b }));
  });
  req.on("error", () => resolve({ status: 0, body: "" })).on("timeout", () => req.destroy());
  req.end(body);
});

async function run(c: Case): Promise<string[]> {
  const problems: string[] = [];
  const port = await freePort();
  const persist = mkdtempSync(join(tmpdir(), "bulkhead-boot-state-"));
  const vars = Object.entries(c.vars).flatMap(([k, v]) => ["--var", `${k}:${v}`]);
  const w = spawn(join(demo, "node_modules/.bin/wrangler"), ["dev", "--local", "--ip", "127.0.0.1", "--port", String(port), "--persist-to", persist, ...vars], { cwd: demo, env: { ...process.env, WRANGLER_SEND_METRICS: "false", CI: "1" }, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  w.stdout.on("data", (d: Buffer) => (out += d));
  w.stderr.on("data", (d: Buffer) => (out += d));
  try {
    const deadline = Date.now() + 90_000;
    let probe = { status: 0, body: "" };
    for (;;) {
      if (w.exitCode !== null) throw new Error(`wrangler exited early:\n${out}`);
      if (Date.now() > deadline) throw new Error(`wrangler not ready after 90s:\n${out}`);
      probe = await http(port, "GET", "/whoami");
      if (probe.status !== 0) break;
      await new Promise((r) => setTimeout(r, 500));
    }
    const note = `boot-canary-${randomBytes(6).toString("hex")}`;
    const answers = [probe, await http(port, "GET", "/notes"), await http(port, "POST", "/notes", JSON.stringify({ text: note })), await http(port, "GET", "/summary")];
    // Miniflare keeps its own metadata.sqlite files; what matters is a tenant database (v3/do) or a control-plane database (v3/d1) with content.
    const written = readdirSync(persist, { recursive: true }).map(String).filter((f) => /^v3\/(do|d1)\//.test(f) && /\.sqlite$/.test(f) && !/(^|\/)metadata\.sqlite$/.test(f));
    if (c.serves) {
      if (!written.length) problems.push("the control wrote no database, so the 'writes nothing' check cannot tell anything");
      if (probe.status !== 200) problems.push(`control did not serve: GET /whoami answered ${probe.status}`);
      if (answers[2]!.status !== 201) problems.push(`control did not store a note: HTTP ${answers[2]!.status}`);
    } else {
      answers.forEach((a, i) => { if (a.status !== 500 || !a.body.includes("service misconfigured")) problems.push(`route ${i} answered ${a.status} ${a.body.slice(0, 80)} instead of refusing with 500 "service misconfigured"`); });
      if (answers.some((a) => a.body.includes(note))) problems.push("the refused request's text came back");
      if (written.length) problems.push(`storage was written although the app refused to boot: ${written.join(", ")}`);
    }
  } finally {
    w.kill("SIGTERM");
    rmSync(persist, { recursive: true, force: true });
  }
  return problems;
}

let bad = 0;
for (const c of CASES) {
  try {
    const problems = await run(c);
    console.log(`${problems.length ? "FAIL" : "ok  "} BOOT-1 ${c.name}${problems.length ? `: ${problems.join("; ")}` : c.serves ? ": serves" : ": refuses to serve, writes nothing"}`);
    if (problems.length) bad++;
  } catch (e) {
    console.log(`FAIL BOOT-1 ${c.name}: ${(e as Error).message}`);
    bad++;
  }
}
console.log(bad ? `${bad} BOOT-1 case(s) failed` : "BOOT-1: every misconfiguration refuses to boot, and the control serves. A pass means these cases only, not every possible misconfiguration.");
process.exitCode = bad ? 1 : 0;
