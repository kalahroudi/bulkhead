// Phase 2 gate harness: boots the demo Worker in local workerd, runs the black-box verify against it over HTTP, tears it down.
// Verify itself never imports the app; this script is only the launcher.
import { spawn, spawnSync } from "node:child_process";
import { request } from "node:http";
import { createServer } from "node:net";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/** Ask the OS for a free loopback port so a busy 8787 does not fail the gate. */
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = createServer();
    s.on("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const address = s.address();
      s.close(() => resolve(typeof address === "object" && address ? address.port : 0));
    });
  });
}

const root = fileURLToPath(new URL("..", import.meta.url));
const demo = join(root, "examples/demo-app");
const persist = mkdtempSync(join(tmpdir(), "bulkhead-demo-state-"));
const logDir = mkdtempSync(join(tmpdir(), "bulkhead-demo-log-"));
// A fresh bootstrap secret per run: handed to the Worker as a var and to verify through the environment, never written to disk.
const bootstrapToken = randomBytes(24).toString("hex");
const port = Number(process.env.DEMO_PORT ?? (await freePort()));

const wrangler = spawn(join(demo, "node_modules/.bin/wrangler"), ["dev", "--local", "--ip", "127.0.0.1", "--port", port, "--persist-to", persist, "--var", `BULKHEAD_BOOTSTRAP_TOKEN:${bootstrapToken}`], {
  cwd: demo,
  env: { ...process.env, WRANGLER_SEND_METRICS: "false", CI: "1" },
  stdio: ["ignore", "pipe", "pipe"],
});
let output = "";
wrangler.stdout.on("data", (d: Buffer) => (output += d));
wrangler.stderr.on("data", (d: Buffer) => (output += d));

function cleanup() {
  wrangler.kill("SIGTERM");
  rmSync(persist, { recursive: true, force: true });
  rmSync(logDir, { recursive: true, force: true });
}

try {
  const deadline = Date.now() + 90_000;
  for (;;) {
    if (wrangler.exitCode !== null) throw new Error(`wrangler exited early:\n${output}`);
    if (Date.now() > deadline) throw new Error(`wrangler not ready after 90s:\n${output}`);
    const status = await new Promise<number>((resolve) => {
      const req = request({ host: "127.0.0.1", port, path: "/whoami", headers: { host: "ready.demo.localhost" }, timeout: 3000 }, (res) => (res.resume(), resolve(res.statusCode ?? 0)));
      req.on("error", () => resolve(0)).on("timeout", () => req.destroy());
      req.end();
    });
    if (status === 200) break;
    await new Promise((r) => setTimeout(r, 500));
  }
  const argRules = (() => { const i = process.argv.indexOf("--rules"); return i >= 0 ? process.argv[i + 1] : undefined; })();
  const rules = argRules ?? process.env.VERIFY_RULES ?? "TENANT-1,TENANT-4,TENANT-5";
  const res = spawnSync(process.execPath, [join(root, "packages/verify/src/cli.ts"), "run", "--target", `http://127.0.0.1:${port}`, "--rules", rules, "--log-dir", logDir], { stdio: "inherit", timeout: 240_000, env: { ...process.env, BULKHEAD_VERIFY_BOOTSTRAP_TOKEN: bootstrapToken } });
  if (res.error) console.error(`verify run failed to complete: ${res.error.message}`);
  if (res.status !== 0) console.error("\nwrangler output:\n" + output.split("\n").slice(-15).join("\n"));
  process.exitCode = res.status ?? 1;
} catch (e) {
  console.error((e as Error).message);
  process.exitCode = 1;
} finally {
  cleanup();
}
