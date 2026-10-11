import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { appendFileSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { EventLog } from "@kalahroudi/bulkhead-verify/eventlog";
import { readLog, trustedEvents } from "../src/log.ts";

const tmp = () => mkdtempSync(join(tmpdir(), "bulkhead-plane-"));

test("reader accepts a chain written by the verify producer", () => {
  const dir = tmp();
  const log = new EventLog(dir, "verify");
  log.append("verify.run", { phase: "started" });
  log.append("verify.run", { phase: "finished" });
  const events = readLog(dir);
  assert.equal(events.length, 2);
  assert.ok(events.every((e) => e.trusted), JSON.stringify(events.map((e) => e.problem)));
});

test("tampered event breaks trust for it and everything the chain no longer vouches for", () => {
  const dir = tmp();
  const log = new EventLog(dir, "verify");
  log.append("verify.run", { phase: "started" });
  log.append("verify.run", { phase: "finished", passed: false });
  const path = join(dir, "events.jsonl");
  writeFileSync(path, readFileSync(path, "utf8").replace('"passed":false', '"passed":true'));
  const events = readLog(dir);
  assert.equal(events[0]?.trusted, true);
  assert.equal(events[1]?.trusted, false);
  assert.equal(trustedEvents(events).length, 1);
});

test("unsigned or unknown-producer events are untrusted (PLANE-2)", () => {
  const dir = tmp();
  const log = new EventLog(dir, "verify");
  const real = log.append("verify.run", { phase: "started" });
  const forged = { ...real, seq: 1, prev: real.hash, producer: "mallory", signature: "AAAA" };
  appendFileSync(join(dir, "events.jsonl"), JSON.stringify(forged) + "\n");
  const events = readLog(dir);
  assert.equal(events[1]?.trusted, false);
});

test("watch follows the log live", async () => {
  const dir = tmp();
  const log = new EventLog(dir, "verify");
  log.append("verify.run", { phase: "started" });
  const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
  const child = spawn(process.execPath, [cli, "--log-dir", dir], { stdio: ["ignore", "pipe", "inherit"] });
  let out = "";
  child.stdout.on("data", (d: Buffer) => (out += d.toString()));
  const waitFor = async (needle: string) => {
    for (let i = 0; i < 50 && !out.includes(needle); i++) await new Promise((r) => setTimeout(r, 100));
    assert.ok(out.includes(needle), `expected "${needle}" in output:\n${out}`);
  };
  try {
    await waitFor("phase=started");
    log.append("verify.run", { phase: "finished-live-marker" });
    await waitFor("finished-live-marker");
  } finally {
    child.kill();
  }
});
