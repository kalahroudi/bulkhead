// DR-0016 decision 2: a probe whose routes the target's manifest lacks is UNVERIFIED, naming the route, and sends nothing.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { missingRoutes, NO_ROUTE_NEEDS, parseManifest, probes, routeListed, type ManifestRoute } from "../src/probes.ts";
import { runProbes } from "../src/run.ts";

const load = (rel: string) => parseManifest(readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8"));
const fixture = load("../fixture/route-manifest.json");
const demo = load("../../../examples/demo-app/route-manifest.json");
const without = (routes: ManifestRoute[], method: string, path: string) => routes.filter((r) => !(r.method === method && r.path === path));
const norm = (p: string) => p.replace(/:[A-Za-z_]\w*|\{[^}/]+\}|\[[^\]/]+\]|\*/g, ":p");

/** A server that records every request: a guarded probe must send none. */
async function recordingServer() {
  const seen: string[] = [];
  const server = createServer((req, res) => { seen.push(`${req.method} ${req.url}`); res.writeHead(404); res.end("{}"); });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as { port: number }).port;
  return { url: new URL(`http://127.0.0.1:${port}`), seen, close: () => new Promise<void>((r) => server.close(() => r())) };
}

test("every probe declares its routes or is exempt with a reason", () => {
  for (const p of probes) {
    if (p.needs !== undefined) { assert.ok(p.needs.length > 0, `${p.id}: empty needs`); assert.equal(NO_ROUTE_NEEDS[p.id], undefined, `${p.id}: has needs, so drop the exemption`); }
    else assert.ok((NO_ROUTE_NEEDS[p.id] ?? "").trim().length > 20, `${p.id}: declare needs or record why none apply`);
  }
});

test("the demo's and the fixture's manifests lack no declared route, so their results do not change", () => {
  for (const [name, routes] of [["fixture", fixture], ["demo", demo]] as const)
    for (const p of probes) assert.deepEqual(missingRoutes(routes, p.needs), [], `${name} manifest lacks a route ${p.id} needs`);
});

test("each declared route removed from the manifest makes its probe UNVERIFIED naming that route, and the probe sends nothing", async () => {
  const srv = await recordingServer();
  try {
    let cases = 0;
    for (const p of probes) for (const need of p.needs ?? []) {
      // Removing the route from the full fixture manifest, in whatever spelling it has there.
      const routes = fixture.filter((r) => !(r.method === need.method && norm(r.path) === norm(need.path)));
      assert.equal(routes.length, fixture.length - 1, `${p.id}: ${need.method} ${need.path} is not in the fixture manifest exactly once`);
      const [res] = await runProbes(srv.url, [p], "tok", { routes });
      assert.ok(res!.unverified !== undefined, `${p.id} without ${need.method} ${need.path}: expected unverified, got ${JSON.stringify({ passed: res!.passed, skipped: res!.skipped, evidence: res!.evidence })}`);
      assert.ok(res!.unverified!.includes(`${need.method} ${need.path}`), `${p.id}: the reason must name ${need.method} ${need.path}: ${res!.unverified}`);
      assert.equal(res!.passed, false);
      cases++;
    }
    assert.ok(cases >= 60, `only ${cases} cases ran`);
    assert.deepEqual(srv.seen, [], "a guarded probe sent a request although its route was missing");
  } finally { await srv.close(); }
});

test("a manifest that is empty makes every guarded probe UNVERIFIED (an app with no routes verifies nothing)", async () => {
  const srv = await recordingServer();
  try {
    const results = await runProbes(srv.url, probes.filter((p) => p.needs), "tok", { routes: [] });
    assert.ok(results.every((r) => r.unverified !== undefined));
    assert.deepEqual(srv.seen, []);
  } finally { await srv.close(); }
});

test("path parameters match in any manifest spelling", () => {
  const need = { method: "PATCH", path: "/users/:id/role" };
  for (const spelled of ["/users/:id/role", "/users/{id}/role", "/users/[id]/role", "/users/:userId/role"]) assert.ok(routeListed([{ method: "PATCH", path: spelled }], need), spelled);
  assert.ok(!routeListed([{ method: "POST", path: "/users/:id/role" }], need), "method must match");
  assert.ok(!routeListed([{ method: "PATCH", path: "/users/:id" }], need), "path must match");
});

test("with no manifest the guard does not fire: probes run and fail on their own setup, never pass", async () => {
  const srv = await recordingServer();
  try {
    const [res] = await runProbes(srv.url, [probes.find((p) => p.id === "notes-list-canary")!], "tok", {});
    assert.equal(res!.unverified, undefined);
    assert.equal(res!.passed, false);
    assert.ok(srv.seen.length > 0, "the probe should have run");
  } finally { await srv.close(); }
});

test("forged-signature: not applicable only without a manifest or when it lists no billing route; a listed billing route that answers 404 is UNVERIFIED", async () => {
  const srv = await recordingServer(); // answers 404 to everything
  try {
    const p = probes.find((x) => x.id === "forged-signature")!;
    const [noManifest] = await runProbes(srv.url, [p], "tok", {});
    assert.ok(noManifest!.skipped !== undefined && noManifest!.unverified === undefined, "no manifest: skipped");
    const [listsNeither] = await runProbes(srv.url, [p], "tok", { routes: [{ method: "GET", path: "/notes" }] });
    assert.ok(listsNeither!.skipped !== undefined && listsNeither!.unverified === undefined, "manifest without billing routes: skipped");
    for (const route of [{ method: "GET", path: "/plan" }, { method: "POST", path: "/webhooks/billing" }]) {
      const [r] = await runProbes(srv.url, [p], "tok", { routes: [route] });
      assert.equal(r!.skipped, undefined, `${route.method} ${route.path} listed: must not be skipped`);
      assert.ok(r!.unverified?.includes(`${route.method} ${route.path}`), r!.unverified);
      assert.equal(r!.passed, false);
    }
  } finally { await srv.close(); }
});
