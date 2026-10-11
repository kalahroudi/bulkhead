// Deliberately vulnerable fixture app. Never deploy. Bugs are toggled by FIXTURE_BUGS (comma list, or "all"/"none").
import { createServer } from "node:http";
import { createHmac, timingSafeEqual } from "node:crypto";

const ALL = ["missing-tenant-filter", "shared-cache-key", "skipped-signature-check", "tenant-from-header"];
const raw = process.env.FIXTURE_BUGS ?? "all";
const bugs = new Set(raw === "all" ? ALL : raw === "none" ? [] : raw.split(",").filter(Boolean));
const SECRET = process.env.FIXTURE_WEBHOOK_SECRET ?? "whsec_fixture";

const notes: { tenant: string; text: string }[] = [];
const plans = new Map<string, string>();
const cache = new Map<string, string>();

function tenantOf(host: string | undefined, header: string | undefined): string | null {
  const m = /^([a-z0-9-]+)\.demo\.localhost(:\d+)?$/.exec(host ?? "");
  if (bugs.has("tenant-from-header") && header) return header;
  return m ? (m[1] as string) : null; // unknown host: fail closed
}

const server = createServer((req, res) => {
  const chunks: Buffer[] = [];
  req.on("data", (c: Buffer) => chunks.push(c));
  req.on("end", () => {
    const body = Buffer.concat(chunks);
    const send = (status: number, obj: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(obj));
    };
    const tenant = tenantOf(req.headers.host, req.headers["x-tenant"] as string | undefined);
    if (!tenant) return send(404, { error: "unknown host" });
    const url = new URL(req.url ?? "/", "http://x");
    const mine = () => notes.filter((n) => n.tenant === tenant).map((n) => n.text);

    if (req.method === "GET" && url.pathname === "/whoami") return send(200, { tenant });
    if (req.method === "POST" && url.pathname === "/notes") {
      notes.push({ tenant, text: String(JSON.parse(body.toString() || "{}").text ?? "") });
      cache.clear();
      return send(201, { ok: true });
    }
    if (req.method === "GET" && url.pathname === "/notes") {
      const list = bugs.has("missing-tenant-filter") ? notes.map((n) => n.text) : mine();
      return send(200, { notes: list });
    }
    if (req.method === "GET" && url.pathname === "/summary") {
      const key = bugs.has("shared-cache-key") ? "summary" : `${tenant}:summary`;
      let v = cache.get(key);
      if (v === undefined) cache.set(key, (v = mine().join(" | ")));
      return send(200, { summary: v });
    }
    if (req.method === "POST" && url.pathname === "/webhooks/billing") {
      const given = String(req.headers["x-signature"] ?? "");
      const want = createHmac("sha256", SECRET).update(body).digest("hex");
      const ok = given.length === want.length && timingSafeEqual(Buffer.from(given), Buffer.from(want));
      if (!ok && !bugs.has("skipped-signature-check")) return send(400, { error: "bad signature" });
      plans.set(tenant, String(JSON.parse(body.toString() || "{}").plan ?? "free"));
      return send(200, { ok: true });
    }
    if (req.method === "GET" && url.pathname === "/plan") return send(200, { plan: plans.get(tenant) ?? "free" });
    return send(404, { error: "not found" });
  });
});

server.listen(Number(process.env.PORT ?? 0), "127.0.0.1", () => {
  const addr = server.address();
  console.log(`LISTENING ${typeof addr === "object" && addr ? addr.port : ""}`);
});
