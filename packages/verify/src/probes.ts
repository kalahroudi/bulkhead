import { createHmac, randomBytes } from "node:crypto";
import type { Oracle } from "@kalahroudi/bulkhead-spec";
import type { Requester } from "./http.ts";
import { canaryOracle, differentialOracle, specOracle, type Verdict } from "./oracles.ts";

export interface Context {
  req: Requester;
  /** Throwaway tenant hostnames. Tenant identity comes from the hostname only. */
  host: (tenant: string) => string;
  /** Webhook secret for the registered test environment. */
  webhookSecret: string;
}

export interface Probe {
  /** Unique probe ID, used by the seeded-bug catalog. */
  id: string;
  /** Spec rule this probe checks, and the scenario stub name from the spec. */
  ruleId: string;
  scenario: string;
  oracle: Oracle;
  run(ctx: Context): Promise<Verdict & { reproduction: string }>;
}

const marker = () => `CANARY-${randomBytes(6).toString("hex")}`;
const json = (o: unknown) => JSON.stringify(o);

export const probes: Probe[] = [
  {
    id: "notes-list-canary",
    ruleId: "TENANT-5",
    scenario: "tenant-isolation/canary-does-not-cross",
    oracle: "canary",
    async run({ req, host }) {
      const m = marker();
      await req(host("canary-a"), "POST", "/notes", { body: json({ text: m }) });
      const r = await req(host("canary-b"), "GET", "/notes");
      return {
        ...canaryOracle(m, [{ where: "GET /notes as tenant B", response: r }]),
        reproduction: `Plant ${m} in tenant A via POST /notes (Host: ${host("canary-a")}). Then GET /notes with Host: ${host("canary-b")} and scan the body for the marker.`,
      };
    },
  },
  {
    id: "cache-canary",
    ruleId: "TENANT-5",
    scenario: "tenant-isolation/canary-does-not-cross",
    oracle: "canary",
    async run({ req, host }) {
      const m = marker();
      await req(host("cache-a"), "POST", "/notes", { body: json({ text: m }) });
      await req(host("cache-a"), "GET", "/summary"); // warm any cache with tenant A's view
      const r = await req(host("cache-b"), "GET", "/summary");
      return {
        ...canaryOracle(m, [{ where: "GET /summary as tenant B after tenant A warmed it", response: r }]),
        reproduction: `Plant ${m} in tenant A, GET /summary as A, then GET /summary with Host: ${host("cache-b")} and scan for the marker.`,
      };
    },
  },
  {
    id: "identity-header-differential",
    ruleId: "TENANT-1",
    scenario: "tenant-isolation/identity-from-host-or-session-only",
    oracle: "differential",
    async run({ req, host }) {
      const plain = await req(host("ident-b"), "GET", "/whoami");
      const spoofed = await req(host("ident-b"), "GET", "/whoami", { headers: { "x-tenant": "ident-a" } });
      return {
        ...differentialOracle(plain, spoofed, "GET /whoami with and without a client-supplied tenant header"),
        reproduction: `GET /whoami with Host: ${host("ident-b")} twice, the second time adding header x-tenant: ident-a. Responses must be identical.`,
      };
    },
  },
  {
    id: "forged-signature",
    ruleId: "BILL-2",
    scenario: "messaging/forged-and-replayed-webhooks",
    oracle: "state", // verdict hinges on tenant state (plan) staying unchanged, plus a spec status check
    async run({ req, host, webhookSecret }) {
      const t = host("hook-a");
      const body = json({ plan: "pro" });
      const forged = await req(t, "POST", "/webhooks/billing", { body, headers: { "x-signature": createHmac("sha256", "not-the-secret").update(body).digest("hex") } });
      const plan = await req(t, "GET", "/plan");
      const genuine = await req(t, "POST", "/webhooks/billing", { body: json({ plan: "free" }), headers: { "x-signature": createHmac("sha256", webhookSecret).update(json({ plan: "free" })).digest("hex") } });
      return {
        ...specOracle([
          { name: "forged webhook rejected", ok: forged.status >= 400 && forged.status < 500, detail: `HTTP ${forged.status}` },
          { name: "plan unchanged after forged webhook", ok: plan.body.includes('"free"'), detail: plan.body },
          { name: "genuine webhook still accepted", ok: genuine.status === 200, detail: `HTTP ${genuine.status}` },
        ]),
        reproduction: `POST /webhooks/billing {"plan":"pro"} to Host: ${t} signed with a wrong key. Expect a 4xx and GET /plan to remain "free". Replay and out-of-order delivery are not yet probed.`,
      };
    },
  },
];
