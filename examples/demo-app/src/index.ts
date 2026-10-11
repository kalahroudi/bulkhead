import { DurableObject } from "cloudflare:workers";
import { makeTenantObject } from "@kalahroudi/bulkhead-core/tenant";
import { createDemoApp } from "./routes.ts";

export class TenantObject extends makeTenantObject(DurableObject) {}

// Bindings are constant for the life of an isolate; the secret is read here and never reaches route code.
let bootstrapToken: string | undefined;
const app = createDemoApp(() => bootstrapToken); // a route without a policy throws here, at module load, and the deploy fails

export default {
  fetch: (req: Request, env: Record<string, unknown>) => {
    const t = env.BULKHEAD_BOOTSTRAP_TOKEN;
    bootstrapToken = typeof t === "string" && t.length >= 32 ? t : undefined; // too short counts as unset: bootstrap stays off
    return app.fetch(req, env);
  },
};
