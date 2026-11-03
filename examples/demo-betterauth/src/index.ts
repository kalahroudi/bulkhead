import { DurableObject } from "cloudflare:workers";
import { makeTenantObject } from "@kalahroudi/bulkhead-core/tenant";
import { createBetterAuthDemoApp } from "./app.ts";

export class TenantObject extends makeTenantObject(DurableObject) {}

// Bindings are constant for the life of an isolate; they are read here and never reach route code.
let bootstrapToken: string | undefined;
let authSecret: string | undefined;
const app = createBetterAuthDemoApp({ bootstrapToken: () => bootstrapToken, authSecret: () => authSecret });

export default {
  fetch: (req: Request, env: Record<string, unknown>) => {
    bootstrapToken = typeof env.BULKHEAD_BOOTSTRAP_TOKEN === "string" ? env.BULKHEAD_BOOTSTRAP_TOKEN : undefined;
    // Signs the session cookie. Absent or short: Better Auth is not served (the hook returns null and the login route throws).
    authSecret = typeof env.BULKHEAD_AUTH_SECRET === "string" && env.BULKHEAD_AUTH_SECRET.length >= 32 ? env.BULKHEAD_AUTH_SECRET : undefined;
    return app.fetch(req, env);
  },
};
