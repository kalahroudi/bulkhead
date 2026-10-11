import { DurableObject } from "cloudflare:workers";
import { makeTenantObject } from "@kalahroudi/bulkhead-core/tenant";
import { createDemoApp } from "./routes.ts";

export class TenantObject extends makeTenantObject(DurableObject) {}

const app = createDemoApp(); // a route without a policy throws here, at module load, and the deploy fails

export default { fetch: (req: Request, env: unknown) => app.fetch(req, env) };
