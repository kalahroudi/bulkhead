// The demo's routes on top of Better Auth. Free of `cloudflare:workers` imports so the manifest can be generated under Node.
import { createBetterAuth } from "@kalahroudi/bulkhead-auth-betterauth";
import { createDemoApp } from "../../demo-app/src/routes.ts";

export function createBetterAuthDemoApp(secrets: { bootstrapToken: () => string | undefined; authSecret: () => string | undefined }) {
  return createDemoApp(secrets.bootstrapToken, createBetterAuth({ bootstrapToken: secrets.bootstrapToken, secret: secrets.authSecret }));
}
