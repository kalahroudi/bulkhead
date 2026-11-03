import { createAuthenticate, type KitOptions } from "./authenticate.ts";
import { registerBetterAuthRoutes } from "./routes.ts";
import { betterAuthFields } from "./classification.ts";
import { betterAuthSchema, keySchema } from "./schema.ts";

export { betterAuthSchema, keySchema } from "./schema.ts";
export { betterAuthFields } from "./classification.ts";
export { tenantDbAdapter } from "./adapter.ts";
export { SESSION_COOKIE } from "./instance.ts";
export type { KitOptions } from "./authenticate.ts";

/** Same shape as `createAuth` in @kalahroudi/bulkhead-auth, so an app can switch by changing one import. */
export function createBetterAuth(options: KitOptions) {
  return {
    schema: [...betterAuthSchema, ...keySchema],
    fields: betterAuthFields,
    authenticate: createAuthenticate(options),
    registerRoutes: (app: Parameters<typeof registerBetterAuthRoutes>[0]) => registerBetterAuthRoutes(app, options),
  };
}
