import { createAuthenticator, type Clock } from "./authenticate.ts";
import { registerAuthRoutes, type AuthRoutesOptions } from "./routes.ts";
import { authSchema } from "./schema.ts";

export { authSchema } from "./schema.ts";
export { createAuthenticator, SESSION_COOKIE, type Clock } from "./authenticate.ts";
export { registerAuthRoutes, type AuthRoutesOptions } from "./routes.ts";
export { hashPassword, verifyPassword } from "./secrets.ts";

/**
 * Convenience wiring:
 *   const auth = createAuth({ bootstrapToken: () => env.BULKHEAD_BOOTSTRAP_TOKEN });
 *   const app = createApp({ schema: [...auth.schema, ...mine], authenticate: auth.authenticate });
 *   auth.registerRoutes(app);
 */
export function createAuth(options: AuthRoutesOptions & { clock?: Clock }) {
  return {
    schema: authSchema,
    authenticate: createAuthenticator(options.clock),
    registerRoutes: (app: Parameters<typeof registerAuthRoutes>[0]) => registerAuthRoutes(app, options),
  };
}
