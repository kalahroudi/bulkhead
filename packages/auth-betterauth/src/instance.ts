// DR-0011 spike: one Better Auth instance per request, built around that request's TenantDb.
import { betterAuth } from "better-auth";
import type { Role } from "@kalahroudi/bulkhead-core/api";
import type { TenantDb } from "@kalahroudi/bulkhead-core/tenant";
import { hashPassword, verifyPassword } from "@kalahroudi/bulkhead-auth";
import { tenantDbAdapter } from "./adapter.ts";

export const SESSION_COOKIE = "__Host-bk_session";
export const SESSION_TTL_S = 7 * 24 * 3600;

export interface InstanceOptions {
  db: TenantDb;
  /** Signs the session cookie. A Worker secret; required (the caller refuses to serve without it). */
  secret: string;
  origin: string;
}

/** `role` for the next created user, supplied by the route that creates it. There is no default role. */
export interface RoleSlot { next: Role | null; /** 1 creates the user disabled, so a claim can be confirmed before the account can sign in. Consumed with the role. */ disabled?: 0 | 1 }

export function createInstance(o: InstanceOptions, slot: RoleSlot) {
  return betterAuth({
    database: tenantDbAdapter(o.db),
    secret: o.secret,
    baseURL: o.origin,
    trustedOrigins: [o.origin],
    telemetry: { enabled: false },
    emailAndPassword: {
      enabled: true,
      autoSignIn: false,
      minPasswordLength: 12,
      maxPasswordLength: 256,
      password: { hash: hashPassword, verify: ({ hash, password }) => verifyPassword(password, hash) },
    },
    session: { expiresIn: SESSION_TTL_S, updateAge: 300, cookieCache: { enabled: false } },
    user: {
      additionalFields: {
        // required:false because Better Auth validates required fields against the sign-up body even when input is false;
        // the hook below and the NOT NULL + CHECK in the schema are what refuse a missing role.
        role: { type: "string", required: false, input: false },
        disabled: { type: "number", required: false, input: false, defaultValue: 0 },
      },
    },
    databaseHooks: {
      user: {
        create: {
          before: async (user) => {
            const role = slot.next;
            const disabled = slot.disabled ?? 0;
            slot.next = null;
            slot.disabled = 0;
            if (!role) throw new Error("a user cannot be created without an explicit role");
            return { data: { ...user, role, disabled } };
          },
        },
      },
    },
    advanced: {
      // false: with true Better Auth prepends "__Secure-" to the configured name, giving "__Secure-__Host-bk_session",
      // which is not a valid __Host- cookie. The name is set in full below and Secure is set explicitly.
      useSecureCookies: false,
      cookies: { session_token: { name: SESSION_COOKIE, attributes: { httpOnly: true, secure: true, sameSite: "lax", path: "/" } } },
    },
  });
}
