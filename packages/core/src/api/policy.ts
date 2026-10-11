export const ROLES = ["member", "admin", "owner"] as const;
export type Role = (typeof ROLES)[number];

/**
 * Every route declares exactly one access mode. There is no default: omitting the policy,
 * or declaring neither/both of `role` and `public`, is a registration error (ROUTE-1, AUTH-1).
 */
export type Policy =
  | { role: Role; feature?: string; public?: never }
  | { public: { reason: string }; role?: never; feature?: never };

export class PolicyError extends Error {}

export function validatePolicy(method: string, path: string, policy: unknown): Policy {
  const where = `${method} ${path}`;
  if (policy === undefined || policy === null || typeof policy !== "object") throw new PolicyError(`${where}: route has no policy`);
  const p = policy as Record<string, unknown>;
  const hasRole = p.role !== undefined;
  const hasPublic = p.public !== undefined;
  if (hasRole === hasPublic) throw new PolicyError(`${where}: policy must declare exactly one of "role" or "public"`);
  if (hasRole) {
    if (!ROLES.includes(p.role as Role)) throw new PolicyError(`${where}: unknown role ${String(p.role)}`);
    if (p.feature !== undefined && (typeof p.feature !== "string" || !p.feature)) throw new PolicyError(`${where}: feature must be a non-empty string`);
  } else {
    const reason = (p.public as { reason?: unknown } | null)?.reason;
    if (typeof reason !== "string" || !reason.trim()) throw new PolicyError(`${where}: public routes need a reason`);
    if (p.feature !== undefined) throw new PolicyError(`${where}: public routes cannot require a feature`);
  }
  return policy as Policy;
}

export const roleAtLeast = (have: Role, need: Role) => ROLES.indexOf(have) >= ROLES.indexOf(need);

export interface ManifestEntry {
  method: string;
  path: string;
  access: { kind: "public"; reason: string } | { kind: "role"; role: Role; feature?: string };
}

export function toManifestEntry(method: string, path: string, p: Policy): ManifestEntry {
  return { method, path, access: p.public ? { kind: "public", reason: p.public.reason } : { kind: "role", role: p.role!, ...(p.feature ? { feature: p.feature } : {}) } };
}
