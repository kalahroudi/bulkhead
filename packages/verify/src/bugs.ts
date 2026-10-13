// Seeded-bug catalog: each bug in the fixture, and the single probe that must catch it.
export interface SeededBug {
  id: string;
  description: string;
  /** Every probe that must fail when only this bug is present, and no others. */
  probeIds: string[];
}

export const seededBugs: SeededBug[] = [
  { id: "missing-tenant-filter", description: "GET /notes returns every tenant's notes", probeIds: ["add-tenant-metamorphic", "notes-list-canary"] },
  { id: "shared-cache-key", description: "Summary cache key omits the tenant", probeIds: ["cache-canary"] },
  { id: "skipped-signature-check", description: "Billing webhook accepted without a valid signature", probeIds: ["forged-signature"] },
  { id: "tenant-from-header", description: "Tenant taken from a client-supplied x-tenant header", probeIds: ["identity-header-differential"] },
  { id: "default-role", description: "A request with no credential is treated as a member", probeIds: ["logout-revokes", "no-default-role", "role-change-revokes", "session-rotation", "cross-tenant-session", "disabled-user-denied"] },
  { id: "session-fixation", description: "Login adopts the session token the client presented", probeIds: ["session-rotation"] },
  { id: "weak-cookie", description: "Session cookie lacks HttpOnly and is scoped to the parent domain", probeIds: ["cookie-flags"] },
  { id: "logout-keeps-session", description: "Logout does not revoke the session", probeIds: ["logout-revokes"] },
  { id: "role-change-keeps-session", description: "Changing a user's role leaves their old sessions valid", probeIds: ["role-change-revokes"] },
  { id: "admin-open-to-member", description: "The admin route only requires the member role", probeIds: ["role-matrix"] },
  { id: "api-key-cross-tenant", description: "An API key minted in one tenant works in another", probeIds: ["api-key-scope"] },
  { id: "api-key-unscoped", description: "API key permissions are not checked, only its role", probeIds: ["api-key-scope"] },
  { id: "session-cross-tenant", description: "A session minted in one tenant is accepted on another tenant's hostname", probeIds: ["cross-tenant-session"] },
  { id: "csrf-ignored", description: "Cookie-authenticated writes are accepted without a same-origin Origin or Sec-Fetch-Site", probeIds: ["csrf-origin"] },
  { id: "member-can-list-users", description: "The user and API-key listings require only the member role", probeIds: ["authority-matrix"] },
  { id: "escalation-allowed", description: "An admin can create a user with a role above their own", probeIds: ["authority-matrix"] },
  { id: "key-revocation-ignored", description: "A revoked API key, or one whose minter was demoted, keeps working", probeIds: ["key-revocation"] },
  { id: "disabled-user-can-login", description: "A disabled user can still log in with the right password", probeIds: ["disabled-user-denied"] },
  { id: "key-secret-unchecked", description: "An API key is accepted on its id alone; the secret is never compared", probeIds: ["key-wrong-secret-denied"] },
  { id: "bootstrap-token-unchecked", description: "First-owner bootstrap accepts any string as the bootstrap token", probeIds: ["bootstrap-token-required"] },
  { id: "bootstrap-second-owner", description: "Bootstrap with the right token still succeeds after the tenant has an owner", probeIds: ["bootstrap-claims-once"] },
  { id: "role-patch-escalation", description: "PATCH /users/:id/role lets an admin set a role above their own", probeIds: ["role-change-authority"] },
  { id: "admin-modifies-owner", description: "An admin may change the role of, or disable, a user above their own role", probeIds: ["role-change-authority"] },
  { id: "key-above-minter-role", description: "An admin may mint an API key with a role above their own", probeIds: ["key-role-ceiling"] },
  { id: "listing-leaks-hash", description: "The user and API-key listings include password and secret hashes", probeIds: ["listings-hide-secrets"] },
  { id: "tenant-from-forwarded-host", description: "Tenant taken from a client-supplied x-forwarded-host header", probeIds: ["identity-header-differential"] },
  { id: "unknown-email-login-errors", description: "Login for an unknown email fails with a 500 instead of the same 401 as a wrong password", probeIds: ["unknown-email-login-same-answer"] },
  { id: "key-secret-length-ignored", description: "An API key is accepted when the presented secret merely starts with the real one (extra characters appended)", probeIds: ["key-wrong-secret-denied"] },
];
