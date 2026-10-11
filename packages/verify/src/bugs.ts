// Seeded-bug catalog: each bug in the fixture, and the single probe that must catch it.
export interface SeededBug {
  id: string;
  description: string;
  probeId: string;
}

export const seededBugs: SeededBug[] = [
  { id: "missing-tenant-filter", description: "GET /notes returns every tenant's notes", probeId: "notes-list-canary" },
  { id: "shared-cache-key", description: "Summary cache key omits the tenant", probeId: "cache-canary" },
  { id: "skipped-signature-check", description: "Billing webhook accepted without a valid signature", probeId: "forged-signature" },
  { id: "tenant-from-header", description: "Tenant taken from a client-supplied x-tenant header", probeId: "identity-header-differential" },
];
