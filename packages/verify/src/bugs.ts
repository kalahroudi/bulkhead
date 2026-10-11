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
];
