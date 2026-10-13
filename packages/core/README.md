# @kalahroudi/bulkhead-core

Tenant resolution (hostname only), a tenant-scoped Durable Object SQLite handle, and policy-gated routes for Cloudflare Workers.

Preview (`0.1.0-preview`): not security-attested. See the [project README](https://github.com/kalahroudi/bulkhead#readme) for a quickstart and the honest limits.

- `@kalahroudi/bulkhead-core/api`: `createApp`, route policies (`role`, `permission`, `public` with a reason), the route manifest.
- `@kalahroudi/bulkhead-core/tenant`: `makeTenantObject`, `loadConfig`, `resolveTenant`, `createTenantDb`.

Apache-2.0.
