# Bulkhead

Multi-tenant security for Cloudflare Workers, enforced by structure and checked by an independent verifier.

> **Preview (`0.1.0-preview`).** Not security-attested, no encryption-at-rest yet, no billing, no tenant provisioning (the first owner is claimed with a bootstrap token). Every rule in [`SPEC.md`](SPEC.md) is still `proposed`. A green verify report means *no known leak paths*, not proof that none exist. Read [`SECURITY.md`](SECURITY.md) before relying on it.

## What you get

- **`@kalahroudi/bulkhead-core`**: tenant comes from the hostname only; each tenant gets its own Durable Object SQLite database behind a scoped handle; every route must declare a policy or the app refuses to start.
- **`@kalahroudi/bulkhead-auth`**: per-tenant users, sessions and API keys (roles, permissions, immediate revocation, CSRF origin check).
- **`@kalahroudi/bulkhead-spec`**: the rule catalog and its linters.
- **`@kalahroudi/bulkhead-verify`**: a black-box verifier that attacks a running app over HTTP and reports leaks. It never imports your code.

## Quickstart

```sh
npm install @kalahroudi/bulkhead-core @kalahroudi/bulkhead-auth
npm install -D wrangler @cloudflare/workers-types
```

`wrangler.jsonc`:

```jsonc
{
  "name": "my-app",
  "main": "src/index.ts",
  "compatibility_date": "2026-01-01",
  "durable_objects": { "bindings": [{ "name": "BULKHEAD_TENANT", "class_name": "TenantObject" }] },
  "migrations": [{ "tag": "v1", "new_sqlite_classes": ["TenantObject"] }],
  "d1_databases": [{ "binding": "BULKHEAD_DB", "database_name": "my-app", "database_id": "00000000-0000-0000-0000-000000000000" }], // any UUID works for local dev; use your real D1 id to deploy
  // Local development only: auto-provisioning is refused in any other environment.
  "vars": { "BULKHEAD_ENV": "development", "BULKHEAD_BASE_DOMAIN": "localhost", "BULKHEAD_AUTO_PROVISION": "true" }
}
```

`src/index.ts`:

```ts
import { DurableObject } from "cloudflare:workers";
import { createApp } from "@kalahroudi/bulkhead-core/api";
import { makeTenantObject } from "@kalahroudi/bulkhead-core/tenant";
import { createAuth } from "@kalahroudi/bulkhead-auth";

export class TenantObject extends makeTenantObject(DurableObject) {}

let bootstrapToken: string | undefined;
const auth = createAuth({ bootstrapToken: () => bootstrapToken });
const app = createApp({
  schema: [...auth.schema, "create table notes (id integer primary key autoincrement, text text not null)"],
  authenticate: auth.authenticate,
});
auth.registerRoutes(app);

// A route without a policy throws here, at startup. `role` is member | admin | owner.
app.route("GET", "/notes", { role: "member" }, async (c) =>
  c.json({ notes: await c.db.query("select text from notes order by id") }));

export default {
  fetch: (req: Request, env: Record<string, unknown>) => {
    bootstrapToken = typeof env.BULKHEAD_BOOTSTRAP_TOKEN === "string" ? env.BULKHEAD_BOOTSTRAP_TOKEN : undefined;
    return app.fetch(req, env);
  },
};
```

Your `tsconfig.json` needs `"types": ["@cloudflare/workers-types"]` and `"moduleResolution": "bundler"` (or `"NodeNext"`) so `cloudflare:workers` typechecks.

Run it locally with a bootstrap secret of **at least 32 characters** (shorter is treated as "bootstrap disabled"). The hostname picks the tenant, so `acme.localhost` is one tenant and `other.localhost` is another:

```sh
export TOKEN=$(openssl rand -hex 24)
npx wrangler dev --local --var BULKHEAD_BOOTSTRAP_TOKEN:$TOKEN

# claim the first owner of the "acme" tenant (password: 12+ characters), then sign in
curl -s -H 'host: acme.localhost' -H 'content-type: application/json' localhost:8787/auth/bootstrap \
  -d "{\"token\":\"$TOKEN\",\"email\":\"you@example.com\",\"password\":\"a long passphrase\"}"
curl -si -H 'host: acme.localhost' -H 'content-type: application/json' localhost:8787/auth/login \
  -d '{"email":"you@example.com","password":"a long passphrase"}'   # sets a __Host- session cookie
```

There is no `/` route; the example serves `GET /notes` and the `/auth/*` and `/users` routes.

**Production tenants.** Auto-provisioning is refused outside `development`, and tenant provisioning is not built yet (planned). Until then a production tenant is a row you insert into the control-plane D1 table: `insert into tenants (id, slug) values ('<uuid>', 'acme')`.

The repository's [`examples/demo-app`](examples/demo-app) is a complete, tested version of this.

## Verify it

```sh
npx bulkhead-verify selfcheck    # proves the verifier catches its own seeded bugs; needs no app
```

`bulkhead-verify run --target <url>` attacks a running app, but today its probes expect a small set of **probe-contract routes** (`/whoami`, `/notes`, `/summary`, `/private/member|admin|owner`) that only [`examples/demo-app`](examples/demo-app) exposes. To verify your own app, add those routes to a non-production copy of it (see `examples/demo-app/src/routes.ts`), set `BULKHEAD_BASE_DOMAIN` to `demo.localhost` (the probes address tenants as `<name>.demo.localhost`), start it with a bootstrap secret of at least 32 characters, and run:

```sh
BULKHEAD_VERIFY_BOOTSTRAP_TOKEN=<the same 32+ character secret> \
  npx bulkhead-verify run --target http://127.0.0.1:8787 --rules TENANT-1,TENANT-4,TENANT-5,AUTH-1,AUTH-2,AUTH-3,AUTH-4
```

A packaged probe-route helper is planned, not built. `run` refuses non-loopback targets unless you register them. Findings and the event log go to `.bulkhead/`.

## Status and limits

See [`CLAUDE.md`](CLAUDE.md) for how the project is built (spec first, frozen paths, decision records in [`docs/decisions`](docs/decisions)) and [`SECURITY.md`](SECURITY.md) for reporting. Requires Node 22+ for the tooling and a Cloudflare Workers runtime with Durable Objects (SQLite) for the app.

Licensed under Apache-2.0.
