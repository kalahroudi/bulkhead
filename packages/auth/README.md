# @kalahroudi/bulkhead-auth

Per-tenant users, sessions and API keys for [`@kalahroudi/bulkhead-core`](https://www.npmjs.com/package/@kalahroudi/bulkhead-core).

Preview (`0.1.0-preview`): not security-attested. Not included: password reset, email verification, MFA, SSO, per-IP login throttle. The first owner is claimed with a bootstrap token. See the [project README](https://github.com/kalahroudi/bulkhead#readme).

```ts
const auth = createAuth({ bootstrapToken: () => env.BULKHEAD_BOOTSTRAP_TOKEN });
const app = createApp({ schema: [...auth.schema, ...mine], authenticate: auth.authenticate });
auth.registerRoutes(app);
```

Apache-2.0.
