# @kalahroudi/bulkhead-verify

Independent black-box verifier for Bulkhead apps. It attacks a running app over HTTP and never imports your code.

Preview (`0.1.0-preview`): a green report means no known leak paths, not proof that none exist. Run `npx @kalahroudi/bulkhead-verify@preview selfcheck` to see it catch its own seeded bugs, and `bulkhead-verify run --target http://127.0.0.1:8787` to attack a running app that exposes the probe-contract routes (today, the demo app's; a packaged helper is planned). See the [project README](https://github.com/kalahroudi/bulkhead#readme).

Apache-2.0.
