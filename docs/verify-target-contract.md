# Verify target contract

What an application must offer for `bulkhead-verify` to verify it (DR-0016 decisions 1 to 3). The demo (`examples/demo-app`) is the reference implementation; the probes in `packages/verify/src/probes.ts` are the source of truth, and `packages/verify/test/contract.test.ts` fails when this page misses a path literal, header or probe id that the probes use. Paths are written with `:id` for parameters; a manifest may spell them `{id}` or `[id]`, for example `/users/{id}/role` or `/users/[id]/role`; they match the `:id` form.

## How a missing piece is reported

- **Manifest supplied (`--route-manifest`)**: every probe declares the routes it cannot run without (`needs`, listed per probe below). If the manifest lacks one, the probe is **UNVERIFIED**, naming the missing route, before it sends a request. The run is then NOT GREEN (exit 3), never a pass. Tested in `packages/verify/test/missing-route.test.ts`.
- **No manifest**: probes run as before. A route the target lacks answers 404 to a setup step, which every probe treats as a failure (`requireSetup`), never a pass. The crypto probes need a manifest for the parts that depend on it (CRYPTO-5 read-back, the secret store) and report UNVERIFIED without one.
- **Optional routes** are not in `needs`; the probe has its own rule for them: `POST /secrets` (without it CRYPTO-2 `aad-transplant-fails` and CRYPTO-5 `secret-write-only-readback` are UNVERIFIED; CRYPTO-1 `storage-canary-at-rest` checks the notes half and reports the secret class unverified; CRYPTO-3 `shredding-makes-data-unreadable` and CRYPTO-4 `nonce-uniqueness-and-rotation` run their notes half), `POST /admin/shred` and `POST /admin/rotate-key` (UNVERIFIED when listed absent, checked in the probe), `GET /secrets`, `GET /secrets/:name`.
- **Exempt**: `forged-signature` (BILL-2) has no `needs`. With no manifest, or a manifest that lists neither billing route, it is skipped as not applicable when both `GET /plan` and `POST /webhooks/billing` answer 404; if the manifest lists either route and both answer 404, it is UNVERIFIED naming the listed route; a manifest-based UNVERIFIED would turn every app without billing into a NOT GREEN run. The demo has neither route, the fixture has both.

## Routes

| Method and path | Role needed | Notes | Probes |
|---|---|---|---|
| POST `/auth/bootstrap` | public, bootstrap token | body `{token, email, password}`; claims an empty tenant for its first owner | every probe that signs in an owner (see per-probe table), `bootstrap-token-required`, `bootstrap-claims-once` |
| POST `/auth/login` | public | body `{email, password}`; sets the session cookie | every probe that signs in, `session-rotation`, `disabled-user-denied`, `unknown-email-login-same-answer` |
| POST `/auth/logout` | member | | `logout-revokes` |
| GET `/private/member` | member | answers 200 for member, admin, owner; 401 without a credential | `no-default-role`, `session-rotation`, `logout-revokes`, `role-change-revokes`, `role-matrix`, `api-key-scope`, `cross-tenant-session`, `disabled-user-denied`, `key-wrong-secret-denied` |
| GET `/private/admin` | admin | permission `private:admin` | `role-matrix`, `api-key-scope`, `key-revocation`, `key-role-ceiling` |
| GET `/private/owner` | owner | | `role-matrix`, `api-key-scope`, `bootstrap-claims-once`, `role-change-authority` |
| GET `/users` | admin | listing must not carry secrets | `authority-matrix`, `bootstrap-claims-once`, `role-change-authority`, `listings-hide-secrets` |
| POST `/users` | admin | body `{email, password, role}`; answers `{id}` | `role-change-revokes`, `role-matrix`, `authority-matrix`, `key-revocation`, `disabled-user-denied`, `role-change-authority`, `key-role-ceiling`, `listings-hide-secrets` |
| PATCH `/users/:id/role` | admin | body `{role}` | `role-change-revokes`, `key-revocation`, `role-change-authority` |
| DELETE `/users/:id` | admin | disables the user | `disabled-user-denied`, `role-change-authority` |
| GET `/api-keys` | admin | | `api-key-scope`, `authority-matrix`, `key-role-ceiling`, `listings-hide-secrets` |
| POST `/api-keys` | admin | body `{name, role, permissions}`; answers `{id, key}` | `api-key-scope`, `csrf-origin`, `key-revocation`, `key-wrong-secret-denied`, `key-role-ceiling`, `listings-hide-secrets` |
| DELETE `/api-keys/:id` | admin | revokes | `key-revocation` |
| GET `/whoami` | public | answers the resolved tenant | `identity-header-differential` |
| POST `/notes` | public | body `{text}`; the canary store (classified field) | `notes-list-canary`, `cache-canary`, `add-tenant-metamorphic`, `storage-canary-at-rest`, `aad-transplant-fails`, `shredding-makes-data-unreadable`, `nonce-uniqueness-and-rotation` |
| GET `/notes` | public | | `notes-list-canary`, `add-tenant-metamorphic`, `aad-transplant-fails`, `shredding-makes-data-unreadable`, `nonce-uniqueness-and-rotation` |
| GET `/summary` | public | a cached aggregate of notes | `cache-canary` |
| POST `/secrets` | owner | body `{name, value}`; optional (see above) | `storage-canary-at-rest`, `secret-write-only-readback`, `aad-transplant-fails`, `shredding-makes-data-unreadable`, `nonce-uniqueness-and-rotation` |
| GET `/secrets` | owner | listing never returns the value | `shredding-makes-data-unreadable`, `secret-write-only-readback` |
| GET `/secrets/:name` | owner | filled from the manifest during read-back | `secret-write-only-readback` |
| POST `/admin/shred` | owner | destroys a tenant's keys | `shredding-makes-data-unreadable` |
| POST `/admin/rotate-key` | owner | rotates the tenant key | `shredding-makes-data-unreadable`, `nonce-uniqueness-and-rotation` |
| GET `/plan` | public | billing only | `forged-signature` |
| POST `/webhooks/billing` | signature | billing only; HMAC-SHA256 of the body in `x-signature` | `forged-signature` |

## Per-probe route needs

A probe is UNVERIFIED when a supplied manifest lacks any route in its row. `contract.test.ts` checks that every row equals the probe's `needs`.

| Probe | Rule | Needs |
|---|---|---|
| `notes-list-canary` | TENANT-5 | POST `/notes`, GET `/notes` |
| `cache-canary` | TENANT-5 | POST `/notes`, GET `/summary` |
| `add-tenant-metamorphic` | TENANT-4 | POST `/notes`, GET `/notes` |
| `identity-header-differential` | TENANT-1 | GET `/whoami` |
| `forged-signature` | BILL-2 | none declared (exempt) |
| `no-default-role` | AUTH-1 | POST `/auth/bootstrap`, POST `/auth/login`, GET `/private/member` |
| `session-rotation` | AUTH-2 | POST `/auth/bootstrap`, POST `/auth/login`, GET `/private/member` |
| `cookie-flags` | AUTH-2 | POST `/auth/bootstrap`, POST `/auth/login` |
| `logout-revokes` | AUTH-2 | POST `/auth/bootstrap`, POST `/auth/login`, POST `/auth/logout`, GET `/private/member` |
| `role-change-revokes` | AUTH-2 | POST `/auth/bootstrap`, POST `/auth/login`, POST `/users`, PATCH `/users/:id/role`, GET `/private/member` |
| `role-matrix` | AUTH-3 | POST `/auth/bootstrap`, POST `/auth/login`, POST `/users`, GET `/private/member`, GET `/private/admin`, GET `/private/owner` |
| `api-key-scope` | AUTH-4 | POST `/auth/bootstrap`, POST `/auth/login`, POST `/api-keys`, GET `/api-keys`, GET `/private/member`, GET `/private/admin`, GET `/private/owner` |
| `cross-tenant-session` | AUTH-2 | POST `/auth/bootstrap`, POST `/auth/login`, GET `/private/member` |
| `csrf-origin` | AUTH-2 | POST `/auth/bootstrap`, POST `/auth/login`, POST `/api-keys` |
| `authority-matrix` | AUTH-3 | POST `/auth/bootstrap`, POST `/auth/login`, POST `/users`, GET `/users`, GET `/api-keys` |
| `key-revocation` | AUTH-4 | POST `/auth/bootstrap`, POST `/auth/login`, POST `/users`, POST `/api-keys`, DELETE `/api-keys/:id`, PATCH `/users/:id/role`, GET `/private/admin` |
| `disabled-user-denied` | AUTH-2 | POST `/auth/bootstrap`, POST `/auth/login`, POST `/users`, DELETE `/users/:id`, GET `/private/member` |
| `key-wrong-secret-denied` | AUTH-4 | POST `/auth/bootstrap`, POST `/auth/login`, POST `/api-keys`, GET `/private/member` |
| `bootstrap-token-required` | AUTH-1 | POST `/auth/bootstrap` |
| `bootstrap-claims-once` | AUTH-1 | POST `/auth/bootstrap`, POST `/auth/login`, GET `/users`, GET `/private/owner` |
| `role-change-authority` | AUTH-3 | POST `/auth/bootstrap`, POST `/auth/login`, POST `/users`, GET `/users`, PATCH `/users/:id/role`, DELETE `/users/:id`, GET `/private/owner` |
| `key-role-ceiling` | AUTH-4 | POST `/auth/bootstrap`, POST `/auth/login`, POST `/users`, POST `/api-keys`, GET `/api-keys`, GET `/private/admin` |
| `listings-hide-secrets` | AUTH-4 | POST `/auth/bootstrap`, POST `/auth/login`, POST `/users`, POST `/api-keys`, GET `/users`, GET `/api-keys` |
| `unknown-email-login-same-answer` | AUTH-2 | POST `/auth/bootstrap`, POST `/auth/login` |
| `storage-canary-at-rest` | CRYPTO-1 | POST `/auth/bootstrap`, POST `/auth/login`, POST `/notes` |
| `secret-write-only-readback` | CRYPTO-5 | POST `/auth/bootstrap`, POST `/auth/login` |
| `aad-transplant-fails` | CRYPTO-2 | POST `/auth/bootstrap`, POST `/auth/login`, POST `/notes`, GET `/notes` |
| `shredding-makes-data-unreadable` | CRYPTO-3 | POST `/auth/bootstrap`, POST `/auth/login`, POST `/notes`, GET `/notes` |
| `nonce-uniqueness-and-rotation` | CRYPTO-4 | POST `/auth/bootstrap`, POST `/auth/login`, POST `/notes`, GET `/notes` |

## Headers

| Header | Direction | Use | Probes |
|---|---|---|---|
| `host` | request | tenant identity comes from the hostname only: `<tenant>.<host suffix>` | all |
| `cookie` | request | the session cookie (name below) | auth probes |
| `set-cookie` | response | session cookie; must be Secure, HttpOnly, Path=/, no Domain, SameSite Lax or Strict | `cookie-flags`, `session-rotation`, login in every auth probe |
| `origin` | request | same-origin on cookie writes; `http://evil.example` for the cross-origin attack | `csrf-origin`, every cookie write |
| `sec-fetch-site` | request | `same-origin` accepted without Origin | `csrf-origin` |
| `authorization` | request | `Bearer bkk_<16 hex>_<43 base64url>` API key | `api-key-scope`, `key-revocation`, `key-wrong-secret-denied`, `key-role-ceiling`, `no-default-role` |
| `x-signature` | request | HMAC-SHA256 hex of the body with the webhook secret | `forged-signature` |
| `x-tenant`, `x-tenant-id`, `x-forwarded-host`, `x-original-host`, `x-host`, `forwarded` | request | spoofed tenant identity, which must change nothing | `identity-header-differential` |

## Cookie, tokens, roles, permissions

| Item | Value | Probes |
|---|---|---|
| Session cookie name | `__Host-bk_session` (override: `cookieName`) | all auth probes |
| Session token shape | starts with `bks_` (the probes forge `bks_` + 43 characters) | `no-default-role`, `session-rotation` |
| API key shape | `bkk_` + 16 hex + `_` + 43 base64url characters | `no-default-role`, `api-key-scope`, `key-wrong-secret-denied` |
| Roles | `owner`, `admin`, `member` (fixed, not configurable) | `role-matrix`, `authority-matrix`, `role-change-authority`, `key-role-ceiling` |
| Permissions | `private:read`, `private:admin`, `self:read` | `api-key-scope`, `csrf-origin`, `key-wrong-secret-denied`, `key-role-ceiling`, `listings-hide-secrets` |
| Probe accounts | `<name>@probe.test`, password `verify-probe-password-1` | all auth probes |

## Environment values

| Value | Set by | Default (the demo's) | Probes |
|---|---|---|---|
| Bootstrap token | env `BULKHEAD_VERIFY_BOOTSTRAP_TOKEN` | none; auth probes fail loudly without it | every probe that bootstraps an owner |
| Cookie name | `--cookie-name`, or `cookieName` in `verify-target.json` | `__Host-bk_session` | all auth probes |
| Tenant host suffix | `--host-suffix`, or `hostSuffix` in `verify-target.json` | `demo.localhost` | all |
| Webhook secret | `--webhook-secret`, or `webhookSecret` in `verify-target.json` | `whsec_fixture` | `forged-signature` |
| Persisted storage directory | `--persist-dir` | none; CRYPTO-1/2/3/4 are UNVERIFIED without it | `storage-canary-at-rest`, `aad-transplant-fails`, `shredding-makes-data-unreadable`, `nonce-uniqueness-and-rotation` |
| Route manifest | `--route-manifest` | none; see "How a missing piece is reported" | all (the `needs` guard), `secret-write-only-readback` |

`verify-target.json` sits next to the route manifest and holds any of `cookieName`, `hostSuffix`, `webhookSecret` (unknown keys are refused). Flags override the file. The webhook secret is the secret of a registered test environment, so committing it is acceptable; never put a production secret there. Role names and the route paths above are not configurable: an app that wants to be verified implements them.
