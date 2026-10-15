# DR-0010: Phase 4 crypto scoping (CRYPTO-1..5): design, order of work and open questions

- Status: proposed (owner answered all six open questions in session on 2026-10-14; the owner has not yet marked this record accepted, so no crypto work starts)
- Date: 2026-10-13
- Rules: CRYPTO-1, CRYPTO-2, CRYPTO-3, CRYPTO-4, CRYPTO-5, BOOT-1

## Context
The spec fixes the goals; it does not fix the design. What it already decides:
- Data classes are `public, internal, personal, sensitive, secret`; `sensitive` and `secret` are the encrypted classes (`ENCRYPTED_CLASSES`), `secret` must be `writeOnly`, and an unclassified field blocks a green verify (`packages/spec/src/formats.ts`).
- CRYPTO-1: classified data never reaches storage as plaintext, proved by a storage-inspector canary.
- CRYPTO-2: sealed fields bind tenant, table and field as additional authenticated data (AAD); ciphertext moved elsewhere fails to open.
- CRYPTO-3: a master key wraps a per-tenant data key, which seals fields; destroying the data key shreds the tenant.
- CRYPTO-4: nonces are never reused under one key; key versions allow rotation without data loss.
- CRYPTO-5: tenant secrets are write-only through every route.
- BOOT-1: missing keys fail closed at boot, never a plaintext fallback.

Nothing of this exists yet: `packages/core/src/crypto/` does not exist. That path is frozen and CODEOWNERS-protected, so building it needs this record accepted. The platform is Cloudflare Workers, so the only primitive is WebCrypto (no XChaCha20, no in-process KMS).

## Decision
Proposed design, each choice with a recommendation. The owner may override any of them.
1. **Scope and order: probes first, then code.** Per CLAUDE.md, each rule's black-box check and its catalog entries are written and shown failing before the implementation: (a) the harness storage inspector and a seeded-bug fixture; (b) the crypto port; (c) classification enforcement; (d) AAD transplant; (e) key hierarchy and shredding; (f) nonces and rotation; (g) write-only secrets. Each step ends with a green `gate:phase4`, an independent review, and a merge. No check: this is a work order, and the checks it names are built in the steps themselves.
2. **Primitive: AES-256-GCM via WebCrypto**, envelope `bk1:<keyVersion>:<nonce>:<ciphertext>` (base64url), so a sealed value is self-describing and its prefix can be enforced structurally. Check: `test:packages/core/test/crypto.test.ts::CRYPTO-1: a sealed value round-trips, is self-describing and does not contain the plaintext`, `test:packages/core/test/crypto.test.ts::malformed envelopes are not sealed values and do not open; one error for every reason`. Built in step (b) (`packages/core/src/crypto/`); the CHECK constraint that makes storage enforce the `bk1:` prefix is step (c).
3. **Nonces (CRYPTO-4): a per-key-version counter held in the tenant's own Durable Object,** incremented in the same atomic storage operation as the write, so uniqueness is guaranteed by structure rather than by probability. Random 96-bit nonces would need a message-count budget and cannot be proven unique by a black-box scenario. Cost: one counter write per seal. Check: `test:packages/core/test/crypto.test.ts::CRYPTO-4: the port never picks a nonce, rejects a wrong-sized one, and distinct nonces give distinct ciphertexts`. The port takes the nonce from the caller and has no default; the counter itself and the uniqueness scenario are step (f).
4. **AAD (CRYPTO-2): `bulkhead/v1|<tenantId>|<table>|<field>|<keyVersion>`.** This is what the spec requires. It does not bind the row, so ciphertext can be swapped between rows of the same column in one tenant. Binding the row id would close that but needs a spec amendment, which only the owner can make (open question 2). Check: `test:packages/core/test/crypto.test.ts::CRYPTO-2: the ciphertext opens only in the tenant, table, field and key version it was sealed for`. The port (step b) binds the AAD and refuses contexts containing `|`; the black-box transplant scenario through the running app is step (d).
5. **Keys (CRYPTO-3): master key as a versioned Worker secret** (`BULKHEAD_MASTER_KEY_V<n>`; BOOT-1 refuses to boot without the current version). A per-tenant data key is generated at provision time and stored wrapped under the master key, with the tenant id as wrap AAD, **in the control-plane D1, not in the tenant's Durable Object.** Shredding is then deleting that one row; the tenant's ciphertext is unreadable even if its object survives. Data keys are cached in isolate memory for at most 60 seconds, so shredding takes effect everywhere within a minute (open question 4). No check: the key hierarchy does not exist yet; BOOT-1's missing-key probe and the shredding scenario are built in step (e).
6. **Structural enforcement (CRYPTO-1):** the classification file (`bulkhead.classification.json`, validated by `validateClassification`) generates `CHECK (col LIKE 'bk1:%')` on every `sensitive` and `secret` column, so a plaintext insert fails in the database itself, and the tenant handle gains a sealed write path. At tenant initialisation every column must be classified or the tenant refuses to initialise (fail closed, as BOOT-1). Raw `run`/`query` stay, because unclassified columns need them; the CHECK constraint, not discipline, protects classified ones. No check: the CHECK generation and the unclassified-column refusal are built in step (c), with catalog entries for each.
7. **Verification needs a storage inspector, and over HTTP none can exist.** Recommended: the gate launcher (`scripts/verify-kernel.ts`) owns the local `--persist-to` directory, so it passes that path to verify, which opens the tenant SQLite files **read-only** and scans for the canary. Verify still never imports app code. On a non-local target (staging, production) no inspector is available, so CRYPTO-1 and CRYPTO-3 are reported **unverified, never green** there. Check: `test:packages/verify/test/inspector.test.ts::inspector never writes: the handle is read-only and a scan leaves every byte of the directory as it was`, `test:packages/verify/test/inspector.test.ts::without a storage directory the CRYPTO-1 probe is UNVERIFIED, never a pass, and the run is not green`. Built in step (a): the inspector reads the directory read-only and is directory-wide (it cannot tell which tenant's file changed); it has only been exercised against the verify fixture, not against workerd's real persist layout.
8. **Write-only secrets (CRYPTO-5):** a secret has a store route and no read route; verify reads the committed route manifest (ROUTE-2) and exercises every route whose manifest entry could return it, looking for the canary. Auth hashes (`password_hash`, `secret_hash`) stay hashed, not sealed, in v1: they are not recoverable by decryption. Check: `test:packages/verify/test/inspector.test.ts::CRYPTO-5 coverage: only the owner's answer counts, a parameter route needs a 2xx, and {x} [x] * are parameters too`. Step (a) built the verify side only, and it reads GET/HEAD routes (parameters filled with the secret's name and id) and assumes a store route `POST /secrets {name, value}`; the real store route and non-GET routes that could echo a secret are step (g).
9. **Honest limits, stated now.** The master key is a Worker secret, readable by anyone with deploy or secret-read rights on the Cloudflare account; there is no HSM or external KMS. Cloudflare's own at-rest encryption is not relied on. Memory in a running isolate holds a plaintext data key for up to 60 seconds. Shredding does not reach backups Cloudflare may hold. Master-key rotation needs a re-wrap job that this record does not scope. A green report still means no known leak paths, not proof of none. No check: these are limits, not behaviours, so nothing can enforce them.

## Open questions for the owner (recommended answers first)
1. Nonces: counter in the tenant object (recommended, provable) or random with a budget (simpler, probabilistic)?
2. AAD: keep the spec's three fields (recommended for v1, weaker) or amend CRYPTO-2 to add the row id (stronger, spec edit by you)?
3. Inspector: local persisted-files only, with staging and production reported unverified (recommended), or build a deployed test-only inspector endpoint (larger attack surface, rejected by the fail-closed rule unless you want it)?
4. Data-key cache: 60 seconds (recommended), shorter at a per-request D1 read, or longer?
5. Demo coverage: classify the demo's `notes.text` as `sensitive` and add a write-only `tenant_secrets` table so every rule has something to bite on (recommended), or keep the demo unchanged and use a dedicated fixture app?
6. Master-key custody for production: Worker secret (recommended for now) or an external KMS later as its own record?

## Owner answers (2026-10-14)
The owner approved the recommended answer to all six questions:
1. Nonces: counter in the tenant's Durable Object.
2. AAD: the spec's three fields (tenant, table, field) plus key version; no row id, no spec amendment.
3. Inspector: local persisted files only; staging and production report CRYPTO-1 and CRYPTO-3 as unverified.
4. Data-key cache: 60 seconds.
5. Demo coverage: extend the existing demo (`notes.text` as `sensitive`, a write-only `tenant_secrets` table); no separate fixture app.
6. Master-key custody: Worker secret now; an external KMS would be its own record.

Order of work agreed in session: this record's crypto steps (a) to (g) first, then the Better Auth spike (DR-0011), then making the verifier usable against an app other than the demo. Each needs its own go-ahead if the scope changes.

## Consequences
Accepting this record unlocks step (a) only: the inspector, fixture and failing probes, with no implementation. Each later step is its own PR with the full gate and an independent review. CRYPTO rules stay `proposed` throughout; no attestation exists until Phase 7.
