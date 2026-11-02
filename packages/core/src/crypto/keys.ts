// Key hierarchy (CRYPTO-3, CRYPTO-4, BOOT-1). A versioned master key (Worker secret) wraps a per-tenant data key; the data key seals fields.
// Wrapped data keys live in the control-plane D1, not in the tenant's object, so deleting a tenant's row shreds it.
import type { D1Like } from "../tenant/types.ts";
import { fromBase64Url, parseEnvelope, toBase64Url } from "./envelope.ts";
import { CryptoError, importDataKey, openText, seal as sealEnvelope, type DataKey, type SealContext } from "./port.ts";
import { nonceFromCounter } from "./nonce.ts";
import { isEncryptedClass, lookupField, type Classification } from "./classification.ts";

export class MasterKeyError extends Error {}
export class KeyUnavailableError extends Error {}

export interface MasterKeys {
  current: number;
  raw: ReadonlyMap<number, Uint8Array>;
}

/** BOOT-1: `BULKHEAD_MASTER_KEY_CURRENT` names the version; `BULKHEAD_MASTER_KEY_V<n>` holds 32 base64url/base64 bytes. Missing or malformed anything throws. */
export function loadMasterKeys(env: Record<string, unknown>): MasterKeys {
  const cur = env.BULKHEAD_MASTER_KEY_CURRENT;
  if (typeof cur !== "string" || !/^[1-9][0-9]{0,5}$/.test(cur)) throw new MasterKeyError("BULKHEAD_MASTER_KEY_CURRENT must be a key version number");
  const raw = new Map<number, Uint8Array>();
  for (const [name, value] of Object.entries(env)) {
    const m = /^BULKHEAD_MASTER_KEY_V([1-9][0-9]{0,5})$/.exec(name);
    if (!m) continue;
    if (typeof value !== "string") throw new MasterKeyError(`${name} must be a string`);
    let bytes: Uint8Array;
    const decoded = fromBase64Url(value.replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, ""));
    if (!decoded) throw new MasterKeyError(`${name} is not base64`);
    bytes = decoded;
    if (bytes.length !== 32) throw new MasterKeyError(`${name} must be exactly 32 bytes`);
    raw.set(Number(m[1]), bytes);
  }
  if (!raw.has(Number(cur))) throw new MasterKeyError(`BULKHEAD_MASTER_KEY_V${cur} is missing`);
  return { current: Number(cur), raw };
}

export const KEY_CACHE_MS = 60_000;

const wrapAad = (tenantId: string, version: number, masterVersion: number) => new TextEncoder().encode(`bulkhead/wrap/v1|${tenantId}|${version}|${masterVersion}`);

export interface KeyRing {
  /** Creates the tenant's first data key if the tenant has no key rows at all. A shredded tenant keeps its (emptied) rows, so it is never re-keyed. */
  ensureTenantKey(tenantId: string): Promise<void>;
  current(tenantId: string): Promise<{ version: number; key: DataKey }>;
  get(tenantId: string, version: number): Promise<DataKey>;
  /** Adds a new data key version. Old versions stay readable. */
  rotate(tenantId: string): Promise<number>;
  /** Destroys every data key of the tenant (CRYPTO-3). Effective in this isolate at once and in others within KEY_CACHE_MS. */
  shred(tenantId: string): Promise<void>;
}

interface KeyRow { version: number; master_version: number; wrapped: string | null }

export function createKeyRing(db: D1Like, master: MasterKeys, now: () => number = Date.now, ttlMs = KEY_CACHE_MS): KeyRing {
  const masterKeys = new Map<number, Promise<DataKey>>();
  const masterKey = (v: number) => {
    const raw = master.raw.get(v);
    if (!raw) throw new KeyUnavailableError(`master key version ${v} is not configured`);
    let k = masterKeys.get(v);
    if (!k) masterKeys.set(v, (k = importDataKey(raw)));
    return k;
  };
  const cache = new Map<string, { key: DataKey; until: number }>();
  const latest = new Map<string, { version: number; until: number }>();
  const ensured = new Map<string, number>();
  let ready: Promise<unknown> | undefined;
  const schema = () => (ready ??= db.prepare("create table if not exists tenant_keys (tenant_id text not null, version integer not null, master_version integer not null, wrapped text, created_at integer not null, shredded_at integer, primary key (tenant_id, version))").run().catch((e) => { ready = undefined; throw e; }));

  async function wrap(tenantId: string, version: number): Promise<string> {
    const dataKey = crypto.getRandomValues(new Uint8Array(32));
    const nonce = crypto.getRandomValues(new Uint8Array(12)); // few wraps ever happen under a master key; a random nonce is within bounds here
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce as BufferSource, additionalData: wrapAad(tenantId, version, master.current) as BufferSource }, (await masterKey(master.current)).cryptoKey, dataKey));
    return toBase64Url(Uint8Array.from([...nonce, ...ct]));
  }

  async function unwrap(tenantId: string, row: KeyRow): Promise<DataKey> {
    if (row.wrapped === null) throw new KeyUnavailableError("tenant key destroyed");
    const blob = fromBase64Url(row.wrapped);
    if (!blob) throw new KeyUnavailableError("tenant key cannot be unwrapped");
    try {
      const raw = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: blob.slice(0, 12) as BufferSource, additionalData: wrapAad(tenantId, row.version, row.master_version) as BufferSource }, (await masterKey(row.master_version)).cryptoKey, blob.slice(12) as BufferSource));
      return await importDataKey(raw);
    } catch (e) {
      if (e instanceof KeyUnavailableError) throw e;
      throw new KeyUnavailableError("tenant key cannot be unwrapped");
    }
  }

  const rows = async (tenantId: string) => (await db.prepare("select version, master_version, wrapped from tenant_keys where tenant_id = ? order by version").bind(tenantId).all<KeyRow>()).results;

  async function insertVersion(tenantId: string, version: number) {
    const wrapped = await wrap(tenantId, version);
    await db.prepare("insert or ignore into tenant_keys (tenant_id, version, master_version, wrapped, created_at) values (?, ?, ?, ?, ?)").bind(tenantId, version, master.current, wrapped, now()).run();
  }

  const ring: KeyRing = {
    async ensureTenantKey(tenantId) {
      if ((ensured.get(tenantId) ?? 0) > now()) return;
      await schema();
      if ((await rows(tenantId)).length === 0) await insertVersion(tenantId, 1);
      ensured.set(tenantId, now() + ttlMs);
    },
    async get(tenantId, version) {
      const id = `${tenantId}:${version}`;
      const hit = cache.get(id);
      if (hit && hit.until > now()) return hit.key;
      cache.delete(id);
      await schema();
      const row = (await rows(tenantId)).find((r) => r.version === version);
      if (!row) throw new KeyUnavailableError("unknown key version");
      const key = await unwrap(tenantId, row);
      cache.set(id, { key, until: now() + ttlMs });
      return key;
    },
    async current(tenantId) {
      let version = latest.get(tenantId);
      if (!version || version.until <= now()) {
        await ring.ensureTenantKey(tenantId);
        const all = await rows(tenantId);
        const last = all[all.length - 1];
        if (!last) throw new KeyUnavailableError("tenant has no key");
        if (last.wrapped === null) throw new KeyUnavailableError("tenant key destroyed");
        version = { version: last.version, until: now() + ttlMs };
        latest.set(tenantId, version);
      }
      return { version: version.version, key: await ring.get(tenantId, version.version) };
    },
    async rotate(tenantId) {
      await schema();
      const all = await rows(tenantId);
      if (all.length === 0 || all.some((r) => r.wrapped === null)) throw new KeyUnavailableError("tenant key destroyed or absent");
      const next = (all[all.length - 1] as KeyRow).version + 1;
      await insertVersion(tenantId, next);
      latest.delete(tenantId);
      return next;
    },
    async shred(tenantId) {
      await schema();
      await ring.ensureTenantKey(tenantId); // a never-keyed tenant still gets marker rows, so a later request cannot mint a fresh key
      await db.prepare("update tenant_keys set wrapped = null, shredded_at = ? where tenant_id = ?").bind(now(), tenantId).run();
      latest.delete(tenantId);
      for (const k of [...cache.keys()]) if (k.startsWith(`${tenantId}:`)) cache.delete(k);
    },
  };
  return ring;
}

export interface Sealer {
  seal(table: string, field: string, plaintext: string): Promise<string>;
  open(table: string, field: string, sealed: string): Promise<string>;
}

/** The sealing path a tenant handle exposes. It only seals fields classified sensitive or secret, and it never opens a write-only field (CRYPTO-5). */
export function createSealer(tenantId: string, ring: KeyRing, classification: Classification, reserveNonce: (keyVersion: number) => Promise<number>): Sealer {
  const check = (table: string, field: string, opening: boolean) => {
    const f = lookupField(classification, table, field);
    if (!f || !isEncryptedClass(f.class)) throw new CryptoError(`${table}.${field} is not a sealed field`);
    if (opening && f.writeOnly) throw new CryptoError(`${table}.${field} is write-only`);
  };
  return {
    async seal(table, field, plaintext) {
      check(table, field, false);
      const { version, key } = await ring.current(tenantId);
      const ctx: SealContext = { tenantId, table, field, keyVersion: version };
      return sealEnvelope(key, ctx, nonceFromCounter(await reserveNonce(version)), plaintext);
    },
    async open(table, field, sealed) {
      check(table, field, true);
      const env = parseEnvelope(sealed);
      if (!env) throw new CryptoError("cannot open");
      return openText(await ring.get(tenantId, env.keyVersion), { tenantId, table, field, keyVersion: env.keyVersion }, sealed);
    },
  };
}
