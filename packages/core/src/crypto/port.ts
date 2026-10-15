// The crypto port (CRYPTO-1, CRYPTO-2): AES-256-GCM through WebCrypto, the only primitive on Workers.
// Callers supply the nonce (CRYPTO-4): the port never invents one, so uniqueness is the caller's structural
// guarantee (a counter, DR-0010 choice 3) and cannot be silently replaced by a random default here.

import { formatEnvelope, isKeyVersion, NONCE_BYTES, parseEnvelope } from "./envelope.ts";

/** Where a sealed value lives. All of it is bound into the ciphertext as additional authenticated data. */
export interface SealContext {
  tenantId: string;
  table: string;
  field: string;
  keyVersion: number;
}

export class CryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CryptoError";
  }
}

const KEY_BYTES = 32;
const AAD_VERSION = "bulkhead/v1";
const encoder = new TextEncoder();
/** A private copy backed by a plain ArrayBuffer, which is what WebCrypto accepts, and which the caller cannot mutate under us. */
/** Strict both ways: a leading BOM is data, not noise, and invalid UTF-8 is a CryptoError, not a raw TypeError. */
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
function decodeUtf8(bytes: Uint8Array): string {
  try {
    return decoder.decode(bytes);
  } catch {
    throw new CryptoError("cannot open");
  }
}
/** True when the text has no lone surrogate, which UTF-8 encoding would silently replace with U+FFFD. */
const wellFormed = (t: string) => !/\p{Cs}/u.test(t);
const copy = (b: Uint8Array) => new Uint8Array(b);

/** An imported, non-extractable AES-256-GCM key. Opaque on purpose: it cannot be read back out. */
export interface DataKey {
  readonly cryptoKey: CryptoKey;
}

export async function importDataKey(raw: Uint8Array): Promise<DataKey> {
  if (!(raw instanceof Uint8Array) || raw.length !== KEY_BYTES) throw new CryptoError(`data key must be ${KEY_BYTES} bytes`);
  const cryptoKey = await crypto.subtle.importKey("raw", copy(raw), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  return { cryptoKey };
}

/** `|` separates the parts, so a part containing it could make two different contexts produce the same AAD. */
function part(label: string, value: string): string {
  if (typeof value !== "string" || value.length === 0 || value.includes("|") || !wellFormed(value)) {
    throw new CryptoError(`${label} must be a non-empty, well-formed string without "|"`);
  }
  return value;
}

export function additionalData(ctx: SealContext): Uint8Array {
  if (!isKeyVersion(ctx.keyVersion)) throw new CryptoError("keyVersion must be a positive integer");
  return encoder.encode(
    [AAD_VERSION, part("tenantId", ctx.tenantId), part("table", ctx.table), part("field", ctx.field), String(ctx.keyVersion)].join("|"),
  );
}

export async function seal(key: DataKey, ctx: SealContext, nonce: Uint8Array, plaintext: string | Uint8Array): Promise<string> {
  if (!(nonce instanceof Uint8Array) || nonce.length !== NONCE_BYTES) throw new CryptoError(`nonce must be ${NONCE_BYTES} bytes`);
  if (typeof plaintext === "string" && !wellFormed(plaintext)) throw new CryptoError("plaintext must be well-formed text: a lone surrogate would be altered on the way in");
  if (typeof plaintext !== "string" && !(plaintext instanceof Uint8Array)) throw new CryptoError("plaintext must be a string or bytes");
  // Take private copies before the first await: the caller may touch its buffers while the encryption is in flight.
  const iv = copy(nonce);
  const data = typeof plaintext === "string" ? encoder.encode(plaintext) : copy(plaintext);
  const additional = additionalData(ctx);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: copy(additional), tagLength: 128 }, key.cryptoKey, data),
  );
  return formatEnvelope({ keyVersion: ctx.keyVersion, nonce: iv, ciphertext });
}

/**
 * Opens a sealed value only for the exact context it was sealed in. Every failure that depends on the stored value or
 * the key (malformed envelope, other key version, other tenant, table or field, tampering, wrong key, invalid text)
 * throws the same CryptoError("cannot open"). A malformed caller-supplied context throws its own message first.
 */
export async function open(key: DataKey, ctx: SealContext, sealed: string): Promise<Uint8Array> {
  const additional = additionalData(ctx);
  const env = parseEnvelope(sealed);
  if (!env || env.keyVersion !== ctx.keyVersion) throw new CryptoError("cannot open");
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv: copy(env.nonce), additionalData: copy(additional), tagLength: 128 }, key.cryptoKey, copy(env.ciphertext)),
    );
  } catch {
    throw new CryptoError("cannot open");
  }
}

export async function openText(key: DataKey, ctx: SealContext, sealed: string): Promise<string> {
  return decodeUtf8(await open(key, ctx, sealed));
}
