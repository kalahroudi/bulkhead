// Sealed-value envelope: `bk1:<keyVersion>:<nonce>:<ciphertext>`, nonce and ciphertext base64url without padding.
// The `bk1:` prefix is what storage can enforce structurally (CRYPTO-1); everything else is for the port.

export const ENVELOPE_PREFIX = "bk1:";
export const NONCE_BYTES = 12;
export const TAG_BYTES = 16;

export interface Envelope {
  keyVersion: number;
  nonce: Uint8Array;
  /** AES-GCM output: ciphertext followed by the 16-byte tag. */
  ciphertext: Uint8Array;
}

const B64URL = /^[A-Za-z0-9_-]*$/;

export function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Strict: only the canonical encoding of some byte string is accepted, so two spellings never open to the same value. */
export function fromBase64Url(text: string): Uint8Array | null {
  if (!B64URL.test(text) || text.length % 4 === 1) return null;
  let bin: string;
  try {
    bin = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  } catch {
    return null;
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return toBase64Url(out) === text ? out : null;
}

export function isKeyVersion(n: unknown): n is number {
  return typeof n === "number" && Number.isSafeInteger(n) && n >= 1;
}

export function formatEnvelope(e: Envelope): string {
  return `${ENVELOPE_PREFIX}${e.keyVersion}:${toBase64Url(e.nonce)}:${toBase64Url(e.ciphertext)}`;
}

/** Returns null for anything that is not exactly a well-formed envelope. Never throws. */
export function parseEnvelope(value: string): Envelope | null {
  if (typeof value !== "string" || !value.startsWith(ENVELOPE_PREFIX)) return null;
  const parts = value.slice(ENVELOPE_PREFIX.length).split(":");
  if (parts.length !== 3) return null;
  const [v, n, c] = parts as [string, string, string];
  if (!/^[1-9][0-9]{0,15}$/.test(v)) return null;
  const keyVersion = Number(v);
  if (!isKeyVersion(keyVersion)) return null;
  const nonce = fromBase64Url(n);
  const ciphertext = fromBase64Url(c);
  if (!nonce || !ciphertext || nonce.length !== NONCE_BYTES || ciphertext.length < TAG_BYTES) return null;
  return { keyVersion, nonce, ciphertext };
}

/** True only for a well-formed envelope, not for any string that merely starts with the prefix. */
export function isSealed(value: unknown): boolean {
  return typeof value === "string" && parseEnvelope(value) !== null;
}
