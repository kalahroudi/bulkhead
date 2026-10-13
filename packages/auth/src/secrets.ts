// Password hashing and random tokens, on WebCrypto only so it runs in workerd and Node alike.
const enc = new TextEncoder();

export const b64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64url = (s: string): Uint8Array<ArrayBuffer> => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const hex = (buf: ArrayBuffer) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

export const randomToken = (bytes = 32) => b64url(crypto.getRandomValues(new Uint8Array(bytes)));

/** SHA-256 hex. Only for high-entropy random tokens; passwords go through `hashPassword`. */
export const sha256 = async (value: string) => hex(await crypto.subtle.digest("SHA-256", enc.encode(value)));

/** Constant-time string comparison (both sides are hashes of equal length in practice). */
export function safeEqual(a: string, b: string): boolean {
  const x = enc.encode(a);
  const y = enc.encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

// Workers' WebCrypto caps PBKDF2 at 100,000 iterations, so that is the ceiling. Parameters are stored with
// each hash so they can be raised later without invalidating existing passwords.
const PBKDF2_ITERATIONS = 100_000;

async function derive(password: string, salt: Uint8Array<ArrayBuffer>, iterations: number): Promise<string> {
  const key = await crypto.subtle.importKey("raw", enc.encode(password.normalize("NFKC")), "PBKDF2", false, ["deriveBits"]);
  return b64url(new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256)));
}

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(new ArrayBuffer(16)));
  return `pbkdf2-sha256$${PBKDF2_ITERATIONS}$${b64url(salt)}$${await derive(password, salt, PBKDF2_ITERATIONS)}`;
}

const DUMMY = hashPassword("bulkhead dummy password for unknown users");

/** Verifies against a stored hash. With `null` (unknown user) it still does the full work, so timing does not reveal which emails exist. */
export async function verifyPassword(password: string, stored: string | null): Promise<boolean> {
  const [alg, iterations, salt, hash] = (stored ?? (await DUMMY)).split("$");
  const n = Number(iterations);
  if (alg !== "pbkdf2-sha256" || !Number.isInteger(n) || n < 1 || n > PBKDF2_ITERATIONS || !salt || !hash) return false;
  const ok = safeEqual(await derive(password, fromB64url(salt), n), hash);
  return stored !== null && ok;
}
