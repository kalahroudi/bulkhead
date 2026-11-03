// Small WebCrypto helpers for the spike's own API keys (copied in shape from @kalahroudi/bulkhead-auth, which does not export them).
const enc = new TextEncoder();
const hex = (buf: ArrayBuffer) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const b64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

export const sha256 = async (v: string) => hex(await crypto.subtle.digest("SHA-256", enc.encode(v)));
export function safeEqual(a: string, b: string): boolean {
  const x = enc.encode(a), y = enc.encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}
export function newKey(): { id: string; secret: string; token: string } {
  const id = [...crypto.getRandomValues(new Uint8Array(8))].map((b) => b.toString(16).padStart(2, "0")).join("");
  const secret = b64url(crypto.getRandomValues(new Uint8Array(32)));
  return { id, secret, token: `bkk_${id}_${secret}` };
}
