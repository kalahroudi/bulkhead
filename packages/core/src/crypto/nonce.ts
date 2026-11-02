import { CryptoError } from "./port.ts";
import { NONCE_BYTES } from "./envelope.ts";

/** CRYPTO-4: the 96-bit nonce is a counter (4 zero bytes, then a 64-bit big-endian count), so under one key it is unique by construction. */
export function nonceFromCounter(counter: number): Uint8Array {
  if (!Number.isSafeInteger(counter) || counter < 1) throw new CryptoError("bad nonce counter");
  const out = new Uint8Array(NONCE_BYTES);
  new DataView(out.buffer).setBigUint64(4, BigInt(counter));
  return out;
}
