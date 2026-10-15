import { test } from "node:test";
import assert from "node:assert/strict";
import { fromBase64Url, toBase64Url } from "../src/crypto/envelope.ts";
import { CryptoError, importDataKey, isSealed, open, openText, parseEnvelope, seal, additionalData, type SealContext } from "../src/crypto/index.ts";

const raw = (fill: number) => new Uint8Array(32).fill(fill);
const nonce = (n: number) => {
  const b = new Uint8Array(12);
  new DataView(b.buffer).setUint32(8, n);
  return b;
};
const ctx: SealContext = { tenantId: "acme", table: "notes", field: "text", keyVersion: 1 };
const rejects = (p: Promise<unknown>, msg = "cannot open") => assert.rejects(p, (e: unknown) => e instanceof CryptoError && e.message === msg);

test("CRYPTO-1: a sealed value round-trips, is self-describing and does not contain the plaintext", async () => {
  const key = await importDataKey(raw(1));
  const sealed = await seal(key, ctx, nonce(1), "canary-plaintext-value");
  assert.match(sealed, /^bk1:1:[A-Za-z0-9_-]{16}:[A-Za-z0-9_-]+$/);
  assert.ok(!sealed.includes("canary-plaintext-value"));
  assert.ok(!Buffer.from(sealed).includes("canary-plaintext-value"));
  assert.ok(isSealed(sealed));
  assert.equal(await openText(key, ctx, sealed), "canary-plaintext-value");
  assert.deepEqual(await open(key, ctx, await seal(key, ctx, nonce(2), new Uint8Array([0, 1, 255]))), new Uint8Array([0, 1, 255]));
  assert.equal(await openText(key, ctx, await seal(key, ctx, nonce(3), "")), "");
});

test("CRYPTO-2: the ciphertext opens only in the tenant, table, field and key version it was sealed for", async () => {
  const key = await importDataKey(raw(1));
  const sealed = await seal(key, ctx, nonce(1), "secret");
  await rejects(open(key, { ...ctx, tenantId: "other" }, sealed));
  await rejects(open(key, { ...ctx, table: "tasks" }, sealed));
  await rejects(open(key, { ...ctx, field: "title" }, sealed));
  await rejects(open(key, { ...ctx, keyVersion: 2 }, sealed));
  // The AAD, not just the envelope header, carries the key version: forging the header does not help.
  const forged = sealed.replace(/^bk1:1:/, "bk1:2:");
  await rejects(open(key, { ...ctx, keyVersion: 2 }, forged));
  assert.equal(await openText(key, ctx, sealed), "secret");
});

test("CRYPTO-2: contexts that would collide as strings are refused, not accepted", async () => {
  const key = await importDataKey(raw(1));
  // Without the separator check these two contexts would produce the same AAD.
  assert.throws(() => additionalData({ ...ctx, tenantId: "a|b", table: "c" }), CryptoError);
  assert.throws(() => additionalData({ ...ctx, table: "x|y" }), CryptoError);
  assert.throws(() => additionalData({ ...ctx, field: "" }), CryptoError);
  for (const keyVersion of [0, -1, 1.5, NaN, Number.MAX_SAFE_INTEGER + 2]) assert.throws(() => additionalData({ ...ctx, keyVersion }), CryptoError);
  await assert.rejects(seal(key, { ...ctx, tenantId: "a|b" }, nonce(1), "x"), CryptoError);
  await assert.rejects(open(key, { ...ctx, tenantId: "a|b" }, "bk1:1:x:y"), CryptoError);
});

test("tampering with any part of a sealed value, or using another key, fails to open", async () => {
  const key = await importDataKey(raw(1));
  const sealed = await seal(key, ctx, nonce(1), "secret value");
  const [prefix, v, n, c] = sealed.split(":") as [string, string, string, string];
  const flip = (s: string) => (s[0] === "A" ? "B" : "A") + s.slice(1);
  await rejects(open(key, ctx, `${prefix}:${v}:${flip(n)}:${c}`));
  await rejects(open(key, ctx, `${prefix}:${v}:${n}:${flip(c)}`));
  await rejects(open(key, ctx, `${prefix}:${v}:${n}:${c.slice(0, -2)}`));
  await rejects(open(await importDataKey(raw(2)), ctx, sealed));
});

test("malformed envelopes are not sealed values and do not open; one error for every reason", async () => {
  const key = await importDataKey(raw(1));
  const good = await seal(key, ctx, nonce(1), "x");
  const [, v, n, c] = good.split(":") as [string, string, string, string];
  const bad = [
    "", "plaintext", "bk1:", "bk1:1", "bk1:1:a", `bk1:1:${n}`, `bk1:1:${n}:`, `bk1:1:${n}:${c}:extra`, `bk2:${v}:${n}:${c}`, `BK1:${v}:${n}:${c}`,
    `bk1:0:${n}:${c}`, `bk1:01:${n}:${c}`, `bk1:-1:${n}:${c}`, `bk1:1.5:${n}:${c}`, `bk1:99999999999999999:${n}:${c}`,
    `bk1:${v}:${n}=:${c}`, `bk1:${v}:${n.slice(0, -1)}:${c}`, `bk1:${v}:${n}:${c}=`, `bk1:${v}:${n}:${c}+`, `bk1:${v}:${n} :${c}`,
    `bk1:${v}:${n}:AAAA`,
  ];
  for (const b of bad) {
    assert.equal(parseEnvelope(b), null, b);
    assert.equal(isSealed(b), false, b);
    await rejects(open(key, ctx, b));
  }
  assert.equal(isSealed("bk1:looks-sealed-but-is-not"), false);
  assert.equal(isSealed(undefined), false);
  assert.equal(isSealed(42), false);
  // A non-canonical spelling of valid bytes (unused trailing bits set) is refused rather than aliased.
  assert.deepEqual(fromBase64Url("AA"), new Uint8Array([0]));
  assert.equal(fromBase64Url("AB"), null);
  assert.equal(fromBase64Url("A"), null);
  assert.equal(fromBase64Url("AA=="), null);
  assert.equal(toBase64Url(new Uint8Array([251, 255, 254])), "-__-");
  assert.deepEqual(fromBase64Url("-__-"), new Uint8Array([251, 255, 254]));
  assert.equal(fromBase64Url("+//+"), null);
});

test("CRYPTO-4: the port never picks a nonce, rejects a wrong-sized one, and distinct nonces give distinct ciphertexts", async () => {
  const key = await importDataKey(raw(1));
  for (const len of [0, 11, 13, 16]) await assert.rejects(seal(key, ctx, new Uint8Array(len), "x"), CryptoError);
  const a = await seal(key, ctx, nonce(1), "same");
  const b = await seal(key, ctx, nonce(2), "same");
  assert.notEqual(a, b);
  assert.equal(a, await seal(key, ctx, nonce(1), "same"), "same key, nonce and context is deterministic: reuse would leak equality, so the caller must never reuse");
  assert.equal(seal.length, 4, "seal takes the nonce as an argument: there is no default");
});

test("keys must be 32 bytes, and an imported key cannot be exported", async () => {
  for (const len of [0, 16, 31, 33, 64]) await assert.rejects(importDataKey(new Uint8Array(len)), CryptoError);
  const key = await importDataKey(raw(1));
  assert.equal(key.cryptoKey.extractable, false);
  await assert.rejects(crypto.subtle.exportKey("raw", key.cryptoKey));
});

test("a sealed value is not mutated by the caller's buffers: nonce and plaintext arrays are copied or read once", async () => {
  const key = await importDataKey(raw(1));
  const n = nonce(7);
  const sealed = await seal(key, ctx, n, "x");
  n.fill(0xff);
  assert.equal(await openText(key, ctx, sealed), "x");
});
