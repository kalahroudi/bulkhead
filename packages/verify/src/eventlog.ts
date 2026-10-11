// Hash-chained, signed event log (producer side). Format: bulkhead.event/1 from @kalahroudi/bulkhead-spec.
import { createHash, createPrivateKey, generateKeyPairSync, sign } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { GENESIS_PREV, type BulkheadEvent, type EventType } from "@kalahroudi/bulkhead-spec";

export function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object")
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`).join(",")}}`;
  return JSON.stringify(v);
}

export type UnsignedEvent = Omit<BulkheadEvent, "hash" | "signature">;

export function hashEvent(e: UnsignedEvent): string {
  return `sha256:${createHash("sha256").update(canonical(e)).digest("hex")}`;
}

/** Creates the producer's Ed25519 key on first use. The public half goes to trusted/ for readers. */
function loadKey(dir: string, producer: string) {
  const priv = join(dir, "keys", `${producer}.key`);
  if (!existsSync(priv)) {
    mkdirSync(join(dir, "keys"), { recursive: true });
    mkdirSync(join(dir, "trusted"), { recursive: true });
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    writeFileSync(priv, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
    writeFileSync(join(dir, "trusted", `${producer}.pub`), publicKey.export({ type: "spki", format: "pem" }));
  }
  return createPrivateKey(readFileSync(priv));
}

export class EventLog {
  readonly dir: string;
  readonly producer: string;
  readonly path: string;
  private key;
  constructor(dir: string, producer: string) {
    this.dir = dir;
    this.producer = producer;
    mkdirSync(dir, { recursive: true });
    this.path = join(dir, "events.jsonl");
    this.key = loadKey(dir, producer);
  }

  append(type: EventType, data: Record<string, unknown>): BulkheadEvent {
    let seq = 0;
    let prev = GENESIS_PREV;
    if (existsSync(this.path)) {
      const lines = readFileSync(this.path, "utf8").trimEnd().split("\n").filter(Boolean);
      const last = lines.at(-1);
      if (last) {
        const e = JSON.parse(last) as BulkheadEvent;
        seq = e.seq + 1;
        prev = e.hash;
      }
    }
    const base: UnsignedEvent = { format: "bulkhead.event/1", seq, prev, type, producer: this.producer, at: new Date().toISOString().replace(/\.\d+Z$/, "Z"), data };
    const hash = hashEvent(base);
    const signature = sign(null, Buffer.from(hash), this.key).toString("base64");
    const event: BulkheadEvent = { ...base, hash, signature };
    appendFileSync(this.path, JSON.stringify(event) + "\n");
    return event;
  }
}
