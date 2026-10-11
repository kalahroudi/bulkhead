// Event log reader. Independent of any producer: it recomputes hashes and checks signatures itself (PLANE-2).
import { createHash, createPublicKey, verify } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { GENESIS_PREV, validateEvent, type BulkheadEvent } from "@kalahroudi/bulkhead-spec";

export interface ReadEvent {
  event: BulkheadEvent;
  /** Untrusted events are shown but never count toward coverage. */
  trusted: boolean;
  /** Why the event is untrusted or the chain broke here. */
  problem?: string;
}

function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object")
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`).join(",")}}`;
  return JSON.stringify(v);
}

export function parseLog(text: string, dir: string, startSeq = 0, startPrev = GENESIS_PREV): ReadEvent[] {
  const out: ReadEvent[] = [];
  let expectSeq = startSeq;
  let expectPrev = startPrev;
  for (const line of text.split("\n").filter(Boolean)) {
    let raw: unknown;
    try {
      raw = JSON.parse(line);
    } catch {
      continue; // partial line being written; picked up on the next read
    }
    const v = validateEvent(raw);
    if (!v.ok) {
      out.push({ event: raw as BulkheadEvent, trusted: false, problem: `malformed: ${v.errors[0]}` });
      continue;
    }
    const e = v.value;
    let problem: string | undefined;
    if (e.seq !== expectSeq) problem = `chain: expected seq ${expectSeq}, got ${e.seq}`;
    else if (e.prev !== expectPrev) problem = "chain: prev hash does not match previous event";
    else {
      const { hash, signature, ...unsigned } = e;
      if (`sha256:${createHash("sha256").update(canonical(unsigned)).digest("hex")}` !== hash) problem = "hash does not match contents";
      else {
        const pub = join(dir, "trusted", `${e.producer}.pub`);
        if (!existsSync(pub)) problem = `unknown producer ${e.producer}`;
        else if (!verify(null, Buffer.from(hash), createPublicKey(readFileSync(pub)), Buffer.from(signature, "base64"))) problem = "bad signature";
      }
    }
    out.push({ event: e, trusted: !problem, problem });
    expectSeq = e.seq + 1;
    expectPrev = e.hash;
  }
  return out;
}

export function readLog(dir: string): ReadEvent[] {
  const path = join(dir, "events.jsonl");
  return existsSync(path) ? parseLog(readFileSync(path, "utf8"), dir) : [];
}

/** Only trusted events count toward coverage and verdicts. */
export const trustedEvents = (events: ReadEvent[]) => events.filter((e) => e.trusted).map((e) => e.event);
