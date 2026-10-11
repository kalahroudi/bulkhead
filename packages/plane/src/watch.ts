import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { parseLog, type ReadEvent } from "./log.ts";

export function formatEvent(r: ReadEvent): string {
  const e = r.event;
  const d = (e.data ?? {}) as Record<string, unknown>;
  let summary = "";
  if (e.type === "verify.run") summary = Object.entries(d).map(([k, v]) => `${k}=${String(v)}`).join(" ");
  else if (e.type === "finding.recorded") {
    const f = d.finding as { id?: string; verdict?: string; ruleId?: string; title?: string } | undefined;
    summary = `${f?.id} ${f?.verdict} ${f?.ruleId} ${f?.title}`;
  } else summary = JSON.stringify(d);
  const flag = r.trusted ? "" : `  [UNTRUSTED: ${r.problem}]`;
  return `#${e.seq} ${e.at} ${e.producer.padEnd(8)} ${e.type.padEnd(16)} ${summary}${flag}`;
}

/** Prints existing events, then follows the log until `signal` aborts. Re-reads from the start each tick so chain checks stay correct. */
export async function watch(dir: string, out: (line: string) => void, opts: { follow: boolean; signal?: AbortSignal; pollMs?: number }) {
  const path = join(dir, "events.jsonl");
  let printed = 0;
  const tick = () => {
    if (!existsSync(path)) return;
    const events = parseLog(readFileSync(path, "utf8"), dir);
    for (const r of events.slice(printed)) out(formatEvent(r));
    printed = events.length;
  };
  tick();
  if (!opts.follow) return;
  let lastSize = existsSync(path) ? statSync(path).size : 0;
  while (!opts.signal?.aborted) {
    await new Promise((r) => setTimeout(r, opts.pollMs ?? 200));
    const size = existsSync(path) ? statSync(path).size : 0;
    if (size !== lastSize) {
      lastSize = size;
      tick();
    }
  }
}
