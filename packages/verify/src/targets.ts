// VERIFY-5: only loopback or explicitly registered environments. Anything else is refused.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const isLoopback = (h: string) => h === "127.0.0.1" || h === "localhost" || h === "[::1]" || h.endsWith(".localhost");

export function checkTarget(target: URL, logDir: string): { ok: true } | { ok: false; reason: string } {
  if (target.protocol !== "http:" && target.protocol !== "https:") return { ok: false, reason: "target must be http(s)" };
  if (isLoopback(target.hostname)) return { ok: true };
  const cfg = join(logDir, "verify.json");
  if (existsSync(cfg)) {
    const registered = (JSON.parse(readFileSync(cfg, "utf8")) as { registeredTargets?: string[] }).registeredTargets ?? [];
    if (registered.includes(target.host)) return { ok: true };
  }
  return { ok: false, reason: `${target.host} is not a registered environment (add it to ${cfg})` };
}
