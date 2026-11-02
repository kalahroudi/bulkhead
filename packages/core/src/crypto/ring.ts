import type { Config } from "../tenant/types.ts";
import { createKeyRing, type KeyRing } from "./keys.ts";

const rings = new WeakMap<object, KeyRing>();

/** One ring per control-plane binding in an isolate, so the 60-second data-key cache outlives a request. */
export function getKeyRing(config: Config): KeyRing {
  if (!config.masterKeys) throw new Error("no master keys configured");
  let r = rings.get(config.db as object);
  if (!r) rings.set(config.db as object, (r = createKeyRing(config.db, config.masterKeys)));
  return r;
}
