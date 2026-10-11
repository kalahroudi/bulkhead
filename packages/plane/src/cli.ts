#!/usr/bin/env node
import { parseArgs } from "node:util";
import { watch } from "./watch.ts";

const { values } = parseArgs({ options: { "log-dir": { type: "string", default: ".bulkhead" }, once: { type: "boolean", default: false } } });
const ac = new AbortController();
process.on("SIGINT", () => ac.abort());
await watch(values["log-dir"] as string, (l) => console.log(l), { follow: !values.once, signal: ac.signal });
