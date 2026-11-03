// Writes or checks the spike's route manifest, which the verifier takes with --route-manifest (ROUTE-1/2: every route has a policy).
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createBetterAuthDemoApp } from "../src/app.ts";

const path = new URL("../route-manifest.json", import.meta.url);
const text = JSON.stringify(createBetterAuthDemoApp({ bootstrapToken: () => undefined, authSecret: () => undefined }).manifest(), null, 2) + "\n";
if (process.argv.includes("--check")) {
  if (!existsSync(path) || readFileSync(path, "utf8") !== text) {
    console.error("route-manifest.json does not match the registered routes. Run: pnpm --filter bulkhead-demo-betterauth manifest");
    process.exit(1);
  }
  console.log("route manifest matches registered routes (betterauth spike)");
} else {
  writeFileSync(path, text);
  console.log("wrote route-manifest.json");
}
