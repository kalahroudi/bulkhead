// Writes or checks route-manifest.json. Lowering a policy changes this file, which CODEOWNERS routes to the owner (ROUTE-3).
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { createDemoApp } from "../src/routes.ts";

const path = new URL("../route-manifest.json", import.meta.url);
const text = JSON.stringify(createDemoApp().manifest(), null, 2) + "\n";
if (process.argv.includes("--check")) {
  if (!existsSync(path) || readFileSync(path, "utf8") !== text) {
    console.error("route-manifest.json does not match the registered routes. Run: pnpm --filter bulkhead-demo-app manifest");
    process.exit(1);
  }
  console.log("route manifest matches registered routes");
} else {
  writeFileSync(path, text);
  console.log("wrote route-manifest.json");
}
