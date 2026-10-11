import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { spec } from "../src/index.ts";

const out = new URL("../../../SPEC.md", import.meta.url);

const lines = [
  "# Bulkhead spec",
  "",
  "<!-- GENERATED from packages/spec/src/rules.ts by `pnpm --filter @kalahroudi/bulkhead-spec catalog`. Do not edit by hand. -->",
  "",
  `Spec version: ${spec.version}`,
  "",
  "Conflict order: security, then performance, then flexibility (SPEC-3).",
  "",
  "A green report means no known leak paths, not proof of none.",
  "",
  "| ID | Tier | State | Statement | Reason | Enforcement | Oracle | Scenario stub |",
  "| --- | --- | --- | --- | --- | --- | --- | --- |",
  ...spec.rules.map((r) =>
    `| ${r.id} | ${r.tier} | ${r.state} | ${r.statement} | ${r.reason} | ${r.enforcement} | ${r.oracle} | \`${r.scenario}\` |`,
  ),
  "",
];
const text = lines.join("\n");

if (process.argv.includes("--check")) {
  if (!existsSync(out) || readFileSync(out, "utf8") !== text) {
    console.error("SPEC.md is out of date with the rule catalog. Run the catalog script.");
    process.exit(1);
  }
  console.log("SPEC.md matches the rule catalog");
} else {
  writeFileSync(out, text);
  console.log(`wrote SPEC.md (${spec.rules.length} rules)`);
}
