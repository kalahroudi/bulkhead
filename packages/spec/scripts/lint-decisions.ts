import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { lintDecisionRecord } from "../src/index.ts";

const dir = join(import.meta.dirname, "../../../docs/decisions");
const files = readdirSync(dir).filter((f) => /^DR-\d+.*\.md$/.test(f)).sort();
const issues = files.flatMap((f) => lintDecisionRecord(f.replace(/\.md$/, ""), readFileSync(join(dir, f), "utf8")));
if (issues.length) {
  for (const i of issues) console.error(`[${i.code}] ${i.message}`);
  console.error(`\ndecision lint FAILED: ${issues.length} issue(s)`);
  process.exit(1);
}
console.log(`decision lint clean: ${files.length} records, every numbered choice cites its check or says why it has none`);
