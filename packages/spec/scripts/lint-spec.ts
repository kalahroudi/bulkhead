import { lintSpec, spec } from "../src/index.ts";

const issues = lintSpec(spec);
if (issues.length) {
  for (const i of issues) console.error(`${i.ruleId}: [${i.code}] ${i.message}`);
  console.error(`\nspec lint FAILED: ${issues.length} issue(s)`);
  process.exit(1);
}
console.log(`spec lint clean: ${spec.rules.length} rules, version ${spec.version}, every rule has an ID, tier and scenario stub`);
