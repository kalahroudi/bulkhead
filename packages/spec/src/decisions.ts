import type { LintIssue } from "./types.ts";

/** Kinds of evidence a decision may cite. Resolving them to real things is verify's job (it can see probes and files); this package checks form. */
export const CHECK_KINDS = ["probe", "mutation", "test", "gate", "script"] as const;
const REF = /`((?:probe|mutation|test|gate|script):[^`\s][^`]*)`/g;
const MIN_REASON = 20;

export interface DecisionItem {
  number: number;
  text: string;
  refs: string[];
}

/** The numbered choices under "## Decision", each with the evidence refs it cites. Records with no `Rules:` header are not covered. */
export function decisionItems(markdown: string): { rules: string; items: DecisionItem[] } | null {
  const rules = /^- Rules:\s*(.+)$/m.exec(markdown)?.[1]?.trim();
  if (!rules) return null;
  const section = /^## Decision\s*$([\s\S]*?)(?=^## |(?![\s\S]))/m.exec(markdown)?.[1] ?? "";
  const items: DecisionItem[] = [];
  let current: { number: number; lines: string[] } | null = null;
  for (const line of section.split("\n")) {
    const start = /^(\d+)\.\s+(.*)$/.exec(line);
    if (start) {
      if (current) items.push(finish(current));
      current = { number: Number(start[1]), lines: [start[2] as string] };
    } else if (current && (line.startsWith("  ") || line.trim() === "")) current.lines.push(line.trim());
    else if (current) { items.push(finish(current)); current = null; }
  }
  if (current) items.push(finish(current));
  return { rules, items };
}

function finish(c: { number: number; lines: string[] }): DecisionItem {
  const text = c.lines.join(" ").replace(/\s+/g, " ").trim();
  return { number: c.number, text, refs: [...text.matchAll(REF)].map((m) => m[1] as string) };
}

/**
 * DR-0007 item 5: every numbered choice in a record that names rules must either cite what enforces it
 * (`Check:` plus at least one backticked ref) or say why nothing can yet (`No check:` plus a reason).
 */
export function lintDecisionRecord(name: string, markdown: string): LintIssue[] {
  const parsed = decisionItems(markdown);
  if (!parsed) return [];
  const issues: LintIssue[] = [];
  for (const it of parsed.items) {
    const where = `${name} decision ${it.number}`;
    const noCheck = /\bNo check:\s*(.*)$/.exec(it.text)?.[1];
    const hasCheck = /\bCheck:/.test(it.text.replace(/No check:/g, ""));
    if (noCheck !== undefined) {
      if (noCheck.trim().length < MIN_REASON) issues.push({ ruleId: name, code: "weak-no-check", message: `${where}: "No check:" needs a reason of at least ${MIN_REASON} characters` });
    } else if (!hasCheck) issues.push({ ruleId: name, code: "unchecked-decision", message: `${where}: cite its enforcement with "Check:" and a \`probe:\`/\`mutation:\`/\`test:\`/\`gate:\`/\`script:\` ref, or say why none exists with "No check:"` });
    else if (it.refs.length === 0) issues.push({ ruleId: name, code: "check-without-ref", message: `${where}: "Check:" must name at least one backticked ref (${CHECK_KINDS.map((k) => `\`${k}:...\``).join(", ")})` });
  }
  return issues;
}
