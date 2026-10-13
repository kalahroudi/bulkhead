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

/**
 * The numbered choices under every "## Decision" heading, each with the evidence refs it cites. Records with no `Rules:`
 * header are not covered. CRLF is normalised, and "1." and "1)" numbering (optionally indented up to three spaces) both count.
 * A record that names rules but has no Decision heading, or an unparseable Rules header, is reported by `lintDecisionRecord`.
 */
export function decisionItems(markdown: string): { rules: string; items: DecisionItem[]; hasDecisionSection: boolean } | null {
  const text = markdown.replace(/\r\n?/g, "\n");
  const rules = /^[-*]\s*rules:\s*(.+)$/im.exec(text)?.[1]?.trim();
  if (!rules) return null;
  const sections = [...text.matchAll(/^##\s+Decision\s*$([\s\S]*?)(?=^##\s|(?![\s\S]))/gim)].map((m) => m[1] as string);
  const items: DecisionItem[] = [];
  for (const section of sections) {
    let current: { number: number; lines: string[] } | null = null;
    for (const line of section.split("\n")) {
      const start = /^ {0,3}(\d+)[.)]\s+(.*)$/.exec(line);
      if (start) {
        if (current) items.push(finish(current));
        current = { number: Number(start[1]), lines: [start[2] as string] };
      } else if (current && (/^ {2,}\S/.test(line) || line.trim() === "")) current.lines.push(line.trim());
      else if (current) { items.push(finish(current)); current = null; }
    }
    if (current) items.push(finish(current));
  }
  return { rules, items, hasDecisionSection: sections.length > 0 };
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
  if (!parsed) {
    // A Rules-looking line the strict header regex did not accept would otherwise leave the record silently uncovered.
    return /^\W*rules\b/im.test(markdown) && !/^[-*]\s*rules:\s*\S/im.test(markdown)
      ? [{ ruleId: name, code: "unparsed-rules-header", message: `${name}: a "Rules" line exists but is not in the form "- Rules: ..."; the record would escape the decision lint` }]
      : [];
  }
  const issues: LintIssue[] = [];
  if (!parsed.hasDecisionSection) issues.push({ ruleId: name, code: "missing-decision-section", message: `${name}: names rules (${parsed.rules}) but has no "## Decision" section` });
  for (const it of parsed.items) {
    const where = `${name} decision ${it.number}`;
    const noCheck = /\bNo check:\s*(.*)$/.exec(it.text)?.[1];
    const hasCheck = /(?<!No )\bCheck:/.test(it.text);
    if (noCheck !== undefined && noCheck.trim().length < MIN_REASON) issues.push({ ruleId: name, code: "weak-no-check", message: `${where}: "No check:" needs a reason of at least ${MIN_REASON} characters` });
    if (hasCheck && it.refs.length === 0) issues.push({ ruleId: name, code: "check-without-ref", message: `${where}: "Check:" must name at least one backticked ref (${CHECK_KINDS.map((k) => `\`${k}:...\``).join(", ")})` });
    if (!hasCheck && noCheck === undefined) issues.push({ ruleId: name, code: "unchecked-decision", message: `${where}: cite its enforcement with "Check:" and a \`probe:\`/\`mutation:\`/\`test:\`/\`gate:\`/\`script:\` ref, or say why none exists with "No check:"` });
  }
  return issues;
}
