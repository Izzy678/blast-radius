/**
 * Tool-calling agent loop. The LLM decides which graph tools to call and writes
 * the explanation; every number it reports comes from a tool result.
 * It ends by drafting a pending fix plan, which only a human can approve.
 */
import { chat, type ChatMessage } from "./llm";
import type { FixPlan } from "./plans";
import { runTool, toolSpecs } from "./tools/registry";
import type { Evidence } from "./tools/types";

const MAX_TURNS = 10;

const SYSTEM = `You are a supply chain security agent. You investigate a CVE by walking a FalkorDB graph of
packages, repos, services, customers and owners, using the tools provided.

Rules:
- Every claim must come from a tool result. Never invent packages, repos, customers or numbers.
- Never do arithmetic on revenue yourself. Use the numbers returned by rank_blast_radius exactly.
- Explain impact with the graph path, e.g. "minimist → handlebars → @lumen/mailer → checkout-api → checkout → Kestrel Banking".
- Distinguish prod exposure from dev-only exposure (dev tooling does not ship to production).
- Customers with no path are safe: say so, and say that "no path found" is the proof.

Investigate step by step, one tool per step, so the reviewer can follow the walk:
1. get_cve: confirm the advisory and the vulnerable package.
2. find_dependent_repos: which repos pull it in, directly or transitively, prod or dev.
3. trace_blast_radius: follow those repos through services to customers.
4. rank_blast_radius: get the revenue at risk and fix order (computed in code).
5. explain_customer_exposure: for the highest-ARR customer marked "none", to prove they are safe.
6. get_past_plans: check for precedent on this CVE.
7. draft_fix_plan: exactly once. The plan stays pending until a human approves it.
Then write the final answer.

Final answer format (plain text, short headings, no markdown tables):
1. Impact: one sentence with total revenue at risk and number of customers exposed.
2. Why: the key transitive path(s).
3. Who is safe: dev-only and no-path customers.
4. Fix order: numbered repos with what to bump and the owner.
5. Status: plan id, pending approval.`;

export type AgentStep = { tool: string; args: Record<string, unknown>; summary: string };

export type AgentResult = {
  answer: string;
  steps: AgentStep[];
  evidence: Evidence[];
  plan: FixPlan | null;
};

export async function runAgent(cveId: string, question?: string): Promise<AgentResult> {
  const messages: ChatMessage[] = [
    {
      role: "user",
      text: question?.trim()
        ? `${question.trim()}\n\nCVE: ${cveId}`
        : `A new advisory just landed: ${cveId}. Investigate its blast radius, rank the fix order by revenue at risk, and draft a fix plan.`,
    },
  ];
  const steps: AgentStep[] = [];
  const evidence: Evidence[] = [];
  let plan: FixPlan | null = null;

  for (let turn = 0; turn < MAX_TURNS; turn++) {
    const res = await chat({ system: SYSTEM, messages, tools: toolSpecs });
    messages.push({ role: "assistant", text: res.text, toolCalls: res.toolCalls, raw: res.raw });

    if (res.toolCalls.length === 0) {
      // Gemini sometimes writes part of the answer alongside earlier tool calls,
      // so keep every turn's text, not just the last one.
      const answer = messages
        .flatMap((m) => (m.role === "assistant" && m.text.trim() ? [m.text.trim()] : []))
        .join("\n\n");
      return { answer, steps, evidence, plan };
    }

    const results = [];
    for (const call of res.toolCalls) {
      // Only one plan per investigation, even if the model asks twice.
      if (call.name === "draft_fix_plan" && plan) {
        results.push({ call, output: { plan_id: plan.id, status: plan.status, note: "Plan already drafted." } });
        continue;
      }
      const run = await runTool(call.name, call.args);
      if (run.plan) plan = run.plan;
      evidence.push(...run.evidence);
      steps.push({ tool: call.name, args: call.args, summary: summarize(run.output) });
      results.push({ call, output: run.output });
    }
    messages.push({ role: "tool", results });
  }

  return {
    answer: "The agent hit its step limit before finishing. The tool results above are still valid.",
    steps,
    evidence,
    plan,
  };
}

/** One-line description of a tool result for the UI's step list. */
function summarize(output: unknown): string {
  if (Array.isArray(output)) return `${output.length} rows`;
  if (output && typeof output === "object") {
    const o = output as Record<string, unknown>;
    if (o.error) return `error: ${o.error}`;
    if (o.plan_id) return `plan ${o.plan_id} (${o.status})`;
    if (o.totals) return "ranked";
    if (o.exposure) return String(o.exposure);
  }
  return "ok";
}
