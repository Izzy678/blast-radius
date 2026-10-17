/**
 * The agent's tools, defined once and shared by the LLM agent (/api/agent) and
 * the MCP server. Each tool returns:
 *  - output: compact JSON for the model (paths flattened to strings to save tokens)
 *  - evidence: the Cypher queries it ran, for the UI
 *  - plan: set only by draft_fix_plan
 */
import type { JsonSchema, ToolSpec } from "../llm";
import { createPlan, listPlans, type FixPlan } from "../plans";
import { rankBlastRadiusForCve } from "./analysis";
import {
  explainCustomerExposure,
  findAffectedPackages,
  findCustomersForServices,
  findDependentRepos,
  findServicesForRepos,
  getCve,
  getOwners,
  traceBlastRadius,
} from "./graph-tools";
import type { Evidence, GraphPath } from "./types";

export type ToolRun = { output: unknown; evidence: Evidence[]; plan?: FixPlan };

type Tool = ToolSpec & { run: (args: Record<string, unknown>) => Promise<ToolRun> };

const pathStr = (p: GraphPath | null) => (p ? p.nodes.map((n) => n.name).join(" → ") : null);

const str = (description: string): JsonSchema => ({ type: "string", description });
const strList = (description: string): JsonSchema => ({ type: "array", items: { type: "string" }, description });
const obj = (properties: Record<string, JsonSchema>, required: string[]): JsonSchema => ({
  type: "object",
  properties,
  required,
});

const CVE_ARG = { cve_id: str("CVE identifier, e.g. CVE-2021-44906") };

export const tools: Tool[] = [
  {
    name: "get_cve",
    description: "Look up a CVE in the graph: severity, CVSS, affected range, fixed version and the package it affects.",
    parameters: obj(CVE_ARG, ["cve_id"]),
    async run({ cve_id }) {
      const r = await getCve(String(cve_id));
      return { output: r.data ?? { error: `${cve_id} is not in the graph` }, evidence: r.evidence };
    },
  },
  {
    name: "find_affected_packages",
    description:
      "Packages that are, or transitively depend on, the package a CVE affects (walks DEPENDS_ON up to 6 hops). depth 0 is the vulnerable package itself.",
    parameters: obj(CVE_ARG, ["cve_id"]),
    async run({ cve_id }) {
      const r = await findAffectedPackages(String(cve_id));
      return {
        output: r.data.map((p) => ({ package: p.package, internal: p.internal, depth: p.depth, chain: pathStr(p.path) })),
        evidence: r.evidence,
      };
    },
  },
  {
    name: "find_dependent_repos",
    description:
      "Repos that depend on the vulnerable package directly or transitively, with scope (prod or dev) and the direct dependency the repo would bump.",
    parameters: obj(CVE_ARG, ["cve_id"]),
    async run({ cve_id }) {
      const r = await findDependentRepos(String(cve_id));
      return {
        output: r.data.map((d) => ({
          repo: d.repo,
          scope: d.scope,
          direct_dependency: d.direct_dependency,
          hops: d.hops,
          path: pathStr(d.path),
        })),
        evidence: r.evidence,
      };
    },
  },
  {
    name: "find_services_for_repos",
    description: "Production services built from the given repos, plus every service that calls them at runtime (up to 4 hops).",
    parameters: obj({ repos: strList("Repo names") }, ["repos"]),
    async run({ repos }) {
      const r = await findServicesForRepos((repos as string[]) ?? []);
      return {
        output: r.data.map((s) => ({ service: s.service, criticality: s.criticality, repo: s.repo, relation: s.relation, path: pathStr(s.path) })),
        evidence: r.evidence,
      };
    },
  },
  {
    name: "find_customers_for_services",
    description: "Customers that use the given services, with ARR and SLA tier.",
    parameters: obj({ services: strList("Service names") }, ["services"]),
    async run({ services }) {
      const r = await findCustomersForServices((services as string[]) ?? []);
      return { output: r.data, evidence: r.evidence };
    },
  },
  {
    name: "trace_blast_radius",
    description:
      "The full multi-hop traversal in one query: CVE → package → transitive packages → repo → service → calling services → customer. One row per path.",
    parameters: obj(CVE_ARG, ["cve_id"]),
    async run({ cve_id }) {
      const r = await traceBlastRadius(String(cve_id));
      return {
        output: r.data.map((b) => ({ customer: b.customer, scope: b.scope, repo: b.repo, path: pathStr(b.path) })),
        evidence: r.evidence,
      };
    },
  },
  {
    name: "explain_customer_exposure",
    description:
      "Why a specific customer is or is not affected by a CVE. Returns exposure (prod, dev-only or none) and the paths; 'none' means no path exists in the graph, which proves they are safe.",
    parameters: obj({ ...CVE_ARG, customer: str("Customer name") }, ["cve_id", "customer"]),
    async run({ cve_id, customer }) {
      const r = await explainCustomerExposure(String(cve_id), String(customer));
      if (!r.data) return { output: { error: `${customer} is not in the graph` }, evidence: r.evidence };
      return {
        output: {
          exposure: r.data.exposure,
          explanation: r.data.explanation,
          uses_services: r.data.uses_services,
          paths: r.data.paths.slice(0, 5).map((p) => ({ scope: p.scope, path: pathStr(p.path) })),
        },
        evidence: r.evidence,
      };
    },
  },
  {
    name: "get_owners",
    description: "Owners (and on-call status) of the given repos or services.",
    parameters: obj({ names: strList("Repo or service names") }, ["names"]),
    async run({ names }) {
      const r = await getOwners((names as string[]) ?? []);
      return { output: r.data, evidence: r.evidence };
    },
  },
  {
    name: "rank_blast_radius",
    description:
      "Deterministic ranking computed in code from the graph: revenue at risk, customers ranked by priority, customers proven safe, and the repo fix order with owners. Use these numbers as-is; never recompute them.",
    parameters: obj(CVE_ARG, ["cve_id"]),
    async run({ cve_id }) {
      const r = await rankBlastRadiusForCve(String(cve_id));
      if (!r.data) return { output: { error: `${cve_id} is not in the graph` }, evidence: r.evidence };
      const { totals, customers, fix_order } = r.data;
      return {
        output: {
          totals,
          customers: customers.map((c) => ({
            customer: c.customer,
            exposure: c.exposure,
            arr_usd: c.arr_usd,
            revenue_at_risk: c.revenue_at_risk,
            sla_tier: c.sla_tier,
            notify_within_hours: c.notify_within_hours,
            path: pathStr(c.best_path),
            uses_services: c.exposure === "none" ? c.uses_services : undefined,
          })),
          fix_order: fix_order.map((f) => ({
            order: f.order,
            repo: f.repo,
            exposure: f.exposure,
            bump: f.bump,
            revenue_at_risk: f.revenue_at_risk,
            customers: f.customers.length,
            owners: f.owners.map((o) => o.name),
          })),
        },
        evidence: r.evidence,
      };
    },
  },
  {
    name: "get_past_plans",
    description: "Earlier fix plans for this CVE stored in the graph, with their approval status and reviewer notes (precedent).",
    parameters: obj(CVE_ARG, ["cve_id"]),
    async run({ cve_id }) {
      const plans = await listPlans(String(cve_id));
      return {
        output: plans.slice(0, 5).map((p) => ({
          id: p.id,
          status: p.status,
          created_at: p.created_at,
          decided_by: p.decided_by,
          decision_note: p.decision_note,
          revenue_at_risk: p.revenue_at_risk,
        })),
        evidence: [],
      };
    },
  },
  {
    name: "draft_fix_plan",
    description:
      "Save the fix plan to the graph with status 'pending'. The repo order comes from rank_blast_radius. A human must approve it; you cannot approve it yourself. Call this once, at the end.",
    parameters: obj(
      { ...CVE_ARG, summary: str("2-4 sentence summary of the impact and the fix order, for the human reviewer") },
      ["cve_id", "summary"],
    ),
    async run({ cve_id, summary }) {
      const r = await rankBlastRadiusForCve(String(cve_id));
      if (!r.data) return { output: { error: `${cve_id} is not in the graph` }, evidence: r.evidence };
      const plan = await createPlan(r.data, String(summary ?? ""));
      return {
        output: { plan_id: plan.id, status: plan.status, steps: plan.steps.length },
        evidence: r.evidence,
        plan,
      };
    },
  },
];

export const toolSpecs: ToolSpec[] = tools.map(({ name, description, parameters }) => ({ name, description, parameters }));

export async function runTool(name: string, args: Record<string, unknown>): Promise<ToolRun> {
  const tool = tools.find((t) => t.name === name);
  if (!tool) return { output: { error: `Unknown tool ${name}` }, evidence: [] };
  try {
    return await tool.run(args);
  } catch (err) {
    return { output: { error: err instanceof Error ? err.message : String(err) }, evidence: [] };
  }
}
