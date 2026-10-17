/**
 * Fix plans live in the graph, next to what they're about:
 *   (:FixPlan {status})-[:FOR]->(:CVE)
 *   (:FixPlan)-[:PATCHES {order, bump, exposure, revenue_at_risk}]->(:Repo)
 * A plan is created as "pending" and only a human can move it to
 * "approved" or "rejected". Nothing is final until then.
 */
import { runQuery, runWrite } from "./falkordb";
import type { BlastRadiusReport } from "./ranking";

export type PlanStatus = "pending" | "approved" | "rejected";

export type FixPlanStep = {
  order: number;
  repo: string;
  exposure: string;
  bump: string[];
  revenue_at_risk: number;
  owners: string[];
};

export type FixPlan = {
  id: string;
  cve_id: string;
  status: PlanStatus;
  created_at: string;
  revenue_at_risk: number;
  summary: string;
  decided_at: string | null;
  decided_by: string | null;
  decision_note: string | null;
  steps: FixPlanStep[];
};

const PLAN_RETURN = `
  OPTIONAL MATCH (fp)-[p:PATCHES]->(r:Repo)
  OPTIONAL MATCH (o:Owner)-[:OWNS]->(r)
  WITH fp, c, p, r, collect(o.name) AS owners
  ORDER BY p.order
  RETURN fp.id AS id, c.id AS cve_id, fp.status AS status, fp.created_at AS created_at,
         fp.revenue_at_risk AS revenue_at_risk, fp.summary AS summary,
         fp.decided_at AS decided_at, fp.decided_by AS decided_by, fp.decision_note AS decision_note,
         collect(CASE WHEN r IS NULL THEN NULL ELSE {order: p.order, repo: r.name, exposure: p.exposure, bump: p.bump,
                      revenue_at_risk: p.revenue_at_risk, owners: owners} END) AS steps`;

/** Save a pending fix plan built from a ranked blast radius report. */
export async function createPlan(report: BlastRadiusReport, summary: string): Promise<FixPlan> {
  const id = `plan-${Date.now().toString(36)}`;
  await runWrite(
    `MATCH (c:CVE {id: $cveId})
     CREATE (fp:FixPlan {id: $id, status: 'pending', created_at: $now, revenue_at_risk: $revenue, summary: $summary})
            -[:FOR]->(c)
     WITH fp
     UNWIND $steps AS st
     MATCH (r:Repo {name: st.repo})
     CREATE (fp)-[:PATCHES {order: st.order, bump: st.bump, exposure: st.exposure,
                            revenue_at_risk: st.revenue_at_risk}]->(r)`,
    {
      id,
      cveId: report.cve.id,
      now: new Date().toISOString(),
      revenue: report.totals.revenue_at_risk,
      summary,
      steps: report.fix_order.map((f) => ({
        order: f.order,
        repo: f.repo,
        bump: f.bump,
        exposure: f.exposure,
        revenue_at_risk: f.revenue_at_risk,
      })),
    },
  );
  const plan = await getPlan(id);
  if (!plan) throw new Error(`Plan ${id} was not saved`);
  return plan;
}

export async function getPlan(id: string): Promise<FixPlan | null> {
  const { rows } = await runQuery<FixPlan>(
    `MATCH (fp:FixPlan {id: $id})-[:FOR]->(c:CVE) ${PLAN_RETURN}`,
    { id },
  );
  return rows[0] ?? null;
}

/** Past plans for a CVE, newest first: earlier decisions act as precedent. */
export async function listPlans(cveId?: string): Promise<FixPlan[]> {
  const { rows } = await runQuery<FixPlan>(
    `MATCH (fp:FixPlan)-[:FOR]->(c:CVE) ${cveId ? "WHERE c.id = $cveId" : ""} ${PLAN_RETURN}`,
    cveId ? { cveId } : {},
  );
  return rows.sort((a, b) => b.created_at.localeCompare(a.created_at));
}

/**
 * Record a human decision. Only a pending plan can be decided, so an approved
 * plan can't be silently flipped. Returns null if the plan doesn't exist.
 */
export async function decidePlan(
  id: string,
  status: Exclude<PlanStatus, "pending">,
  by: string,
  note: string | null,
): Promise<{ plan: FixPlan | null; error?: string }> {
  const current = await getPlan(id);
  if (!current) return { plan: null, error: "not_found" };
  if (current.status !== "pending") return { plan: current, error: `already_${current.status}` };

  await runWrite(
    `MATCH (fp:FixPlan {id: $id}) WHERE fp.status = 'pending'
     SET fp.status = $status, fp.decided_at = $now, fp.decided_by = $by, fp.decision_note = $note`,
    { id, status, now: new Date().toISOString(), by, note },
  );
  return { plan: await getPlan(id) };
}
