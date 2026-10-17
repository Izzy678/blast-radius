/**
 * Deterministic ranking. The LLM never does this maths: it gets these numbers
 * back from a tool and only explains them.
 *
 * Rules:
 *  - revenue at risk: a customer's full ARR if any PROD path reaches them,
 *    0 if they're reachable only through dev tooling (the vulnerable code
 *    never ships), 0 if there's no path at all.
 *  - priority score = revenue at risk x SLA weight x (CVSS / 10).
 *  - fix order: repos with prod exposure first, ordered by the distinct ARR
 *    they put at risk; dev-only repos last.
 */
import type { BlastRadiusRow, Cve, CustomerSummary, DependentRepo, Ownership } from "./tools/graph-tools";
import type { GraphPath, PathNode, Scope } from "./tools/types";

const SLA_WEIGHT: Record<string, number> = { platinum: 1.5, gold: 1.25, silver: 1, bronze: 0.8 };

export type Exposure = "prod" | "dev-only" | "none";

export type RankedCustomer = {
  customer: string;
  arr_usd: number;
  sla_tier: string;
  notify_within_hours: number | null;
  exposure: Exposure;
  revenue_at_risk: number;
  priority_score: number;
  /** Shortest prod path if there is one, else the shortest path, else null. */
  best_path: GraphPath | null;
  path_count: number;
  via_repos: string[];
  uses_services: string[];
};

export type RepoFix = {
  order: number;
  repo: string;
  exposure: "prod" | "dev-only";
  /** Packages this repo lists directly that pull in the vulnerable package. */
  bump: string[];
  customers: string[];
  revenue_at_risk: number;
  services: string[];
  owners: { name: string; team: string; on_call: boolean }[];
  path: GraphPath;
};

export type BlastRadiusReport = {
  cve: Cve;
  totals: {
    revenue_at_risk: number;
    customers_prod: number;
    customers_dev_only: number;
    customers_safe: number;
    repos_prod: number;
    repos_dev_only: number;
    paths: number;
  };
  customers: RankedCustomer[];
  fix_order: RepoFix[];
  /** Every node and edge on any traversed path, for drawing the cascade. */
  graph: CascadeGraph;
};

export type CascadeNode = PathNode & { id: string; scope: "prod" | "dev" };
export type CascadeEdge = { from: string; to: string; rel: string; scope: "prod" | "dev" };
export type CascadeGraph = { nodes: CascadeNode[]; edges: CascadeEdge[] };

const pathLen = (p: GraphPath) => p.rels.length;

export function rankBlastRadius(
  cve: Cve,
  rows: BlastRadiusRow[],
  allCustomers: CustomerSummary[],
  dependentRepos: DependentRepo[],
  ownership: Ownership[],
): BlastRadiusReport {
  const severity = cve.cvss / 10;

  // --- customers ----------------------------------------------------------
  const byCustomer = new Map<string, BlastRadiusRow[]>();
  for (const r of rows) byCustomer.set(r.customer, [...(byCustomer.get(r.customer) ?? []), r]);

  const customers: RankedCustomer[] = allCustomers.map((c) => {
    const paths = byCustomer.get(c.customer) ?? [];
    const prod = paths.filter((p) => p.scope === "prod");
    const exposure: Exposure = prod.length ? "prod" : paths.length ? "dev-only" : "none";
    const revenue = exposure === "prod" ? c.arr_usd : 0;
    const best = [...(prod.length ? prod : paths)].sort((a, b) => pathLen(a.path) - pathLen(b.path))[0];
    return {
      customer: c.customer,
      arr_usd: c.arr_usd,
      sla_tier: c.sla_tier,
      notify_within_hours: paths[0]?.notify_within_hours ?? null,
      exposure,
      revenue_at_risk: revenue,
      priority_score: Math.round(revenue * (SLA_WEIGHT[c.sla_tier] ?? 1) * severity),
      best_path: best?.path ?? null,
      path_count: paths.length,
      via_repos: [...new Set((prod.length ? prod : paths).map((p) => p.repo))],
      uses_services: c.services,
    };
  });

  const exposureRank: Record<Exposure, number> = { prod: 0, "dev-only": 1, none: 2 };
  customers.sort(
    (a, b) =>
      exposureRank[a.exposure] - exposureRank[b.exposure] ||
      b.priority_score - a.priority_score ||
      b.arr_usd - a.arr_usd,
  );

  // --- repos (fix order) ----------------------------------------------------
  const arrOf = new Map(allCustomers.map((c) => [c.customer, c.arr_usd]));
  const byRepo = new Map<string, BlastRadiusRow[]>();
  for (const r of rows) byRepo.set(r.repo, [...(byRepo.get(r.repo) ?? []), r]);

  const repoFixes: Omit<RepoFix, "order">[] = [...byRepo.entries()].map(([repo, repoRows]) => {
    const prod = repoRows.filter((r) => r.scope === "prod");
    const relevant = prod.length ? prod : repoRows;
    const customerNames = [...new Set(relevant.map((r) => r.customer))];
    return {
      repo,
      exposure: prod.length ? "prod" : "dev-only",
      bump: [...new Set(relevant.map((r) => r.direct_dependency))],
      customers: customerNames,
      revenue_at_risk: prod.length ? customerNames.reduce((sum, n) => sum + (arrOf.get(n) ?? 0), 0) : 0,
      services: [...new Set(relevant.map((r) => r.vulnerable_service))],
      owners: ownership
        .filter((o) => o.target === repo)
        .map((o) => ({ name: o.owner, team: o.team, on_call: o.on_call })),
      // Trim the path at the repo: the CVE -> ... -> repo part is what the patch removes.
      path: trimPathAt(relevant.sort((a, b) => pathLen(a.path) - pathLen(b.path))[0].path, repo),
    };
  });

  // Repos that depend on the vulnerable package but reach no customer (e.g. a CLI
  // no service is built from) still need a patch, so add them with $0 at risk.
  for (const d of dependentRepos) {
    if (byRepo.has(d.repo) || repoFixes.some((r) => r.repo === d.repo)) continue;
    const sameRepo = dependentRepos.filter((x) => x.repo === d.repo);
    const prod = sameRepo.filter((x) => x.scope === "prod");
    const relevant = prod.length ? prod : sameRepo;
    repoFixes.push({
      repo: d.repo,
      exposure: prod.length ? "prod" : "dev-only",
      bump: [...new Set(relevant.map((x) => x.direct_dependency))],
      customers: [],
      revenue_at_risk: 0,
      services: [],
      owners: ownership
        .filter((o) => o.target === d.repo)
        .map((o) => ({ name: o.owner, team: o.team, on_call: o.on_call })),
      path: relevant.sort((a, b) => a.hops - b.hops)[0].path,
    });
  }

  repoFixes.sort(
    (a, b) =>
      (a.exposure === "prod" ? 0 : 1) - (b.exposure === "prod" ? 0 : 1) ||
      b.revenue_at_risk - a.revenue_at_risk ||
      b.customers.length - a.customers.length,
  );

  const prodCustomers = customers.filter((c) => c.exposure === "prod");
  return {
    cve,
    totals: {
      revenue_at_risk: prodCustomers.reduce((s, c) => s + c.revenue_at_risk, 0),
      customers_prod: prodCustomers.length,
      customers_dev_only: customers.filter((c) => c.exposure === "dev-only").length,
      customers_safe: customers.filter((c) => c.exposure === "none").length,
      repos_prod: repoFixes.filter((r) => r.exposure === "prod").length,
      repos_dev_only: repoFixes.filter((r) => r.exposure === "dev-only").length,
      paths: rows.length,
    },
    customers,
    fix_order: repoFixes.map((r, i) => ({ ...r, order: i + 1 })),
    graph: buildCascade([
      ...rows.map((r) => ({ path: r.path, scope: r.scope })),
      ...dependentRepos.map((r) => ({ path: r.path, scope: r.scope })),
    ]),
  };
}

/**
 * Merge paths into one node/edge set. A node or edge is "prod" if any prod path
 * uses it. Node ids are label-qualified because a repo and a service could share a name.
 */
function buildCascade(paths: { path: GraphPath; scope: Scope }[]): CascadeGraph {
  const nodes = new Map<string, CascadeNode>();
  const edges = new Map<string, CascadeEdge>();
  const idOf = (n: PathNode) => `${n.label}:${n.name}`;

  for (const { path, scope } of paths) {
    path.nodes.forEach((n, i) => {
      const id = idOf(n);
      const existing = nodes.get(id);
      if (!existing || (scope === "prod" && existing.scope === "dev")) nodes.set(id, { ...n, id, scope });
      if (i === 0) return;
      const from = idOf(path.nodes[i - 1]);
      const key = `${from}->${id}`;
      const e = edges.get(key);
      if (!e || (scope === "prod" && e.scope === "dev")) edges.set(key, { from, to: id, rel: path.rels[i - 1], scope });
    });
  }
  return { nodes: [...nodes.values()], edges: [...edges.values()] };
}

function trimPathAt(path: GraphPath, nodeName: string): GraphPath {
  const i = path.nodes.findIndex((n) => n.name === nodeName);
  if (i < 0) return path;
  return { nodes: path.nodes.slice(0, i + 1), rels: path.rels.slice(0, i) };
}
