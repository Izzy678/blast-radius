/**
 * Typed Cypher tools. Each one runs one or more read-only queries against
 * FalkorDB and returns { data, evidence } so the caller can show the exact
 * query, params and latency behind every answer.
 *
 * Traversal limits: DEPENDS_ON up to 6 hops, CALLS up to 4 hops. That is far
 * deeper than the demo data needs, but keeps queries bounded.
 */
import { runQuery, type QueryParams } from "../falkordb";
import type { Evidence, GraphPath, PathNode, Scope, ToolResult } from "./types";

// Cypher fragment that turns a matched `path` into plain JSON the UI can draw.
const PATH_PROJECTION = `
  [n IN nodes(path) | {label: labels(n)[0], name: coalesce(n.name, n.id)}] AS nodes,
  [x IN relationships(path) | type(x)] AS rels`;

async function query<T>(tool: string, cypher: string, params: QueryParams) {
  const res = await runQuery<T>(cypher.trim(), params);
  const evidence: Evidence = {
    tool,
    cypher: res.cypher,
    params: res.params,
    ms: res.ms,
    rowCount: res.rows.length,
  };
  return { rows: res.rows, evidence };
}

// ---------------------------------------------------------------------------

export type Cve = {
  id: string;
  severity: string;
  cvss: number;
  published_at: string;
  affected_range: string;
  fixed_in: string;
  summary: string;
  package: string;
  installed_version: string;
};

/** Look up a CVE and the package it affects. Returns null if the CVE isn't in the graph. */
export async function getCve(cveId: string): Promise<ToolResult<Cve | null>> {
  const { rows, evidence } = await query<Cve>(
    "get_cve",
    `MATCH (c:CVE {id: $cveId})-[:AFFECTS]->(p:Package)
     RETURN c.id AS id, c.severity AS severity, c.cvss AS cvss, c.published_at AS published_at,
            c.affected_range AS affected_range, c.fixed_in AS fixed_in, c.summary AS summary,
            p.name AS package, p.version AS installed_version`,
    { cveId },
  );
  return { data: rows[0] ?? null, evidence: [evidence] };
}

export type AffectedPackage = {
  package: string;
  internal: boolean;
  /** 0 = the vulnerable package itself, 1 = depends on it directly, ... */
  depth: number;
  path: GraphPath;
};

/** Every package that is, or transitively depends on, the package the CVE affects. */
export async function findAffectedPackages(cveId: string): Promise<ToolResult<AffectedPackage[]>> {
  const { rows, evidence } = await query<{
    package: string;
    internal: boolean;
    depth: number;
    nodes: PathNode[];
    rels: string[];
  }>(
    "find_affected_packages",
    `MATCH path = (:CVE {id: $cveId})-[:AFFECTS]->(:Package)<-[:DEPENDS_ON*0..6]-(p:Package)
     RETURN p.name AS package, p.internal AS internal, length(path) - 1 AS depth, ${PATH_PROJECTION}
     ORDER BY depth`,
    { cveId },
  );
  // A package can be reached by several chains; keep the shortest (rows are sorted by depth).
  const seen = new Map<string, AffectedPackage>();
  for (const r of rows) {
    if (!seen.has(r.package)) {
      seen.set(r.package, {
        package: r.package,
        internal: r.internal,
        depth: r.depth,
        path: { nodes: r.nodes, rels: r.rels },
      });
    }
  }
  return { data: [...seen.values()], evidence: [evidence] };
}

export type DependentRepo = {
  repo: string;
  owner_team: string;
  scope: Scope;
  /** The package the repo lists in its own manifest (what it must bump). */
  direct_dependency: string;
  hops: number;
  path: GraphPath;
};

/** Repos that use an affected package, directly or transitively, with prod/dev scope. */
export async function findDependentRepos(cveId: string): Promise<ToolResult<DependentRepo[]>> {
  const { rows, evidence } = await query<{
    repo: string;
    owner_team: string;
    scope: Scope;
    direct_dependency: string;
    hops: number;
    nodes: PathNode[];
    rels: string[];
  }>(
    "find_dependent_repos",
    `MATCH path = (:CVE {id: $cveId})-[:AFFECTS]->(:Package)<-[:DEPENDS_ON*0..6]-(d:Package)<-[u:USES]-(r:Repo)
     RETURN r.name AS repo, r.owner_team AS owner_team, u.scope AS scope, d.name AS direct_dependency,
            length(path) AS hops, ${PATH_PROJECTION}
     ORDER BY scope DESC, hops`,
    { cveId },
  );
  return {
    data: rows.map(({ nodes, rels, ...r }) => ({ ...r, path: { nodes, rels } })),
    evidence: [evidence],
  };
}

export type ImpactedService = {
  service: string;
  criticality: string;
  /** The repo the vulnerable code ships in. */
  repo: string;
  /** "built_from" if the service is built from the repo, "calls" if it depends on such a service at runtime. */
  relation: "built_from" | "calls";
  path: GraphPath;
};

/** Services built from the given repos, plus every service that calls them (up to 4 hops). */
export async function findServicesForRepos(repos: string[]): Promise<ToolResult<ImpactedService[]>> {
  const { rows, evidence } = await query<{
    service: string;
    criticality: string;
    repo: string;
    call_hops: number;
    nodes: PathNode[];
    rels: string[];
  }>(
    "find_services_for_repos",
    `MATCH (r:Repo) WHERE r.name IN $repos
     MATCH path = (r)<-[:BUILT_FROM]-(:Service)<-[:CALLS*0..4]-(s:Service)
     RETURN s.name AS service, s.criticality AS criticality, r.name AS repo,
            length(path) - 1 AS call_hops, ${PATH_PROJECTION}
     ORDER BY call_hops`,
    { repos },
  );
  return {
    data: rows.map(({ nodes, rels, call_hops, ...r }) => ({
      ...r,
      relation: call_hops === 0 ? "built_from" : "calls",
      path: { nodes, rels },
    })),
    evidence: [evidence],
  };
}

export type ServiceCustomer = {
  customer: string;
  arr_usd: number;
  sla_tier: string;
  notify_within_hours: number;
  service: string;
};

/** Customers that use any of the given services directly. */
export async function findCustomersForServices(services: string[]): Promise<ToolResult<ServiceCustomer[]>> {
  const { rows, evidence } = await query<ServiceCustomer>(
    "find_customers_for_services",
    `MATCH (c:Customer)-[:USES]->(s:Service) WHERE s.name IN $services
     RETURN c.name AS customer, c.arr_usd AS arr_usd, c.sla_tier AS sla_tier,
            c.notify_within_hours AS notify_within_hours, s.name AS service
     ORDER BY arr_usd DESC`,
    { services },
  );
  return { data: rows, evidence: [evidence] };
}

export type BlastRadiusRow = {
  customer: string;
  arr_usd: number;
  sla_tier: string;
  notify_within_hours: number;
  /** The service the customer uses. */
  entry_service: string;
  /** The service actually built from the vulnerable repo (may equal entry_service). */
  vulnerable_service: string;
  service_criticality: string;
  repo: string;
  scope: Scope;
  direct_dependency: string;
  /** Edges on the path from the CVE to the customer. */
  hops: number;
  path: GraphPath;
};

/**
 * The full multi-hop walk in one query:
 * CVE -> package <- (transitive) packages <- repo <- service <- (calling) services <- customer.
 * Returns one row per distinct path, so a customer can appear several times.
 */
export async function traceBlastRadius(
  cveId: string,
  customer?: string,
): Promise<ToolResult<BlastRadiusRow[]>> {
  const { rows, evidence } = await query<Omit<BlastRadiusRow, "path"> & { nodes: PathNode[]; rels: string[] }>(
    customer ? "explain_customer_exposure" : "trace_blast_radius",
    `MATCH path = (:CVE {id: $cveId})-[:AFFECTS]->(:Package)<-[:DEPENDS_ON*0..6]-(d:Package)
                  <-[u:USES]-(r:Repo)<-[:BUILT_FROM]-(vs:Service)<-[:CALLS*0..4]-(es:Service)<-[:USES]-(c:Customer)
     ${customer ? "WHERE c.name = $customer" : ""}
     RETURN c.name AS customer, c.arr_usd AS arr_usd, c.sla_tier AS sla_tier,
            c.notify_within_hours AS notify_within_hours, es.name AS entry_service,
            vs.name AS vulnerable_service, vs.criticality AS service_criticality, r.name AS repo,
            u.scope AS scope, d.name AS direct_dependency, length(path) AS hops, ${PATH_PROJECTION}
     ORDER BY hops`,
    customer ? { cveId, customer } : { cveId },
  );
  return {
    data: rows.map(({ nodes, rels, ...r }) => ({ ...r, path: { nodes, rels } })),
    evidence: [evidence],
  };
}

export type CustomerExposure = {
  customer: string;
  exposure: "prod" | "dev-only" | "none";
  paths: BlastRadiusRow[];
  /** Services the customer uses; for "none" this is the proof that nothing connects. */
  uses_services: string[];
  explanation: string;
};

/** Why is (or isn't) this customer affected? "No path" is returned as an explicit safety proof. */
export async function explainCustomerExposure(
  cveId: string,
  customer: string,
): Promise<ToolResult<CustomerExposure | null>> {
  const blast = await traceBlastRadius(cveId, customer);
  const usesQ = await query<{ customer: string; services: string[] }>(
    "get_customer_services",
    `MATCH (c:Customer {name: $customer})
     OPTIONAL MATCH (c)-[:USES]->(s:Service)
     RETURN c.name AS customer, collect(s.name) AS services`,
    { customer },
  );
  const evidence = [...blast.evidence, usesQ.evidence];
  const row = usesQ.rows[0];
  if (!row) return { data: null, evidence };

  const paths = blast.data;
  const exposure = paths.length === 0 ? "none" : paths.some((p) => p.scope === "prod") ? "prod" : "dev-only";
  const explanation =
    exposure === "none"
      ? `No path exists from ${cveId} to ${customer}. They use ${row.services.join(", ")}, and none of those services is built from, or calls, a repo that depends on the vulnerable package.`
      : exposure === "dev-only"
        ? `${customer} is only reachable through dev-only dependencies (test/build tooling), so the vulnerable code does not ship to production.`
        : `${customer} is exposed through ${paths.filter((p) => p.scope === "prod").length} production path(s).`;

  return { data: { customer, exposure, paths, uses_services: row.services, explanation }, evidence };
}

export type Ownership = { target: string; target_type: string; owner: string; team: string; on_call: boolean };

/** Who owns the given repos/services (and so must do or approve the fix). */
export async function getOwners(names: string[]): Promise<ToolResult<Ownership[]>> {
  const { rows, evidence } = await query<Ownership>(
    "get_owners",
    `MATCH (o:Owner)-[:OWNS]->(x) WHERE x.name IN $names
     RETURN x.name AS target, labels(x)[0] AS target_type, o.name AS owner, o.team AS team, o.on_call AS on_call`,
    { names },
  );
  return { data: rows, evidence: [evidence] };
}

export type CustomerSummary = { customer: string; arr_usd: number; sla_tier: string; services: string[] };

/** All customers, so the agent can list who is safe (not reached by any path). */
export async function listCustomers(): Promise<ToolResult<CustomerSummary[]>> {
  const { rows, evidence } = await query<CustomerSummary>(
    "list_customers",
    `MATCH (c:Customer)
     OPTIONAL MATCH (c)-[:USES]->(s:Service)
     RETURN c.name AS customer, c.arr_usd AS arr_usd, c.sla_tier AS sla_tier, collect(s.name) AS services
     ORDER BY arr_usd DESC`,
    {},
  );
  return { data: rows, evidence: [evidence] };
}

export type CveSummary = { id: string; severity: string; cvss: number; package: string };

/** CVEs currently in the graph (for the UI picker). */
export async function listCves(): Promise<ToolResult<CveSummary[]>> {
  const { rows, evidence } = await query<CveSummary>(
    "list_cves",
    `MATCH (c:CVE)-[:AFFECTS]->(p:Package)
     RETURN c.id AS id, c.severity AS severity, c.cvss AS cvss, p.name AS package
     ORDER BY c.cvss DESC`,
    {},
  );
  return { data: rows, evidence: [evidence] };
}
