/**
 * Wipes the graph and loads the synthetic supply chain from src/data/seed-data.ts.
 * Run with: npm run seed
 */
import { falkordbConfig, getDb, getGraph, type QueryParams } from "../src/lib/falkordb";
import {
  calls,
  customers,
  cves,
  dependsOn,
  owners,
  packages,
  repos,
  services,
} from "../src/data/seed-data";

async function main() {
  const db = await getDb();
  const graph = await getGraph();

  // Start from a clean graph so re-running the seed is idempotent.
  if ((await db.list()).includes(falkordbConfig.graph)) {
    await graph.delete();
  }

  // Each step uses UNWIND so a whole node/edge type loads in one query.
  const steps: [string, string, QueryParams][] = [
    [
      "packages",
      `UNWIND $rows AS row
       CREATE (:Package {name: row.name, ecosystem: row.ecosystem, version: row.version, internal: row.internal})`,
      { rows: packages.map((p) => ({ ...p, internal: p.internal ?? false })) },
    ],
    [
      "DEPENDS_ON edges",
      `UNWIND $rows AS row
       MATCH (a:Package {name: row[0]}), (b:Package {name: row[1]})
       CREATE (a)-[:DEPENDS_ON]->(b)`,
      { rows: dependsOn },
    ],
    [
      "repos + USES edges",
      `UNWIND $rows AS row
       CREATE (r:Repo {name: row.name, url: 'https://git.lumen.example/' + row.name, owner_team: row.owner_team})
       WITH r, row
       UNWIND row.uses AS u
       MATCH (p:Package {name: u.pkg})
       CREATE (r)-[:USES {scope: u.scope}]->(p)`,
      { rows: repos },
    ],
    [
      "services + BUILT_FROM edges",
      `UNWIND $rows AS row
       MATCH (r:Repo {name: row.builtFrom})
       CREATE (:Service {name: row.name, env: row.env, criticality: row.criticality})-[:BUILT_FROM]->(r)`,
      { rows: services },
    ],
    [
      "CALLS edges",
      `UNWIND $rows AS row
       MATCH (a:Service {name: row[0]}), (b:Service {name: row[1]})
       CREATE (a)-[:CALLS]->(b)`,
      { rows: calls },
    ],
    [
      "customers + USES edges",
      `UNWIND $rows AS row
       CREATE (c:Customer {name: row.name, arr_usd: row.arr_usd, sla_tier: row.sla_tier,
                           notify_within_hours: row.notify_within_hours})
       WITH c, row
       UNWIND row.uses AS svc
       MATCH (s:Service {name: svc})
       CREATE (c)-[:USES]->(s)`,
      { rows: customers },
    ],
    [
      "owners + OWNS edges",
      `UNWIND $rows AS row
       CREATE (o:Owner {name: row.name, team: row.team, on_call: row.on_call})
       WITH o, row
       UNWIND row.owns AS target
       MATCH (x) WHERE (x:Repo OR x:Service) AND x.name = target
       CREATE (o)-[:OWNS]->(x)`,
      { rows: owners },
    ],
    [
      "CVEs + AFFECTS edges",
      `UNWIND $rows AS row
       MATCH (p:Package {name: row.package})
       CREATE (:CVE {id: row.id, severity: row.severity, cvss: row.cvss, published_at: row.published_at,
                     affected_range: row.affected_range, fixed_in: row.fixed_in, summary: row.summary})
              -[:AFFECTS]->(p)`,
      { rows: cves },
    ],
  ];

  for (const [label, cypher, params] of steps) {
    const res = await graph.query(cypher, { params });
    const created = res.metadata.filter((m) => m.startsWith("Nodes created") || m.startsWith("Relationships created"));
    console.log(`  ${label}: ${created.join(", ") || "nothing created"}`);
  }

  // Indexes on the properties every tool looks up by.
  for (const label of ["Package", "Repo", "Service", "Customer", "Owner"]) {
    await graph.createNodeRangeIndex(label, "name");
  }
  await graph.createNodeRangeIndex("CVE", "id");

  const counts = await graph.query<{ label: string; n: number }>(
    "MATCH (n) RETURN labels(n)[0] AS label, count(n) AS n ORDER BY label",
  );
  console.log(`\nSeeded graph "${falkordbConfig.graph}":`);
  for (const row of counts.data ?? []) console.log(`  ${row.label}: ${row.n}`);

  await db.close();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
