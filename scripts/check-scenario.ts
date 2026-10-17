/**
 * Checks the demo scenario from CLAUDE.md against the live graph.
 * Run with: npm run check   (after npm run seed)
 */
import assert from "node:assert/strict";
import { getDb } from "../src/lib/falkordb";
import { naiveManifestScan } from "../src/lib/baseline";
import { rankBlastRadiusForCve } from "../src/lib/tools/analysis";
import { explainCustomerExposure } from "../src/lib/tools/graph-tools";

const CVE = "CVE-2021-44906";
const usd = (n: number) => `$${n.toLocaleString("en-US")}`;

async function main() {
  const { data: report, evidence } = await rankBlastRadiusForCve(CVE);
  assert(report, `${CVE} should be in the graph`);

  console.log(`${CVE} (${report.cve.package}, CVSS ${report.cve.cvss})`);
  console.log(`  ${evidence.length} queries, ${evidence.reduce((s, e) => s + e.ms, 0).toFixed(1)} ms total`);
  console.log(`  revenue at risk: ${usd(report.totals.revenue_at_risk)}`, report.totals);

  console.log("\nCustomers:");
  for (const c of report.customers) {
    const path = c.best_path?.nodes.map((n) => n.name).join(" -> ") ?? "(no path)";
    console.log(`  ${c.exposure.padEnd(8)} ${c.customer.padEnd(26)} ${usd(c.revenue_at_risk).padStart(11)}  ${path}`);
  }

  console.log("\nFix order:");
  for (const r of report.fix_order) {
    console.log(
      `  ${r.order}. ${r.repo.padEnd(18)} ${r.exposure.padEnd(8)} bump ${r.bump.join(", ").padEnd(16)} ` +
        `${usd(r.revenue_at_risk).padStart(11)}  owner: ${r.owners.map((o) => o.name).join(", ")}`,
    );
  }

  // --- Definition of done --------------------------------------------------
  const prod = report.customers.filter((c) => c.exposure === "prod");
  assert(prod.length > 0, "some customers are affected");
  assert(
    prod.every((c) => (c.best_path?.nodes.filter((n) => n.label === "Package").length ?? 0) >= 3),
    "every prod path reaches the vulnerable package transitively (2+ package hops)",
  );
  assert(report.customers.some((c) => c.exposure === "dev-only"), "at least one dev-only customer");
  assert(report.customers.some((c) => c.exposure === "none"), "at least one customer with no path");
  assert(report.fix_order.every((r) => r.owners.length > 0), "every repo in the fix plan has an owner");

  const safe = await explainCustomerExposure(CVE, "Orchard Analytics Co");
  assert.equal(safe.data?.exposure, "none");
  console.log(`\nSafety proof: ${safe.data?.explanation}`);

  const baseline = naiveManifestScan(CVE);
  const baselineProd = baseline.flagged_repos.filter((r) => r.scope === "prod");
  assert.equal(baselineProd.length, 0, "baseline finds no prod repos (it misses transitive impact)");
  console.log(`Baseline (no graph): ${baseline.notes}`);

  const micro = await rankBlastRadiusForCve("CVE-2024-4067");
  assert.equal(micro.data?.totals.customers_prod, 0, "micromatch only reaches dev tooling");
  console.log(`CVE-2024-4067: ${micro.data?.totals.customers_prod} prod customers, ${micro.data?.totals.repos_dev_only} dev-only repos`);

  console.log("\nAll scenario checks passed.");
  await (await getDb()).close();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
