/**
 * "Without the graph" baseline, for the side-by-side comparison.
 *
 * This is what a typical flat approach does: read each repo's manifest and grep
 * its *direct* dependencies for the vulnerable package name. It deliberately
 * does not touch FalkorDB. It has no transitive dependency edges, no
 * repo -> service -> customer links and no prod/dev distinction beyond the
 * manifest line, so it misses everything reachable only through other packages.
 */
import { cves, repos } from "@/data/seed-data";

export type BaselineResult = {
  method: string;
  vulnerable_package: string | null;
  flagged_repos: { repo: string; scope: string }[];
  customers_identified: number;
  revenue_identified: number;
  notes: string;
};

export function naiveManifestScan(cveId: string): BaselineResult {
  const cve = cves.find((c) => c.id === cveId);
  if (!cve) {
    return {
      method: "grep direct dependencies in each repo manifest",
      vulnerable_package: null,
      flagged_repos: [],
      customers_identified: 0,
      revenue_identified: 0,
      notes: `Unknown CVE ${cveId}.`,
    };
  }
  const flagged = repos.flatMap((r) =>
    r.uses.filter((u) => u.pkg === cve.package).map((u) => ({ repo: r.name, scope: u.scope })),
  );
  return {
    method: "grep direct dependencies in each repo manifest",
    vulnerable_package: cve.package,
    flagged_repos: flagged,
    // A manifest has no link to services or customers, so nothing can be said about revenue.
    customers_identified: 0,
    revenue_identified: 0,
    notes: flagged.length
      ? `Found ${cve.package} listed directly in ${flagged.length} repo(s). No way to tell which services or customers are affected.`
      : `${cve.package} isn't listed directly in any repo manifest, so this approach reports nothing affected.`,
  };
}
