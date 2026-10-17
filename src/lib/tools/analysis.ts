import { rankBlastRadius, type BlastRadiusReport } from "../ranking";
import { findDependentRepos, getCve, getOwners, listCustomers, traceBlastRadius } from "./graph-tools";
import type { ToolResult } from "./types";

/**
 * Full blast radius for a CVE: runs the graph traversals, then hands the rows to
 * the deterministic ranking. Returns null if the CVE isn't in the graph.
 */
export async function rankBlastRadiusForCve(cveId: string): Promise<ToolResult<BlastRadiusReport | null>> {
  const cve = await getCve(cveId);
  if (!cve.data) return { data: null, evidence: cve.evidence };

  const [blast, customers, repos] = await Promise.all([
    traceBlastRadius(cveId),
    listCustomers(),
    findDependentRepos(cveId),
  ]);
  const repoNames = [...new Set(repos.data.map((r) => r.repo))];
  const owners = await getOwners(repoNames);

  return {
    data: rankBlastRadius(cve.data, blast.data, customers.data, repos.data, owners.data),
    evidence: [...cve.evidence, ...blast.evidence, ...customers.evidence, ...repos.evidence, ...owners.evidence],
  };
}
