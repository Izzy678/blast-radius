import { NextResponse, type NextRequest } from "next/server";
import { naiveManifestScan } from "@/lib/baseline";
import { rankBlastRadiusForCve } from "@/lib/tools/analysis";

// GET /api/blast-radius?cve=CVE-2021-44906
// Deterministic graph answer (no LLM) plus the "without the graph" baseline.
export async function GET(req: NextRequest) {
  const cveId = req.nextUrl.searchParams.get("cve");
  if (!cveId) return NextResponse.json({ error: "missing ?cve=" }, { status: 400 });

  const { data, evidence } = await rankBlastRadiusForCve(cveId);
  if (!data) return NextResponse.json({ error: `${cveId} is not in the graph`, evidence }, { status: 404 });

  return NextResponse.json({ report: data, evidence, baseline: naiveManifestScan(cveId) });
}
