import { NextResponse, type NextRequest } from "next/server";
import { createPlan, listPlans } from "@/lib/plans";
import { rankBlastRadiusForCve } from "@/lib/tools/analysis";

// GET /api/plans?cve=...: past plans (newest first).
export async function GET(req: NextRequest) {
  const cveId = req.nextUrl.searchParams.get("cve") ?? undefined;
  return NextResponse.json({ plans: await listPlans(cveId) });
}

// POST /api/plans { cveId, summary? }: draft a pending fix plan from the ranked blast radius.
export async function POST(req: NextRequest) {
  const body = (await req.json().catch(() => ({}))) as { cveId?: string; summary?: string };
  if (!body.cveId) return NextResponse.json({ error: "missing cveId" }, { status: 400 });

  const { data: report } = await rankBlastRadiusForCve(body.cveId);
  if (!report) return NextResponse.json({ error: `${body.cveId} is not in the graph` }, { status: 404 });

  const plan = await createPlan(report, body.summary ?? "");
  return NextResponse.json({ plan }, { status: 201 });
}
