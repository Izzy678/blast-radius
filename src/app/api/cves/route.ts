import { NextResponse } from "next/server";
import { listCves } from "@/lib/tools/graph-tools";

// GET /api/cves: CVEs in the graph, for the UI picker.
export async function GET() {
  const { data } = await listCves();
  return NextResponse.json({ cves: data });
}
