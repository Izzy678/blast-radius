import { NextResponse, type NextRequest } from "next/server";
import { getPlan } from "@/lib/plans";

// GET /api/plans/:id
export async function GET(_req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  const plan = await getPlan(id);
  if (!plan) return NextResponse.json({ error: "not_found" }, { status: 404 });
  return NextResponse.json({ plan });
}
