import { NextResponse, type NextRequest } from "next/server";
import { decidePlan } from "@/lib/plans";

/** Shared handler for /approve and /reject. Body: { by?, note? } */
export async function decide(
  req: NextRequest,
  ctx: { params: Promise<{ id: string }> },
  status: "approved" | "rejected",
) {
  const { id } = await ctx.params;
  const body = (await req.json().catch(() => ({}))) as { by?: string; note?: string };
  const { plan, error } = await decidePlan(id, status, body.by?.trim() || "reviewer", body.note?.trim() || null);
  if (error === "not_found") return NextResponse.json({ error }, { status: 404 });
  if (error) return NextResponse.json({ error, plan }, { status: 409 });
  return NextResponse.json({ plan });
}
