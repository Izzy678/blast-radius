import type { NextRequest } from "next/server";
import { decide } from "../decide";

// POST /api/plans/:id/approve: a human signs off on the fix order.
export function POST(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  return decide(req, ctx, "approved");
}
