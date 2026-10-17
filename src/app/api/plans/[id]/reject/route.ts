import type { NextRequest } from "next/server";
import { decide } from "../decide";

// POST /api/plans/:id/reject
export function POST(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  return decide(req, ctx, "rejected");
}
