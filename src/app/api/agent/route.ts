import { NextResponse, type NextRequest } from "next/server";
import { runAgent } from "@/lib/agent";
import { LlmNotConfiguredError } from "@/lib/llm";

// POST /api/agent { cveId, question? }: the LLM investigates with the graph tools
// and drafts a pending fix plan.
export async function POST(req: NextRequest) {
  const body = (await req.json().catch(() => ({}))) as { cveId?: string; question?: string };
  if (!body.cveId) return NextResponse.json({ error: "missing cveId" }, { status: 400 });

  try {
    return NextResponse.json(await runAgent(body.cveId, body.question));
  } catch (err) {
    if (err instanceof LlmNotConfiguredError) {
      return NextResponse.json({ error: "LLM is not configured: set LLM_API_KEY in .env" }, { status: 501 });
    }
    console.error(err);
    return NextResponse.json({ error: err instanceof Error ? err.message : String(err) }, { status: 502 });
  }
}
