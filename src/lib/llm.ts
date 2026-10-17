/**
 * Small LLM adapter so the provider can be swapped. Only `chat` is used:
 * it sends the conversation plus tool definitions and returns either text
 * or tool calls. Currently implemented for Google Gemini (REST, no SDK).
 *
 * Env: LLM_API_KEY, LLM_MODEL (default gemini-2.5-flash).
 */

export type JsonSchema = {
  type: "object" | "string" | "number" | "integer" | "boolean" | "array";
  description?: string;
  properties?: Record<string, JsonSchema>;
  items?: JsonSchema;
  required?: string[];
};

export type ToolSpec = { name: string; description: string; parameters: JsonSchema };

export type ToolCall = { id: string; name: string; args: Record<string, unknown> };

export type ChatMessage =
  | { role: "user"; text: string }
  // `raw` is the provider's own representation, replayed verbatim on the next turn
  // (Gemini requires its thought signatures to be sent back unchanged).
  | { role: "assistant"; text: string; toolCalls: ToolCall[]; raw: unknown }
  | { role: "tool"; results: { call: ToolCall; output: unknown }[] };

export type ChatResponse = { text: string; toolCalls: ToolCall[]; raw: unknown };

export class LlmNotConfiguredError extends Error {}

export function llmConfig() {
  return {
    apiKey: process.env.LLM_API_KEY ?? "",
    model: process.env.LLM_MODEL || "gemini-2.5-flash",
  };
}

export async function chat(opts: { system: string; messages: ChatMessage[]; tools: ToolSpec[] }): Promise<ChatResponse> {
  const { apiKey, model } = llmConfig();
  if (!apiKey) throw new LlmNotConfiguredError("LLM_API_KEY is not set");
  return geminiChat(apiKey, model, opts);
}

// --- Gemini -----------------------------------------------------------------

type GeminiPart = {
  text?: string;
  thought?: boolean;
  functionCall?: { id?: string; name: string; args?: Record<string, unknown> };
  functionResponse?: { id?: string; name: string; response: Record<string, unknown> };
};
type GeminiContent = { role: "user" | "model"; parts: GeminiPart[] };

async function geminiChat(
  apiKey: string,
  model: string,
  { system, messages, tools }: { system: string; messages: ChatMessage[]; tools: ToolSpec[] },
): Promise<ChatResponse> {
  const contents: GeminiContent[] = messages.map((m) => {
    if (m.role === "user") return { role: "user", parts: [{ text: m.text }] };
    if (m.role === "assistant") return m.raw as GeminiContent;
    return {
      role: "user",
      parts: m.results.map(({ call, output }) => ({
        functionResponse: { id: call.id, name: call.name, response: { result: output } },
      })),
    };
  });

  const body = {
    systemInstruction: { parts: [{ text: system }] },
    contents,
    tools: [{ functionDeclarations: tools }],
    generationConfig: { temperature: 0.2 },
  };

  // Free-tier keys hit rate limits and occasionally hang, so each attempt has a
  // timeout and 429/503/network errors are retried with backoff.
  let res: Response | null = null;
  let lastError: unknown = null;
  for (let attempt = 0; attempt < 4; attempt++) {
    if (attempt > 0) await new Promise((r) => setTimeout(r, 2000 * 2 ** (attempt - 1)));
    const started = Date.now();
    try {
      res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-goog-api-key": apiKey },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(60_000),
      });
    } catch (err) {
      lastError = err;
      res = null;
      console.warn(`[llm] attempt ${attempt + 1} failed after ${Date.now() - started} ms: ${String(err)}`);
      continue;
    }
    console.info(`[llm] ${model} ${res.status} in ${Date.now() - started} ms`);
    if (res.status !== 429 && res.status !== 503) break;
  }
  if (!res) throw new Error(`Gemini request failed: ${String(lastError)}`);
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(`Gemini ${res.status}: ${detail.slice(0, 300)}`);
  }

  const json = (await res.json()) as { candidates?: { content?: GeminiContent; finishReason?: string }[] };
  const content = json.candidates?.[0]?.content ?? { role: "model", parts: [] };
  const parts = content.parts ?? [];

  return {
    text: parts
      .filter((p) => p.text && !p.thought)
      .map((p) => p.text)
      .join(""),
    toolCalls: parts
      .filter((p) => p.functionCall)
      .map((p, i) => ({
        id: p.functionCall!.id ?? `call-${i}`,
        name: p.functionCall!.name,
        args: p.functionCall!.args ?? {},
      })),
    raw: { role: "model", parts },
  };
}
