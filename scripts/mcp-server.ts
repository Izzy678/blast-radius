/**
 * MCP server exposing the same graph tools the in-app agent uses, over stdio.
 * Any MCP client (Claude Desktop, Claude Code, Cursor, ...) can then pick tools
 * and walk the FalkorDB graph itself.
 *
 * Run with: npm run mcp
 * Client config example:
 *   { "command": "npm", "args": ["run", "--silent", "mcp"], "cwd": "<path to this repo>" }
 *
 * stdout carries the MCP protocol, so nothing else may print to it.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { runTool, tools } from "../src/lib/tools/registry";

const server = new Server(
  { name: "blast-radius", version: "0.1.0" },
  {
    capabilities: { tools: {} },
    instructions:
      "Supply chain security tools over a FalkorDB graph. Start with get_cve, then find_dependent_repos and trace_blast_radius; " +
      "use rank_blast_radius for revenue numbers (never compute them yourself). draft_fix_plan saves a plan as pending; only a human can approve it.",
  },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: tools.map((t) => ({ name: t.name, description: t.description, inputSchema: t.parameters })),
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const result = await runTool(req.params.name, req.params.arguments ?? {});
  const isError = !!(result.output && typeof result.output === "object" && "error" in result.output);
  return {
    isError,
    content: [
      { type: "text", text: JSON.stringify(result.output, null, 2) },
      // The Cypher behind the answer, so the client can show its evidence too.
      { type: "text", text: `Cypher evidence:\n${result.evidence.map((e) => `-- ${e.tool} (${e.ms} ms)\n${e.cypher}`).join("\n\n")}` },
    ],
  };
});

// The FalkorDB connection would keep the process alive after the client goes away.
server.onclose = () => process.exit(0);
process.stdin.on("end", () => process.exit(0));

server
  .connect(new StdioServerTransport())
  .then(() => console.error("blast-radius MCP server running on stdio"))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
