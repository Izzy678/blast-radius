import type { QueryParams } from "../falkordb";

/** One query the agent ran: shown in the UI so every claim links to its Cypher. */
export type Evidence = {
  tool: string;
  cypher: string;
  params: QueryParams;
  ms: number;
  rowCount: number;
};

/** Every tool returns its data plus the queries (evidence) behind it. */
export type ToolResult<T> = { data: T; evidence: Evidence[] };

/** A node on a traversed path, e.g. { label: "Package", name: "minimist" }. */
export type PathNode = { label: string; name: string };

/** A full path as returned by Cypher: nodes in order plus the edge types between them. */
export type GraphPath = { nodes: PathNode[]; rels: string[] };

export type Scope = "prod" | "dev";
