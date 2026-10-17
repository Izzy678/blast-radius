import { FalkorDB } from "falkordb";

// FalkorDB connection config. Values come from .env.local (see .env.example).
export const falkordbConfig = {
  host: process.env.FALKORDB_HOST ?? "localhost",
  port: Number(process.env.FALKORDB_PORT ?? 6379),
  password: process.env.FALKORDB_PASSWORD || undefined,
  graph: process.env.FALKORDB_GRAPH ?? "supplychain",
};

// Keep a single connection per process. In `next dev`, modules are reloaded on
// every edit, so the client is cached on globalThis to avoid leaking sockets.
const globalForDb = globalThis as unknown as { falkordb?: Promise<FalkorDB> };

export function getDb(): Promise<FalkorDB> {
  if (!globalForDb.falkordb) {
    globalForDb.falkordb = FalkorDB.connect({
      socket: { host: falkordbConfig.host, port: falkordbConfig.port },
      password: falkordbConfig.password,
    }).catch((err) => {
      // Drop the failed promise so the next call retries instead of failing forever.
      globalForDb.falkordb = undefined;
      throw err;
    });
  }
  return globalForDb.falkordb;
}

export async function getGraph() {
  const db = await getDb();
  return db.selectGraph(falkordbConfig.graph);
}

// Mirrors the client's (unexported) QueryParams type.
export type QueryParam = null | string | number | boolean | QueryParams | QueryParam[];
export type QueryParams = { [key: string]: QueryParam };

/**
 * Run a read-only Cypher query and return its rows plus timing.
 * Every tool goes through here so the UI can show the exact query and latency.
 */
export async function runQuery<T>(
  cypher: string,
  params: QueryParams = {},
): Promise<{ rows: T[]; cypher: string; params: QueryParams; ms: number }> {
  const graph = await getGraph();
  const start = performance.now();
  const res = await graph.roQuery<T>(cypher, { params });
  const ms = Math.round((performance.now() - start) * 100) / 100;
  return { rows: res.data ?? [], cypher, params, ms };
}
