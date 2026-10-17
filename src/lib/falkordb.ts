// FalkorDB connection config (stub). Values come from .env.local.
export const falkordbConfig = {
  host: process.env.FALKORDB_HOST ?? "localhost",
  port: Number(process.env.FALKORDB_PORT ?? 6379),
  password: process.env.FALKORDB_PASSWORD || undefined,
};
