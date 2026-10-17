import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Load the FalkorDB client from node_modules at runtime instead of bundling it:
  // bundling breaks its @js-temporal/polyfill dependency ("BigInt is not a function").
  serverExternalPackages: ["falkordb"],
  cacheComponents: true,
  partialPrefetching: true,
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
