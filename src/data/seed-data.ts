/**
 * Synthetic supply chain for the demo company "Lumen".
 *
 * Everything here is made up except:
 *  - third-party package names (real npm packages; the dependency edges are
 *    simplified and illustrative, not an exact copy of their real trees), and
 *  - the two CVE records, which are real public advisories.
 *
 * Planted scenario (see CLAUDE.md "Demo scenario"):
 *  - CVE-2021-44906 hits `minimist`. No production repo uses minimist directly.
 *    It reaches prod only transitively:
 *      notifications-svc -> @lumen/notify -> @lumen/mailer -> handlebars -> minimist  (3 hops)
 *      checkout-api      -> @lumen/mailer -> handlebars -> minimist                   (2 hops)
 *  - admin-portal and auth-service reach minimist only through dev tooling
 *    (mocha -> mkdirp -> minimist), so their customers rank low.
 *  - dev-cli lists minimist directly, but only as a dev dependency and no
 *    service is built from it. A "grep direct deps" approach finds only this one.
 *  - Customers on search / media / analytics have no path at all, so they're safe.
 *  - CVE-2024-4067 hits `micromatch`, which is reachable only through dev tools.
 */

export type Scope = "prod" | "dev";

export const packages: { name: string; ecosystem: string; version: string; internal?: boolean }[] = [
  // Internal Lumen packages
  { name: "@lumen/mailer", ecosystem: "npm", version: "2.3.1", internal: true },
  { name: "@lumen/notify", ecosystem: "npm", version: "1.8.0", internal: true },
  { name: "@lumen/auth", ecosystem: "npm", version: "3.0.2", internal: true },
  { name: "@lumen/logger", ecosystem: "npm", version: "1.4.0", internal: true },
  { name: "@lumen/db", ecosystem: "npm", version: "2.1.0", internal: true },
  { name: "@lumen/ui", ecosystem: "npm", version: "4.2.0", internal: true },
  // Third-party packages
  { name: "express", ecosystem: "npm", version: "4.18.2" },
  { name: "body-parser", ecosystem: "npm", version: "1.20.1" },
  { name: "qs", ecosystem: "npm", version: "6.11.0" },
  { name: "debug", ecosystem: "npm", version: "4.3.4" },
  { name: "ms", ecosystem: "npm", version: "2.1.3" },
  { name: "axios", ecosystem: "npm", version: "1.6.0" },
  { name: "follow-redirects", ecosystem: "npm", version: "1.15.3" },
  { name: "handlebars", ecosystem: "npm", version: "4.7.7" },
  { name: "minimist", ecosystem: "npm", version: "1.2.5" },
  { name: "mkdirp", ecosystem: "npm", version: "0.5.5" },
  { name: "mocha", ecosystem: "npm", version: "9.1.3" },
  { name: "jest", ecosystem: "npm", version: "29.5.0" },
  { name: "fast-glob", ecosystem: "npm", version: "3.2.12" },
  { name: "micromatch", ecosystem: "npm", version: "4.0.5" },
  { name: "braces", ecosystem: "npm", version: "3.0.2" },
  { name: "react", ecosystem: "npm", version: "18.2.0" },
  { name: "react-dom", ecosystem: "npm", version: "18.2.0" },
  { name: "next", ecosystem: "npm", version: "14.1.0" },
  { name: "pg", ecosystem: "npm", version: "8.11.3" },
  { name: "pg-pool", ecosystem: "npm", version: "3.6.1" },
  { name: "jsonwebtoken", ecosystem: "npm", version: "9.0.2" },
  { name: "jws", ecosystem: "npm", version: "3.2.2" },
  { name: "semver", ecosystem: "npm", version: "7.5.4" },
  { name: "socket.io", ecosystem: "npm", version: "4.7.2" },
  { name: "engine.io", ecosystem: "npm", version: "6.5.4" },
  { name: "ws", ecosystem: "npm", version: "8.14.2" },
  { name: "winston", ecosystem: "npm", version: "3.11.0" },
  { name: "logform", ecosystem: "npm", version: "2.6.0" },
  { name: "nodemailer", ecosystem: "npm", version: "6.9.7" },
  { name: "stripe", ecosystem: "npm", version: "14.5.0" },
  { name: "sharp", ecosystem: "npm", version: "0.33.0" },
  { name: "uuid", ecosystem: "npm", version: "9.0.1" },
  { name: "zod", ecosystem: "npm", version: "3.22.4" },
  { name: "lodash", ecosystem: "npm", version: "4.17.21" },
  { name: "dotenv", ecosystem: "npm", version: "16.3.1" },
  { name: "commander", ecosystem: "npm", version: "11.1.0" },
  { name: "chalk", ecosystem: "npm", version: "4.1.2" },
  { name: "eslint", ecosystem: "npm", version: "8.54.0" },
  { name: "typescript", ecosystem: "npm", version: "5.3.2" },
  { name: "prettier", ecosystem: "npm", version: "3.1.0" },
];

// [from, to]: `from` DEPENDS_ON `to`
export const dependsOn: [string, string][] = [
  ["@lumen/notify", "@lumen/mailer"],
  ["@lumen/notify", "ws"],
  ["@lumen/mailer", "handlebars"],
  ["@lumen/mailer", "nodemailer"],
  ["@lumen/auth", "jsonwebtoken"],
  ["@lumen/logger", "winston"],
  ["@lumen/db", "pg"],
  ["@lumen/ui", "react"],
  ["express", "body-parser"],
  ["express", "qs"],
  ["express", "debug"],
  ["body-parser", "qs"],
  ["debug", "ms"],
  ["axios", "follow-redirects"],
  ["handlebars", "minimist"],
  ["mkdirp", "minimist"],
  ["mocha", "mkdirp"],
  ["mocha", "debug"],
  ["mocha", "chalk"],
  ["jest", "micromatch"],
  ["fast-glob", "micromatch"],
  ["micromatch", "braces"],
  ["eslint", "debug"],
  ["eslint", "fast-glob"],
  ["react-dom", "react"],
  ["next", "react"],
  ["next", "react-dom"],
  ["pg", "pg-pool"],
  ["jsonwebtoken", "jws"],
  ["jsonwebtoken", "semver"],
  ["socket.io", "engine.io"],
  ["engine.io", "ws"],
  ["winston", "logform"],
];

export const repos: {
  name: string;
  owner_team: string;
  uses: { pkg: string; scope: Scope }[];
}[] = [
  {
    name: "storefront-web",
    owner_team: "web",
    uses: [
      { pkg: "next", scope: "prod" },
      { pkg: "@lumen/ui", scope: "prod" },
      { pkg: "axios", scope: "prod" },
      { pkg: "zod", scope: "prod" },
      { pkg: "jest", scope: "dev" },
      { pkg: "eslint", scope: "dev" },
      { pkg: "typescript", scope: "dev" },
    ],
  },
  {
    name: "checkout-api",
    owner_team: "payments",
    uses: [
      { pkg: "express", scope: "prod" },
      { pkg: "stripe", scope: "prod" },
      { pkg: "@lumen/auth", scope: "prod" },
      { pkg: "@lumen/db", scope: "prod" },
      { pkg: "@lumen/logger", scope: "prod" },
      { pkg: "@lumen/mailer", scope: "prod" }, // sends receipts -> minimist, 2 hops
      { pkg: "mocha", scope: "dev" },
    ],
  },
  {
    name: "notifications-svc",
    owner_team: "messaging",
    uses: [
      { pkg: "@lumen/notify", scope: "prod" }, // -> minimist, 3 hops
      { pkg: "@lumen/logger", scope: "prod" },
      { pkg: "socket.io", scope: "prod" },
      { pkg: "jest", scope: "dev" },
    ],
  },
  {
    name: "auth-service",
    owner_team: "identity",
    uses: [
      { pkg: "express", scope: "prod" },
      { pkg: "@lumen/auth", scope: "prod" },
      { pkg: "@lumen/db", scope: "prod" },
      { pkg: "mocha", scope: "dev" }, // dev-only path to minimist
    ],
  },
  {
    name: "search-api",
    owner_team: "search",
    uses: [
      { pkg: "express", scope: "prod" },
      { pkg: "lodash", scope: "prod" },
      { pkg: "@lumen/logger", scope: "prod" },
      { pkg: "jest", scope: "dev" },
    ],
  },
  {
    name: "media-pipeline",
    owner_team: "media",
    uses: [
      { pkg: "sharp", scope: "prod" },
      { pkg: "uuid", scope: "prod" },
      { pkg: "axios", scope: "prod" },
      { pkg: "jest", scope: "dev" },
    ],
  },
  {
    name: "reporting-jobs",
    owner_team: "data",
    uses: [
      { pkg: "pg", scope: "prod" },
      { pkg: "commander", scope: "prod" },
      { pkg: "@lumen/notify", scope: "prod" }, // emails reports -> minimist, 3 hops
      { pkg: "jest", scope: "dev" },
    ],
  },
  {
    name: "admin-portal",
    owner_team: "internal-tools",
    uses: [
      { pkg: "next", scope: "prod" },
      { pkg: "@lumen/ui", scope: "prod" },
      { pkg: "mocha", scope: "dev" }, // dev-only path to minimist
    ],
  },
  {
    name: "billing-worker",
    owner_team: "payments",
    uses: [
      { pkg: "stripe", scope: "prod" },
      { pkg: "@lumen/db", scope: "prod" },
      { pkg: "@lumen/logger", scope: "prod" },
      { pkg: "dotenv", scope: "prod" },
      { pkg: "mocha", scope: "dev" },
    ],
  },
  {
    name: "analytics-ingest",
    owner_team: "data",
    uses: [
      { pkg: "ws", scope: "prod" },
      { pkg: "uuid", scope: "prod" },
      { pkg: "zod", scope: "prod" },
      { pkg: "jest", scope: "dev" },
    ],
  },
  {
    name: "dev-cli",
    owner_team: "devex",
    uses: [
      { pkg: "commander", scope: "prod" },
      { pkg: "chalk", scope: "prod" },
      { pkg: "minimist", scope: "dev" }, // the only *direct* minimist dependency
    ],
  },
  {
    name: "docs-site",
    owner_team: "devex",
    uses: [
      { pkg: "next", scope: "prod" },
      { pkg: "prettier", scope: "dev" },
    ],
  },
];

export const services: {
  name: string;
  env: "prod";
  criticality: "high" | "medium" | "low";
  builtFrom: string;
}[] = [
  { name: "storefront", env: "prod", criticality: "high", builtFrom: "storefront-web" },
  { name: "checkout", env: "prod", criticality: "high", builtFrom: "checkout-api" },
  { name: "notifications", env: "prod", criticality: "medium", builtFrom: "notifications-svc" },
  { name: "auth", env: "prod", criticality: "high", builtFrom: "auth-service" },
  { name: "search", env: "prod", criticality: "medium", builtFrom: "search-api" },
  { name: "media", env: "prod", criticality: "low", builtFrom: "media-pipeline" },
  { name: "reporting", env: "prod", criticality: "medium", builtFrom: "reporting-jobs" },
  { name: "admin", env: "prod", criticality: "low", builtFrom: "admin-portal" },
  { name: "billing", env: "prod", criticality: "high", builtFrom: "billing-worker" },
  { name: "analytics", env: "prod", criticality: "medium", builtFrom: "analytics-ingest" },
];

// [caller, callee]: runtime calls between services
export const calls: [string, string][] = [
  ["storefront", "checkout"],
  ["storefront", "search"],
  ["storefront", "auth"],
  ["storefront", "media"],
  ["checkout", "billing"],
  ["checkout", "auth"],
  ["checkout", "notifications"],
  ["billing", "notifications"],
  ["reporting", "analytics"],
  ["admin", "auth"],
];

export const customers: {
  name: string;
  arr_usd: number;
  sla_tier: "platinum" | "gold" | "silver" | "bronze";
  notify_within_hours: number;
  uses: string[];
}[] = [
  { name: "Kestrel Banking", arr_usd: 1_450_000, sla_tier: "platinum", notify_within_hours: 2, uses: ["checkout", "billing"] },
  { name: "Meridian Health Group", arr_usd: 1_100_000, sla_tier: "platinum", notify_within_hours: 4, uses: ["notifications", "reporting"] },
  { name: "Harbor & Pine Outfitters", arr_usd: 820_000, sla_tier: "gold", notify_within_hours: 8, uses: ["storefront"] },
  { name: "Quillfeather Logistics", arr_usd: 640_000, sla_tier: "gold", notify_within_hours: 8, uses: ["billing"] },
  { name: "Bluefin Insurance", arr_usd: 560_000, sla_tier: "gold", notify_within_hours: 8, uses: ["reporting"] },
  { name: "Orchard Analytics Co", arr_usd: 520_000, sla_tier: "gold", notify_within_hours: 8, uses: ["analytics"] }, // no path: safe
  { name: "Brightwater Grocers", arr_usd: 410_000, sla_tier: "silver", notify_within_hours: 24, uses: ["storefront"] },
  { name: "Northstar Freight", arr_usd: 350_000, sla_tier: "silver", notify_within_hours: 24, uses: ["notifications"] },
  { name: "Tidewell Media", arr_usd: 310_000, sla_tier: "silver", notify_within_hours: 24, uses: ["media"] }, // no path: safe
  { name: "Peakform Fitness", arr_usd: 290_000, sla_tier: "silver", notify_within_hours: 24, uses: ["checkout"] },
  { name: "Copperline Travel", arr_usd: 240_000, sla_tier: "silver", notify_within_hours: 24, uses: ["search", "media"] }, // no path: safe
  { name: "Juniper Schools", arr_usd: 180_000, sla_tier: "bronze", notify_within_hours: 48, uses: ["admin"] }, // dev-only path
  { name: "Saltmarsh Studios", arr_usd: 150_000, sla_tier: "bronze", notify_within_hours: 48, uses: ["search"] }, // no path: safe
  { name: "Lanternfish Games", arr_usd: 120_000, sla_tier: "bronze", notify_within_hours: 48, uses: ["auth"] }, // dev-only path
  { name: "Marigold Clinics", arr_usd: 95_000, sla_tier: "bronze", notify_within_hours: 48, uses: ["storefront"] },
];

export const owners: { name: string; team: string; on_call: boolean; owns: string[] }[] = [
  { name: "Ada Okafor", team: "payments", on_call: true, owns: ["checkout-api", "billing-worker", "checkout", "billing"] },
  { name: "Tunde Bakare", team: "messaging", on_call: true, owns: ["notifications-svc", "notifications"] },
  { name: "Priya Raman", team: "web", on_call: false, owns: ["storefront-web", "storefront"] },
  { name: "Marco Bianchi", team: "identity", on_call: true, owns: ["auth-service", "auth"] },
  { name: "Lena Fischer", team: "search", on_call: false, owns: ["search-api", "search"] },
  { name: "Kenji Sato", team: "media", on_call: false, owns: ["media-pipeline", "media"] },
  { name: "Sofia Alvarez", team: "data", on_call: true, owns: ["reporting-jobs", "analytics-ingest", "reporting", "analytics"] },
  { name: "Omar Haddad", team: "internal-tools", on_call: false, owns: ["admin-portal", "admin"] },
  { name: "Grace Mensah", team: "devex", on_call: false, owns: ["dev-cli", "docs-site"] },
];

// Real public advisories (summarised from the NVD / GitHub Advisory Database).
export const cves: {
  id: string;
  package: string;
  severity: "critical" | "high" | "medium" | "low";
  cvss: number;
  published_at: string;
  affected_range: string;
  fixed_in: string;
  summary: string;
}[] = [
  {
    id: "CVE-2021-44906",
    package: "minimist",
    severity: "critical",
    cvss: 9.8,
    published_at: "2022-03-17",
    affected_range: "<1.2.6",
    fixed_in: "1.2.6",
    summary: "Prototype pollution in minimist argument parsing.",
  },
  {
    id: "CVE-2024-4067",
    package: "micromatch",
    severity: "medium",
    cvss: 5.3,
    published_at: "2024-05-14",
    affected_range: "<4.0.8",
    fixed_in: "4.0.8",
    summary: "Regular expression denial of service (ReDoS) in micromatch.braces().",
  },
];
