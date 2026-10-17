# CLAUDE.md — instructions for Claude Code

Read this first, then `README.md` (the full spec). Then do step 0.

## 0. Validate against the hackathon before coding
This is an entry for **Graph Hacks: Context for AI Agents (FalkorDB × WeMakeDevs)**, **Track 1: Agents That Act on Connected Data**.
- Event page: https://www.wemakedevs.org/hackathons/falkordb
- Rules: https://www.wemakedevs.org/hackathons/falkordb/rules
- Schedule: https://www.wemakedevs.org/hackathons/falkordb/schedule

Fetch these pages and check this plan against them. If anything here conflicts with the official pages, the official pages win. Flag the conflict to Amune before building.

## Goal
Win, or place in, Track 1, not just ship a demo. The organisers' own test is this: **if the product still works with FalkorDB removed, the graph is just decoration.** Every answer must come from a multi-hop Cypher traversal and show the path behind it.

**Product:** a supply chain security agent. When a CVE lands, it walks the graph from the CVE to packages (including transitive dependencies), then to repos, services and customers. It ranks the fix order by blast radius and revenue at risk, and drafts a fix plan that a human must approve. "No path found" counts as proof that a customer is safe.

## Hard deadline
Submissions close **18 Oct 2026, 11:59 PM IST, which is 7:29 PM Lagos (Africa/Lagos)**. Treat **5:00 PM Lagos on 18 Oct** as code freeze, so there's time to record the video and submit. Cut scope before you'd miss that time.

## Compressed plan (from now, 17 Oct)
1. **Foundation:** FalkorDB in Docker (README §4), the Node client connection in `src/lib/falkordb.ts`, and `scripts/seed.ts` loading the synthetic data.
2. **Tools:** typed Cypher tool functions in `src/lib/tools/` (README §6, day one list), each returning both its results **and** the path it followed.
3. **Agent:** `POST /api/agent` runs a tool-calling loop. The LLM chooses tools and writes the explanation. **Deterministic code** computes the rankings and dollar totals.
4. **Approval:** the agent drafts a fix plan with status `pending`. `POST /api/plans/:id/approve` and `/reject` change it, and nothing counts as final without approval.
5. **UI:** one page where you enter a CVE, see the cascade path (CVE to customers) with revenue at risk, and approve or reject the plan. The page also shows a side-by-side "without the graph" answer.
6. **If time allows:** expose the tools through MCP, deploy, and save incidents back to the graph as precedent.
7. **Submission:** README with the data model and key queries, the AI-use disclosure, and setup steps.

## Demo scenario (definition of done)
Seed data: about 40 packages, 12 repos, 10 services, 15 customers (with `arr_usd`, `sla_tier`), and owners. Plant **one CVE** on a package that reaches production only **transitively, 2 or more hops away**.
- Querying that CVE returns the affected customers ranked by revenue at risk, each with its full path.
- At least one customer depends only on a dev-only path, and is correctly ranked low or shown as safe.
- At least one customer has no path at all, and is shown as safe with an explanation.
- The fix plan lists repos to patch in order, with owners, and stays `pending` until approved.
- The "without the graph" comparison misses the transitive impact.

## Decisions
- **LLM:** not chosen yet. Ask Amune which provider to use. Keep the LLM code behind one small adapter (`src/lib/llm.ts`) reading `LLM_API_KEY` (plus `LLM_MODEL`), so the provider can be swapped.
- **Data:** synthetic data only, plus real public CVE IDs if useful. No private data.
- **Stack:** Next.js App Router + TypeScript (already scaffolded). Use npm. Keep dependencies minimal.
- Check the FalkorDB Node client package name and API in the official docs before installing it.

## Rules you must respect
- Work must be new and done during the event (15–18 Oct). Libraries and templates are fine.
- Amune must disclose AI coding assistant use and be able to explain the code, so keep it readable and commented where it's not obvious.
- Ask Amune before anything that needs his accounts: Docker Desktop install, GitHub repo or push, deployment, LLM keys, registration or submission. **Never register or submit on his behalf.**

## Working style
- Commit after each working step with a clear message.
- Run `npx tsc --noEmit` and `npm run lint` before each commit.
- Ports: Next.js on 3000, FalkorDB on 6379, FalkorDB Browser on 3002 (3001 is taken by another local project).
