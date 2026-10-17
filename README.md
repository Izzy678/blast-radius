# Falkor DB Hackathon (temporary name)

> Entry for **Graph Hacks: Context for AI Agents — FalkorDB × WeMakeDevs**, **Track 1: Agents That Act on Connected Data**.
> The project name is a placeholder and will be renamed later.
> This README is written so another developer or AI agent can start building from it with no other context.

---

## 1. Pitch

**A supply chain security agent.** When a new CVE drops, the agent walks the FalkorDB graph from the vulnerable package through every repo, service and customer that depends on it, directly or through other packages. It then:

1. **Calculates the blast radius**, meaning every affected repo, service and customer, along with the exact graph path that connects each one to the CVE.
2. **Ranks patches** by blast radius and **revenue at risk**, using the customers' contract value and SLA exposure.
3. **Drafts a fix order**, a prioritized patch plan with owners, and waits for a **human to approve** it before anything counts as decided.

**Why it's different.** It merges three ideas that previous projects only did separately:
- **Promise Breaker:** puts a dollar figure on an incident by tracing it to customers and revenue.
- **Faultline:** shows the failure spreading live, as a cascade view.
- **ORBIT Security Blast Radius Agent:** focuses on the blast radius of a security vulnerability.

None of the projects we researched did all three: security, dollars and a live cascade.

**Core principle (from the hackathon rules):** the graph must do real work. If the product still works with FalkorDB removed, the graph is just decoration. Every answer the agent gives must come from a multi-hop Cypher traversal, and every claim must show the path behind it. A "no path found" result counts as proof that a customer is **not** affected.

---

## 2. Tech stack

| Layer | Choice |
|---|---|
| App | **Next.js (App Router) + TypeScript**: frontend and backend in one app; API routes in `src/app/api/*` act as the backend |
| Styling | Tailwind CSS (already scaffolded) |
| Graph database | **FalkorDB**, run locally in **Docker** |
| DB client | FalkorDB Node.js client (npm package `falkordb`; check the name and API in the official docs before installing) |
| Agent tools | Cypher queries wrapped as typed TypeScript functions ("tools") |
| MCP | The same tools exposed through an MCP server so the agent can choose which one to call |
| LLM | Any LLM API with tool calling. The LLM chooses tools and writes explanations; **deterministic code does the maths** (ranking, revenue totals) |
| UI | A lightweight cascade screen showing the traversed graph path. A graph visualisation library such as React Flow or Cytoscape is optional |

### Current repo state
- `src/app/page.tsx`: placeholder home page that shows the title.
- `src/app/api/hello/route.ts`: `GET /api/hello` returns `{ "message": "Hello from Falco DB Hackathon" }`.
- `src/lib/falkordb.ts`: connection config stub that reads the env vars below.
- `.env.example`: placeholders for the FalkorDB connection.
- **No hackathon logic has been built yet.**

---

## 3. Graph model

### Nodes
| Label | Key properties |
|---|---|
| `Package` | `name`, `ecosystem` (npm, pypi…), `version` |
| `CVE` | `id` (e.g. CVE-2026-1234), `severity`, `cvss`, `published_at`, `affected_range` |
| `Repo` | `name`, `url`, `owner_team` |
| `Service` | `name`, `env` (prod/staging), `criticality` |
| `Customer` | `name`, `arr_usd` (annual revenue), `sla_tier`, `notify_within_hours` |
| `Owner` (optional) | `name`, `team`, `on_call` |

### Edges
| Edge | Meaning |
|---|---|
| `(:CVE)-[:AFFECTS]->(:Package)` | the vulnerability hits this package version |
| `(:Package)-[:DEPENDS_ON]->(:Package)` | transitive dependency chain |
| `(:Repo)-[:USES {scope:"prod"\|"dev"}]->(:Package)` | repo depends on a package (dev-only usage is lower risk) |
| `(:Service)-[:BUILT_FROM]->(:Repo)` | a deployed service is built from a repo |
| `(:Service)-[:CALLS]->(:Service)` | runtime dependency between services |
| `(:Customer)-[:USES]->(:Service)` | customer relies on the service |
| `(:Owner)-[:OWNS]->(:Repo\|:Service)` | who has to approve or do the fix |

### Example traversal (blast radius for one CVE)
```cypher
MATCH path = (c:CVE {id: $cveId})-[:AFFECTS]->(:Package)<-[:DEPENDS_ON*0..5]-(:Package)
             <-[:USES]-(r:Repo)<-[:BUILT_FROM]-(s:Service)<-[:CALLS*0..3]-(:Service)<-[:USES]-(cust:Customer)
RETURN cust.name AS customer, cust.arr_usd AS revenue, s.name AS service, r.name AS repo, path
```
Note that variable-length paths in this direction need checking against FalkorDB's Cypher support; split the query into smaller steps if needed.

### Data
Use **public or made-up data only**: a synthetic generator for packages, repos, services and customers, plus real public CVE entries (for example from OSV.dev or the NVD) if useful.

---

## 4. FalkorDB setup

### Run FalkorDB in Docker
```bash
docker run -d --name falkordb -p 6379:6379 -p 3001:3000 falkordb/falkordb:latest
```
- `6379` is the database port.
- `3001` serves the FalkorDB Browser UI, which runs on 3000 inside the container. It's mapped to 3001 so it doesn't clash with `next dev` on 3000.

### Connection env vars
Copy `.env.example` to `.env.local` and fill it in:
```env
FALKORDB_HOST=localhost
FALKORDB_PORT=6379
FALKORDB_PASSWORD=
```
These are read in `src/lib/falkordb.ts`.

### Check that it's running
```bash
docker ps --filter name=falkordb            # container is up
docker exec -it falkordb redis-cli PING     # should print PONG
docker exec -it falkordb redis-cli GRAPH.QUERY test "RETURN 1"
```
You can also open http://localhost:3001 to use FalkorDB Browser.

---

## 5. External tools

| Tool | Needed for | Who installs |
|---|---|---|
| **Docker Desktop** | Running FalkorDB | **Amune**: needs a GUI install and admin rights on the Mac |
| **FalkorDB image** (`falkordb/falkordb:latest`) | Graph database | The agent can pull and run it once Docker is installed |
| **Node.js** (v24 is already installed) and npm | Next.js app | Already done |
| **npm packages** (FalkorDB client, MCP SDK `@modelcontextprotocol/sdk`, LLM SDK, graph visualisation library) | App features | The agent can run `npm install` |
| **LLM API key** (whichever provider is chosen) | Agent reasoning | **Amune**: creates the key and puts it in `.env.local` |
| **GitHub account + public repo** | Required for submission | **Amune** creates the repo or signs in; the agent can push once it's authorised |
| **Deployment host** (e.g. Vercel for Next.js, plus a hosted FalkorDB such as FalkorDB Cloud) | Live demo | **Amune** handles the accounts and sign-in; the agent can configure the rest |
| **Screen recorder** | Demo video | **Amune** |
| **WeMakeDevs account** | Registration and submission | **Amune** |

---

## 6. Build phases

**Coding starts 15 Oct, 12:01 AM IST, which is 14 Oct, 8:31 PM Lagos.** Before then, only planning and sketching are allowed.

### Tonight (before 8:31 PM Lagos)
- Sketch the graph model: packages, repos, services and customers, and the dependency edges between them (section 3).
- Plan the synthetic data shape and pick 1–2 public CVEs for the demo.

### Day one
- Start FalkorDB in Docker and connect to it from `src/lib/falkordb.ts`.
- Write a data loader that seeds the graph with synthetic and public data (e.g. `scripts/seed.ts`).
- Write 5–6 Cypher queries and wrap them as typed tools, for example:
  - `findAffectedPackages(cveId)`
  - `findDependentRepos(packageName)`
  - `findServicesForRepos(repoIds)`
  - `findCustomersForServices(serviceIds)`
  - `getOwners(nodeIds)`
  - `explainPath(cveId, customerId)`
- Build a basic agent loop: the LLM picks tools, gets the results and writes an answer (an API route such as `POST /api/agent`).

### Day two
- Build the full CVE-to-blast-radius traversal.
- Rank by revenue at risk, calculated deterministically from customer ARR, SLA tier and service criticality, with prod vs dev usage weighting.
- Add a **human approval step**: the agent drafts the fix order, and the UI shows Approve and Reject; nothing is final until it's approved.
- Expose the tools through MCP.
- Deploy.

### Day three (and the morning of 18 Oct)
- A cascade screen that shows the path from the CVE out to customers, with the revenue at risk.
- A **side-by-side comparison** of the same question answered without the graph, to show FalkorDB doing real work.
- Finish this README with the final data model, the key Cypher queries and an **AI-use disclosure**.
- Record the demo video.
- **Submit before 7:29 PM Lagos on 18 Oct**, which is 11:59 PM IST. The event runs 15–18 Oct.

**What judges notice:** one high-stakes question that only a graph walk can answer, the evidence and exact query behind every claim, a risky action held for approval, a live visual of the agent's path, and hard numbers such as query latency and dollars at risk.

---

## 7. Hackathon rules checklist
- [ ] FalkorDB is the primary graph database and central to the product
- [ ] All work is new, done during the event (15–18 Oct); general libraries and templates are fine
- [ ] Public repository
- [ ] README with setup steps, graph data model, and the Cypher queries/algorithms the product depends on
- [ ] Demo video
- [ ] Live deployment, **or** complete local setup instructions
- [ ] Every track entered is named at submission (Track 1; possibly Track 2 if incident memory is added)
- [ ] AI coding assistant use disclosed; the builder can explain everything that was built
- [ ] Only public, synthetic or own data

---

## 8. Registration
- Free to enter, solo entry allowed (teams up to 4).
- Register on WeMakeDevs: sign in or create a free account, then click **Register now** at https://www.wemakedevs.org/hackathons/falkordb
- Rules: https://www.wemakedevs.org/hackathons/falkordb/rules · Schedule: https://www.wemakedevs.org/hackathons/falkordb/schedule
- Registration and submission are done by Amune; nothing has been registered or submitted yet.
