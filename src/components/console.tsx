"use client";

import { useEffect, useMemo, useState } from "react";
import type { BaselineResult } from "@/lib/baseline";
import type { FixPlan } from "@/lib/plans";
import type { BlastRadiusReport, RankedCustomer } from "@/lib/ranking";
import type { CveSummary } from "@/lib/tools/graph-tools";
import type { Evidence, GraphPath } from "@/lib/tools/types";
import { Cascade } from "./cascade";

type BlastResponse = { report: BlastRadiusReport; evidence: Evidence[]; baseline: BaselineResult };

type AgentStep = { tool: string; args: unknown; summary?: string };
type AgentResponse = { answer: string; steps: AgentStep[]; evidence: Evidence[] };

const usd = (n: number) =>
  n >= 1_000_000 ? `$${(n / 1_000_000).toFixed(2)}M` : n >= 1_000 ? `$${Math.round(n / 1_000)}K` : `$${n}`;

export function Console({ initialCve }: { initialCve?: string }) {
  const [cves, setCves] = useState<CveSummary[]>([]);
  const [cveId, setCveId] = useState(initialCve ?? "CVE-2021-44906");
  const [data, setData] = useState<BlastResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [plan, setPlan] = useState<FixPlan | null>(null);
  const [agent, setAgent] = useState<{ status: "idle" | "running" | "done" | "error"; result?: AgentResponse; error?: string }>({
    status: "idle",
  });

  useEffect(() => {
    fetch("/api/cves")
      .then((r) => r.json())
      .then((d: { cves: CveSummary[] }) => setCves(d.cves))
      .catch(() => setCves([]));
    // Deep link: /?cve=CVE-2021-44906 traces straight away.
    if (initialCve) trace(initialCve);
    // Runs once on mount; `trace` is intentionally not a dependency.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function trace(id = cveId) {
    setLoading(true);
    setError(null);
    setSelected(null);
    setPlan(null);
    setAgent({ status: "idle" });
    try {
      const res = await fetch(`/api/blast-radius?cve=${encodeURIComponent(id.trim())}`);
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? `Request failed (${res.status})`);
      setData(body);
    } catch (e) {
      setData(null);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  async function askAgent() {
    if (!data) return;
    setAgent({ status: "running" });
    try {
      const res = await fetch("/api/agent", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ cveId: data.report.cve.id }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error ?? `Agent unavailable (${res.status})`);
      setAgent({ status: "done", result: body });
      if (body.plan) setPlan(body.plan);
    } catch (e) {
      setAgent({ status: "error", error: e instanceof Error ? e.message : String(e) });
    }
  }

  const report = data?.report;
  const highlight = useMemo(() => {
    const c = report?.customers.find((x) => x.customer === selected);
    if (!c?.best_path) return null;
    return new Set(c.best_path.nodes.map((n) => `${n.label}:${n.name}`));
  }, [report, selected]);
  const queryMs = data?.evidence.reduce((s, e) => s + e.ms, 0) ?? 0;

  return (
    <div className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6">
      <header className="flex flex-col gap-4 border-b border-line pb-5 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p className="font-mono text-xs uppercase tracking-[0.2em] text-muted">FalkorDB · supply chain security agent</p>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight">Blast Radius</h1>
          <p className="mt-1 max-w-xl text-sm text-muted">
            Walks the graph from a CVE through transitive dependencies to repos, services and customers, ranks the fix
            order by revenue at risk, and holds the plan for human approval.
          </p>
        </div>
        <form
          className="flex w-full flex-col gap-2 sm:flex-row lg:w-auto"
          onSubmit={(e) => {
            e.preventDefault();
            trace();
          }}
        >
          <input
            list="cve-options"
            value={cveId}
            onChange={(e) => setCveId(e.target.value)}
            placeholder="CVE-2021-44906"
            aria-label="CVE ID"
            className="min-w-0 rounded-md border border-line bg-panel px-3 py-2 font-mono text-sm outline-none focus:border-accent sm:w-56"
          />
          <datalist id="cve-options">
            {cves.map((c) => (
              <option key={c.id} value={c.id}>{`${c.package} · ${c.severity} ${c.cvss}`}</option>
            ))}
          </datalist>
          <button
            type="submit"
            disabled={loading || !cveId.trim()}
            className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-accent-ink disabled:opacity-50"
          >
            {loading ? "Tracing…" : "Trace blast radius"}
          </button>
        </form>
      </header>

      {cves.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-2 text-xs">
          {cves.map((c) => (
            <button
              key={c.id}
              onClick={() => {
                setCveId(c.id);
                trace(c.id);
              }}
              className="rounded-full border border-line px-3 py-1 font-mono text-muted hover:border-accent hover:text-ink"
            >
              {c.id} · {c.package} · {c.severity}
            </button>
          ))}
        </div>
      )}

      {error && <p className="mt-6 rounded-md border border-prod/40 bg-prod/10 p-3 text-sm">{error}</p>}

      {!report && !error && (
        <p className="mt-16 text-center text-sm text-muted">Pick a CVE above to trace its blast radius through the graph.</p>
      )}

      {report && data && (
        <>
          <CveBanner report={report} />

          <section className="mt-4 grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-6">
            <Kpi label="Revenue at risk" value={usd(report.totals.revenue_at_risk)} tone="prod" />
            <Kpi label="Customers exposed" value={report.totals.customers_prod} tone="prod" />
            <Kpi label="Dev-only exposure" value={report.totals.customers_dev_only} tone="dev" />
            <Kpi label="Proven safe" value={report.totals.customers_safe} tone="safe" />
            <Kpi label="Repos to patch" value={report.fix_order.length} />
            <Kpi label="Graph paths" value={report.totals.paths} hint={`${data.evidence.length} queries · ${queryMs.toFixed(1)} ms`} />
          </section>

          <section className="mt-6">
            <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
              <h2 className="text-sm font-semibold">Cascade</h2>
              <Legend />
            </div>
            <Cascade
              graph={report.graph}
              safeCustomers={report.customers.filter((c) => c.exposure === "none")}
              highlight={highlight}
              onSelectCustomer={(n) => setSelected((cur) => (cur === n ? null : n))}
            />
            <p className="mt-2 text-xs text-muted">
              Click a customer (here or in the table) to highlight its path. Dashed lines are dev-only dependencies.
            </p>
          </section>

          <div className="mt-6 grid gap-6 lg:grid-cols-5">
            <section className="lg:col-span-3">
              <h2 className="mb-2 text-sm font-semibold">Customers ranked by revenue at risk</h2>
              <CustomerTable customers={report.customers} selected={selected} onSelect={setSelected} />
            </section>
            <section className="lg:col-span-2">
              <h2 className="mb-2 text-sm font-semibold">With the graph vs without it</h2>
              <Comparison report={report} baseline={data.baseline} />
            </section>
          </div>

          <div className="mt-6 grid gap-6 lg:grid-cols-5">
            <section className="lg:col-span-3">
              <h2 className="mb-2 text-sm font-semibold">Fix plan</h2>
              <FixPlanPanel report={report} plan={plan} onPlan={setPlan} />
            </section>
            <section className="lg:col-span-2">
              <h2 className="mb-2 text-sm font-semibold">Agent</h2>
              <AgentPanel state={agent} onAsk={askAgent} />
            </section>
          </div>

          <section className="mt-6">
            <h2 className="mb-2 text-sm font-semibold">Evidence: every Cypher query behind this answer</h2>
            <EvidenceList evidence={[...data.evidence, ...(agent.result?.evidence ?? [])]} />
          </section>
        </>
      )}
    </div>
  );
}

function CveBanner({ report }: { report: BlastRadiusReport }) {
  const { cve } = report;
  return (
    <section className="mt-6 flex flex-col gap-1 rounded-lg border border-line bg-panel p-4 sm:flex-row sm:items-center sm:gap-4">
      <span className="font-mono text-sm font-semibold">{cve.id}</span>
      <span className={`w-fit rounded px-2 py-0.5 text-xs font-medium uppercase ${cve.severity === "critical" || cve.severity === "high" ? "bg-prod/15 text-prod" : "bg-dev/15 text-dev"}`}>
        {cve.severity} · CVSS {cve.cvss}
      </span>
      <span className="text-sm text-muted">
        <span className="font-mono text-ink">
          {cve.package}@{cve.installed_version}
        </span>{" "}
        (affected {cve.affected_range}, fixed in {cve.fixed_in}). {cve.summary}
      </span>
    </section>
  );
}

function Kpi({ label, value, hint, tone }: { label: string; value: string | number; hint?: string; tone?: "prod" | "dev" | "safe" }) {
  const color = tone === "prod" ? "text-prod" : tone === "dev" ? "text-dev" : tone === "safe" ? "text-safe" : "text-ink";
  return (
    <div className="rounded-lg border border-line bg-panel p-3">
      <p className="text-xs text-muted">{label}</p>
      <p className={`mt-1 font-mono text-xl font-semibold ${color}`}>{value}</p>
      {hint && <p className="mt-0.5 text-[11px] text-muted">{hint}</p>}
    </div>
  );
}

function Legend() {
  return (
    <div className="flex flex-wrap gap-3 text-xs text-muted">
      <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm bg-prod" /> prod path</span>
      <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm bg-dev" /> dev-only</span>
      <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm bg-safe" /> no path (safe)</span>
    </div>
  );
}

const EXPOSURE_LABEL = { prod: "exposed", "dev-only": "dev-only", none: "safe" } as const;
const EXPOSURE_CLASS = { prod: "bg-prod/15 text-prod", "dev-only": "bg-dev/15 text-dev", none: "bg-safe/15 text-safe" } as const;

function CustomerTable({
  customers,
  selected,
  onSelect,
}: {
  customers: RankedCustomer[];
  selected: string | null;
  onSelect: (name: string | null) => void;
}) {
  return (
    <div className="overflow-x-auto rounded-lg border border-line bg-panel">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-line text-xs text-muted">
          <tr>
            <th className="px-3 py-2 font-medium">Customer</th>
            <th className="px-3 py-2 font-medium">Status</th>
            <th className="px-3 py-2 text-right font-medium">ARR</th>
            <th className="px-3 py-2 text-right font-medium">At risk</th>
            <th className="px-3 py-2 font-medium">SLA</th>
            <th className="px-3 py-2 font-medium">Why</th>
          </tr>
        </thead>
        <tbody>
          {customers.map((c) => (
            <tr
              key={c.customer}
              onClick={() => onSelect(selected === c.customer ? null : c.customer)}
              className={`cursor-pointer border-b border-line/60 last:border-0 hover:bg-panel-2 ${selected === c.customer ? "bg-panel-2" : ""}`}
            >
              <td className="whitespace-nowrap px-3 py-2">{c.customer}</td>
              <td className="px-3 py-2">
                <span className={`whitespace-nowrap rounded px-1.5 py-0.5 text-xs ${EXPOSURE_CLASS[c.exposure]}`}>{EXPOSURE_LABEL[c.exposure]}</span>
              </td>
              <td className="px-3 py-2 text-right font-mono text-muted">{usd(c.arr_usd)}</td>
              <td className="px-3 py-2 text-right font-mono">{c.revenue_at_risk ? usd(c.revenue_at_risk) : "—"}</td>
              <td className="whitespace-nowrap px-3 py-2 text-xs text-muted">
                {c.sla_tier}
                {c.exposure === "prod" && c.notify_within_hours ? ` · notify ≤${c.notify_within_hours}h` : ""}
              </td>
              <td className="px-3 py-2 text-xs text-muted">
                {c.best_path ? (
                  <PathSummary path={c.best_path} />
                ) : (
                  <span>no path from CVE · uses {c.uses_services.join(", ")}</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** "3 package hops · checkout-api → checkout → storefront": the full path is in the cascade. */
function PathSummary({ path }: { path: GraphPath }) {
  const pkgHops = path.nodes.filter((n) => n.label === "Package").length - 1;
  const tail = path.nodes.filter((n) => n.label === "Repo" || n.label === "Service").map((n) => n.name);
  return (
    <span>
      {pkgHops === 0 ? "direct" : `${pkgHops} package hop${pkgHops > 1 ? "s" : ""}`} ·{" "}
      <span className="font-mono">{tail.join(" → ")}</span>
    </span>
  );
}

function Comparison({ report, baseline }: { report: BlastRadiusReport; baseline: BaselineResult }) {
  const prodRepos = report.fix_order.filter((r) => r.exposure === "prod");
  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-1 xl:grid-cols-2">
      <div className="rounded-lg border border-line bg-panel p-3">
        <p className="text-xs font-medium uppercase tracking-wider text-muted">Without the graph</p>
        <p className="mt-1 text-xs text-muted">{baseline.method}</p>
        <dl className="mt-3 space-y-1.5 text-sm">
          <Row k="Repos flagged" v={baseline.flagged_repos.map((r) => `${r.repo} (${r.scope})`).join(", ") || "none"} />
          <Row k="Prod repos" v={String(baseline.flagged_repos.filter((r) => r.scope === "prod").length)} />
          <Row k="Customers found" v="unknown" />
          <Row k="Revenue at risk" v="unknown" />
        </dl>
        <p className="mt-3 text-xs text-muted">{baseline.notes}</p>
      </div>
      <div className="rounded-lg border border-accent/50 bg-panel p-3">
        <p className="text-xs font-medium uppercase tracking-wider text-accent">With FalkorDB</p>
        <p className="mt-1 text-xs text-muted">multi-hop Cypher traversal</p>
        <dl className="mt-3 space-y-1.5 text-sm">
          <Row k="Repos flagged" v={String(report.fix_order.length)} />
          <Row k="Prod repos" v={prodRepos.map((r) => r.repo).join(", ") || "none"} />
          <Row k="Customers found" v={`${report.totals.customers_prod} exposed, ${report.totals.customers_safe} proven safe`} />
          <Row k="Revenue at risk" v={usd(report.totals.revenue_at_risk)} />
        </dl>
        <p className="mt-3 text-xs text-muted">
          Finds the vulnerable package up to {Math.max(0, ...report.customers.map((c) => (c.best_path?.nodes.filter((n) => n.label === "Package").length ?? 1) - 1))}{" "}
          dependency hops deep and follows it to the customers who pay for it.
        </p>
      </div>
    </div>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex justify-between gap-3">
      <dt className="shrink-0 text-muted">{k}</dt>
      <dd className="text-right font-mono text-xs leading-5">{v}</dd>
    </div>
  );
}

function FixPlanPanel({ report, plan, onPlan }: { report: BlastRadiusReport; plan: FixPlan | null; onPlan: (p: FixPlan) => void }) {
  const [busy, setBusy] = useState(false);
  const [reviewer, setReviewer] = useState("");
  const [note, setNote] = useState("");
  const [err, setErr] = useState<string | null>(null);

  async function call(url: string, body: unknown) {
    setBusy(true);
    setErr(null);
    try {
      const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      const json = await res.json();
      if (json.plan) onPlan(json.plan);
      if (!res.ok) throw new Error(json.error ?? `Request failed (${res.status})`);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const statusClass =
    plan?.status === "approved" ? "bg-safe/15 text-safe" : plan?.status === "rejected" ? "bg-prod/15 text-prod" : "bg-dev/15 text-dev";

  return (
    <div className="rounded-lg border border-line bg-panel">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-3 py-2">
        <p className="text-xs text-muted">
          Order is computed in code: prod exposure first, then by revenue at risk. Bump each package so it resolves{" "}
          <span className="font-mono text-ink">
            {report.cve.package} ≥ {report.cve.fixed_in}
          </span>
          .
        </p>
        {plan && <span className={`rounded px-2 py-0.5 text-xs font-medium uppercase ${statusClass}`}>{plan.status}</span>}
      </div>
      <ol className="divide-y divide-line/60">
        {report.fix_order.map((f) => (
          <li key={f.repo} className="flex flex-col gap-1 px-3 py-2.5 sm:flex-row sm:items-center sm:gap-3">
            <span className="w-6 shrink-0 font-mono text-sm text-muted">{f.order}.</span>
            <div className="min-w-0 flex-1">
              <p className="text-sm">
                <span className="font-mono">{f.repo}</span>{" "}
                <span className={`ml-1 rounded px-1.5 py-0.5 text-[11px] ${f.exposure === "prod" ? "bg-prod/15 text-prod" : "bg-dev/15 text-dev"}`}>
                  {f.exposure}
                </span>
              </p>
              <p className="text-xs text-muted">
                bump <span className="font-mono text-ink">{f.bump.join(", ")}</span>
                {f.services.length > 0 && <> · ships in {f.services.join(", ")}</>}
                {f.customers.length > 0 && <> · {f.customers.length} customer{f.customers.length > 1 ? "s" : ""}</>}
              </p>
            </div>
            <div className="flex shrink-0 items-center gap-3 text-xs sm:text-right">
              <span className="font-mono text-sm">{f.revenue_at_risk ? usd(f.revenue_at_risk) : "$0"}</span>
              <span className="text-muted">
                {f.owners.map((o) => `${o.name}${o.on_call ? " (on call)" : ""}`).join(", ") || "no owner"}
              </span>
            </div>
          </li>
        ))}
      </ol>

      <div className="border-t border-line p-3">
        {!plan && (
          <button
            disabled={busy}
            onClick={() => call("/api/plans", { cveId: report.cve.id })}
            className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-ink disabled:opacity-50"
          >
            Draft fix plan for approval
          </button>
        )}
        {plan?.status === "pending" && (
          <div className="flex flex-col gap-2">
            <p className="text-xs text-muted">
              Plan <span className="font-mono text-ink">{plan.id}</span> is saved in the graph as pending. Nothing is final until a human decides.
            </p>
            <div className="flex flex-col gap-2 sm:flex-row">
              <input
                value={reviewer}
                onChange={(e) => setReviewer(e.target.value)}
                placeholder="Your name"
                aria-label="Reviewer name"
                className="rounded-md border border-line bg-panel-2 px-2 py-1.5 text-sm outline-none focus:border-accent sm:w-36"
              />
              <input
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="Note (optional)"
                aria-label="Decision note"
                className="min-w-0 flex-1 rounded-md border border-line bg-panel-2 px-2 py-1.5 text-sm outline-none focus:border-accent"
              />
              <button
                disabled={busy}
                onClick={() => call(`/api/plans/${plan.id}/approve`, { by: reviewer, note })}
                className="rounded-md bg-safe px-3 py-1.5 text-sm font-medium text-accent-ink disabled:opacity-50"
              >
                Approve
              </button>
              <button
                disabled={busy}
                onClick={() => call(`/api/plans/${plan.id}/reject`, { by: reviewer, note })}
                className="rounded-md border border-prod px-3 py-1.5 text-sm font-medium text-prod disabled:opacity-50"
              >
                Reject
              </button>
            </div>
          </div>
        )}
        {plan && plan.status !== "pending" && (
          <p className="text-sm">
            {plan.status === "approved" ? "Approved" : "Rejected"} by <span className="font-medium">{plan.decided_by}</span>
            {plan.decided_at && <> at {new Date(plan.decided_at).toLocaleString()}</>}
            {plan.decision_note && <span className="text-muted"> · “{plan.decision_note}”</span>}
          </p>
        )}
        {err && <p className="mt-2 text-xs text-prod">{err}</p>}
      </div>
    </div>
  );
}

function AgentPanel({
  state,
  onAsk,
}: {
  state: { status: "idle" | "running" | "done" | "error"; result?: AgentResponse; error?: string };
  onAsk: () => void;
}) {
  return (
    <div className="rounded-lg border border-line bg-panel p-3">
      <p className="text-xs text-muted">
        The agent chooses which graph tools to call and writes the explanation. Numbers come from the tools, not the model.
      </p>
      <button
        onClick={onAsk}
        disabled={state.status === "running"}
        className="mt-3 rounded-md border border-accent px-3 py-1.5 text-sm font-medium text-accent disabled:opacity-50"
      >
        {state.status === "running" ? "Agent is walking the graph…" : "Ask the agent to investigate"}
      </button>
      {state.status === "error" && <p className="mt-3 text-xs text-prod">{state.error}</p>}
      {state.result && (
        <div className="mt-3 space-y-3">
          <ol className="space-y-1 text-xs">
            {state.result.steps.map((s, i) => (
              <li key={i} className="font-mono text-muted">
                {i + 1}. <span className="text-ink">{s.tool}</span>({JSON.stringify(s.args)}){s.summary ? ` → ${s.summary}` : ""}
              </li>
            ))}
          </ol>
          <div className="whitespace-pre-wrap text-sm leading-6">{state.result.answer}</div>
        </div>
      )}
    </div>
  );
}

function EvidenceList({ evidence }: { evidence: Evidence[] }) {
  return (
    <div className="space-y-2">
      {evidence.map((e, i) => (
        <details key={i} className="rounded-lg border border-line bg-panel">
          <summary className="flex cursor-pointer flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-sm">
            <span className="font-mono">{e.tool}</span>
            <span className="text-xs text-muted">
              {e.rowCount} rows · {e.ms} ms
            </span>
          </summary>
          <pre className="overflow-x-auto border-t border-line px-3 py-2 font-mono text-xs leading-5 text-muted">
            {e.cypher}
            {Object.keys(e.params).length > 0 && `\n\n// params\n${JSON.stringify(e.params)}`}
          </pre>
        </details>
      ))}
    </div>
  );
}
