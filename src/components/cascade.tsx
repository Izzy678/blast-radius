"use client";

/**
 * Layered drawing of the traversed graph: CVE -> packages -> repos -> services -> customers.
 * Columns come from the graph structure (BFS depth), not from hard-coded positions,
 * so any CVE's blast radius lays itself out.
 */
import { useMemo } from "react";
import type { CascadeGraph, CascadeNode, RankedCustomer } from "@/lib/ranking";

const COL_W = 176;
const NODE_W = 148;
const NODE_H = 30;
const ROW_GAP = 12;
const PAD = 16;

type Placed = CascadeNode & { col: number; x: number; y: number; safe?: boolean };

export function Cascade({
  graph,
  safeCustomers,
  highlight,
  onSelectCustomer,
}: {
  graph: CascadeGraph;
  safeCustomers: RankedCustomer[];
  /** Node ids on the selected customer's path. */
  highlight: Set<string> | null;
  onSelectCustomer: (name: string) => void;
}) {
  const layout = useMemo(() => layoutGraph(graph, safeCustomers), [graph, safeCustomers]);
  const byId = new Map(layout.nodes.map((n) => [n.id, n]));

  return (
    <div className="overflow-x-auto rounded-lg border border-line bg-panel-2">
      {/* Scales to the container width; below ~900px it scrolls sideways instead of shrinking further. */}
      <svg
        viewBox={`0 0 ${layout.width} ${layout.height}`}
        width="100%"
        style={{ minWidth: 900 }}
        role="img"
        aria-label="Cascade from the CVE through packages, repos and services to customers"
        className="block"
      >
        {layout.headers.map((h) => (
          <text key={h.col} x={PAD + h.col * COL_W} y={PAD + 4} className="fill-muted text-[10px] uppercase tracking-wider">
            {h.label}
          </text>
        ))}

        {graph.edges.map((e) => {
          const a = byId.get(e.from);
          const b = byId.get(e.to);
          if (!a || !b) return null;
          const on = highlight ? highlight.has(e.from) && highlight.has(e.to) : true;
          const x1 = a.x + NODE_W;
          const y1 = a.y + NODE_H / 2;
          const x2 = b.x;
          const y2 = b.y + NODE_H / 2;
          const mid = (x1 + x2) / 2;
          return (
            <path
              key={`${e.from}->${e.to}`}
              d={`M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`}
              fill="none"
              strokeWidth={on && highlight ? 2.5 : 1.25}
              strokeDasharray={e.scope === "dev" ? "4 4" : undefined}
              className={e.scope === "prod" ? "stroke-prod" : "stroke-dev"}
              opacity={on ? (highlight ? 1 : 0.55) : 0.08}
            >
              <title>{e.rel}</title>
            </path>
          );
        })}

        {layout.nodes.map((n) => {
          const dim = highlight && !highlight.has(n.id);
          const isCustomer = n.label === "Customer";
          const tone = n.label === "CVE" ? "cve" : n.safe ? "safe" : n.scope === "prod" ? "prod" : "dev";
          return (
            <g
              key={n.id}
              transform={`translate(${n.x},${n.y})`}
              opacity={dim ? 0.25 : 1}
              className={isCustomer ? "cursor-pointer" : undefined}
              onClick={isCustomer ? () => onSelectCustomer(n.name) : undefined}
            >
              <rect width={NODE_W} height={NODE_H} rx={6} className={`node-${tone}`} strokeWidth={1} />
              <text x={10} y={NODE_H / 2 + 4} className="fill-ink text-[11px] font-mono">
                {truncate(n.name, 19)}
              </text>
              <title>
                {n.label}: {n.name}
                {n.safe ? " (no path from the CVE)" : n.scope === "dev" ? " (dev-only path)" : ""}
              </title>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

function truncate(s: string, n: number) {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

function layoutGraph(graph: CascadeGraph, safeCustomers: RankedCustomer[]) {
  const out = new Map<string, string[]>();
  const inc = new Map<string, string[]>();
  for (const e of graph.edges) {
    out.set(e.from, [...(out.get(e.from) ?? []), e.to]);
    inc.set(e.to, [...(inc.get(e.to) ?? []), e.from]);
  }
  const nodeById = new Map(graph.nodes.map((n) => [n.id, n]));

  // Depth inside a group (packages by dependency depth, services by call depth),
  // found with BFS that only walks edges within that group.
  const groupDepth = (label: string, isRoot: (id: string) => boolean) => {
    const depth = new Map<string, number>();
    const queue = graph.nodes.filter((n) => n.label === label && isRoot(n.id)).map((n) => n.id);
    queue.forEach((id) => depth.set(id, 0));
    while (queue.length) {
      const id = queue.shift()!;
      for (const next of out.get(id) ?? []) {
        if (nodeById.get(next)?.label === label && !depth.has(next)) {
          depth.set(next, depth.get(id)! + 1);
          queue.push(next);
        }
      }
    }
    return depth;
  };
  const fromLabel = (label: string) => (id: string) => (inc.get(id) ?? []).some((p) => nodeById.get(p)?.label === label);
  const pkgDepth = groupDepth("Package", fromLabel("CVE"));
  const svcDepth = groupDepth("Service", fromLabel("Repo"));
  const maxPkg = Math.max(0, ...pkgDepth.values());
  const maxSvc = Math.max(0, ...svcDepth.values());

  const repoCol = 1 + maxPkg + 1;
  const svcCol = repoCol + 1;
  const custCol = svcCol + maxSvc + 1;
  const colOf = (n: CascadeNode) =>
    n.label === "CVE"
      ? 0
      : n.label === "Package"
        ? 1 + (pkgDepth.get(n.id) ?? 0)
        : n.label === "Repo"
          ? repoCol
          : n.label === "Service"
            ? svcCol + (svcDepth.get(n.id) ?? 0)
            : custCol;

  const columns: Placed[][] = Array.from({ length: custCol + 1 }, () => []);
  for (const n of graph.nodes) columns[colOf(n)].push({ ...n, col: colOf(n), x: 0, y: 0 });

  // Order each column by the average row of its parents (barycenter) to cut crossings.
  const rowOf = new Map<string, number>();
  columns.forEach((col) => {
    col.sort((a, b) => avgParentRow(a.id) - avgParentRow(b.id) || a.name.localeCompare(b.name));
    col.forEach((n, i) => rowOf.set(n.id, i));
  });
  function avgParentRow(id: string) {
    const rows = (inc.get(id) ?? []).map((p) => rowOf.get(p)).filter((r): r is number => r !== undefined);
    return rows.length ? rows.reduce((a, b) => a + b, 0) / rows.length : 0;
  }

  // Customers with no path go at the bottom of the last column, unconnected.
  for (const c of safeCustomers) {
    columns[custCol].push({ id: `Customer:${c.customer}`, label: "Customer", name: c.customer, scope: "prod", col: custCol, x: 0, y: 0, safe: true });
  }

  const top = PAD + 18;
  const nodes = columns.flatMap((col, ci) =>
    col.map((n, i) => ({ ...n, x: PAD + ci * COL_W, y: top + i * (NODE_H + ROW_GAP) + (n.safe ? ROW_GAP * 2 : 0) })),
  );
  const tallest = Math.max(...columns.map((c) => c.length));

  const headers = [
    { col: 0, label: "CVE" },
    { col: 1, label: "Packages" },
    { col: repoCol, label: "Repos" },
    { col: svcCol, label: "Services" },
    { col: custCol, label: "Customers" },
  ];

  return {
    nodes,
    headers,
    width: PAD * 2 + custCol * COL_W + NODE_W,
    height: top + tallest * (NODE_H + ROW_GAP) + ROW_GAP * 2 + PAD,
  };
}
