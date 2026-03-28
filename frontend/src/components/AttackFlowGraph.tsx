"use client";

import { useEffect, useRef } from "react";
import * as d3 from "d3";

interface AttackNode {
  id: string;
  type: string;
  label: string;
  file: string;
  line: number;
  code?: string;
  is_vulnerable: boolean;
}

interface AttackEdge {
  source_id: string;
  target_id: string;
  label: string;
  taint_state: string;
  edge_type?: string;  // "taint" or "chain"
}

interface Props {
  nodes: AttackNode[];
  edges: AttackEdge[];
}

const NODE_COLORS: Record<string, string> = {
  source: "#FF1744",
  sink: "#FF6D00",
  sanitizer: "#00E676",
  transform: "#448AFF",
};

const EDGE_COLORS: Record<string, string> = {
  tainted: "#FF1744",
  partially_sanitized: "#FFD600",
  cleared: "#00E676",
};

export function AttackFlowGraph({ nodes, edges }: Props) {
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    if (!svgRef.current || nodes.length === 0) return;
    const width = 860;
    const height = 420;
    const nodeRadius = 22;

    const svg = d3.select(svgRef.current)
      .attr("width", width)
      .attr("height", height)
      .attr("viewBox", `0 0 ${width} ${height}`);

    svg.selectAll("*").remove();

    // Defs: arrowhead markers + pulse animation for sink nodes
    const defs = svg.append("defs");

    // Arrowhead per taint state
    (["tainted", "partially_sanitized", "cleared"] as const).forEach((state) => {
      defs.append("marker")
        .attr("id", `arrow-${state}`)
        .attr("viewBox", "0 -5 10 10")
        .attr("refX", nodeRadius + 10)
        .attr("refY", 0)
        .attr("markerWidth", 6)
        .attr("markerHeight", 6)
        .attr("orient", "auto")
        .append("path")
        .attr("d", "M0,-5L10,0L0,5")
        .attr("fill", EDGE_COLORS[state] ?? "#FF1744");
    });

    defs.append("marker")
      .attr("id", "arrow-chain")
      .attr("viewBox", "0 -5 10 10")
      .attr("refX", nodeRadius + 10)
      .attr("refY", 0)
      .attr("markerWidth", 6)
      .attr("markerHeight", 6)
      .attr("orient", "auto")
      .append("path")
      .attr("d", "M0,-5L10,0L0,5")
      .attr("fill", "#7C4DFF");

    // CSS keyframe pulse injected once into SVG
    defs.append("style").text(`
      @keyframes vexis-pulse {
        0%, 100% { opacity: 0.75; r: ${nodeRadius}px; }
        50% { opacity: 1; r: ${nodeRadius + 4}px; }
      }
      .sink-pulse {
        animation: vexis-pulse 1.5s ease-in-out infinite;
        transform-origin: center;
      }
    `);

    // Build D3 link data (source_id → target_id)
    const linkData = edges.map((e) => ({
      source: e.source_id,
      target: e.target_id,
      label: e.label,
      taint_state: e.taint_state ?? "tainted",
      edge_type: e.edge_type ?? "taint",
    }));

    const simulation = d3
      .forceSimulation(nodes as any)
      .force(
        "link",
        d3
          .forceLink(linkData)
          .id((d: any) => d.id)
          .distance(160)
      )
      .force("charge", d3.forceManyBody().strength(-400))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide(nodeRadius + 20));

    // Edges
    const linkGroup = svg.append("g");
    const link = linkGroup
      .selectAll("line")
      .data(linkData)
      .join("line")
      .attr("stroke", (d: any) => d.edge_type === "chain" ? "#7C4DFF" : (EDGE_COLORS[d.taint_state] ?? "#FF1744"))
      .attr("stroke-width", (d: any) => d.edge_type === "chain" ? 2.5 : 2)
      .attr("stroke-dasharray", (d: any) => d.edge_type === "chain" ? "6 3" : null)
      .attr("stroke-opacity", 0.8)
      .attr("marker-end", (d: any) => d.edge_type === "chain" ? "url(#arrow-chain)" : `url(#arrow-${d.taint_state ?? "tainted"})`);

    // Edge labels
    const edgeLabelGroup = svg.append("g");
    const edgeLabel = edgeLabelGroup
      .selectAll("text")
      .data(linkData)
      .join("text")
      .text((d: any) => d.edge_type === "chain" ? "⛓ enables" : (d.label ?? "").slice(0, 32))
      .attr("fill", (d: any) => d.edge_type === "chain" ? "#7C4DFF" : "#8B949E")
      .attr("font-size", "9px")
      .attr("font-family", "JetBrains Mono, monospace")
      .attr("text-anchor", "middle");

    // Node groups
    const nodeGroup = svg.append("g");
    const node = nodeGroup
      .selectAll("g")
      .data(nodes)
      .join("g")
      .style("cursor", "pointer");

    // Glow filter for sink nodes
    const filter = defs.append("filter").attr("id", "glow");
    filter.append("feGaussianBlur").attr("stdDeviation", "3").attr("result", "blur");
    const feMerge = filter.append("feMerge");
    feMerge.append("feMergeNode").attr("in", "blur");
    feMerge.append("feMergeNode").attr("in", "SourceGraphic");

    // Circle per node
    node
      .append("circle")
      .attr("r", nodeRadius)
      .attr("fill", (d) => NODE_COLORS[d.type] ?? "#636E7B")
      .attr("fill-opacity", 0.15)
      .attr("stroke", (d) => NODE_COLORS[d.type] ?? "#636E7B")
      .attr("stroke-width", 2)
      .attr("class", (d) => (d.type === "sink" ? "sink-pulse" : ""))
      .attr("filter", (d) => (d.type === "sink" ? "url(#glow)" : null));

    // Node type icon text (first letter uppercase)
    node
      .append("text")
      .text((d) => d.type[0].toUpperCase())
      .attr("fill", (d) => NODE_COLORS[d.type] ?? "#636E7B")
      .attr("font-size", "12px")
      .attr("font-weight", "bold")
      .attr("font-family", "JetBrains Mono, monospace")
      .attr("text-anchor", "middle")
      .attr("dominant-baseline", "central");

    // Primary label (node.label truncated)
    node
      .append("text")
      .text((d) => (d.label ?? "").slice(0, 28))
      .attr("fill", "#E6EDF3")
      .attr("font-size", "10px")
      .attr("font-family", "JetBrains Mono, monospace")
      .attr("text-anchor", "middle")
      .attr("dy", nodeRadius + 14);

    // Code subtitle (node.code truncated to 60 chars)
    node
      .filter((d) => !!(d.code ?? d.label))
      .append("text")
      .text((d) => (d.code ?? d.label ?? "").slice(0, 60))
      .attr("fill", "#484F58")
      .attr("font-size", "8px")
      .attr("font-family", "JetBrains Mono, monospace")
      .attr("text-anchor", "middle")
      .attr("dy", nodeRadius + 26);

    // Drag behavior
    const drag = d3
      .drag<SVGGElement, any>()
      .on("start", (event, d) => {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
      })
      .on("drag", (event, d) => {
        d.fx = event.x;
        d.fy = event.y;
      })
      .on("end", (event, d) => {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
      });

    node.call(drag as any);

    // Tick
    simulation.on("tick", () => {
      link
        .attr("x1", (d: any) => d.source.x)
        .attr("y1", (d: any) => d.source.y)
        .attr("x2", (d: any) => d.target.x)
        .attr("y2", (d: any) => d.target.y);

      edgeLabel
        .attr("x", (d: any) => (d.source.x + d.target.x) / 2)
        .attr("y", (d: any) => (d.source.y + d.target.y) / 2 - 6);

      node.attr("transform", (d: any) => `translate(${d.x},${d.y})`);
    });

    return () => {
      simulation.stop();
    };
  }, [nodes, edges]);

  if (nodes.length === 0) {
    return (
      <div className="bg-bg-secondary border border-border rounded-xl p-8 text-center text-text-muted">
        No attack flow data available.
      </div>
    );
  }

  return (
    <div className="bg-bg-secondary border border-border rounded-xl overflow-hidden">
      <svg ref={svgRef} className="w-full" style={{ minHeight: 420 }} />
    </div>
  );
}
