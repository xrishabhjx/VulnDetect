"use client";

import { useMemo, useState, useEffect } from "react";
import dynamic from "next/dynamic";
import type { RepositoryKnowledgeGraph, RKGNode, RKGEdge } from "@/lib/types";

// Import only the 2D renderer. The umbrella package also evaluates VR/AR code
// that requires a global AFRAME object, even when this dashboard uses 2D only.
const ForceGraph2D = dynamic(
  () => import("react-force-graph-2d"),
  { ssr: false }
);

interface KnowledgeGraphViewerProps {
  graph: RepositoryKnowledgeGraph;
}

export function KnowledgeGraphViewer({ graph }: KnowledgeGraphViewerProps) {
  const [mounted, setMounted] = useState(false);
  const [containerWidth, setContainerWidth] = useState(700);

  useEffect(() => {
    setMounted(true);
    const updateWidth = () => {
      const el = document.getElementById("graph-container");
      if (el) {
        setContainerWidth(el.clientWidth - 48); // account for padding
      }
    };
    updateWidth();
    window.addEventListener("resize", updateWidth);
    return () => window.removeEventListener("resize", updateWidth);
  }, []);

  // Format data for react-force-graph
  const graphData = useMemo(() => {
    if (!graph || !graph.nodes) return { nodes: [], links: [] };

    const nodes = graph.nodes.map((node: RKGNode) => ({
      id: node.id,
      name: node.label,
      type: node.type,
      val: node.type === "Repository" ? 12 : node.type === "Threat" ? 10 : 6,
    }));

    const links = graph.edges.map((edge: RKGEdge) => ({
      source: edge.source,
      target: edge.target,
      relationship: edge.relationship,
    }));

    return { nodes, links };
  }, [graph]);

  const getNodeColor = (type: string) => {
    switch (type) {
      case "Repository":
        return "#5B8DEF"; // Accent
      case "File":
        return "#E8EAED"; // Text primary
      case "Module":
        return "#8B92A0"; // Text secondary
      case "Dependency":
        return "#F5A524"; // High / Warning
      case "Package":
        return "#F5D90A"; // Medium
      case "Threat":
        return "#E5484D"; // Critical
      default:
        return "#8B92A0";
    }
  };

  const nodeStats = useMemo(() => {
    const stats: Record<string, number> = {};
    (graph?.nodes || []).forEach((n) => {
      stats[n.type] = (stats[n.type] || 0) + 1;
    });
    return stats;
  }, [graph]);

  return (
    <div id="graph-container" className="card p-6 sm:p-8 space-y-6 border-border">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-4">
        <div>
          <span className="text-xs font-mono uppercase tracking-wider text-secondary">
            Structural Context
          </span>
          <h2 className="text-2xl font-display font-semibold text-primary">
            Repository Knowledge Graph
          </h2>
        </div>

        {/* Legend */}
        <div className="flex flex-wrap items-center gap-3 text-xs font-mono">
          {["Repository", "File", "Module", "Dependency", "Threat"].map((type) => (
            <div key={type} className="flex items-center gap-1.5">
              <span
                className="w-2.5 h-2.5 rounded-full"
                style={{ backgroundColor: getNodeColor(type) }}
              />
              <span className="text-secondary">{type}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Force-directed graph view */}
      <div className="w-full bg-background border border-border rounded-lg overflow-hidden flex justify-center items-center relative min-h-[400px]">
        {mounted && graphData.nodes.length > 0 ? (
          <ForceGraph2D
            graphData={graphData}
            width={containerWidth}
            height={420}
            backgroundColor="#0B0D10"
            nodeColor={(node: any) => getNodeColor(node.type)}
            nodeLabel={(node: any) => `${node.type}: ${node.name}`}
            linkColor={() => "#262B31"}
            linkDirectionalParticles={1}
            linkDirectionalParticleSpeed={0.005}
            linkDirectionalParticleWidth={2}
            linkDirectionalParticleColor={() => "#5B8DEF"}
            nodeRelSize={4}
          />
        ) : (
          <div className="text-xs font-mono text-secondary py-12">
            Loading Knowledge Graph visualization...
          </div>
        )}
      </div>

      {/* Summary Chips */}
      <div className="flex flex-wrap gap-4 text-xs font-mono pt-2 text-secondary">
        <div>Total Nodes: <span className="text-primary font-semibold">{graph.nodes.length}</span></div>
        <div>Total Relationships: <span className="text-primary font-semibold">{graph.edges.length}</span></div>
        {Object.entries(nodeStats).map(([type, count]) => (
          <div key={type}>{type}s: <span className="text-primary">{count}</span></div>
        ))}
      </div>
    </div>
  );
}
