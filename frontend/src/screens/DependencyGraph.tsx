import React, { useEffect, useMemo, useState } from 'react';
import {
  Cpu,
  FileCode2,
  Layers,
  Maximize2,
  Network,
  ShieldAlert,
  ShieldCheck,
  ZoomIn,
  ZoomOut,
} from 'lucide-react';
import { GraphData } from '../types';
import { fetchCryptoGraph } from '../lib/api';

interface DependencyGraphProps {
  scanId: string | null;
  projectName: string;
}

interface PositionedNode {
  id: string;
  type: string;
  data: {
    label?: string;
    severity?: string;
    hndl?: boolean;
    full_path?: string;
    kind?: string;
    usage?: string;
    subtitle?: string;
    [key: string]: any;
  };
  position: { x: number; y: number };
  layoutX: number;
  layoutY: number;
  width: number;
  height: number;
}

export const DependencyGraph: React.FC<DependencyGraphProps> = ({ scanId, projectName }) => {
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [zoom, setZoom] = useState(1);
  const [selectedNode, setSelectedNode] = useState<PositionedNode | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setGraphData(null);
    setError(null);
    if (!scanId) return;
    fetchCryptoGraph(scanId)
      .then((data) => {
        if (!cancelled) setGraphData(data);
      })
      .catch((reason: unknown) => {
        if (!cancelled) setError(reason instanceof Error ? reason.message : 'Graph could not be loaded.');
      });
    return () => {
      cancelled = true;
    };
  }, [scanId]);

  // Compute clean hierarchical column layout: Application (0) -> Files (1) -> Libraries (2) -> Algorithms (3)
  const { positionedNodes, nodesById, canvasHeight } = useMemo(() => {
    const rawNodes = graphData?.nodes || [];
    if (!rawNodes.length) {
      return { positionedNodes: [], nodesById: new Map<string, PositionedNode>(), canvasHeight: 460 };
    }

    const appNodes: GraphData['nodes'][number][] = [];
    const fileNodes: GraphData['nodes'][number][] = [];
    const libNodes: GraphData['nodes'][number][] = [];
    const algNodes: GraphData['nodes'][number][] = [];

    for (const node of rawNodes) {
      if (node.type === 'application') appNodes.push(node);
      else if (node.type === 'file') fileNodes.push(node);
      else if (node.type === 'library') libNodes.push(node);
      else algNodes.push(node);
    }

    const maxCount = Math.max(1, appNodes.length, fileNodes.length, libNodes.length, algNodes.length);
    const rowHeight = 92;
    const computedHeight = Math.max(480, maxCount * rowHeight + 100);

    const layoutColumn = (items: GraphData['nodes'][number][], x: number, width: number, height: number): PositionedNode[] => {
      const totalColHeight = items.length * rowHeight;
      const startY = Math.max(40, (computedHeight - totalColHeight) / 2);
      return items.map((item, idx) => ({
        ...item,
        layoutX: x,
        layoutY: startY + idx * rowHeight,
        width,
        height,
      }));
    };

    const pApps = layoutColumn(appNodes, 40, 200, 68);
    const pFiles = layoutColumn(fileNodes, 310, 210, 64);
    const pLibs = layoutColumn(libNodes, 590, 190, 64);
    const pAlgs = layoutColumn(algNodes, 860, 240, 72);

    const allPositioned = [...pApps, ...pFiles, ...pLibs, ...pAlgs];
    const map = new Map<string, PositionedNode>(allPositioned.map((n) => [n.id, n]));

    return { positionedNodes: allPositioned, nodesById: map, canvasHeight: computedHeight };
  }, [graphData]);

  return (
    <div className="p-6 md:p-8 space-y-5 max-w-7xl mx-auto h-full flex flex-col">
      <header className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 p-5 rounded-xl bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 shadow-sm">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
            <Network className="w-4 h-4 text-blue-500" /> Architecture
          </div>
          <h1 className="text-xl font-semibold text-zinc-900 dark:text-zinc-100 mt-1">Cryptographic dependency graph</h1>
          <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">{projectName || 'Active Codebase'}</p>
        </div>
        <div className="flex items-center gap-1 bg-zinc-100 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 p-1 rounded-lg text-xs">
          <button
            disabled={!scanId || !graphData}
            onClick={() => setZoom((value) => Math.max(0.6, value - 0.1))}
            className="p-1.5 rounded text-zinc-500 hover:bg-white dark:hover:bg-zinc-800 disabled:opacity-40 disabled:cursor-not-allowed"
            title="Zoom out"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <span className="px-2 font-mono text-zinc-700 dark:text-zinc-300">{Math.round(zoom * 100)}%</span>
          <button
            disabled={!scanId || !graphData}
            onClick={() => setZoom((value) => Math.min(1.5, value + 0.1))}
            className="p-1.5 rounded text-zinc-500 hover:bg-white dark:hover:bg-zinc-800 disabled:opacity-40 disabled:cursor-not-allowed"
            title="Zoom in"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <button
            disabled={!scanId || !graphData}
            onClick={() => setZoom(1)}
            className="p-1.5 rounded text-zinc-500 hover:bg-white dark:hover:bg-zinc-800 disabled:opacity-40 disabled:cursor-not-allowed"
            title="Reset zoom"
          >
            <Maximize2 className="w-4 h-4" />
          </button>
        </div>
      </header>

      {error ? (
        <div className="p-5 rounded-xl bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900/50 text-sm text-red-600 dark:text-red-400">
          {error}
        </div>
      ) : null}

      {scanId && !error && !graphData ? (
        <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 text-sm text-zinc-500">
          Loading scan graph…
        </div>
      ) : null}

      {!scanId || (graphData && positionedNodes.length === 0) ? (
        <div className="architecture-empty flex-1 rounded-xl min-h-[460px] relative overflow-hidden border border-zinc-200 dark:border-zinc-800 flex items-center justify-center px-6 py-12">
          <div className="architecture-empty-grid" aria-hidden="true" />
          <div className="relative z-10 max-w-md text-center">
            <div className="architecture-empty-icon mx-auto mb-5">
              <Network className="w-6 h-6" />
            </div>
            <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-500 dark:text-zinc-400 mb-2">
              Architecture map
            </p>
            <h2 className="text-lg font-semibold text-zinc-900 dark:text-zinc-100">
              Your dependency graph will appear here
            </h2>
            <p className="mt-2 text-sm leading-6 text-zinc-500 dark:text-zinc-400">
              Upload a code archive to map cryptographic components and their relationships.
            </p>
          </div>
        </div>
      ) : null}

      {graphData && positionedNodes.length > 0 ? (
        <div className="graph-canvas-viewport flex-1 rounded-xl p-6 min-h-[500px] relative overflow-auto shadow-inner border">
          <div
            className="relative"
            style={{
              width: 1140,
              height: canvasHeight,
              transform: `scale(${zoom})`,
              transformOrigin: 'top left',
            }}
          >
            {/* SVG Connecting Edges */}
            <svg
              className="absolute inset-0 pointer-events-none"
              style={{ width: 1140, height: canvasHeight }}
            >
              {graphData.edges.map((edge) => {
                const source = nodesById.get(edge.source);
                const target = nodesById.get(edge.target);
                if (!source || !target) return null;

                const sx = source.layoutX + source.width;
                const sy = source.layoutY + source.height / 2;
                const tx = target.layoutX;
                const ty = target.layoutY + target.height / 2;

                const dx = Math.max(30, tx - sx);
                const cx1 = sx + dx * 0.45;
                const cx2 = tx - dx * 0.45;

                const isVulnerable =
                  Boolean(target.data.hndl) ||
                  target.data.severity === 'critical' ||
                  target.data.severity === 'high';

                const strokeColor = isVulnerable ? '#ef4444' : '#64748b';

                return (
                  <path
                    key={edge.id}
                    d={`M ${sx} ${sy} C ${cx1} ${sy}, ${cx2} ${ty}, ${tx} ${ty}`}
                    fill="none"
                    stroke={strokeColor}
                    strokeWidth={isVulnerable ? '2.5' : '1.8'}
                    strokeDasharray={isVulnerable ? '6 4' : undefined}
                  />
                );
              })}
            </svg>

            {/* Render Nodes with High-Contrast Themed Cards */}
            {positionedNodes.map((node) => {
              const severity = String(node.data.severity || '').toLowerCase();
              const label = String(node.data.label || node.id);
              const isHndl = Boolean(node.data.hndl);
              const isSelected = selectedNode?.id === node.id;

              let nodeClass = 'dep-node-card ';
              if (isSelected) nodeClass += 'selected ';
              if (node.type === 'application') {
                nodeClass += 'dep-node-application';
              } else if (node.type === 'file') {
                nodeClass += 'dep-node-file';
              } else if (node.type === 'library') {
                nodeClass += 'dep-node-library';
              } else if (isHndl || severity === 'critical') {
                nodeClass += 'dep-node-critical';
              } else if (severity === 'high') {
                nodeClass += 'dep-node-high';
              } else {
                nodeClass += 'dep-node-safe';
              }

              return (
                <button
                  key={node.id}
                  type="button"
                  onClick={() => setSelectedNode(node)}
                  className={nodeClass}
                  style={{
                    position: 'absolute',
                    left: `${node.layoutX}px`,
                    top: `${node.layoutY}px`,
                    width: `${node.width}px`,
                    height: `${node.height}px`,
                  }}
                >
                  <div className="flex items-center justify-between gap-1.5">
                    <div className="flex items-center gap-2 min-w-0">
                      {node.type === 'application' ? (
                        <Layers className="w-4 h-4 shrink-0 text-blue-400" />
                      ) : node.type === 'file' ? (
                        <FileCode2 className="w-4 h-4 shrink-0 text-sky-400" />
                      ) : node.type === 'library' ? (
                        <Cpu className="w-4 h-4 shrink-0 text-purple-400" />
                      ) : isHndl || severity === 'critical' ? (
                        <ShieldAlert className="w-4 h-4 shrink-0 text-red-400" />
                      ) : severity === 'high' ? (
                        <ShieldAlert className="w-4 h-4 shrink-0 text-orange-400" />
                      ) : (
                        <ShieldCheck className="w-4 h-4 shrink-0 text-emerald-400" />
                      )}
                      <span className="dep-node-title text-xs truncate">
                        {label}
                      </span>
                    </div>

                    {isHndl ? (
                      <span className="dep-badge-hndl shrink-0">
                        HNDL
                      </span>
                    ) : null}
                  </div>

                  <div className="mt-1 flex items-center justify-between text-[10px] truncate">
                    <span className="dep-node-sub truncate">
                      {node.data.full_path || node.data.kind || node.data.usage || (node.type === 'application' ? 'Service Boundary' : 'Asset')}
                    </span>
                    {severity ? (
                      <span className={`dep-badge-sev sev-${severity} ml-1 shrink-0`}>
                        {severity}
                      </span>
                    ) : null}
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      ) : null}

      {/* Selected Node Details Drawer */}
      {selectedNode ? (
        <div className="dep-detail-drawer flex items-center justify-between">
          <div className="min-w-0 flex-1 mr-4">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="dep-detail-drawer-title">
                {String(selectedNode.data.label || selectedNode.id)}
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-blue-500/20 text-blue-300 border border-blue-500/40">
                {selectedNode.type}
              </span>
              {selectedNode.data.hndl && (
                <span className="dep-badge-hndl">
                  HNDL Threat
                </span>
              )}
            </div>
            <div className="dep-detail-drawer-text mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1">
              {selectedNode.data.full_path && (
                <span>
                  <strong>Path:</strong>{' '}
                  <code className="dep-detail-drawer-code">
                    {selectedNode.data.full_path}
                  </code>
                </span>
              )}
              {selectedNode.data.usage && (
                <span>
                  <strong>Usage:</strong> {selectedNode.data.usage}
                </span>
              )}
              {selectedNode.data.severity && (
                <span>
                  <strong>Severity:</strong>{' '}
                  <span className={`dep-badge-sev sev-${selectedNode.data.severity}`}>
                    {selectedNode.data.severity}
                  </span>
                </span>
              )}
            </div>
          </div>
          <button
            type="button"
            onClick={() => setSelectedNode(null)}
            className="dep-detail-drawer-btn shrink-0"
          >
            Dismiss
          </button>
        </div>
      ) : null}
    </div>
  );
};
