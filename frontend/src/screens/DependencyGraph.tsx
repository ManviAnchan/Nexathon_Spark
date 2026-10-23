import React, { useEffect, useState } from 'react';
import { Cpu, FileCode2, Layers, Maximize2, Network, ShieldAlert, ZoomIn, ZoomOut } from 'lucide-react';
import { GraphData } from '../types';
import { fetchCryptoGraph } from '../lib/api';

interface DependencyGraphProps {
  scanId: string | null;
  projectName: string;
}

export const DependencyGraph: React.FC<DependencyGraphProps> = ({ scanId, projectName }) => {
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [zoom, setZoom] = useState(1);
  const [selectedNode, setSelectedNode] = useState<GraphData['nodes'][number] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setGraphData(null);
    setError(null);
    if (!scanId) return;
    fetchCryptoGraph(scanId)
      .then((data) => { if (!cancelled) setGraphData(data); })
      .catch((reason: unknown) => {
        if (!cancelled) setError(reason instanceof Error ? reason.message : 'Graph could not be loaded.');
      });
    return () => { cancelled = true; };
  }, [scanId]);

  const nodes = graphData?.nodes || [];
  const nodesById = new Map(nodes.map((node) => [node.id, node]));
  const canvasHeight = Math.max(360, ...nodes.map((node) => node.position.y + 100));
  const nodeWidth = (type: string) => type === 'application' ? 180 : type === 'algorithm' ? 190 : 170;

  return (
    <div className="p-6 md:p-8 space-y-5 max-w-7xl mx-auto h-full flex flex-col">
      <header className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 p-5 rounded-xl bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
            <Network className="w-4 h-4" /> Architecture
          </div>
          <h1 className="text-xl font-semibold text-zinc-900 dark:text-zinc-100 mt-1">Cryptographic dependency graph</h1>
          <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">{projectName}</p>
        </div>
        <div className="flex items-center gap-1 bg-zinc-100 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 p-1 rounded-lg text-xs">
          <button disabled={!scanId || !graphData} onClick={() => setZoom((value) => Math.max(0.6, value - 0.1))} className="p-1.5 rounded text-zinc-500 hover:bg-white dark:hover:bg-zinc-800 disabled:opacity-40 disabled:cursor-not-allowed" title="Zoom out"><ZoomOut className="w-4 h-4" /></button>
          <span className="px-2 font-mono text-zinc-700 dark:text-zinc-300">{Math.round(zoom * 100)}%</span>
          <button disabled={!scanId || !graphData} onClick={() => setZoom((value) => Math.min(1.5, value + 0.1))} className="p-1.5 rounded text-zinc-500 hover:bg-white dark:hover:bg-zinc-800 disabled:opacity-40 disabled:cursor-not-allowed" title="Zoom in"><ZoomIn className="w-4 h-4" /></button>
          <button disabled={!scanId || !graphData} onClick={() => setZoom(1)} className="p-1.5 rounded text-zinc-500 hover:bg-white dark:hover:bg-zinc-800 disabled:opacity-40 disabled:cursor-not-allowed" title="Reset zoom"><Maximize2 className="w-4 h-4" /></button>
        </div>
      </header>

      {error ? <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 text-sm text-red-600">{error}</div> : null}
      {scanId && !error && !graphData ? <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 text-sm text-zinc-500">Loading scan graph…</div> : null}
      {!scanId || (graphData && nodes.length === 0) ? (
        <div className="architecture-empty flex-1 rounded-xl min-h-[460px] relative overflow-hidden border border-zinc-200 dark:border-zinc-800 flex items-center justify-center px-6 py-12">
          <div className="architecture-empty-grid" aria-hidden="true" />
          <div className="relative z-10 max-w-md text-center">
            <div className="architecture-empty-icon mx-auto mb-5"><Network className="w-6 h-6" /></div>
            <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-500 dark:text-zinc-400 mb-2">Architecture map</p>
            <h2 className="text-lg font-semibold text-zinc-900 dark:text-zinc-100">Your dependency graph will appear here</h2>
            <p className="mt-2 text-sm leading-6 text-zinc-500 dark:text-zinc-400">Upload a code archive to map cryptographic components and their relationships.</p>
          </div>
        </div>
      ) : null}
      {graphData && nodes.length > 0 ? (
        <div className="flex-1 rounded-xl p-6 min-h-[460px] relative overflow-auto bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800">
          <div className="relative min-w-[1000px]" style={{ height: canvasHeight, transform: `scale(${zoom})`, transformOrigin: 'top left' }}>
            <svg className="absolute inset-0 w-full h-full pointer-events-none">
              {graphData.edges.map((edge) => {
                const source = nodesById.get(edge.source);
                const target = nodesById.get(edge.target);
                if (!source || !target) return null;
                const sx = source.position.x + nodeWidth(source.type);
                const sy = source.position.y + 36;
                const tx = target.position.x;
                const ty = target.position.y + 36;
                const bend = (sx + tx) / 2;
                const vulnerable = Boolean(target.data.hndl) || target.data.severity === 'critical' || target.data.severity === 'high';
                return <path key={edge.id} d={`M ${sx} ${sy} C ${bend} ${sy}, ${bend} ${ty}, ${tx} ${ty}`} fill="none" stroke={vulnerable ? '#c68170' : '#a9a398'} strokeWidth="1.5" strokeDasharray={edge.animated ? '4 4' : undefined} />;
              })}
            </svg>
            {nodes.map((node) => {
              const Icon = node.type === 'application' ? Layers : node.type === 'file' ? FileCode2 : node.type === 'library' ? Cpu : ShieldAlert;
              const severity = String(node.data.severity || '');
              const label = String(node.data.label || node.id);
              const info = [node.data.full_path, node.data.kind, node.data.usage, severity && `Severity: ${severity}`, node.data.hndl && 'HNDL exposure'].filter(Boolean).join(' · ');
              return (
                <button
                  key={node.id}
                  type="button"
                  onClick={() => setSelectedNode(node)}
                  className="absolute p-3 rounded-lg bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-700 shadow-sm text-left hover:border-zinc-400"
                  style={{ left: node.position.x, top: node.position.y, width: nodeWidth(node.type) }}
                >
                  <span className="flex items-center gap-2 text-xs font-medium text-zinc-800 dark:text-zinc-200"><Icon className="w-4 h-4 shrink-0 text-zinc-500" /> <span className="truncate">{label}</span></span>
                  {info ? <span className="block mt-1 text-[10px] text-zinc-500 truncate">{info}</span> : null}
                </button>
              );
            })}
          </div>
        </div>
      ) : null}

      {selectedNode ? (
        <div className="p-4 rounded-xl bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 flex items-center justify-between">
          <div><div className="text-xs font-semibold text-zinc-900 dark:text-zinc-100">{String(selectedNode.data.label || selectedNode.id)}</div><div className="text-[11px] text-zinc-500 mt-1">{selectedNode.type} · {String(selectedNode.data.full_path || selectedNode.data.usage || selectedNode.data.kind || '')}</div></div>
          <button onClick={() => setSelectedNode(null)} className="text-xs text-zinc-500">Dismiss</button>
        </div>
      ) : null}
    </div>
  );
};
