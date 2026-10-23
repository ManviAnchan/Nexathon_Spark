import React, { useEffect, useState } from 'react';
import { Network, ZoomIn, ZoomOut, Maximize2, FileCode2, Layers, Cpu, ShieldAlert } from 'lucide-react';
import { GraphData } from '../types';
import { fetchCryptoGraph } from '../lib/api';

interface DependencyGraphProps {
  scanId: string | null;
  projectName: string;
}

export const DependencyGraph: React.FC<DependencyGraphProps> = ({
  scanId,
  projectName
}) => {
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [zoom, setZoom] = useState(1);
  const [selectedNode, setSelectedNode] = useState<{ label: string; type: string; info: string } | null>(null);

  useEffect(() => {
    async function loadGraph() {
      if (!scanId) return;
      try {
        const data = await fetchCryptoGraph(scanId);
        setGraphData(data);
      } catch (e) {
        console.error(e);
      }
    }
    loadGraph();
  }, [scanId]);

  return (
    <div className="p-6 md:p-8 space-y-5 max-w-7xl mx-auto h-full flex flex-col">
      {/* Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 p-5 rounded-2xl bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 shadow-sm">
        <div>
          <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-blue-600 dark:text-blue-400">
            <Network className="w-3.5 h-3.5" />
            <span>Architecture Visualizer</span>
          </div>
          <h1 className="text-xl font-bold text-zinc-900 dark:text-zinc-100 font-['Outfit'] mt-1">
            Cryptographic Dependency Graph
          </h1>
          <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">
            Topology mapping Application &rarr; Source Files &rarr; Libraries &rarr; Cryptographic Primitives.
          </p>
        </div>

        {/* Zoom controls */}
        <div className="flex items-center gap-1 bg-zinc-100 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 p-1 rounded-xl text-xs">
          <button
            onClick={() => setZoom(z => Math.max(0.6, z - 0.1))}
            className="p-1.5 rounded-lg text-zinc-500 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100 hover:bg-white dark:hover:bg-zinc-800 transition-colors"
            title="Zoom Out"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <span className="text-xs font-mono text-zinc-700 dark:text-zinc-300 px-2 font-semibold">{Math.round(zoom * 100)}%</span>
          <button
            onClick={() => setZoom(z => Math.min(1.5, z + 0.1))}
            className="p-1.5 rounded-lg text-zinc-500 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100 hover:bg-white dark:hover:bg-zinc-800 transition-colors"
            title="Zoom In"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <button
            onClick={() => setZoom(1)}
            className="p-1.5 rounded-lg text-zinc-500 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100 hover:bg-white dark:hover:bg-zinc-800 transition-colors"
            title="Reset"
          >
            <Maximize2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Main Canvas */}
      <div className="flex-1 rounded-2xl p-6 min-h-[520px] relative overflow-hidden flex items-center justify-center bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 shadow-inner">
        <div 
          className="relative w-full h-full min-h-[480px] transition-transform duration-150"
          style={{ transform: `scale(${zoom})`, transformOrigin: 'center center' }}
        >
          {/* Level Headers */}
          <div className="absolute top-2 left-6 text-[10px] font-mono font-bold tracking-wider uppercase text-zinc-400 dark:text-zinc-500">01. Service Boundary</div>
          <div className="absolute top-2 left-[280px] text-[10px] font-mono font-bold tracking-wider uppercase text-zinc-400 dark:text-zinc-500">02. Source Files</div>
          <div className="absolute top-2 left-[540px] text-[10px] font-mono font-bold tracking-wider uppercase text-zinc-400 dark:text-zinc-500">03. Libraries</div>
          <div className="absolute top-2 left-[780px] text-[10px] font-mono font-bold tracking-wider uppercase text-zinc-400 dark:text-zinc-500">04. Algorithms</div>

          {/* SVG Connection Lines */}
          <svg className="absolute inset-0 w-full h-full pointer-events-none">
            <path d="M 170 200 C 230 200, 230 80, 280 80" stroke="#94a3b8" strokeWidth="1.5" fill="none" strokeDasharray="3 3" />
            <path d="M 170 200 C 230 200, 230 180, 280 180" stroke="#94a3b8" strokeWidth="1.5" fill="none" strokeDasharray="3 3" />
            <path d="M 170 200 C 230 200, 230 280, 280 280" stroke="#94a3b8" strokeWidth="1.5" fill="none" strokeDasharray="3 3" />
            <path d="M 170 200 C 230 200, 230 380, 280 380" stroke="#94a3b8" strokeWidth="1.5" fill="none" strokeDasharray="3 3" />

            <path d="M 440 80 C 490 80, 490 120, 540 120" stroke="#64748b" strokeWidth="1.5" fill="none" />
            <path d="M 440 180 C 490 180, 490 120, 540 120" stroke="#64748b" strokeWidth="1.5" fill="none" />
            <path d="M 440 280 C 490 280, 490 280, 540 280" stroke="#64748b" strokeWidth="1.5" fill="none" />
            <path d="M 440 380 C 490 380, 490 380, 540 380" stroke="#64748b" strokeWidth="1.5" fill="none" />

            <path d="M 680 120 C 730 120, 730 80, 780 80" stroke="#ef4444" strokeWidth="1.5" fill="none" opacity="0.6" />
            <path d="M 680 120 C 730 120, 730 180, 780 180" stroke="#f59e0b" strokeWidth="1.5" fill="none" opacity="0.6" />
            <path d="M 680 280 C 730 280, 730 280, 780 280" stroke="#3b82f6" strokeWidth="1.5" fill="none" opacity="0.6" />
            <path d="M 680 380 C 730 380, 730 380, 780 380" stroke="#f59e0b" strokeWidth="1.5" fill="none" opacity="0.6" />
          </svg>

          {/* Root Application Node */}
          <div 
            onClick={() => setSelectedNode({ label: projectName || 'Quantum Vault Demo', type: 'Application Root', info: 'Microservice root boundary container' })}
            className="absolute left-6 top-[160px] w-40 p-3.5 rounded-xl bg-white dark:bg-zinc-900 border border-zinc-300 dark:border-zinc-700 shadow-md cursor-pointer hover:border-blue-500 transition-colors text-center"
          >
            <div className="w-8 h-8 rounded-lg bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 mx-auto flex items-center justify-center mb-1.5 border border-blue-200 dark:border-blue-900/40">
              <Layers className="w-4 h-4" />
            </div>
            <div className="font-bold text-zinc-900 dark:text-zinc-100 text-xs font-['Outfit'] truncate">{projectName || 'Quantum Vault Demo'}</div>
            <div className="text-[10px] text-zinc-400 font-mono uppercase mt-0.5">App Root</div>
          </div>

          {/* File Nodes */}
          {[
            { label: 'crypto_service.py', top: 55, path: 'backend/crypto_service.py' },
            { label: 'auth.py', top: 155, path: 'backend/auth.py' },
            { label: 'hasher.py', top: 255, path: 'backend/hasher.py' },
            { label: 'requirements.txt', top: 355, path: 'manifests/requirements.txt' }
          ].map((file, idx) => (
            <div
              key={idx}
              onClick={() => setSelectedNode({ label: file.label, type: 'Source File', info: file.path })}
              className="absolute left-[280px] w-40 p-3 rounded-xl bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 shadow-sm cursor-pointer hover:border-blue-500 transition-colors"
              style={{ top: file.top }}
            >
              <div className="flex items-center gap-2">
                <FileCode2 className="w-3.5 h-3.5 text-zinc-400 shrink-0" />
                <div className="font-mono text-xs font-medium text-zinc-800 dark:text-zinc-200 truncate">{file.label}</div>
              </div>
              <div className="text-[10px] text-zinc-400 mt-0.5 truncate font-mono">{file.path}</div>
            </div>
          ))}

          {/* Library Nodes */}
          {[
            { label: 'cryptography', top: 95, desc: 'hazmat.primitives.asymmetric' },
            { label: 'hashlib', top: 255, desc: 'Python standard library' },
            { label: 'pycryptodome', top: 355, desc: 'Legacy package v3.10.1' }
          ].map((lib, idx) => (
            <div
              key={idx}
              onClick={() => setSelectedNode({ label: lib.label, type: 'Dependency Library', info: lib.desc })}
              className="absolute left-[540px] w-36 p-3 rounded-xl bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 shadow-sm cursor-pointer hover:border-blue-500 transition-colors"
              style={{ top: lib.top }}
            >
              <div className="flex items-center gap-2">
                <Cpu className="w-3.5 h-3.5 text-blue-500 shrink-0" />
                <div className="font-medium text-xs text-zinc-800 dark:text-zinc-200 truncate">{lib.label}</div>
              </div>
              <div className="text-[10px] text-zinc-400 mt-0.5 font-mono">{lib.desc}</div>
            </div>
          ))}

          {/* Algorithm Nodes */}
          {[
            { label: 'RSA-2048', top: 55, sev: 'critical', hndl: true, color: 'border-red-300 dark:border-red-900/60 bg-red-50/80 dark:bg-red-950/40 text-red-600 dark:text-red-300' },
            { label: 'ECC SECP256R1', top: 155, sev: 'high', hndl: true, color: 'border-amber-300 dark:border-amber-900/60 bg-amber-50/80 dark:bg-amber-950/40 text-amber-600 dark:text-amber-300' },
            { label: 'MD5 Hashing', top: 255, sev: 'low', hndl: false, color: 'border-zinc-300 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-900 text-zinc-700 dark:text-zinc-300' },
            { label: 'DES / RC4', top: 355, sev: 'low', hndl: false, color: 'border-amber-300 dark:border-amber-900/60 bg-amber-50/80 dark:bg-amber-950/40 text-amber-600 dark:text-amber-300' }
          ].map((alg, idx) => (
            <div
              key={idx}
              onClick={() => setSelectedNode({ label: alg.label, type: 'Cryptographic Primitive', info: `Severity: ${alg.sev.toUpperCase()} ${alg.hndl ? '| Harvest-Now-Decrypt-Later Risk' : ''}` })}
              className={`absolute left-[780px] w-48 p-3 rounded-xl border ${alg.color} shadow-sm cursor-pointer hover:border-zinc-500 transition-colors`}
              style={{ top: alg.top }}
            >
              <div className="flex items-center justify-between font-mono">
                <div className="font-bold text-xs">{alg.label}</div>
                {alg.hndl && (
                  <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-950 text-red-600 dark:text-red-400 border border-red-200 dark:border-red-900/50">
                    HNDL
                  </span>
                )}
              </div>
              <div className="text-[10px] text-zinc-500 dark:text-zinc-400 mt-1 capitalize font-sans">Risk: {alg.sev}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Selected Node Details Box */}
      {selectedNode && (
        <div className="p-4 rounded-xl bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 flex items-center justify-between shadow-sm">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <div className="text-xs font-bold text-zinc-900 dark:text-zinc-100">{selectedNode.label}</div>
              <div className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-0.5">{selectedNode.type} · {selectedNode.info}</div>
            </div>
          </div>
          <button
            onClick={() => setSelectedNode(null)}
            className="text-xs text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 px-2 py-1 rounded"
          >
            Dismiss
          </button>
        </div>
      )}
    </div>
  );
};
