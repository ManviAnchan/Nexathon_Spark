import { useEffect, useMemo, useState } from 'react';
import { FileCode2, Layers, Maximize2, Network, Package, ShieldAlert, ZoomIn, ZoomOut, X } from 'lucide-react';
import { fetchScanGraph } from '../lib/api';
import type { Finding, GraphData } from '../types';

interface DependencyGraphProps { scanId: string | null; projectName: string; findings: Finding[]; }
type GraphKind = 'application' | 'file' | 'library' | 'algorithm';
interface ViewNode { id: string; label: string; kind: GraphKind; detail: string; severity?: string; hndl?: boolean; }
interface ViewEdge { source: string; target: string; risk: boolean; }
const labelFrom = (node: GraphData['nodes'][number]) => {
  const values = node.data as Record<string, unknown>;
  for (const key of ['label', 'name', 'algorithm', 'file_path', 'path', 'title']) if (typeof values[key] === 'string' && values[key]) return values[key] as string;
  return node.id;
};
const kindFrom = (raw: string): GraphKind => {
  const type = raw.toLowerCase();
  if (type.includes('file') || type.includes('source')) return 'file';
  if (type.includes('lib') || type.includes('depend')) return 'library';
  if (type.includes('algorithm') || type.includes('crypto') || type.includes('primitive')) return 'algorithm';
  return 'application';
};
const makeFindingGraph = (findings: Finding[], projectName: string) => {
  const nodes: ViewNode[] = [{ id: 'app-root', label: projectName, kind: 'application', detail: 'Scanned application boundary' }];
  const edges: ViewEdge[] = [];
  const seen = new Set<string>(['app-root']);
  for (const finding of findings) {
    const fileId = `file:${finding.file_path}`;
    if (!seen.has(fileId)) { nodes.push({ id: fileId, label: finding.file_path.split('/').pop() || finding.file_path, kind: 'file', detail: finding.file_path }); seen.add(fileId); edges.push({ source: 'app-root', target: fileId, risk: false }); }
    let upstream = fileId;
    if (finding.library) {
      const libraryId = `library:${finding.library}`;
      if (!seen.has(libraryId)) { nodes.push({ id: libraryId, label: finding.library, kind: 'library', detail: `Dependency used in ${finding.file_path}` }); seen.add(libraryId); }
      edges.push({ source: fileId, target: libraryId, risk: false }); upstream = libraryId;
    }
    const algorithmId = `algorithm:${finding.algorithm}`;
    if (!seen.has(algorithmId)) { nodes.push({ id: algorithmId, label: finding.algorithm, kind: 'algorithm', detail: finding.usage.replace(/_/g, ' '), severity: finding.severity, hndl: finding.hndl }); seen.add(algorithmId); }
    edges.push({ source: upstream, target: algorithmId, risk: finding.hndl || finding.severity === 'critical' });
  }
  return { nodes, edges };
};

export function DependencyGraph({ scanId, projectName, findings }: DependencyGraphProps) {
  const [serverGraph, setServerGraph] = useState<GraphData | null>(null);
  const [zoom, setZoom] = useState(1);
  const [selected, setSelected] = useState<ViewNode | null>(null);
  useEffect(() => {
    let live = true;
    setServerGraph(null);
    if (scanId) void fetchScanGraph(scanId).then(graph => { if (live) setServerGraph(graph); }).catch(() => { if (live) setServerGraph(null); });
    return () => { live = false; };
  }, [scanId]);

  const graph = useMemo(() => {
    if (!serverGraph?.nodes.length) return makeFindingGraph(findings, projectName);
    const nodes: ViewNode[] = serverGraph.nodes.map(node => {
      const values = node.data as Record<string, unknown>;
      const kind = kindFrom(node.type);
      return { id: node.id, label: labelFrom(node), kind, detail: String(values.path ?? values.description ?? values.library ?? node.type), severity: typeof values.severity === 'string' ? values.severity : undefined, hndl: values.hndl === true };
    });
    const root = nodes.find(node => node.kind === 'application');
    if (!root) nodes.unshift({ id: 'app-root', label: projectName, kind: 'application', detail: 'Scanned application boundary' });
    const edges: ViewEdge[] = serverGraph.edges.map(edge => ({ source: edge.source, target: edge.target, risk: edge.animated === true }));
    return { nodes, edges };
  }, [serverGraph, findings, projectName]);

  const columns: GraphKind[] = ['application', 'file', 'library', 'algorithm'];
  const labels: Record<GraphKind, string> = { application: 'APPLICATION', file: 'SOURCE FILES', library: 'DEPENDENCIES', algorithm: 'CRYPTO PRIMITIVES' };
  const x: Record<GraphKind, number> = { application: 32, file: 300, library: 585, algorithm: 870 };
  const width: Record<GraphKind, number> = { application: 190, file: 210, library: 210, algorithm: 220 };
  const grouped = Object.fromEntries(columns.map(kind => [kind, graph.nodes.filter(node => node.kind === kind)])) as Record<GraphKind, ViewNode[]>;
  const rowY = new Map<string, number>();
  for (const kind of columns) grouped[kind].forEach((node, index) => rowY.set(node.id, 64 + index * 104));
  const height = Math.max(400, ...columns.map(kind => 64 + grouped[kind].length * 104));
  const byId = new Map(graph.nodes.map(node => [node.id, node]));
  const colorFor = (node?: ViewNode) => node?.hndl || node?.severity === 'critical' ? '#a87369' : node?.severity === 'high' ? '#9d795e' : '#8d8577';

  return <section className="graph-page"><div className="graph-content"><div className="graph-heading"><div><span className="eyebrow"><Network size={13}/> DEPENDENCY MAP</span><h1>Cryptographic graph</h1><p>Trace how code paths connect to cryptographic dependencies and algorithms.</p></div><div className="graph-controls"><button onClick={() => setZoom(value => Math.max(.65, value - .1))} aria-label="Zoom out"><ZoomOut size={15}/></button><span>{Math.round(zoom * 100)}%</span><button onClick={() => setZoom(value => Math.min(1.35, value + .1))} aria-label="Zoom in"><ZoomIn size={15}/></button><button onClick={() => setZoom(1)} aria-label="Reset zoom"><Maximize2 size={15}/></button></div></div>
    <div className="graph-legend"><span><i className="legend-safe"/>Dependency path</span><span><i className="legend-risk"/>HNDL or critical path</span><span>{graph.nodes.length} nodes <b>·</b> {graph.edges.length} links</span></div>
    {findings.length === 0 && !serverGraph?.nodes.length ? <div className="graph-empty"><Network size={28}/><strong>No dependency graph yet</strong><span>Run a scan to map files, libraries, and cryptographic primitives.</span></div> : <div className="graph-viewport"><div className="graph-stage" style={{ width: 1120, height, transform: `scale(${zoom})` }}>
      {columns.map(kind => <div className="graph-column-label" key={kind} style={{ left: x[kind], width: width[kind] }}>{labels[kind]}</div>)}
      <svg className="graph-lines" width="1120" height={height} aria-hidden="true">{graph.edges.map((edge,index) => { const source=byId.get(edge.source), target=byId.get(edge.target); if(!source||!target)return null; const sy=(rowY.get(source.id)??64)+30, ty=(rowY.get(target.id)??64)+30, sx=x[source.kind]+width[source.kind], tx=x[target.kind]; const mid=(sx+tx)/2; return <path key={`${edge.source}:${edge.target}:${index}`} d={`M ${sx} ${sy} C ${mid} ${sy}, ${mid} ${ty}, ${tx} ${ty}`} className={edge.risk?'graph-edge-risk':'graph-edge'} />; })}</svg>
      {graph.nodes.map(node => <button key={node.id} className={`graph-node ${node.kind}${selected?.id===node.id?' selected':''}`} onClick={() => setSelected(node)} style={{ left:x[node.kind], top:rowY.get(node.id)??64, width:width[node.kind], borderColor:selected?.id===node.id?colorFor(node):undefined }}><span className="graph-node-icon">{node.kind==='application'?<Layers size={15}/>:node.kind==='file'?<FileCode2 size={15}/>:node.kind==='library'?<Package size={15}/>:<ShieldAlert size={15}/>}</span><span className="graph-node-copy"><strong>{node.label}</strong><small>{node.detail}</small></span>{node.hndl&&<i className="node-risk-dot"/>}</button>)}
      {selected && <div className="graph-detail"><button onClick={() => setSelected(null)} aria-label="Close node details"><X size={14}/></button><span className="eyebrow">{selected.kind.toUpperCase()}</span><strong>{selected.label}</strong><p>{selected.detail}</p>{selected.severity&&<small className={`finding-severity ${selected.severity}`}>{selected.severity} {selected.hndl?'· HNDL risk':''}</small>}</div>}
    </div></div>}
    <footer className="graph-foot"><span>KEYNOVA <i/> ARCHITECTURE VIEW</span><span>Click a node to inspect its details</span></footer></div></section>;
}
