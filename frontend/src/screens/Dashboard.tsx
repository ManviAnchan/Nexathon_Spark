import { useState } from 'react';
import { AlertTriangle, ArrowRight, Download, FileCode2, RefreshCw, ShieldCheck, Upload } from 'lucide-react';
import { Cell, Pie, PieChart, PolarAngleAxis, RadialBar, RadialBarChart, ResponsiveContainer, Tooltip } from 'recharts';
import type { Finding, ScanStatus } from '../types';
import { downloadScanExport } from '../lib/api';

interface DashboardProps { scan: ScanStatus | null; findings: Finding[]; isDemo?: boolean; onOpenFinding: (finding: Finding) => void; onNavigate: (screen: string) => void; }
const severityColors = ['#fb7185', '#fb923c', '#fbbf24', '#60a5fa', '#34d399'];
const severityLabels = ['Critical', 'High', 'Medium', 'Low', 'Quantum safe'];

export function Dashboard({ scan, findings, isDemo = false, onOpenFinding, onNavigate }: DashboardProps) {
  const [exportError, setExportError] = useState('');
  const [exporting, setExporting] = useState<'cbom' | 'pdf' | null>(null);
  const counts = scan?.severity_counts ?? { critical: 0, high: 0, medium: 0, low: 0, quantum_safe: 0 };
  const score = scan?.readiness_score ?? 0;
  const tier = score >= 80 ? 'Quantum ready' : score >= 50 ? 'Needs upgrade' : 'Critical risk';
  const tierClass = score >= 80 ? 'ready' : score >= 50 ? 'upgrade' : 'critical';
  const chartData = [counts.critical, counts.high, counts.medium, counts.low, counts.quantum_safe].map((value, index) => ({ name: severityLabels[index], value, color: severityColors[index] }));
  const hasHndl = (scan?.hndl_count ?? 0) > 0 || findings.some(finding => finding.hndl);

  const exportReport = async (format: 'cbom' | 'pdf') => {
    if (!scan) return;
    setExporting(format); setExportError('');
    try { await downloadScanExport(scan.id, format); }
    catch (cause) { setExportError(cause instanceof Error ? cause.message : 'The export could not be downloaded.'); }
    finally { setExporting(null); }
  };

  return <section className="dashboard-page"><div className="workspace-content">
    <div className="dashboard-heading"><div><span className="eyebrow">SECURITY POSTURE <i/> {scan?.status ?? 'READY'}</span><h1>Executive dashboard</h1><p>Understand your cryptographic exposure and where to focus next.</p></div><button className="primary-action" onClick={() => onNavigate('upload')}><Upload size={15}/> Upload new archive</button></div>
    {isDemo && <div className="demo-strip"><span/> Sample workspace data · Upload a ZIP to analyze your own code.</div>}
    <div className="dashboard-overview">
      <article className="readiness-card"><div className="section-label">KEYNOVA READINESS INDEX <span>R</span></div><div className="readiness-main"><div><div className={`risk-tier ${tierClass}`}><i/>{tier}</div><div className="readiness-score">{score}<small>/100</small></div><p>{scan ? 'Post-quantum readiness score' : 'No scan results yet'}</p></div><div className="gauge-wrap"><ResponsiveContainer width="100%" height="100%"><RadialBarChart innerRadius="76%" outerRadius="100%" barSize={13} data={[{ name: 'Readiness', value: score, fill: score < 50 ? '#fb7185' : score < 80 ? '#fbbf24' : '#34d399' }]} startAngle={90} endAngle={-270}><PolarAngleAxis type="number" domain={[0, 100]} tick={false}/><RadialBar background={{ fill: '#26364d' }} dataKey="value" cornerRadius={9}/></RadialBarChart></ResponsiveContainer><span><ShieldCheck size={25}/></span></div></div><div className="score-meter"><i style={{ width: `${score}%` }}/></div><div className="readiness-foot"><span>Readiness index</span><span>{tier}</span></div></article>
      <article className="severity-card"><div className="card-heading"><div><span className="section-label">FINDINGS BY SEVERITY</span><h2>Risk distribution</h2></div><button className="icon-action" onClick={() => onNavigate('findings')} aria-label="View findings"><ArrowRight size={16}/></button></div><div className="severity-content"><div className="donut-wrap"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={chartData} dataKey="value" nameKey="name" innerRadius="68%" outerRadius="92%" paddingAngle={3} stroke="none">{chartData.map(item => <Cell key={item.name} fill={item.color}/>)}</Pie><Tooltip contentStyle={{ background: '#101a2b', border: '1px solid #26364d', borderRadius: 8, color: '#e5edf7' }}/></PieChart></ResponsiveContainer><div className="donut-total"><strong>{findings.length || Object.values(counts).reduce((a, b) => a + b, 0)}</strong><small>signals</small></div></div><div className="severity-legend">{chartData.map(item => <div key={item.name}><i style={{ background: item.color }}/><span>{item.name}</span><strong>{item.value}</strong></div>)}</div></div></article>
      <article className="coverage-card"><span className="section-label">CODE COVERAGE</span><strong>{Math.round(scan?.coverage_percent ?? 0)}<small>%</small></strong><p><FileCode2 size={14}/>{scan?.scanned_files ?? 0} of {scan?.total_files ?? 0} files scanned</p><div className="coverage-track"><i style={{ width: `${scan?.coverage_percent ?? 0}%` }}/></div><span className="coverage-note">Coverage factor <b>{((scan?.coverage_percent ?? 0) / 100).toFixed(2)}</b></span></article>
    </div>
    {hasHndl && <div className="hndl-banner"><span className="hndl-icon"><AlertTriangle size={18}/></span><div><strong>Harvest-now, decrypt-later exposure detected</strong><p>Classical public-key cryptography can expose data to future decryption. Prioritize the RSA or ECC findings in this scan.</p></div><button onClick={() => onNavigate('findings')}>Review findings <ArrowRight size={14}/></button></div>}
    <div className="dashboard-bottom"><article className="queue-card"><div className="card-heading"><div><span className="section-label">PRIORITY QUEUE</span><h2>Highest severity findings</h2></div><button className="text-action" onClick={() => onNavigate('findings')}>All findings <ArrowRight size={14}/></button></div>{findings.length ? findings.slice().sort((a,b) => ['critical','high','medium','low','quantum_safe'].indexOf(a.severity)-['critical','high','medium','low','quantum_safe'].indexOf(b.severity)).slice(0,3).map((finding,index) => <button className="finding-row" key={finding.id} onClick={() => { onOpenFinding(finding); onNavigate('findings'); }}><span className="finding-index">0{index+1}</span><span className="finding-detail"><strong>{finding.algorithm}</strong><small>{finding.file_path}:{finding.line_start}</small></span><span className={`severity-pill ${finding.severity}`}>{finding.severity.replace('_', ' ')}</span><ArrowRight size={14}/></button>) : <div className="queue-empty"><ShieldCheck size={19}/><span>No findings available in this scan.</span></div>}</article>
      <article className="export-card"><span className="section-label">REPORTS & EXPORTS</span><h2>Share a clear picture</h2><p>Export the scan inventory or a concise executive report.</p><div className="export-actions"><button onClick={() => void exportReport('cbom')} disabled={!scan || exporting !== null}><Download size={15}/>{exporting === 'cbom' ? 'Preparing CBOM…' : 'Export CycloneDX CBOM'}</button><button onClick={() => void exportReport('pdf')} disabled={!scan || exporting !== null}><Download size={15}/>{exporting === 'pdf' ? 'Preparing PDF…' : 'Download executive PDF'}</button></div>{exportError && <small className="export-error" role="alert">{exportError}</small>}<div className="export-foot"><RefreshCw size={13}/> Exports use the selected scan</div></article></div>
  </div></section>;
}
