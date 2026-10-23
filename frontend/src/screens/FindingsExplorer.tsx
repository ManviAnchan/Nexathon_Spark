import { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, ArrowLeft, ArrowRight, CheckCircle2, ChevronRight, LoaderCircle, Search, ShieldAlert, WandSparkles, X } from 'lucide-react';
import { suggestPqcMigration } from '../lib/api';
import type { Finding, FindingSeverity } from '../types';

interface FindingsExplorerProps {
  findings: Finding[];
  selectedFinding?: Finding | null;
  onSelectFinding: (finding: Finding | null) => void;
  onNavigate: (screen: string) => void;
}
const filters: Array<{ label: string; value: FindingSeverity | 'all' }> = [
  { label: 'All', value: 'all' }, { label: 'Critical', value: 'critical' }, { label: 'High', value: 'high' },
  { label: 'Medium', value: 'medium' }, { label: 'Low', value: 'low' },
];

export function FindingsExplorer({ findings, selectedFinding, onSelectFinding, onNavigate }: FindingsExplorerProps) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState<FindingSeverity | 'all'>('all');
  const [remediation, setRemediation] = useState<RemediationResponse | null>(null);
  const [remediationError, setRemediationError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => { setRemediation(null); setRemediationError(''); }, [selectedFinding?.id]);
  const visible = useMemo(() => findings.filter(finding => {
    const normalized = query.trim().toLowerCase();
    const matchesQuery = !normalized || [finding.algorithm, finding.file_path, finding.usage, finding.rule_id].some(value => value.toLowerCase().includes(normalized));
    return matchesQuery && (severity === 'all' || finding.severity === severity);
  }), [findings, query, severity]);

  const requestMigration = async () => {
    if (!selectedFinding) return;
    setLoading(true); setRemediation(null); setRemediationError('');
    try { setRemediation(await suggestPqcMigration(selectedFinding.id)); }
    catch (cause) { setRemediationError(cause instanceof Error ? cause.message : 'A migration suggestion could not be generated.'); }
    finally { setLoading(false); }
  };

  return <section className="findings-page"><div className="findings-content">
    <div className="findings-heading"><div><button className="back-link" onClick={() => onNavigate('dashboard')}><ArrowLeft size={14}/> Dashboard</button><span className="eyebrow">CRYPTOGRAPHIC INVENTORY</span><h1>Findings explorer</h1><p>Review detected algorithms, code locations, and migration priorities.</p></div><div className="findings-total"><ShieldAlert size={15}/><strong>{findings.length}</strong><span>findings</span></div></div>
    <div className="findings-toolbar"><label className="findings-search"><Search size={15}/><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search algorithm, file, or usage" aria-label="Search findings"/>{query && <button onClick={() => setQuery('')} aria-label="Clear search"><X size={14}/></button>}</label><div className="severity-filters" aria-label="Filter by severity">{filters.map(filter => <button key={filter.value} className={severity === filter.value ? 'active' : ''} onClick={() => setSeverity(filter.value)}>{filter.label}</button>)}</div></div>
    <div className={`findings-layout${selectedFinding ? ' has-selection' : ''}`}>
      <article className="findings-table-card"><div className="findings-table-scroll"><table><thead><tr><th>File & line</th><th>Algorithm / usage</th><th>Quantum status</th><th>Severity</th><th>HNDL</th><th/></tr></thead><tbody>
        {visible.map(finding => <tr key={finding.id} className={selectedFinding?.id === finding.id ? 'selected' : ''} onClick={() => onSelectFinding(finding)} tabIndex={0} onKeyDown={event => { if (event.key === 'Enter') onSelectFinding(finding); }}><td><code>{finding.file_path}:{finding.line_start}</code></td><td><strong>{finding.algorithm}</strong><small>{finding.usage.replace(/_/g, ' ')}</small></td><td><span className="quantum-status">{finding.quantum_status.replace(/_/g, ' ')}</span></td><td><span className={`finding-severity ${finding.severity}`}>{finding.severity.replace('_', ' ')}</span></td><td>{finding.hndl ? <span className="hndl-flag">HNDL</span> : <span className="no-hndl">—</span>}</td><td><ChevronRight size={15}/></td></tr>)}
      </tbody></table>{visible.length === 0 && <div className="findings-empty"><ShieldAlert size={21}/><strong>{findings.length ? 'No matching findings' : 'No findings to display'}</strong><span>{findings.length ? 'Try another search or severity filter.' : 'Run a scan to populate the cryptographic inventory.'}</span>{!findings.length && <button onClick={() => onNavigate('upload')}>Upload an archive <ArrowRight size={14}/></button>}</div>}</div><div className="findings-table-foot"><span>Showing {visible.length} of {findings.length}</span><span>Source locations from the scan</span></div></article>
      {selectedFinding && <aside className="finding-drawer"><div className="drawer-heading"><div><span className="eyebrow">FINDING DETAILS</span><h2>{selectedFinding.algorithm}</h2></div><button onClick={() => onSelectFinding(null)} aria-label="Close details"><X size={16}/></button></div><div className="drawer-location"><code>{selectedFinding.file_path}</code><span>Lines {selectedFinding.line_start}–{selectedFinding.line_end}</span></div><div className="drawer-tags"><span className={`finding-severity ${selectedFinding.severity}`}>{selectedFinding.severity.replace('_', ' ')}</span>{selectedFinding.hndl && <span className="hndl-flag">HNDL exposure</span>}<span>{Math.round(selectedFinding.confidence * 100)}% confidence</span></div><div className="code-heading"><span>CODE SNIPPET</span><span>AST evidence</span></div><pre className="finding-code"><code>{selectedFinding.code_snippet || 'No source snippet was returned for this finding.'}</code></pre><div className="finding-rationale"><div><AlertTriangle size={15}/><strong>Why it matters</strong></div><p>{selectedFinding.evidence || `${selectedFinding.algorithm} is a classical cryptographic primitive that may be vulnerable to future quantum attacks. Review its usage and migration path.`}</p><small>Rule: {selectedFinding.rule_id}</small></div><button className="migration-button" onClick={() => void requestMigration()} disabled={loading}>{loading ? <LoaderCircle size={15} className="spin"/> : <WandSparkles size={15}/>} {loading ? 'Preparing suggestion…' : 'Suggest PQC migration'} <ArrowRight size={14}/></button>{remediationError && <p className="migration-error" role="alert">{remediationError}</p>}{remediation && <div className="remediation-result"><div className="remediation-title"><CheckCircle2 size={15}/><span>{remediation.target_standard} suggestion</span><small>{remediation.provider}</small></div><p>{remediation.explanation}</p><pre><code>{remediation.proposed_diff}</code></pre>{remediation.warnings.length > 0 && <ul>{remediation.warnings.map(warning => <li key={warning}>{warning}</li>)}</ul>}</div>}</aside>}
    </div>
    <footer className="findings-footnote"><span>KEYNOVA <i/> CRYPTOGRAPHIC DISCOVERY</span><span>Findings are tied to the selected scan</span></footer>
  </div></section>;
}
