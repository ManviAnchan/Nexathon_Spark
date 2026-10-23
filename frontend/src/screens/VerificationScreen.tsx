import { useEffect, useState } from 'react';
import { ArrowDown, ArrowRight, CheckCircle2, FileCode2, GitCompareArrows, RefreshCw, ShieldAlert, TrendingUp } from 'lucide-react';
import { fetchScanDiff } from '../lib/api';
import type { Finding, ScanComparison, ScanStatus } from '../types';

interface VerificationScreenProps { currentScan: ScanStatus | null; baselineScan: ScanStatus | null; onTriggerRescan: () => void; }
export function VerificationScreen({ currentScan, baselineScan, onTriggerRescan }: VerificationScreenProps) {
  const [comparison, setComparison] = useState<ScanComparison | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    let live = true;
    setComparison(null); setError('');
    if (!currentScan || !baselineScan || currentScan.id === baselineScan.id) return () => { live = false; };
    setLoading(true);
    void fetchScanDiff(currentScan.id, baselineScan.id).then(result => { if (live) setComparison(result); }).catch(cause => { if (live) setError(cause instanceof Error ? cause.message : 'The scan comparison could not be loaded.'); }).finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
  }, [currentScan?.id, baselineScan?.id]);

  const hasPair = Boolean(currentScan && baselineScan && currentScan.id !== baselineScan.id);
  const delta = hasPair ? currentScan!.readiness_score - baselineScan!.readiness_score : 0;
  const resolved: Finding[] = comparison?.resolved_findings ?? [];
  const added: Finding[] = comparison?.added_findings ?? [];
  const verified = comparison?.verification_status?.toLowerCase().includes('verified') || (comparison?.resolved_count ?? 0) > 0 && (comparison?.added_count ?? 0) === 0;

  return <section className="verification-page"><div className="verification-content"><div className="verification-heading"><div><span className="eyebrow"><GitCompareArrows size={13}/> SCAN COMPARISON</span><h1>Before & after verification</h1><p>Compare scan results to see what changed after a migration.</p></div><button className="verification-rescan" onClick={onTriggerRescan}><RefreshCw size={14}/> Upload comparison scan</button></div>
    {!hasPair ? <div className="verification-empty"><div><GitCompareArrows size={25}/></div><strong>Choose two scans to verify a migration</strong><p>Run an initial scan, then upload a second build. Keynova will compare the findings and readiness scores.</p><button onClick={onTriggerRescan}>Upload a scan <ArrowRight size={14}/></button></div> : <>
      <div className="comparison-card"><div className="comparison-side baseline"><span>BASELINE</span><strong>{baselineScan!.readiness_score}<small>/100</small></strong><p>{baselineScan!.archive_name || 'Earlier scan'}</p><small>{baselineScan!.scanned_files} of {baselineScan!.total_files} files scanned</small></div><div className="comparison-change"><div className={`delta-pill ${delta >= 0 ? 'improved' : 'regressed'}`}>{delta >= 0 ? <TrendingUp size={14}/> : <ArrowDown size={14}/>} {delta > 0 ? '+' : ''}{delta} points</div><span>Readiness change</span><div className="comparison-arrow"><ArrowRight size={18}/></div></div><div className="comparison-side target"><span>AFTER</span><strong>{currentScan!.readiness_score}<small>/100</small></strong><p>{currentScan!.archive_name || 'Current scan'}</p><small>{currentScan!.scanned_files} of {currentScan!.total_files} files scanned</small></div></div>
      <div className="verification-metrics"><article><span>RESOLVED</span><strong>{comparison?.resolved_count ?? '—'}</strong><small>Prior findings absent from the new scan</small></article><article><span>NEW FINDINGS</span><strong>{comparison?.added_count ?? '—'}</strong><small>Potential regressions to review</small></article><article><span>UNCHANGED</span><strong>{comparison?.unchanged_count ?? '—'}</strong><small>Findings present in both scans</small></article><article className={verified ? 'verified' : ''}><span>COMPARISON STATUS</span><strong>{loading ? 'Loading…' : verified ? 'Improved' : comparison ? 'Review results' : 'Pending'}</strong><small>{verified ? 'No new findings were reported' : 'Review the changes below'}</small></article></div>
      {loading && <div className="verification-loading">Comparing scan fingerprints…</div>}{error && <div className="verification-error" role="alert">{error}</div>}
      <div className="comparison-findings"><article className="change-list"><header><CheckCircle2 size={15}/><div><strong>Resolved findings</strong><small>Present in baseline, absent from current scan</small></div><b>{resolved.length}</b></header>{resolved.length ? resolved.map(finding => <FindingChange key={finding.id} finding={finding} kind="resolved"/>) : <p className="change-empty">No resolved findings in this comparison.</p>}</article><article className="change-list added"><header><ShieldAlert size={15}/><div><strong>New findings</strong><small>Newly present in current scan</small></div><b>{added.length}</b></header>{added.length ? added.map(finding => <FindingChange key={finding.id} finding={finding} kind="added"/>) : <p className="change-empty">No new findings in this comparison.</p>}</article></div>
      <p className="diff-note"><FileCode2 size={14}/> Comparison is based on finding fingerprints. Source-code diffs are not included in the scan response.</p>
    </>}
    <footer className="verification-foot"><span>KEYNOVA <i/> MIGRATION VERIFICATION</span><span>Evidence from scan comparison</span></footer></div></section>;
}
function FindingChange({ finding, kind }: { finding: Finding; kind: 'resolved' | 'added' }) {
  return <div className="change-item"><div className="change-item-top"><strong>{finding.algorithm}</strong><span className={`finding-severity ${finding.severity}`}>{finding.severity.replace('_', ' ')}</span></div><code>{finding.file_path}:{finding.line_start}</code><p>{finding.code_snippet || finding.evidence || 'No code excerpt was included in the finding.'}</p><small className={kind}>{kind === 'resolved' ? 'Removed from current scan' : 'Introduced in current scan'}</small></div>;
}
