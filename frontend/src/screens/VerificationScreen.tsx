import React, { useEffect, useState } from 'react';
import { ArrowRight, GitCompare, RefreshCw } from 'lucide-react';
import { ScanComparison, ScanStatus } from '../types';
import { fetchScanDiff } from '../lib/api';

interface VerificationScreenProps {
  currentScan: ScanStatus | null;
  baselineScan: ScanStatus | null;
  availableScans: ScanStatus[];
  onSelectBaseline: (scanId: string) => void;
  onTriggerRescan: () => void;
}

export const VerificationScreen: React.FC<VerificationScreenProps> = ({
  currentScan,
  baselineScan,
  availableScans,
  onSelectBaseline,
  onTriggerRescan,
}) => {
  const [comparison, setComparison] = useState<ScanComparison | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setComparison(null);
    setError(null);
    setIsLoading(false);
    if (!currentScan || !baselineScan || currentScan.id === baselineScan.id) return;

    setIsLoading(true);
    fetchScanDiff(currentScan.id, baselineScan.id)
      .then((result) => { if (!cancelled) setComparison(result); })
      .catch((reason: unknown) => {
        if (!cancelled) setError(reason instanceof Error ? reason.message : 'Comparison could not be loaded.');
      })
      .finally(() => { if (!cancelled) setIsLoading(false); });

    return () => { cancelled = true; };
  }, [currentScan?.id, baselineScan?.id]);

  const cardClass = 'p-5 rounded-xl bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800';
  const title = (finding: Record<string, unknown>) => String(finding.algorithm || finding.fingerprint || 'Finding');

  if (!currentScan) {
    return (
      <div className="p-6 md:p-8 space-y-5 max-w-7xl mx-auto">
        <header className={`${cardClass} flex flex-col md:flex-row md:items-center justify-between gap-4`}>
          <div>
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400"><GitCompare className="w-4 h-4" /> Scan comparison</div>
            <h1 className="text-xl font-semibold text-zinc-900 dark:text-zinc-100 mt-1">Verification</h1>
            <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">Before & after comparison</p>
          </div>
          <button onClick={onTriggerRescan} className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-zinc-900 dark:bg-zinc-100 text-white dark:text-zinc-900 text-xs font-medium"><RefreshCw className="w-3.5 h-3.5" /> Upload archive</button>
        </header>
        <section className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {['Previous readiness score', 'Readiness change', 'Current readiness score'].map((label) => <div className={cardClass} key={label}><div className="text-xs text-zinc-500">{label}</div><div className="h-9 mt-2" /></div>)}
        </section>
        <section className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {['Resolved', 'Added', 'Unchanged'].map((label) => <div className={cardClass} key={label}><div className="text-xs text-zinc-500">{label}</div><div className="h-8 mt-2" /></div>)}
        </section>
        <section className={cardClass}><h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 mb-3">Resolved findings</h2><div className="h-20" /><h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 mt-5 mb-3">Added findings</h2><div className="h-20" /></section>
      </div>
    );
  }

  return (
    <div className="p-6 md:p-8 space-y-5 max-w-7xl mx-auto">
      <header className={`${cardClass} flex flex-col md:flex-row md:items-center justify-between gap-4`}>
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
            <GitCompare className="w-4 h-4" /> Scan comparison
          </div>
          <h1 className="text-xl font-semibold text-zinc-900 dark:text-zinc-100 mt-1">Verification</h1>
          <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
            {baselineScan
              ? `${baselineScan.archive_name || 'Previous upload'} compared with ${currentScan.archive_name || 'Current upload'}`
              : `${currentScan.archive_name || 'Uploaded archive'} is ready for comparison after another upload.`}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {availableScans.filter((scan) => scan.id !== currentScan.id).length > 0 && (
            <label className="flex items-center gap-2 text-xs text-zinc-500 dark:text-zinc-400">
              Compare against
              <select
                aria-label="Baseline scan"
                value={baselineScan?.id || ''}
                onChange={(event) => onSelectBaseline(event.target.value)}
                className="max-w-56 rounded-lg border border-zinc-200 bg-white px-2.5 py-2 text-xs text-zinc-800 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-200"
              >
                <option value="" disabled>Select a previous scan</option>
                {availableScans.filter((scan) => scan.id !== currentScan.id).map((scan) => (
                  <option value={scan.id} key={scan.id}>
                    {scan.archive_name || 'Uploaded archive'} · {new Date(scan.created_at).toLocaleDateString()}
                  </option>
                ))}
              </select>
            </label>
          )}
          <button onClick={onTriggerRescan} className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-zinc-900 dark:bg-zinc-100 text-white dark:text-zinc-900 text-xs font-medium">
            <RefreshCw className="w-3.5 h-3.5" /> Upload another archive
          </button>
        </div>
      </header>

      {!baselineScan || baselineScan.id === currentScan.id ? (
        <div className={cardClass}>
          <p className="text-sm text-zinc-500 dark:text-zinc-400">A second uploaded archive is needed to calculate a scan comparison.</p>
        </div>
      ) : isLoading ? (
        <div className={cardClass}><p className="text-sm text-zinc-500 dark:text-zinc-400">Loading comparison…</p></div>
      ) : error ? (
        <div className={cardClass}><p className="text-sm text-red-600 dark:text-red-400">{error}</p></div>
      ) : comparison ? (
        <>
          <section className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className={cardClass}>
              <div className="text-xs text-zinc-500">Previous readiness score</div>
              <div className="text-3xl font-semibold mt-2 text-zinc-900 dark:text-zinc-100">{baselineScan.readiness_score}</div>
            </div>
            <div className={`${cardClass} flex flex-col justify-center`}>
              <div className="text-xs text-zinc-500">Readiness change</div>
              <div className="flex items-center gap-2 text-2xl font-semibold mt-2 text-zinc-900 dark:text-zinc-100">
                {comparison.readiness_delta > 0 ? '+' : ''}{comparison.readiness_delta}<ArrowRight className="w-5 h-5" />
              </div>
            </div>
            <div className={cardClass}>
              <div className="text-xs text-zinc-500">Current readiness score</div>
              <div className="text-3xl font-semibold mt-2 text-zinc-900 dark:text-zinc-100">{currentScan.readiness_score}</div>
            </div>
          </section>

          <section className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {[
              ['Resolved', comparison.resolved_count],
              ['Added', comparison.added_count],
              ['Unchanged', comparison.unchanged_count],
            ].map(([label, count]) => (
              <div className={cardClass} key={label}>
                <div className="text-xs text-zinc-500">{label}</div>
                <div className="text-2xl font-semibold mt-2 text-zinc-900 dark:text-zinc-100">{count}</div>
              </div>
            ))}
          </section>

          <section className={cardClass}>
            <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 mb-3">Resolved findings</h2>
            {comparison.resolved_findings.length ? (
              <ul className="divide-y divide-zinc-100 dark:divide-zinc-800">
                {comparison.resolved_findings.map((finding, index) => (
                  <li className="py-3 text-xs text-zinc-700 dark:text-zinc-300" key={`${String(finding.fingerprint)}-${index}`}>
                    <span className="font-medium">{title(finding)}</span>
                    {finding.file_path ? <span className="ml-2 text-zinc-500">{String(finding.file_path)}</span> : null}
                  </li>
                ))}
              </ul>
            ) : <p className="text-xs text-zinc-500">No findings were resolved between these uploads.</p>}
            <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 mt-5 mb-3">Added findings</h2>
            {comparison.added_findings.length ? (
              <ul className="divide-y divide-zinc-100 dark:divide-zinc-800">
                {comparison.added_findings.map((finding, index) => (
                  <li className="py-3 text-xs text-zinc-700 dark:text-zinc-300" key={`${String(finding.fingerprint)}-${index}`}>
                    <span className="font-medium">{title(finding)}</span>
                    {finding.file_path ? <span className="ml-2 text-zinc-500">{String(finding.file_path)}</span> : null}
                  </li>
                ))}
              </ul>
            ) : <p className="text-xs text-zinc-500">No findings were added between these uploads.</p>}
          </section>
        </>
      ) : null}
    </div>
  );
};
