import React, { useState, useEffect } from 'react';
import {
  ArrowDown,
  ArrowUp,
  ShieldAlert,
  Search,
  X,
  Code2,
  AlertTriangle,
  FileCode,
  CheckCircle2,
  Sparkles,
  GitPullRequest,
  Loader2,
  Info,
  Copy,
  Check
} from 'lucide-react';
import { Finding } from '../types';
import { fetchRemediation, RemediationData } from '../lib/api';

interface FindingsExplorerProps {
  findings: Finding[];
}

export const FindingsExplorer: React.FC<FindingsExplorerProps> = ({ findings }) => {
  const [search, setSearch] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [activeFinding, setActiveFinding] = useState<Finding | null>(findings[0] || null);
  const [activeTab, setActiveTab] = useState<'source' | 'remediation'>('source');
  const [remediation, setRemediation] = useState<RemediationData | null>(null);
  const [remediationError, setRemediationError] = useState<string | null>(null);
  const [isLoadingRemediation, setIsLoadingRemediation] = useState(false);
  const [copiedPatch, setCopiedPatch] = useState(false);
  const [sortBy, setSortBy] = useState<'algorithm' | 'severity' | 'file_path' | 'usage'>('severity');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('asc');
  const [page, setPage] = useState(0);
  const pageSize = 10;

  useEffect(() => {
    if (!activeFinding) return;
    setActiveTab('source');
    setRemediation(null);
    setRemediationError(null);
  }, [activeFinding]);

  useEffect(() => {
    setActiveFinding((selected) => selected && findings.some((finding) => finding.id === selected.id)
      ? selected
      : findings[0] || null);
  }, [findings]);

  const loadRemediation = async () => {
    if (!activeFinding) return;
    setIsLoadingRemediation(true);
    setRemediationError(null);
    try {
      const data = await fetchRemediation(activeFinding.id);
      setRemediation(data);
    } catch (err) {
      console.error('Failed to load remediation:', err);
      setRemediationError(err instanceof Error ? err.message : 'Remediation could not be loaded.');
    } finally {
      setIsLoadingRemediation(false);
    }
  };

  const handleTabChange = (tab: 'source' | 'remediation') => {
    setActiveTab(tab);
    if (tab === 'remediation' && !remediation && !isLoadingRemediation) {
      loadRemediation();
    }
  };

  const handleCopyDiff = (diffText: string) => {
    navigator.clipboard.writeText(diffText);
    setCopiedPatch(true);
    setTimeout(() => setCopiedPatch(false), 2000);
  };

  const filtered = findings.filter((f) => {
    const matchesSearch =
      f.algorithm.toLowerCase().includes(search.toLowerCase()) ||
      f.file_path.toLowerCase().includes(search.toLowerCase()) ||
      f.rule_id.toLowerCase().includes(search.toLowerCase());
    const matchesSev = selectedSeverity === 'all' || f.severity.toLowerCase() === selectedSeverity.toLowerCase();
    return matchesSearch && matchesSev;
  });
  const filteredFindingIds = filtered.map((finding) => finding.id).join('|');
  useEffect(() => {
    if (activeFinding && !filtered.some((finding) => finding.id === activeFinding.id)) {
      setActiveFinding(filtered[0] || null);
    }
  }, [activeFinding?.id, filteredFindingIds]);
  const severityRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, quantum_safe: 4 };
  const sortedFindings = [...filtered].sort((left, right) => {
    const leftValue = sortBy === 'severity' ? severityRank[left.severity] ?? 99 : left[sortBy].toLowerCase();
    const rightValue = sortBy === 'severity' ? severityRank[right.severity] ?? 99 : right[sortBy].toLowerCase();
    const order = typeof leftValue === 'number' && typeof rightValue === 'number'
      ? leftValue - rightValue
      : String(leftValue).localeCompare(String(rightValue));
    return sortDirection === 'asc' ? order : -order;
  });
  const pageCount = Math.max(1, Math.ceil(sortedFindings.length / pageSize));
  const visibleFindings = sortedFindings.slice(page * pageSize, (page + 1) * pageSize);
  const changeSort = (column: typeof sortBy) => {
    setPage(0);
    if (sortBy === column) setSortDirection((direction) => direction === 'asc' ? 'desc' : 'asc');
    else { setSortBy(column); setSortDirection('asc'); }
  };
  const sortLabel = (column: typeof sortBy) => sortBy === column
    ? sortDirection === 'asc' ? <ArrowUp className="inline w-3 h-3 ml-1" /> : <ArrowDown className="inline w-3 h-3 ml-1" />
    : null;

  useEffect(() => setPage(0), [search, selectedSeverity]);

  return (
    <div className="p-6 md:p-8 space-y-5 max-w-7xl mx-auto h-full flex flex-col">
      {/* Header & Search */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 p-5 rounded-2xl bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 shadow-sm">
        <div>
          <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-blue-600 dark:text-blue-400">
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Cryptographic Inventory</span>
          </div>
          <h1 className="text-xl font-bold text-zinc-900 dark:text-zinc-100 font-['Outfit'] mt-1">
            AST Findings & Quantum Vulnerabilities
          </h1>
          <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">
            AST-verified cryptographic invocations, key lengths, and Harvest-Now-Decrypt-Later flags.
          </p>
        </div>

          <div className="flex flex-wrap items-center gap-2.5 w-full md:w-auto">
          {/* Search Input */}
          <div className="relative flex-1 md:w-64">
            <Search className="w-3.5 h-3.5 text-zinc-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search algorithm, file..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Severity Filter */}
          <div className="flex flex-wrap items-center gap-1 bg-zinc-100 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 p-0.5 rounded-lg text-xs">
            {[
              ['all', 'All'],
              ['critical', 'Critical'],
              ['high', 'High'],
              ['medium', 'Medium'],
              ['low', 'Low'],
              ['quantum_safe', 'Quantum safe'],
            ].map(([sev, label]) => (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(sev)}
                className={`px-2.5 py-1 rounded-md text-[11px] font-medium capitalize transition-colors ${
                  selectedSeverity === sev
                    ? 'bg-white dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 shadow-sm font-semibold'
                    : 'text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-200'
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Main Grid: Table (Left) + Drawer (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 flex-1 min-h-0">
        {/* Table View (Left) */}
        <div className={`overflow-hidden rounded-2xl bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 shadow-sm flex flex-col ${activeFinding ? 'lg:col-span-7' : 'lg:col-span-12'}`}>
          <div className="overflow-x-auto flex-1">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-zinc-100 dark:border-zinc-800 bg-zinc-50/70 dark:bg-zinc-950/50 text-[10px] text-zinc-400 font-mono uppercase tracking-wider">
                  <th className="py-3 px-4" aria-sort={sortBy === 'algorithm' ? sortDirection === 'asc' ? 'ascending' : 'descending' : 'none'}><button type="button" onClick={() => changeSort('algorithm')}>Algorithm{sortLabel('algorithm')}</button></th>
                  <th className="py-3 px-4" aria-sort={sortBy === 'severity' ? sortDirection === 'asc' ? 'ascending' : 'descending' : 'none'}><button type="button" onClick={() => changeSort('severity')}>Severity{sortLabel('severity')}</button></th>
                  <th className="py-3 px-4">HNDL Risk</th>
                  <th className="py-3 px-4" aria-sort={sortBy === 'file_path' ? sortDirection === 'asc' ? 'ascending' : 'descending' : 'none'}><button type="button" onClick={() => changeSort('file_path')}>File Location{sortLabel('file_path')}</button></th>
                  <th className="py-3 px-4" aria-sort={sortBy === 'usage' ? sortDirection === 'asc' ? 'ascending' : 'descending' : 'none'}><button type="button" onClick={() => changeSort('usage')}>Usage{sortLabel('usage')}</button></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800 font-sans">
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-12 text-center text-zinc-500 dark:text-zinc-400">
                      No cryptographic findings match the selected criteria.
                    </td>
                  </tr>
                ) : (
                  visibleFindings.map((f) => {
                    const isSelected = activeFinding?.id === f.id;
                    return (
                      <tr
                        key={f.id}
                        onClick={() => setActiveFinding(f)}
                        className={`cursor-pointer transition-colors ${isSelected ? 'finding-row-selected' : ''} ${
                          isSelected
                          ? 'bg-blue-50/70 dark:bg-blue-950/20 border-l-2 border-l-blue-600'
                            : 'hover:bg-zinc-50/80 dark:hover:bg-zinc-800/40'
                        }`}
                      >
                        <td className="py-3 px-4">
                          <div className="font-semibold text-zinc-900 dark:text-zinc-100 flex items-center gap-1.5 font-mono">
                            <Code2 className="w-3.5 h-3.5 text-zinc-400 shrink-0" />
                            <span>{f.algorithm}</span>
                          </div>
                          <div className="text-[10px] text-zinc-400 font-mono mt-0.5">{f.rule_id}</div>
                        </td>

                        <td className="py-3 px-4">
                          <span
                            className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider ${
                              f.severity === 'critical'
                                ? 'bg-red-50 dark:bg-red-950/60 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-900/40'
                                : f.severity === 'high'
                                ? 'bg-orange-50 dark:bg-orange-950/60 text-orange-700 dark:text-orange-400 border border-orange-200 dark:border-orange-900/40'
                                : 'bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400 border border-zinc-200 dark:border-zinc-700'
                            }`}
                          >
                            {f.severity}
                          </span>
                        </td>

                        <td className="py-3 px-4">
                          {f.hndl ? (
                            <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-red-600 dark:text-red-400">
                              <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse"></span>
                              HNDL Exposure
                            </span>
                          ) : (
                            <span className="text-zinc-400 text-[11px]">Standard</span>
                          )}
                        </td>

                        <td className="py-3 px-4">
                          <div className="font-mono text-zinc-700 dark:text-zinc-300 text-[11px] truncate max-w-xs flex items-center gap-1">
                            <FileCode className="w-3 h-3 text-zinc-400 shrink-0" />
                            <span className="truncate">{f.file_path}</span>
                          </div>
                          <span className="text-[10px] text-zinc-400 font-mono">Line {f.line_start}</span>
                        </td>

                        <td className="py-3 px-4 text-zinc-600 dark:text-zinc-400 text-[11px] capitalize font-mono">
                          {f.usage.replace(/_/g, ' ')}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
          <div className="flex items-center justify-between gap-3 border-t border-zinc-100 dark:border-zinc-800 px-4 py-2 text-[11px] text-zinc-500 dark:text-zinc-400">
            <span>{sortedFindings.length ? `${page * pageSize + 1}–${Math.min((page + 1) * pageSize, sortedFindings.length)} of ${sortedFindings.length}` : '0 findings'}</span>
            <div className="flex items-center gap-2">
              <button type="button" className="rounded px-2 py-1 hover:bg-zinc-100 dark:hover:bg-zinc-800 disabled:opacity-40" disabled={page === 0} onClick={() => setPage((value) => Math.max(0, value - 1))}>Previous</button>
              <span>Page {page + 1} of {pageCount}</span>
              <button type="button" className="rounded px-2 py-1 hover:bg-zinc-100 dark:hover:bg-zinc-800 disabled:opacity-40" disabled={page + 1 >= pageCount} onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}>Next</button>
            </div>
          </div>
        </div>

        {/* Detail Drawer (Right) */}
        {activeFinding && (
          <div className="lg:col-span-5 p-5 rounded-2xl bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 shadow-sm flex flex-col justify-between space-y-4 overflow-y-auto">
            <div>
              {/* Header */}
              <div className="flex items-start justify-between pb-3 border-b border-zinc-100 dark:border-zinc-800">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-base font-bold text-zinc-900 dark:text-zinc-100 font-['Outfit']">
                      {activeFinding.algorithm}
                    </span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-300 border border-zinc-200 dark:border-zinc-700">
                      {activeFinding.usage}
                    </span>
                  </div>
                  <p className="text-[11px] text-zinc-500 dark:text-zinc-400 font-mono mt-0.5">
                    {activeFinding.file_path}:{activeFinding.line_start}-{activeFinding.line_end}
                  </p>
                </div>
                <button
                  onClick={() => setActiveFinding(null)}
                  className="p-1 rounded text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-800"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* View Switcher Tabs */}
              <div className="flex items-center gap-2 mt-3 p-1 rounded-xl bg-zinc-100 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 text-xs">
                <button
                  onClick={() => handleTabChange('source')}
                  className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 rounded-lg font-medium transition-colors ${
                    activeTab === 'source'
                      ? 'bg-white dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 shadow-sm font-semibold'
                      : 'text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-200'
                  }`}
                >
                  <Code2 className="w-3.5 h-3.5" />
                  <span>Source Invocation</span>
                </button>
                <button
                  onClick={() => handleTabChange('remediation')}
                  className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 rounded-lg font-medium transition-colors ${
                    activeTab === 'remediation'
                      ? 'bg-white dark:bg-zinc-800 text-blue-600 dark:text-blue-400 shadow-sm font-semibold'
                      : 'text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-200'
                  }`}
                >
                  <Sparkles className="w-3.5 h-3.5 text-blue-500" />
                  <span>PQC Remediation</span>
                </button>
              </div>

              {activeTab === 'source' ? (
                <>
                  {/* Exact Code Snippet */}
                  <div className="mt-3">
                    <div className="flex items-center justify-between text-[11px] text-zinc-500 dark:text-zinc-400 bg-zinc-100 dark:bg-zinc-950 px-3 py-1.5 rounded-t-xl border border-b-0 border-zinc-200 dark:border-zinc-800 font-mono">
                      <span>Syntax AST Block</span>
                      <span>Lines {activeFinding.line_start}-{activeFinding.line_end}</span>
                    </div>
                    <pre className="p-3.5 rounded-b-xl bg-zinc-900 text-zinc-100 font-mono text-xs overflow-x-auto leading-relaxed border border-zinc-800">
                      <code>{activeFinding.code_snippet}</code>
                    </pre>
                  </div>

                  {/* Threat Evidence */}
                  <div className="mt-3 p-3.5 rounded-xl bg-amber-50/70 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-900/50 space-y-1">
                    <div className="text-[10px] font-semibold uppercase tracking-wider text-amber-700 dark:text-amber-400 flex items-center gap-1.5">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      <span>Vulnerability Assessment</span>
                    </div>
                    <p className="text-xs text-zinc-700 dark:text-zinc-300 leading-relaxed">
                      {activeFinding.evidence}
                    </p>
                  </div>

                  {/* Metadata Grid */}
                  <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
                    <div className="p-3 rounded-xl bg-zinc-50 dark:bg-zinc-950/60 border border-zinc-200 dark:border-zinc-800">
                      <div className="text-[10px] text-zinc-500 dark:text-zinc-400 uppercase font-medium">AST Rule</div>
                      <div className="font-mono text-zinc-800 dark:text-zinc-200 text-[11px] mt-0.5 truncate">
                        {activeFinding.rule_id}
                      </div>
                    </div>
                    <div className="p-3 rounded-xl bg-zinc-50 dark:bg-zinc-950/60 border border-zinc-200 dark:border-zinc-800">
                      <div className="text-[10px] text-zinc-500 dark:text-zinc-400 uppercase font-medium">Quantum Status</div>
                      <div className="text-red-600 dark:text-red-400 font-semibold uppercase text-[11px] mt-0.5">
                        {activeFinding.quantum_status}
                      </div>
                    </div>
                  </div>
                </>
              ) : (
                /* Remediation View */
                <div className="mt-3 space-y-3">
                  {isLoadingRemediation ? (
                    <div className="flex flex-col items-center justify-center p-8 space-y-2 text-zinc-400">
                      <Loader2 className="w-5 h-5 animate-spin text-blue-500" />
                      <span className="text-xs">Generating quantum-safe code migration...</span>
                    </div>
                  ) : remediation ? (
                    <>
                      {/* Target Standard Banner */}
                      <div className="p-3.5 rounded-xl bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-900/50 space-y-1">
                        <div className="text-[10px] font-bold uppercase tracking-wider text-emerald-700 dark:text-emerald-400 flex items-center gap-1.5">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Recommended Standard: {remediation.target_standard}</span>
                        </div>
                        <p className="text-xs text-zinc-700 dark:text-zinc-300 leading-relaxed">
                          {remediation.explanation}
                        </p>
                      </div>

                      {/* Proposed Unified Diff */}
                      <div>
                        <div className="flex items-center justify-between text-[11px] text-zinc-500 dark:text-zinc-400 bg-zinc-100 dark:bg-zinc-950 px-3 py-1.5 rounded-t-xl border border-b-0 border-zinc-200 dark:border-zinc-800 font-mono">
                          <span className="flex items-center gap-1">
                            <GitPullRequest className="w-3.5 h-3.5 text-blue-500" />
                            Unified Migration Diff
                          </span>
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] uppercase font-bold text-amber-500">
                              Effort: {remediation.migration_effort}
                            </span>
                            <button
                              onClick={() => handleCopyDiff(remediation.proposed_diff)}
                              className="px-2 py-0.5 rounded bg-zinc-200 dark:bg-zinc-800 hover:bg-zinc-300 dark:hover:bg-zinc-700 text-zinc-800 dark:text-zinc-200 text-[10px] flex items-center gap-1 transition-colors"
                            >
                              {copiedPatch ? (
                                <>
                                  <Check className="w-3 h-3 text-emerald-500" />
                                  <span>Copied</span>
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3 h-3" />
                                  <span>Copy</span>
                                </>
                              )}
                            </button>
                          </div>
                        </div>
                        <pre className="p-3.5 rounded-b-xl bg-zinc-950 text-zinc-200 font-mono text-[11px] overflow-x-auto leading-relaxed border border-zinc-800 max-h-56">
                          <code>{remediation.proposed_diff}</code>
                        </pre>
                      </div>

                      {/* Warnings / Caveats */}
                      {remediation.warnings && remediation.warnings.length > 0 && (
                        <div className="p-3 rounded-xl bg-zinc-50 dark:bg-zinc-950/60 border border-zinc-200 dark:border-zinc-800 space-y-1.5 text-xs text-zinc-600 dark:text-zinc-400">
                          <div className="text-[10px] font-semibold uppercase text-zinc-500 flex items-center gap-1">
                            <Info className="w-3 h-3 text-blue-500" />
                            <span>Architecture Migration Notes</span>
                          </div>
                          <ul className="list-disc pl-4 space-y-1 text-[11px]">
                            {remediation.warnings.map((w, idx) => (
                              <li key={idx}>{w}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </>
                  ) : (
                    <div className="p-6 text-center">
                      {remediationError && <p role="alert" className="mb-3 text-xs text-red-600 dark:text-red-400">{remediationError}</p>}
                      <button
                        onClick={loadRemediation}
                        className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-sm transition-all inline-flex items-center gap-1.5"
                      >
                        <Sparkles className="w-3.5 h-3.5" />
                        Generate FIPS 203/204 Remediation
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="p-3 rounded-xl bg-zinc-50 dark:bg-zinc-950/80 border border-zinc-200 dark:border-zinc-800 text-[11px] text-zinc-500 dark:text-zinc-400 flex items-center gap-2">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
              <span>Deterministic Python AST parser certitude: {Math.round(activeFinding.confidence * 100)}%</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
