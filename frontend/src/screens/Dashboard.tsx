import React from 'react';
import {
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  Check,
  ChevronRight,
  CircleAlert,
  Clock3,
  Download,
  FileCode2,
  FileText,
  Fingerprint,
  LockKeyhole,
  ShieldCheck,
  Upload,
  Zap,
} from 'lucide-react';
import type { Finding, ScanStatus } from '../types';
import { getCbomExportUrl, getPdfExportUrl } from '../lib/api';

interface DashboardProps {
  scan: ScanStatus | null;
  findings: Finding[];
  isDemo?: boolean;
  onOpenFinding: (finding: Finding) => void;
  onNavigate: (screen: string) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({
  scan,
  findings,
  isDemo = false,
  onOpenFinding,
  onNavigate,
}) => {
  if (!scan) {
    return (
      <section className="dashboard-page">
        <div className="workspace-content">
          <div className="new-page-heading">
            <div>
              <span className="eyebrow">SECURITY POSTURE</span>
              <h1>Readiness overview</h1>
            </div>
          </div>
          <div className="empty-state-card">
            <div className="empty-state-icon">
              <FileCode2 />
            </div>
            <h2>Start with a repository scan</h2>
            <p>
              Map the cryptography in your codebase and understand what needs to change for a post-quantum future.
            </p>
            <button className="scan-button" onClick={() => onNavigate('upload')}>
              <Upload size={15} /> Start a scan
            </button>
          </div>
        </div>
      </section>
    );
  }

  const score = scan.readiness_score;
  const severityRank: Record<Finding['severity'], number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    quantum_safe: 4,
  };
  const risk = score >= 80 ? 'Quantum Ready' : score >= 50 ? 'Needs Modernization' : 'Critical Exposure';
  const riskClass = score >= 80 ? 'calm' : score >= 50 ? 'watch' : 'alert';
  const priority = [...findings].sort((a, b) => severityRank[a.severity] - severityRank[b.severity]);
  const stages = [
    { label: 'Inventory', detail: `${scan.scanned_files} files inspected`, complete: scan.coverage_percent >= 100, icon: FileCode2 },
    { label: 'Assess exposure', detail: `${findings.length} cryptographic findings`, complete: true, icon: Fingerprint },
    { label: 'Plan migration', detail: 'Review priority algorithms', complete: score >= 80, icon: Zap },
  ];

  return (
    <section className="dashboard-page">
      <div className="workspace-content">
        <div className="new-page-heading">
          <div>
            <span className="eyebrow">
              SECURITY POSTURE <i /> {scan.status.toUpperCase()}
            </span>
            <h1>Readiness overview</h1>
            <p>A deterministic assessment of your post-quantum cryptographic readiness.</p>
          </div>
          <div className="flex items-center gap-2">
            <a
              href={getCbomExportUrl(scan.id)}
              download={`Keynova_CBOM_${scan.id.slice(0, 8)}.json`}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 text-zinc-700 dark:text-zinc-200 hover:bg-zinc-50 dark:hover:bg-zinc-800 transition-colors shadow-sm"
              title="Download CycloneDX Cryptographic Bill of Materials"
            >
              <Download size={14} />
              <span>CycloneDX CBOM</span>
            </a>
            <a
              href={getPdfExportUrl(scan.id)}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 text-zinc-700 dark:text-zinc-200 hover:bg-zinc-50 dark:hover:bg-zinc-800 transition-colors shadow-sm"
              title="Download Executive PDF Audit Report"
            >
              <FileText size={14} />
              <span>Executive PDF</span>
            </a>
            <button className="text-action ml-2" onClick={() => onNavigate('verification')}>
              <Clock3 size={15} /> Verification <ArrowRight size={14} />
            </button>
          </div>
        </div>

        {isDemo && (
          <div className="p-3 mb-4 rounded-xl border border-amber-200 dark:border-amber-900/50 bg-amber-50/50 dark:bg-amber-950/20 text-xs text-amber-700 dark:text-amber-400 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-amber-500 animate-pulse" />
            <span>Preview Mode · Connect a live scan to view active AST results.</span>
          </div>
        )}

        <div className="overview-grid">
          <article className="posture-card interactive-surface">
            <div className="posture-topline">
              <span className="eyebrow">POST-QUANTUM READINESS INDEX (R)</span>
              <button className="round-arrow" onClick={() => onNavigate('verification')} aria-label="View verification">
                <ArrowUpRight size={17} />
              </button>
            </div>
            <div className="posture-score-row">
              <div>
                <span className={`status-label ${riskClass}`}>
                  <i />
                  {risk}
                </span>
                <div className="score-number">
                  {score}
                  <small>/100</small>
                </div>
              </div>
              <div
                className="score-orbit"
                style={{ '--score': `${score * 3.6}deg` } as React.CSSProperties}
              >
                <div>
                  <ShieldCheck size={28} />
                </div>
              </div>
            </div>
            <div className="score-track">
              <i style={{ width: `${score}%` }} />
            </div>
            <div className="posture-foot">
              <span>Readiness Formula: R = 100 - [Penalties] · C</span>
              <span>{score < 50 ? 'Immediate Attention Required' : score >= 80 ? 'Quantum Resilient' : 'Migration Recommended'}</span>
            </div>
          </article>

          <div className="signal-column">
            <article className="signal-card">
              <span className="signal-icon subdued-red">
                <CircleAlert size={18} />
              </span>
              <div>
                <small>PRIORITY FINDINGS</small>
                <strong>{findings.length.toString().padStart(2, '0')}</strong>
                <span>
                  {scan.severity_counts.critical} critical · {scan.severity_counts.high} high risk
                </span>
              </div>
              <button onClick={() => onNavigate('findings')} aria-label="Explore findings">
                <ArrowUpRight size={16} />
              </button>
            </article>

            <article className="signal-card">
              <span className="signal-icon subdued-sand">
                <FileCode2 size={18} />
              </span>
              <div>
                <small>CODE COVERAGE (C)</small>
                <strong>
                  {Math.round(scan.coverage_percent)}
                  <em>%</em>
                </strong>
                <span>
                  {scan.scanned_files} of {scan.total_files} files analyzed
                </span>
              </div>
              <span className="mini-bars">
                {[35, 54, 46, 74, 60, 92, Math.max(20, scan.coverage_percent)].map((h, i) => (
                  <i key={i} style={{ height: `${h}%` }} />
                ))}
              </span>
            </article>

            <article className="signal-card">
              <span className="signal-icon subdued-gray">
                <LockKeyhole size={18} />
              </span>
              <div>
                <small>HNDL EXPOSURE</small>
                <strong>{scan.hndl_count.toString().padStart(2, '0')}</strong>
                <span>Harvest-Now-Decrypt-Later alerts</span>
              </div>
              <button onClick={() => onNavigate('findings')} aria-label="Explore HNDL findings">
                <ArrowUpRight size={16} />
              </button>
            </article>
          </div>
        </div>

        <div className="dashboard-lower-grid">
          <article className="next-steps-card">
            <div className="section-heading">
              <div>
                <span className="eyebrow">STANDARDS ALIGNMENT</span>
                <h2>Migration Path</h2>
              </div>
              <span className="step-count">01 / 03</span>
            </div>
            <div className="steps-list">
              {stages.map(({ label, detail, complete, icon: Icon }, i) => (
                <div className={`step-row ${complete ? 'done' : ''}`} key={label}>
                  <span className="step-index">{complete ? <Check size={14} /> : `0${i + 1}`}</span>
                  <span className="step-icon">
                    <Icon size={16} />
                  </span>
                  <div className="step-copy">
                    <strong>{label}</strong>
                    <small>{detail}</small>
                  </div>
                  <ChevronRight size={15} />
                </div>
              ))}
            </div>
            <button className="text-action mt-4" onClick={() => onNavigate('verification')}>
              Review verification delta <ArrowRight size={14} />
            </button>
          </article>

          <article className="priority-card">
            <div className="section-heading">
              <div>
                <span className="eyebrow">REVIEW QUEUE</span>
                <h2>Detected Cryptography</h2>
              </div>
              <button className="text-action compact" onClick={() => onNavigate('findings')}>
                All findings <ArrowRight size={14} />
              </button>
            </div>
            {priority.length ? (
              <div className="priority-list">
                {priority.slice(0, 4).map((finding, i) => (
                  <button
                    className="priority-item"
                    key={finding.id}
                    onClick={() => {
                      onOpenFinding(finding);
                      onNavigate('findings');
                    }}
                  >
                    <span className={`priority-rank rank-${finding.severity}`}>0{i + 1}</span>
                    <span className="priority-info">
                      <strong>{finding.algorithm}</strong>
                      <small>
                        <code>
                          {finding.file_path}:{finding.line_start}
                        </code>
                        <i /> {finding.usage.replace(/_/g, ' ')}
                      </small>
                    </span>
                    <span className={`severity-tag ${finding.severity}`}>{finding.severity}</span>
                    <ArrowUpRight size={15} />
                  </button>
                ))}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center p-8 text-center text-emerald-600 dark:text-emerald-400">
                <ShieldCheck size={28} />
                <span className="text-xs font-semibold mt-2">Zero cryptographic debt detected!</span>
              </div>
            )}
            <div className="flex items-center justify-between pt-3 mt-3 border-t border-zinc-100 dark:border-zinc-800 text-[11px] text-zinc-400">
              <span className="flex items-center gap-1.5">
                <span className="project-status-dot" />
                Scan: {scan.status}
              </span>
              <span>{scan.archive_name || 'Active repository'}</span>
              <ArrowDownRight size={14} />
            </div>
          </article>
        </div>

        <footer className="dashboard-footnote">
          <span>KEYNOVA · AUTONOMOUS PQC READINESS PLATFORM</span>
          <span>NIST Standards: FIPS 203 (ML-KEM) · FIPS 204 (ML-DSA)</span>
        </footer>
      </div>
    </section>
  );
};
