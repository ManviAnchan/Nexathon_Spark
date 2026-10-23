import React, { useEffect } from 'react';
import confetti from 'canvas-confetti';
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
  onOpenFinding: (finding: Finding) => void;
  onNavigate: (screen: string) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({
  scan,
  findings,
  onOpenFinding,
  onNavigate,
}) => {
  useEffect(() => {
    if (!scan || scan.readiness_score < 100) return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const celebrationKey = `keynova-score-celebrated:${scan.id}`;
    if (sessionStorage.getItem(celebrationKey)) return;
    sessionStorage.setItem(celebrationKey, 'true');
    confetti({
      particleCount: 48,
      spread: 42,
      startVelocity: 22,
      gravity: 0.85,
      scalar: 0.7,
      origin: { y: 0.72 },
      colors: ['#8b806d', '#a0ad96', '#c3b38c'],
      disableForReducedMotion: true,
    });
  }, [scan?.id, scan?.readiness_score]);

  if (!scan) {
    return (
      <section className="dashboard-page">
        <div className="workspace-content">
          <div className="new-page-heading">
            <div>
              <span className="eyebrow">SECURITY POSTURE</span>
              <h1>Readiness overview</h1>
              <p>A deterministic assessment of your post-quantum cryptographic readiness.</p>
            </div>
            <div className="heading-actions">
              <button className="scan-button" onClick={() => onNavigate('upload')}><Upload size={15} /> New scan</button>
              <button className="heading-action verification-action" onClick={() => onNavigate('verification')}><Clock3 size={15} /> Verification <ArrowRight size={14} /></button>
            </div>
          </div>

          <div className="overview-grid">
            <article className="posture-card">
              <div className="posture-topline">
                <span className="eyebrow">POST-QUANTUM READINESS INDEX (R)</span>
                <button className="round-arrow" onClick={() => onNavigate('verification')} aria-label="View verification"><ArrowUpRight size={17} /></button>
              </div>
              <div className="posture-score-row">
                <div className="score-number"><small>/100</small></div>
                <div className="score-orbit" style={{ '--score': '0deg' } as React.CSSProperties}><div><ShieldCheck size={28} /></div></div>
              </div>
              <div className="score-track"><i style={{ width: '0%' }} /></div>
              <div className="posture-foot"><span>Readiness Formula</span><span /></div>
            </article>

            <div className="signal-column">
              {[
                { label: 'PRIORITY FINDINGS', icon: CircleAlert, tone: 'subdued-red' },
                { label: 'CODE COVERAGE (C)', icon: FileCode2, tone: 'subdued-sand' },
                { label: 'HNDL EXPOSURE', icon: LockKeyhole, tone: 'subdued-gray' },
              ].map(({ label, icon: Icon, tone }) => (
                <article className="signal-card" key={label}>
                  <span className={`signal-icon ${tone}`}><Icon size={18} /></span>
                  <div className="signal-copy"><small>{label}</small><strong>&nbsp;</strong><span>&nbsp;</span></div>
                  <ArrowUpRight className="signal-arrow" size={16} />
                </article>
              ))}
            </div>
          </div>

          <div className="dashboard-lower-grid">
            <section className="next-steps-card">
              <div className="section-heading"><div><span className="eyebrow">STANDARDS ALIGNMENT</span><h2>Migration Path</h2></div></div>
              <div className="steps-list">
                {[FileCode2, Fingerprint, Zap].map((Icon, index) => (
                  <div className="step-row" key={index}>
                    <span className="step-index">{`0${index + 1}`}</span><span className="step-icon"><Icon size={16} /></span><span className="step-copy"><strong>&nbsp;</strong><small>&nbsp;</small></span><ChevronRight size={15} />
                  </div>
                ))}
              </div>
            </section>
            <section className="priority-card">
              <div className="section-heading"><div><span className="eyebrow">REVIEW QUEUE</span><h2>Detected Cryptography</h2></div><button className="text-action" onClick={() => onNavigate('findings')}>All findings <ArrowRight size={14} /></button></div>
              <div className="priority-list" />
            </section>
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
    {
      label: 'Plan migration',
      detail: findings.length ? 'Review priority algorithms' : 'No priority algorithms detected',
      complete: findings.length === 0,
      icon: Zap,
    },
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
          <div className="heading-actions">
            <a
              href={getCbomExportUrl(scan.id)}
              download={`Keynova_CBOM_${scan.id.slice(0, 8)}.json`}
              className="heading-action"
              title="Download CycloneDX Cryptographic Bill of Materials"
            >
              <Download size={14} />
              <span>CycloneDX CBOM</span>
            </a>
            <a
              href={getPdfExportUrl(scan.id)}
              target="_blank"
              rel="noopener noreferrer"
              className="heading-action"
              title="Download Executive PDF Audit Report"
            >
              <FileText size={14} />
              <span>Executive PDF</span>
            </a>
            <button className="heading-action verification-action" onClick={() => onNavigate('verification')}>
              <Clock3 size={15} /> Verification <ArrowRight size={14} />
            </button>
          </div>
        </div>

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
            <button className="signal-card signal-card-button" type="button" onClick={() => onNavigate('findings')} aria-label="Explore priority findings">
              <span className="signal-icon subdued-red">
                <CircleAlert size={18} />
              </span>
              <span className="signal-copy">
                <small>PRIORITY FINDINGS</small>
                <strong>{findings.length.toString().padStart(2, '0')}</strong>
                <span>
                  {scan.severity_counts.critical} critical · {scan.severity_counts.high} high risk
                </span>
              </span>
              <ArrowUpRight className="signal-arrow" size={16} />
            </button>

            <article className="signal-card">
              <span className="signal-icon subdued-sand">
                <FileCode2 size={18} />
              </span>
              <div className="signal-copy">
                <small>CODE COVERAGE (C)</small>
                <strong>
                  {Math.round(scan.coverage_percent)}
                  <em>%</em>
                </strong>
                <span>
                  {scan.scanned_files} of {scan.total_files} files analyzed
                </span>
              </div>
              <span
                className="coverage-meter"
                role="meter"
                aria-label="Code coverage"
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={Math.max(0, Math.min(100, scan.coverage_percent))}
              >
                <i style={{ width: `${Math.max(0, Math.min(100, scan.coverage_percent))}%` }} />
              </span>
            </article>

            <button className="signal-card signal-card-button" type="button" onClick={() => onNavigate('findings')} aria-label="Explore HNDL findings">
              <span className="signal-icon subdued-gray">
                <LockKeyhole size={18} />
              </span>
              <span className="signal-copy">
                <small>HNDL EXPOSURE</small>
                <strong>{scan.hndl_count.toString().padStart(2, '0')}</strong>
                <span>Harvest-Now-Decrypt-Later alerts</span>
              </span>
              <ArrowUpRight className="signal-arrow" size={16} />
            </button>
          </div>
        </div>

        <div className="dashboard-lower-grid">
          <article className="next-steps-card">
            <div className="section-heading">
              <div>
                <span className="eyebrow">STANDARDS ALIGNMENT</span>
                <h2>Migration Path</h2>
              </div>
              <span className="step-count">{String(stages.filter((stage) => stage.complete).length).padStart(2, '0')} / {String(stages.length).padStart(2, '0')}</span>
            </div>
            <div className="steps-list">
              {stages.map(({ label, detail, complete, icon: Icon }, i) => (
                <button
                  className={`step-row ${complete ? 'done' : ''}`}
                  type="button"
                  key={label}
                  onClick={() => onNavigate(i === 2 ? 'verification' : 'findings')}
                  aria-label={`${label}: ${detail}`}
                >
                  <span className="step-index">{complete ? <Check size={14} /> : `0${i + 1}`}</span>
                  <span className="step-icon">
                    <Icon size={16} />
                  </span>
                  <div className="step-copy">
                    <strong>{label}</strong>
                    <small>{detail}</small>
                  </div>
                  <ChevronRight size={15} />
                </button>
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
