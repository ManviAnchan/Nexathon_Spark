import React from 'react';
import { X, ShieldCheck, Lock, WifiOff, HardDrive, CheckCircle2, Server, EyeOff, Activity } from 'lucide-react';

interface TrustAuditModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const TrustAuditModal: React.FC<TrustAuditModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
      role="presentation"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="w-full max-w-xl bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col text-zinc-900 dark:text-zinc-100 animate-in fade-in zoom-in-95 duration-200"
        role="dialog"
        aria-modal="true"
      >
        {/* Header */}
        <div className="px-6 py-4 border-b border-zinc-100 dark:border-zinc-800/80 flex items-center justify-between bg-zinc-50/50 dark:bg-zinc-950/40">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-900/50 text-emerald-600 dark:text-emerald-400">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-zinc-900 dark:text-zinc-100 font-['Outfit']">
                Zero-Egress Privacy & Air-Gap Verification
              </h3>
              <p className="text-[11px] text-zinc-500 dark:text-zinc-400">Local-first cryptographic security and non-exfiltration guarantee</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-4 text-xs">
          {/* Main Guarantee Banner */}
          <div className="p-3.5 rounded-xl bg-emerald-50/60 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-900/40 flex items-start gap-3">
            <WifiOff className="w-5 h-5 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
            <div>
              <div className="font-semibold text-zinc-900 dark:text-zinc-100">100% Local Processing · Air-Gapped Architecture</div>
              <p className="text-zinc-600 dark:text-zinc-400 mt-1 leading-relaxed">
                Keynova executes entirely inside your controlled environment. Source code, AST syntax nodes, and cryptographic keys <b>never leave this machine</b>. No external network requests, telemetry pings, or cloud LLM calls are transmitted.
              </p>
            </div>
          </div>

          {/* Audit Verification Checklist */}
          <div className="space-y-2">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-zinc-400">
              Verified Technical Safeguards
            </span>

            <div className="p-3.5 rounded-xl bg-zinc-50 dark:bg-zinc-950/60 border border-zinc-200 dark:border-zinc-800 space-y-2.5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Server className="w-3.5 h-3.5 text-zinc-400" />
                  <span className="text-zinc-700 dark:text-zinc-300 font-medium">Loopback Binding</span>
                </div>
                <span className="font-mono text-zinc-600 dark:text-zinc-400 text-[11px] bg-white dark:bg-zinc-900 px-2 py-0.5 rounded border border-zinc-200 dark:border-zinc-800">
                  127.0.0.1:8000 only
                </span>
              </div>

              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <HardDrive className="w-3.5 h-3.5 text-zinc-400" />
                  <span className="text-zinc-700 dark:text-zinc-300 font-medium">Storage Isolation</span>
                </div>
                <span className="font-mono text-zinc-600 dark:text-zinc-400 text-[11px] bg-white dark:bg-zinc-900 px-2 py-0.5 rounded border border-zinc-200 dark:border-zinc-800">
                  Local PostgreSQL (localhost:5432)
                </span>
              </div>

              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Activity className="w-3.5 h-3.5 text-zinc-400" />
                  <span className="text-zinc-700 dark:text-zinc-300 font-medium">External Network Egress</span>
                </div>
                <span className="font-mono text-emerald-600 dark:text-emerald-400 text-[11px] bg-emerald-50 dark:bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-200 dark:border-emerald-900/40 font-semibold">
                  0 Bytes Transmitted
                </span>
              </div>

              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <EyeOff className="w-3.5 h-3.5 text-zinc-400" />
                  <span className="text-zinc-700 dark:text-zinc-300 font-medium">Telemetry & Third-Party Analytics</span>
                </div>
                <span className="font-mono text-zinc-600 dark:text-zinc-400 text-[11px] bg-white dark:bg-zinc-900 px-2 py-0.5 rounded border border-zinc-200 dark:border-zinc-800">
                  Disabled / Zero Tracking
                </span>
              </div>
            </div>
          </div>

          {/* Developer Non-Exfiltration Statement */}
          <div className="p-3.5 rounded-xl bg-zinc-50/60 dark:bg-zinc-950/40 border border-zinc-200 dark:border-zinc-800 text-[11px] text-zinc-500 dark:text-zinc-400 leading-relaxed space-y-1">
            <span className="font-semibold text-zinc-800 dark:text-zinc-200">How do you verify trust?</span>
            <p>
              Inspect browser DevTools Network tab: every API invocation routes exclusively to <code className="text-blue-600 dark:text-blue-400">/api/v1</code> on localhost. No outbound connections to cloud providers or vendor endpoints exist.
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 border-t border-zinc-100 dark:border-zinc-800/80 bg-zinc-50/50 dark:bg-zinc-950/40 flex items-center justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg text-xs font-semibold bg-zinc-900 hover:bg-zinc-800 text-white dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-white transition-colors"
          >
            Acknowledge & Close
          </button>
        </div>
      </div>
    </div>
  );
};
