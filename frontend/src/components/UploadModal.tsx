import React, { useEffect, useState } from 'react';
import { X, UploadCloud, FileCode2, Loader2, ScanLine, ArrowRight } from 'lucide-react';
import { uploadArchive } from '../lib/api';

interface UploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  projectId: string;
  onEnsureProject: (archiveName: string) => Promise<string>;
  onScanCompleted: (scanId: string, baselineScanId: string | null) => void;
  baselineScanId?: string | null;
}

export const UploadModal: React.FC<UploadModalProps> = ({
  isOpen,
  onClose,
  projectId,
  onEnsureProject,
  onScanCompleted,
  baselineScanId
}) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [compareWithBaseline, setCompareWithBaseline] = useState(Boolean(baselineScanId));

  useEffect(() => {
    setCompareWithBaseline(Boolean(baselineScanId));
  }, [baselineScanId]);

  if (!isOpen) return null;

  const chooseFile = (file?: File) => {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith('.zip')) {
      setError('Please choose a .zip archive to continue.');
      return;
    }
    setSelectedFile(file);
    setError(null);
  };

  const startScan = async (file: File) => {
    setIsProcessing(true);
    setError(null);
    try {
      const targetProjectId = projectId || await onEnsureProject(file.name);
      const result = await uploadArchive(
        targetProjectId,
        file,
        compareWithBaseline ? (baselineScanId || undefined) : undefined
      );
      onScanCompleted(result.scan_id, compareWithBaseline ? baselineScanId || null : null);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The archive could not be scanned.');
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm transition-opacity"
      role="presentation"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && !isProcessing) onClose();
      }}
    >
      <div
        className="w-full max-w-lg bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col text-zinc-900 dark:text-zinc-100 animate-in fade-in zoom-in-95 duration-200"
        role="dialog"
        aria-modal="true"
        aria-labelledby="scan-modal-title"
      >
        {/* Header */}
        <div className="px-6 py-5 border-b border-zinc-100 dark:border-zinc-800/80 flex items-center justify-between bg-zinc-50/50 dark:bg-zinc-950/40">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-blue-50 dark:bg-blue-950/50 border border-blue-200 dark:border-blue-900/50 text-blue-600 dark:text-blue-400">
              <ScanLine className="w-5 h-5" />
            </div>
            <div>
              <span className="text-[10px] font-bold tracking-wider uppercase text-blue-600 dark:text-blue-400">
                New Cryptographic Analysis
              </span>
              <h2 id="scan-modal-title" className="text-base font-bold text-zinc-900 dark:text-zinc-100 font-['Outfit']">
                Scan Codebase for PQC Debt
              </h2>
              <p className="text-xs text-zinc-500 dark:text-zinc-400">
                Upload a ZIP archive for local AST syntax and dependency analysis.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            disabled={isProcessing}
            className="p-1.5 rounded-lg text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors"
            aria-label="Close"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-4">
          {/* Drag & Drop Upload Zone */}
          <div>
            <div className="text-[11px] font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wider mb-2">
              Or Upload Source Archive
            </div>
            <label
              className={`flex flex-col items-center justify-center p-6 border-2 border-dashed rounded-xl cursor-pointer transition-colors ${
                selectedFile
                  ? 'border-blue-500 bg-blue-50/40 dark:bg-blue-950/20'
                  : 'border-zinc-300 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-950/40 hover:bg-zinc-100 dark:hover:bg-zinc-900'
              }`}
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault();
                chooseFile(e.dataTransfer.files[0]);
              }}
            >
              <input
                type="file"
                accept=".zip,application/zip"
                className="hidden"
                onChange={(e) => chooseFile(e.target.files?.[0])}
                disabled={isProcessing}
              />
              <div className="p-3 rounded-full bg-white dark:bg-zinc-800 shadow-sm border border-zinc-200 dark:border-zinc-700 text-zinc-500 dark:text-zinc-400 mb-2">
                <UploadCloud className="w-5 h-5 text-blue-600 dark:text-blue-400" />
              </div>
              <span className="text-xs font-semibold text-zinc-800 dark:text-zinc-200">
                {selectedFile ? selectedFile.name : 'Click to select or drag and drop ZIP'}
              </span>
              <span className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-0.5">
                {selectedFile
                  ? `${(selectedFile.size / 1024).toFixed(1)} KB · Ready to scan`
                  : 'Supported: .zip archives up to 25 MB'}
              </span>
            </label>
          </div>

          {/* Baseline Comparison Option */}
          {baselineScanId && (
            <label className="flex items-center gap-2.5 p-3 rounded-xl bg-zinc-50 dark:bg-zinc-950/40 border border-zinc-200 dark:border-zinc-800 text-xs cursor-pointer select-none">
              <input
                type="checkbox"
                checked={compareWithBaseline}
                onChange={(e) => setCompareWithBaseline(e.target.checked)}
                className="rounded border-zinc-300 dark:border-zinc-700 text-blue-600 focus:ring-blue-500"
              />
              <span className="text-zinc-700 dark:text-zinc-300">
                Auto-compare and calculate mathematical delta against baseline scan{' '}
                <code className="text-blue-600 dark:text-blue-400 font-mono text-[11px]">
                  {baselineScanId.slice(0, 8)}
                </code>
              </span>
            </label>
          )}

          {/* Error Message */}
          {error && (
            <div className="p-3 rounded-xl bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-400 text-xs">
              {error}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-zinc-100 dark:border-zinc-800/80 bg-zinc-50/50 dark:bg-zinc-950/40 flex items-center justify-between">
          <span className="text-[11px] text-zinc-400 flex items-center gap-1.5">
            <FileCode2 className="w-3.5 h-3.5" />
            Air-gapped local AST parse
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              disabled={isProcessing}
              className="px-3.5 py-1.5 rounded-lg text-xs font-medium text-zinc-600 dark:text-zinc-300 hover:bg-zinc-200/60 dark:hover:bg-zinc-800 transition-colors"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => selectedFile && startScan(selectedFile)}
              disabled={!selectedFile || isProcessing}
              className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-40 disabled:cursor-not-allowed shadow-sm transition-all"
            >
              {isProcessing ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  Analyzing Codebase...
                </>
              ) : (
                <>
                  Start Analysis
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
